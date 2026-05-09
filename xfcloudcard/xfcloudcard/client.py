"""
卡密验证客户端库
支持作为库导入使用，也支持命令行运行。

作为库使用：
    from xfcloudcard import CardClient

    def my_callback():
        print("卡密已过期！")

    # 方式一：手动验证
    with CardClient(server_url="http://...", key="...") as client:
        result = client.verify("CARD-XXXX-...")
        if result['success']:
            pass  # 业务代码

    # 方式二：传入 card_key，自动验证
    with CardClient(card_key="CARD-XXXX-...", on_expire=my_callback) as client:
        pass  # 验证成功，心跳已启动，直接写业务代码
    # 退出 with 块时自动停止心跳并发送离线通知
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import time
import signal
import threading
from typing import Optional, Callable, Any

from crypto import CryptoManager
from device_info import get_device_sn, get_ip_address


# 默认配置（可通过环境变量或参数覆盖）
DEFAULT_SERVER_URL = "http://localhost:8000"
DEFAULT_KEY = "cloud-card-system-key-32bytes!!"


class CardClient:
    """
    卡密验证客户端（支持上下文管理器）

    用法一：手动验证
        with CardClient(server_url="http://...", key="...") as client:
            result = client.verify("CARD-XXXX-...")
            if result['success']:
                pass  # 业务代码

    用法二：初始化时传入 card_key，自动验证
        with CardClient(card_key="CARD-XXXX-...", on_expire=cb) as client:
            # 验证成功，心跳已启动
            pass  # 业务代码
    """

    def __init__(
        self,
        server_url: str = None,
        key: str = None,
        card_key: str = None,
        heartbeat_interval: int = 60,
        on_expire: Callable = None,
    ):
        """
        Args:
            server_url:         服务器URL，默认 http://localhost:8000
            key:                加密密钥（必须与服务器端相同）
            card_key:           卡密（传入则 __enter__ 时自动验证并启动心跳）
            heartbeat_interval: 心跳间隔秒数（默认60秒）
            on_expire:          卡密过期时的回调函数（可选）
        """
        self.server_url = (server_url or DEFAULT_SERVER_URL).rstrip('/')
        raw_key = (key or DEFAULT_KEY).encode('utf-8')
        self.crypto = CryptoManager(raw_key)
        self.device_sn = get_device_sn()
        self.ip_address = get_ip_address()
        self.heartbeat_interval = heartbeat_interval
        self._on_expire = on_expire
        self._init_card_key = card_key  # 初始化时传入的卡密

        self._heartbeat_running = False
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._current_card_key: Optional[str] = None
        self._lock = threading.Lock()
        self._verify_result: Optional[dict] = None  # __enter__ 的验证结果

    # ─────────────────────────────────────────────
    # 上下文管理器
    # ─────────────────────────────────────────────
    def __enter__(self):
        """如果初始化时传入了 card_key，自动验证。验证失败则抛异常。"""
        if self._init_card_key is not None:
            result = self.verify(self._init_card_key)
            self._verify_result = result
            if not result.get('success'):
                raise RuntimeError(f"卡密验证失败: {result['message']}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    # ─────────────────────────────────────────────
    # 公开 API
    # ─────────────────────────────────────────────

    def verify(self, card_key: str) -> dict:
        """
        验证卡密。
        验证成功时自动启动心跳线程；验证失败或卡密不变时复用已有心跳。

        Returns:
            dict: {
                'success': bool,
                'message': str,
                'remaining_seconds': int,
                'rate_limited': bool,   # 是否因频率限制被拒
            }
        """
        result = self._send_verify_request(card_key)

        if result.get('success') and not result.get('rate_limited'):
            with self._lock:
                self._current_card_key = card_key
                self._start_heartbeat_unsafe()

        return result

    def verify_only(self, card_key: str) -> dict:
        """
        只验证卡密，不启动心跳（适用于一次性检查场景）。

        Returns:
            同 verify()
        """
        return self._send_verify_request(card_key)

    def close(self):
        """停止心跳并发送离线通知。可重复调用。"""
        self._stop_heartbeat()
        self._send_offline()
        self._current_card_key = None

    def is_online(self) -> bool:
        """当前是否有活跃心跳"""
        return self._heartbeat_running

    # ─────────────────────────────────────────────
    # 内部方法
    # ─────────────────────────────────────────────

    def _send_verify_request(self, card_key: str) -> dict:
        """构造、加密、发送验证请求，返回解析后的结果字典。"""
        import requests

        request_data = {
            'card_key': card_key,
            'device_sn': self.device_sn,
            'ip_address': self.ip_address,
            'timestamp': int(time.time()),
        }

        try:
            payload = self._encrypt_and_sign(request_data)
        except Exception as e:
            return _err(f"加密失败: {e}")

        try:
            response = requests.post(
                f"{self.server_url}/api/card/verify",
                json=payload,
                timeout=10,
            )
            if response.status_code != 200:
                return _err(f"服务器错误: {response.status_code}")
        except requests.exceptions.RequestException as e:
            return _err(f"网络错误: {e}")

        result = self._decrypt_response(response.json())
        return result

    def _start_heartbeat_unsafe(self):
        """调用前需持有 self._lock"""
        if self._heartbeat_running:
            return
        self._heartbeat_running = True
        self._hb_printed = False  # 重置打印标记
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self):
        with self._lock:
            if not self._heartbeat_running:
                return
            self._heartbeat_running = False
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)

    def _heartbeat_loop(self):
        """心跳循环，自动检测卡密过期并触发 on_expire 回调。"""
        import requests

        while self._heartbeat_running and self._current_card_key:
            try:
                request_data = {
                    'device_sn': self.device_sn,
                    'ip_address': self.ip_address,
                    'card_key': self._current_card_key,
                    'timestamp': int(time.time()),
                }
                payload = self._encrypt_and_sign(request_data)

                resp = requests.post(
                    f"{self.server_url}/api/client/heartbeat",
                    json=payload,
                    timeout=5,
                )

                if resp.status_code == 200:
                    resp_json = resp.json()
                    resp_data = self._decrypt_response(resp_json)
                    if not resp_data.get('success'):
                        print(f"[心跳] 服务端返回失败: {resp_data.get('message', '')}")
                    else:
                        remaining = resp_data.get('remaining_seconds')
                        expire_minutes = resp_data.get('expire_minutes', 0)
                        valid_str = _format_minutes(expire_minutes) if expire_minutes else ""
                        if remaining is not None and remaining <= 0:
                            if self._on_expire:
                                try:
                                    self._on_expire()
                                except Exception:
                                    pass
                            self._heartbeat_running = False
                            break
                        # 首次成功时打印有效期
                        if not hasattr(self, '_hb_printed'):
                            if valid_str:
                                print(f"[心跳] 卡密有效期: {valid_str}，剩余: {_format_time(remaining)}")
                            else:
                                print(f"[心跳] 剩余: {_format_time(remaining)}")
                            self._hb_printed = True
                        # 剩余不足5分钟时每次提醒
                        elif remaining is not None and remaining < 300:
                            print(f"[心跳] ⚠️ 即将过期，剩余: {_format_time(remaining)}")
                else:
                    # 打印详细错误信息便于排查
                    try:
                        err_detail = resp.json().get('detail', resp.text[:200])
                    except Exception:
                        err_detail = resp.text[:200]
                    print(f"[心跳] 发送失败({resp.status_code}): {err_detail}")

            except Exception as e:
                print(f"[心跳] 发送失败: {e}")

            # 可中断的休眠
            for _ in range(self.heartbeat_interval):
                if not self._heartbeat_running:
                    break
                time.sleep(1)

    def _send_offline(self):
        if not self._current_card_key:
            return
        import requests

        try:
            request_data = {
                'device_sn': self.device_sn,
                'timestamp': int(time.time()),
            }
            payload = self._encrypt_and_sign(request_data)

            resp = requests.post(
                f"{self.server_url}/api/client/offline",
                json=payload,
                timeout=5,
            )
            if resp.status_code == 200:
                print("[离线] 已通知服务器")
            else:
                print(f"[离线] 通知失败: {resp.status_code}")
        except Exception as e:
            print(f"[离线] 发送失败: {e}")

    # ─────────────────────────────────────────────
    # 加密 / 解密辅助
    # ─────────────────────────────────────────────

    def _encrypt_and_sign(self, data: dict) -> dict:
        plaintext = json.dumps(data)
        encrypted = self.crypto.encrypt(plaintext)
        data_to_sign = encrypted['ciphertext'] + encrypted['iv']
        signature = self.crypto.generate_hmac(data_to_sign)
        return {
            'ciphertext': encrypted['ciphertext'],
            'iv': encrypted['iv'],
            'signature': signature,
        }

    def _decrypt_response(self, response_data: dict) -> dict:
        try:
            to_verify = response_data['ciphertext'] + response_data['iv']
            if not self.crypto.verify_hmac(to_verify, response_data['signature']):
                return _err("响应签名验证失败")

            decrypted = self.crypto.decrypt(
                response_data['ciphertext'],
                response_data['iv'],
            )
            return json.loads(decrypted)
        except Exception as e:
            return _err(f"解析响应失败: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# 装饰器：@require_card(...)
# ─────────────────────────────────────────────────────────────────────────────

def require_card(
    server_url: str = None,
    key: str = None,
    card_key: str = None,
    heartbeat_interval: int = 60,
    exit_on_fail: bool = True,
    on_expire: Callable = None,
):
    """
    装饰器：在业务函数执行前自动验证卡密。
    验证成功时自动管理心跳和离线通知。

    用法一：传入 card_key（推荐，无需交互）
        @require_card(card_key="CARD-XXXX-...")
        def main():
            pass  # 验证通过后才执行

    用法二：不传 card_key，运行时从环境变量 CARD_KEY 或交互输入获取
        @require_card()
        def main():
            pass

    参数:
        card_key:    卡密字符串（直接传入，无需交互）
        exit_on_fail: 验证失败时是否直接退出进程（默认 True）
        on_expire:   卡密过期时的回调函数（可选）
    """
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            with CardClient(
                server_url=server_url,
                key=key,
                card_key=card_key,   # 直接传入，__enter__ 时自动验证
                heartbeat_interval=heartbeat_interval,
                on_expire=on_expire,
            ) as client:
                # 如果初始化时没传 card_key，则走交互/环境变量
                if card_key is None:
                    ck = _prompt_or_env_card_key()
                    if not ck:
                        print("未提供卡密，退出。")
                        if exit_on_fail:
                            sys.exit(1)
                        return None
                    result = client.verify(ck)
                else:
                    # card_key 已在 __enter__ 中验证，直接取结果
                    result = client._verify_result

                _print_result(result)

                if not result.get('success'):
                    if exit_on_fail:
                        sys.exit(1)
                    return None

                return func(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# CLI 辅助函数（供命令行使用）
# ─────────────────────────────────────────────────────────────────────────────

def _prompt_or_env_card_key() -> Optional[str]:
    """优先从环境变量 CARD_KEY 读取，否则交互式输入"""
    import os
    key = os.environ.get("CARD_KEY")
    if key:
        return key.strip()
    try:
        return input("请输入卡密: ").strip() or None
    except (EOFError, KeyboardInterrupt):
        return None


def _print_result(result: dict):
    remaining = result.get('remaining_seconds', 0)
    expire_minutes = result.get('expire_minutes', 0)
    if result['success']:
        print(f"✅ 验证成功: {result['message']}")
        print(f"   剩余时间: {_format_time(remaining)}")
        if expire_minutes:
            print(f"   卡密有效期: {_format_minutes(expire_minutes)}")
    else:
        print(f"❌ 验证失败: {result['message']}")


def _format_time(seconds: int) -> str:
    if seconds <= 0:
        return "已过期"
    d, h = divmod(seconds, 86400)
    h, m = divmod(h, 3600)
    m, s = divmod(m, 60)
    parts = []
    if d:
        parts.append(f"{d}天")
    if h:
        parts.append(f"{h}小时")
    if m:
        parts.append(f"{m}分钟")
    if s or not parts:
        parts.append(f"{s}秒")
    return "".join(parts) or "0秒"


def _format_minutes(minutes: int) -> str:
    """将总分钟数格式化为「xx天xx时xx分」"""
    if minutes <= 0:
        return "0分"
    d, h = divmod(minutes, 1440)
    h, m = divmod(h, 60)
    parts = []
    if d:
        parts.append(f"{d}天")
    if h:
        parts.append(f"{h}时")
    if m or not parts:
        parts.append(f"{m}分")
    return "".join(parts)


def _err(msg: str) -> dict:
    return {'success': False, 'message': msg, 'remaining_seconds': 0}


# ─────────────────────────────────────────────────────────────────────────────
# CLI 入口（python -m xfcloudcard）
# ─────────────────────────────────────────────────────────────────────────────

def _cli_main():
    import argparse

    parser = argparse.ArgumentParser(description='卡密验证客户端')
    parser.add_argument('--server', default=DEFAULT_SERVER_URL, help='服务器URL')
    parser.add_argument('--key', default=DEFAULT_KEY, help='加密密钥')
    parser.add_argument('--card', help='卡密（直接验证模式）')
    parser.add_argument('--once', action='store_true', help='只验证一次，不启动心跳')
    parser.add_argument('--interactive', action='store_true', help='交互模式')
    parser.add_argument('--heartbeat', type=int, default=60, help='心跳间隔秒数')
    args = parser.parse_args()

    client = CardClient(
        server_url=args.server,
        key=args.key,
        heartbeat_interval=args.heartbeat,
    )

    # 信号处理：Ctrl+C 时优雅退出
    def _cleanup(signum=None, frame=None):
        print("\n正在退出...")
        client.close()
        print("感谢使用，再见！")
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, _cleanup)
        signal.signal(signal.SIGTERM, _cleanup)
    except ValueError:
        pass  # 非主线程中无法设置 signal

    print("=" * 60)
    print(f"设备序列号: {client.device_sn}")
    print(f"IP地址: {client.ip_address}")
    print("=" * 60)

    if args.card:
        result = client.verify_only(args.card) if args.once else client.verify(args.card)
        _print_result(result)
        if result.get('success') and not args.once:
            print(f"\n💓 心跳已启动（间隔 {args.heartbeat} 秒），按 Ctrl+C 退出...")
            _wait_forever()
        return

    if args.once:
        card_key = _prompt_or_env_card_key()
        if not card_key:
            return
        result = client.verify_only(card_key)
        _print_result(result)
        return

    # 交互模式（默认）
    print("交互模式（输入 'quit' 退出）\n")
    while True:
        try:
            card_key = input("请输入卡密: ").strip()
            if card_key.lower() == 'quit':
                _cleanup()
            if not card_key:
                print("卡密不能为空！")
                continue
            result = client.verify(card_key)
            _print_result(result)
            if result.get('success'):
                print(f"\n💓 心跳已启动，按 Ctrl+C 退出...")
                _wait_forever()
        except KeyboardInterrupt:
            _cleanup()
        except Exception as e:
            print(f"错误: {e}")


def _wait_forever():
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    _cli_main()
