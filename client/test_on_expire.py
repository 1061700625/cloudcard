"""测试 on_expire 回调功能

用法:
    python3 test_on_expire.py

然后输入一个有效的卡密，观察卡密过期时是否触发回调。
"""

import sys
import time

from xfcloudcard import CardClient


expired = False

def my_callback():
    """卡密过期时的回调函数"""
    global expired
    expired = True
    print("\n🔴 on_expire 回调触发：卡密已过期！")


def main():
    with CardClient(
        server_url="http://localhost:8000",
        key="cloud-card-system-key-32bytes!!",
        heartbeat_interval=60,
        on_expire=my_callback,
    ) as client:
        card_key = input("请输入卡密: ").strip()
        if not card_key:
            print("未提供卡密，退出。")
            return

        result = client.verify(card_key)
        if not result['success']:
            print(f"❌ 验证失败: {result['message']}")
            return

        remaining = result.get('remaining_seconds', 0)
        print(f"✅ 验证成功，剩余时间: {remaining} 秒")
        print("心跳已启动，等待卡密过期...\n")

        while not expired:
            time.sleep(1)

        print("已触发过期回调，退出。")


if __name__ == "__main__":
    main()
