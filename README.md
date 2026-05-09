# 云控卡密验证系统

基于 FastAPI + SQLite 的卡密验证系统，支持 AES-256-CBC + HMAC-SHA256 加密通信、心跳保活、过期回调、离线上报。


<p align="center">
  <img src="https://github.com/user-attachments/assets/fb07b615-4133-4187-8c88-7d107dec0fd9" alt="" width="800"/>
</p>

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/00a27d7c-50b2-499a-8e48-e89632aab7d9" alt="" width="800"/>
</p>

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/9e19d2f3-1e71-4f65-8645-731bc70686dd" alt="" width="800"/>
</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/4f357cc8-3542-47d3-934a-f4e8acadb3be" alt="" width="800"/>
</p>

## 目录结构

```
card/
├── README.md          ← 本文件
├── client/            ← 测试客户端代码（import xfcloudcard）
├── server/            ← 服务端代码（FastAPI）
└── xfcloudcard/       ← 客户端库（PyPI 包，pip install xfcloudcard）
```

## 快速开始

### 安装客户端库

```bash
pip install xfcloudcard
```

### 服务端启动

```bash
cd server
pip install -r requirements.txt
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

管理后台：http://localhost:8000/admin

---

## 客户端使用方式

### 方式一：`with` 上下文管理器 —— 传入 `card_key`（推荐）

传入 `card_key` 后，`with` 块进入时自动完成验证并启动心跳，业务代码直接写：

```python
from xfcloudcard import CardClient

def on_expire():
    print("卡密已过期，请续费！")

with CardClient(
    card_key="CARD-XXXX-XXXX-XXXX-XXXX",  # ← 直接传卡密，自动验证
    on_expire=on_expire,
) as client:
    print("验证通过，心跳运行中...")
    # 直接写业务代码
# 退出 with 块时自动停止心跳并通知服务器离线
```

### 方式二：`with` 上下文管理器 —— 手动验证

不传 `card_key`，在 `with` 块内手动调用 `verify()`：

```python
from xfcloudcard import CardClient

with CardClient() as client:
    result = client.verify("CARD-XXXX-XXXX-XXXX-XXXX")
    if not result['success']:
        print(f"验证失败: {result['message']}")
        exit(1)
    print(f"剩余时间: {result['remaining_seconds']} 秒")
    # 业务代码
```

### 方式三：`@require_card` 装饰器 —— 传入 `card_key`（推荐）

```python
from xfcloudcard import require_card

@require_card(card_key="CARD-XXXX-XXXX-XXXX-XXXX")
def main():
    # 只有卡密验证通过后才会执行这里
    print("业务代码运行中...")

if __name__ == "__main__":
    main()
```

### 方式四：`@require_card` 装饰器 —— 交互式

不传 `card_key` 时，运行时从环境变量 `CARD_KEY` 读取，或直接交互输入：

```bash
export CARD_KEY="CARD-XXXX-XXXX-XXXX-XXXX"
python your_script.py
```

```python
from xfcloudcard import require_card

@require_card()   # 不传 card_key，运行时提示输入
def main():
    print("业务代码运行中...")

if __name__ == "__main__":
    main()
```

### 方式五：只验证不心跳

适合一次性检查场景（如启动时校验一次）：

```python
from xfcloudcard import CardClient

client = CardClient()
result = client.verify_only("CARD-XXXX-XXXX-XXXX-XXXX")
if result['success']:
    print("卡密有效")
else:
    print(f"无效: {result['message']}")
```

---

## on_expire 回调说明

当服务端检测到卡密过期时，会在下一次心跳响应中返回 `remaining_seconds <= 0`，客户端自动触发 `on_expire` 回调并停止心跳。

```python
def on_expire():
    """卡密过期时的处理"""
    print("卡密已过期！")
    # 可以做什么：
    # - 弹出提示让用户续费
    # - 停止业务功能
    # - 记录日志

client = CardClient(..., on_expire=on_expire)
```

**触发条件：**
1. 卡密到达过期时间
2. 下一次心跳请求时，服务端返回 `remaining_seconds <= 0`
3. 客户端触发 `on_expire()` 并自动停止心跳

---

## API 参考

### `CardClient` 参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `server_url` | str | `http://localhost:8000` | 服务端地址（含协议和端口） |
| `key` | str | 内置默认值 | AES 加密密钥（需与服务端一致，建议 32 字节） |
| `card_key` | str | `None` | 卡密（传入则 `with` 进入时自动验证并启动心跳） |
| `heartbeat_interval` | int | `60` | 心跳间隔（秒），建议 30~120 |
| `on_expire` | Callable | `None` | 卡密过期时的回调函数，格式：`def cb()` |

#### `server_url` 示例

```python
# 本地开发
CardClient(server_url="http://localhost:8000")

# 远程服务器
CardClient(server_url="https://api.example.com")

# 自定义端口
CardClient(server_url="http://192.168.1.100:9000")
```

#### `key` 示例

```python
# 使用默认密钥（开发环境）
CardClient()

# 使用自定义密钥（必须与服务端 DEFAULT_KEY 一致）
CardClient(key="my-32byte-secret-key-1234567890ab")
```

#### `card_key` 示例

```python
# 传入卡密，with 块进入时自动验证
with CardClient(card_key="CARD-XXXX-XXXX-XXXX-XXXX") as client:
    print("验证通过")
```

#### `heartbeat_interval` 示例

```python
# 每 30 秒发送一次心跳（更及时，但增加服务器负担）
CardClient(heartbeat_interval=30)

# 每 120 秒发送一次心跳（减轻服务器负担）
CardClient(heartbeat_interval=120)
```

#### `on_expire` 示例

```python
def my_callback():
    print("卡密已过期，请续费！")
    # 可以：弹窗提示、停止业务功能、记录日志等

with CardClient(card_key="...", on_expire=my_callback) as client:
    # 业务代码
```

### `CardClient` 方法

| 方法 | 说明 |
|------|------|
| `verify(card_key)` | 验证卡密，成功时自动启动心跳 |
| `verify_only(card_key)` | 只验证，不启动心跳 |
| `is_online()` | 返回当前心跳是否在运行 |
| `close()` | 停止心跳并发送离线通知 |

### 返回值（`verify` / `verify_only` / 心跳）

```python
{
    'success': True/False,
    'message': '验证成功',
    'remaining_seconds': 82510,   # 剩余秒数
    'expire_minutes': 1440,       # 卡密总有效分钟数（可用于显示「有效期」）
    'rate_limited': False,        # 是否因频率限制被拒
}
```

#### 返回值字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `success` | bool | 验证是否成功 |
| `message` | str | 成功/失败的描述信息 |
| `remaining_seconds` | int | 剩余有效秒数（`<=0` 表示已过期） |
| `expire_minutes` | int | 卡密总有效分钟数（客户端可用于显示「有效期：xx天xx时xx分」） |
| `rate_limited` | bool | 是否因验证频率过高被服务端拒绝 |

---

## 功能特性

- AES-256-CBC 加密 + HMAC-SHA256 签名
- 卡密激活/验证/过期检测
- **心跳保活（自动管理在线状态）**
- **`on_expire` 过期回调**
- 离线上报（`close()` 自动触发）
- 设备绑定（一卡一设备）
- IP 白名单（支持 CIDR）
- 频率限制防刷
- 管理后台（生成/禁用/删除/导入导出卡密）
- 在线设备实时查看
- 审计日志

## 许可

MIT
