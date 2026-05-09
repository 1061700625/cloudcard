# xfcloudcard

云控卡密验证客户端库，支持 AES-256-CBC + HMAC-SHA256 加密通信、心跳保活、**卡密过期回调**。

## 安装

```bash
pip install xfcloudcard
```

## 快速开始

### 方式一：`with` 上下文管理器（推荐）

```python
from xfcloudcard import CardClient

def on_expire():
    print("卡密已过期！")

# 传入 card_key，自动验证并启动心跳
with CardClient(card_key="CARD-XXXX-...", on_expire=on_expire) as client:
    # 验证通过，直接写业务代码
    pass
# 退出时自动停止心跳 + 发送离线通知
```

### 方式二：`@require_card` 装饰器

```python
from xfcloudcard import require_card

@require_card(card_key="CARD-XXXX-...")
def main():
    # 验证通过后才执行
    pass

main()
```

### 方式三：只验证不心跳

```python
from xfcloudcard import CardClient

client = CardClient()
result = client.verify_only("CARD-XXXX-...")
print(result['success'], result['message'])
```

## API

### `CardClient` 参数

| 参数 | 说明 |
|------|------|
| `card_key` | 卡密（传入则 `with` 进入时自动验证） |
| `server_url` | 服务端地址，默认 `http://localhost:8000` |
| `key` | 加密密钥，默认内置 |
| `heartbeat_interval` | 心跳间隔秒数，默认 `60` |
| `on_expire` | 卡密过期时的回调函数 |

### `CardClient` 方法

| 方法 | 说明 |
|------|------|
| `verify(card_key)` | 验证卡密，成功后自动启动心跳 |
| `verify_only(card_key)` | 只验证，不启动心跳 |
| `close()` | 停止心跳并发送离线通知 |
| `is_online()` | 返回心跳是否运行中 |

### `require_card()` 参数

| 参数 | 说明 |
|------|------|
| `card_key` | 卡密（直接传入，无需交互） |
| `exit_on_fail` | 验证失败是否直接退出，默认 `True` |
| `on_expire` | 卡密过期时的回调函数 |

## 依赖

- `requests >= 2.25.0`
- `pycryptodome >= 3.15.0`

## 许可

MIT
