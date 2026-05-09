"""基本功能测试：验证 xfcloudcard 库导入和基本使用"""

from xfcloudcard import CardClient, require_card

def test_import():
    print("✅ xfcloudcard 导入成功")
    print(f"   CardClient: {CardClient}")
    print(f"   require_card: {require_card}")

def test_init():
    client = CardClient(
        server_url="http://localhost:8000",
        key="cloud-card-system-key-32bytes!!",
        on_expire=lambda: print("卡密已过期！"),
    )
    print("✅ CardClient 实例化成功")
    print(f"   设备SN: {client.device_sn[:16]}...")
    print(f"   IP地址:  {client.ip_address}")
    print(f"   on_expire 回调: 已设置")

if __name__ == "__main__":
    test_import()
    print()
    test_init()
    print()
    print("✅ 基本测试通过")
