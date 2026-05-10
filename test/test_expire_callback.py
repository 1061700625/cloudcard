#!/usr/bin/env python3
"""测试 on_expire 回调：1分钟卡密，等待回调触发"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xfcloudcard import CardClient

callback_fired = False

def on_expire():
    global callback_fired
    callback_fired = True
    print("\n🔔 on_expire 回调触发！卡密已过期！\n")

card = os.environ.get('TEST_CARD', 'CARD-XXXX')
print(f"开始测试：1分钟卡密 + on_expire 回调")
print(f"卡密：{card}")
print("预计 60 秒左右触发回调...\n")

with CardClient(
    server_url="http://localhost:8000",
    card_key=card,
    heartbeat_interval=10,
    on_expire=on_expire,
) as client:
    print("✅ 验证成功，心跳已启动（间隔10秒）")
    print("等待过期回调触发...\n")
    for i in range(90):
        if callback_fired:
            print("✅ 测试通过：on_expire 回调已触发！")
            break
        print(f"  等待中... ({i+1}0s)", end="\r")
        time.sleep(1)
    else:
        print("\n❌ 测试失败：90秒内回调未触发")
        sys.exit(1)

print("\n测试完成。")
