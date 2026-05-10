"""
xfcloudcard - 云控卡密验证客户端库

支持 AES-256-CBC + HMAC-SHA256 加密通信、
心跳保活、过期回调，可作为库集成到业务代码中。

快速开始（方式一：传入 card_key，自动验证）:
    >>> from xfcloudcard import CardClient
    >>> with CardClient(card_key="CARD-XXXX-...", on_expire=cb) as client:
    ...     # 验证成功，心跳已启动
    ...     pass  # 业务代码

快速开始（方式二：手动验证）:
    >>> from xfcloudcard import CardClient
    >>> with CardClient(server_url="http://localhost:8000") as client:
    ...     result = client.verify("CARD-XXXX-...")
    ...     if result['success']:
    ...         pass  # 业务代码
"""

from .client import CardClient, require_card

__version__ = "1.0.4"
__author__ = "songxf"
__license__ = "MIT"

__all__ = [
    "CardClient",
    "require_card",
]
