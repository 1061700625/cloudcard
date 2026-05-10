"""
配置文件
"""
import os
from pathlib import Path

# 项目根目录
BASE_DIR = Path(__file__).parent

# 数据库配置
DATABASE_PATH = os.getenv('DATABASE_PATH', str(BASE_DIR / 'card_system.db'))

# 加密密钥（生产环境应从环境变量或密钥管理服务获取）
# 使用固定的密钥，客户端和服务器使用相同的密钥
# 默认密钥，生产环境请修改
DEFAULT_KEY = b'cloud-card-system-key-32bytes!!'

# API配置
API_HOST = os.getenv('API_HOST', '0.0.0.0')
API_PORT = int(os.getenv('API_PORT', '8000'))
API_DEBUG = os.getenv('API_DEBUG', 'False').lower() == 'true'

# 管理接口API Key（用于保护管理接口）
# 可通过环境变量 ADMIN_API_KEY 覆盖
ADMIN_API_KEY = os.getenv('ADMIN_API_KEY', 'admin-secret-key-12345')

# 卡密配置
CARD_KEY_LENGTH = 16  # 卡密长度（不包括分隔符）
CARD_KEY_PREFIX = 'CARD'  # 卡密前缀
CARD_KEY_SEPARATOR = '-'  # 卡密分隔符

# 设备绑定配置
MAX_DEVICES_PER_CARD = 1  # 每个卡密最多绑定的设备数量
VERIFY_INTERVAL_SECONDS = 300  # 验证间隔（秒），防止频繁验证
HEARTBEAT_OFFLINE_TIMEOUT = 120  # 心跳离线超时（秒），超过此时间未心跳则标记离线

# IP白名单配置
IP_WHITELIST_ENABLED = os.getenv('IP_WHITELIST_ENABLED', 'False').lower() == 'true'
# 格式：CIDR列表，如 ["127.0.0.1", "192.168.1.0/24"]
IP_WHITELIST = os.getenv('IP_WHITELIST', '').split(',') if os.getenv('IP_WHITELIST') else []

# 管理员操作审计日志保留天数（0=永久）
ADMIN_LOG_RETENTION_DAYS = int(os.getenv('ADMIN_LOG_RETENTION_DAYS', '90'))
