"""
客户端加密解密模块
使用AES-256-CBC加密和HMAC SHA256签名
密钥派生：从主密钥派生独立的加密密钥和HMAC密钥（与服务端保持一致）
"""
import base64
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class CryptoManager:
    """加密管理器（客户端版本）"""

    def __init__(self, key: bytes):
        """
        初始化加密管理器，从主密钥派生独立密钥

        Args:
            key: 主密钥（必须与服务器端相同，任意长度）
        """
        # 主密钥归一化为32字节
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        # 派生独立密钥：加密密钥 和 HMAC密钥（与服务端一致）
        self.enc_key = hashlib.sha256(key + b"enc").digest()
        self.hmac_key = hashlib.sha256(key + b"hmac").digest()

    def encrypt(self, data: str) -> dict:
        """
        加密数据

        Args:
            data: 要加密的字符串数据

        Returns:
            包含加密数据和IV的字典
        """
        from Crypto.Random import get_random_bytes

        # 生成随机IV (16字节)
        iv = get_random_bytes(16)

        # 创建AES加密器
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv)

        # 加密数据
        ciphertext = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))

        # 返回base64编码的密文和IV
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }

    def decrypt(self, ciphertext: str, iv: str) -> str:
        """
        解密数据

        Args:
            ciphertext: base64编码的密文
            iv: base64编码的IV

        Returns:
            解密后的字符串
        """
        # 解码base64
        ciphertext_bytes = base64.b64decode(ciphertext)
        iv_bytes = base64.b64decode(iv)

        # 创建AES解密器
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv_bytes)

        # 解密并去除填充
        plaintext = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)

        return plaintext.decode('utf-8')

    def generate_hmac(self, data: str) -> str:
        """
        生成HMAC签名

        Args:
            data: 要签名的数据

        Returns:
            HMAC签名（十六进制字符串）
        """
        return hmac.new(self.hmac_key, data.encode('utf-8'), hashlib.sha256).hexdigest()

    def verify_hmac(self, data: str, signature: str) -> bool:
        """
        验证HMAC签名

        Args:
            data: 原始数据
            signature: HMAC签名

        Returns:
            签名是否有效
        """
        expected_signature = self.generate_hmac(data)
        return hmac.compare_digest(expected_signature, signature)
