"""
AES-256-GCM 加密/解密工具 — 反诈数据加密防护
密钥通过外部文件或环境变量注入，代码中无任何硬编码密钥
"""
import os
import struct
from Crypto.Cipher import AES  # nosec B413
from Crypto.Random import get_random_bytes  # nosec B413


class KeyManager:
    """密钥管理器：生成、读取、验证 AES-256 密钥"""

    KEY_LENGTH = 32  # 256 bits
    KEY_FILE_MAGIC = b"AFS_KEY_V1"  # 密钥文件标识头

    @classmethod
    def generate_key(cls) -> bytes:
        """生成 256 位随机密钥"""
        return get_random_bytes(cls.KEY_LENGTH)

    @classmethod
    def save_key(cls, key: bytes, filepath: str):
        """将密钥保存到文件（带校验头）"""
        if len(key) != cls.KEY_LENGTH:
            raise ValueError(f"密钥长度必须为 {cls.KEY_LENGTH} 字节")
        with open(filepath, "wb") as f:
            f.write(cls.KEY_FILE_MAGIC)
            f.write(key)

    @classmethod
    def load_key(cls, filepath: str) -> bytes:
        """从文件加载密钥并校验"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"密钥文件不存在: {filepath}")
        with open(filepath, "rb") as f:
            magic = f.read(len(cls.KEY_FILE_MAGIC))
            if magic != cls.KEY_FILE_MAGIC:
                raise ValueError("密钥文件格式不正确")
            key = f.read(cls.KEY_LENGTH)
        if len(key) != cls.KEY_LENGTH:
            raise ValueError("密钥文件内容不完整")
        return key

    @classmethod
    def load_key_from_env(cls, env_var: str = "AFS_ENCRYPTION_KEY") -> bytes:
        """从环境变量加载 Base64 编码的密钥"""
        import base64
        key_b64 = os.environ.get(env_var, "")
        if not key_b64:
            raise ValueError(f"环境变量 {env_var} 未设置")
        key = base64.b64decode(key_b64)
        if len(key) != cls.KEY_LENGTH:
            raise ValueError(f"密钥长度不正确，期望 {cls.KEY_LENGTH} 字节")
        return key


class AESCipher:
    """AES-256-GCM 加密器，提供认证加密与防篡改能力"""

    NONCE_LENGTH = 12  # GCM 推荐 12 字节 nonce
    TAG_LENGTH = 16    # GCM 认证标签 16 字节

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 需要 32 字节密钥")
        self._key = key

    def encrypt(self, plaintext: str) -> bytes:
        """加密字符串，返回 nonce + tag + ciphertext 的二进制数据"""
        nonce = get_random_bytes(self.NONCE_LENGTH)
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
        # 格式: nonce(12) + tag(16) + ciphertext
        return nonce + tag + ciphertext

    def decrypt(self, encrypted_data: bytes) -> str:
        """解密二进制数据，返回原始字符串"""
        if len(encrypted_data) < self.NONCE_LENGTH + self.TAG_LENGTH:
            raise ValueError("密文数据不完整")
        nonce = encrypted_data[:self.NONCE_LENGTH]
        tag = encrypted_data[self.NONCE_LENGTH:self.NONCE_LENGTH + self.TAG_LENGTH]
        ciphertext = encrypted_data[self.NONCE_LENGTH + self.TAG_LENGTH:]
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")

    def encrypt_file(self, input_path: str, output_path: str):
        """加密文件：读取明文文件，写入加密文件"""
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"输入文件不存在: {input_path}")
        with open(input_path, "r", encoding="utf-8") as f:
            plaintext = f.read()
        encrypted = self.encrypt(plaintext)
        with open(output_path, "wb") as f:
            f.write(encrypted)

    def decrypt_file(self, input_path: str, output_path: str):
        """解密文件：读取加密文件，写入明文文件"""
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"输入文件不存在: {input_path}")
        with open(input_path, "rb") as f:
            encrypted = f.read()
        plaintext = self.decrypt(encrypted)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(plaintext)

    def encrypt_bytes(self, data: bytes) -> bytes:
        """加密二进制数据"""
        nonce = get_random_bytes(self.NONCE_LENGTH)
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext

    def decrypt_bytes(self, encrypted_data: bytes) -> bytes:
        """解密二进制数据"""
        nonce = encrypted_data[:self.NONCE_LENGTH]
        tag = encrypted_data[self.NONCE_LENGTH:self.NONCE_LENGTH + self.TAG_LENGTH]
        ciphertext = encrypted_data[self.NONCE_LENGTH + self.TAG_LENGTH:]
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
