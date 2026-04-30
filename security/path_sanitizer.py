"""
路径安全校验器 — 防止文件路径遍历与目录穿越攻击
遵循 OWASP 文件系统安全规范，对所有文件读写路径进行安全约束
"""
import os
import re


class PathSanitizer:
    """文件路径安全处理器：拦截路径遍历攻击，限制文件操作范围"""

    # 允许操作的基础目录列表（白名单模式）
    _ALLOWED_BASE_DIRS = []

    # 禁止的路径模式
    _BLOCKED_PATTERNS = [
        r"\.\.[/\\]",        # 父目录穿越
        r"\.\.$",            # 以 .. 结尾
        r"~[/\\]",           # 用户目录引用
        r"%(?:2e|2E){2}",   # URL编码的 ..
        r"%(?:25){2}(?:2e|2E|5c|5C)",  # 双重编码穿越
    ]

    # 保留设备名（Windows）
    _WINDOWS_DEVICE_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    }

    @classmethod
    def set_allowed_dirs(cls, dirs: list):
        """设置允许操作的基础目录白名单"""
        cls._ALLOWED_BASE_DIRS = [
            os.path.realpath(os.path.abspath(d)) for d in dirs
        ]

    @classmethod
    def sanitize(cls, path: str, base_dir: str = None) -> str:
        """
        对文件路径进行安全清洗

        检查项：
        1. 父目录穿越 (../, ..\\)
        2. 绝对路径越权（未在白名单内）
        3. Windows 保留设备名
        4. 符号链接逃逸
        """
        if not path:
            raise ValueError("路径不能为空")

        # 检查禁止模式
        for pattern in cls._BLOCKED_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                raise ValueError(f"检测到路径遍历攻击特征: {path}")

        # 解析真实路径
        abs_path = os.path.realpath(os.path.abspath(path))

        # 检查是否为 Windows 设备名
        name = os.path.splitext(os.path.basename(abs_path))[0].upper()
        if name in cls._WINDOWS_DEVICE_NAMES:
            raise ValueError(f"禁止访问系统保留设备: {path}")

        # 白名单范围校验
        if cls._ALLOWED_BASE_DIRS:
            allowed = any(
                abs_path.startswith(allowed_dir)
                for allowed_dir in cls._ALLOWED_BASE_DIRS
            )
            if not allowed:
                raise ValueError(f"路径超出允许范围: {path}")

        # 如果指定了 base_dir，要求路径在其下
        if base_dir:
            base_real = os.path.realpath(os.path.abspath(base_dir))
            if not abs_path.startswith(base_real):
                raise ValueError(f"路径 {path} 不在基础目录 {base_dir} 内")

        return abs_path

    @classmethod
    def safe_join(cls, base_dir: str, *paths: str) -> str:
        """
        安全路径拼接：防止通过用户输入绕过基础目录
        """
        base_real = os.path.realpath(os.path.abspath(base_dir))
        combined = os.path.join(base_real, *paths)
        abs_combined = os.path.realpath(os.path.abspath(combined))
        if not abs_combined.startswith(base_real):
            raise ValueError(f"路径拼接结果 '{combined}' 越出了基础目录 '{base_dir}'")
        return abs_combined

    @classmethod
    def validate_filename(cls, filename: str) -> bool:
        """
        校验文件名合法性：
        - 不能包含路径分隔符
        - 不能为空
        - 不能为设备名
        - 长度限制 255 字符
        """
        if not filename or len(filename) > 255:
            return False
        if os.sep in filename or os.altsep in filename:
            return False
        if "/" in filename or "\\" in filename:
            return False
        name_upper = os.path.splitext(filename)[0].upper()
        if name_upper in cls._WINDOWS_DEVICE_NAMES:
            return False
        # 不能包含控制字符
        if any(ord(c) < 32 for c in filename):
            return False
        return True
