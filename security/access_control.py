"""
安全访问控制 — 本地账号权限校验，防止非授权执行
"""
import os
import sys
import ctypes
import getpass
import platform


class AccessController:
    """执行权限控制器：验证当前用户是否有权运行反诈数据处理脚本"""

    # 已授权的管理员账号白名单（用户名）
    _AUTHORIZED_USERS = set()

    @classmethod
    def _is_windows(cls) -> bool:
        return platform.system() == "Windows"

    @classmethod
    def check_admin_privilege(cls) -> bool:
        """
        检查当前进程是否以管理员权限运行
        Windows: 通过 ctypes 调用 Shell32.IsUserAnAdmin()
        Linux/macOS: 检查 UID 是否为 0
        """
        if cls._is_windows():
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        else:
            return os.getuid() == 0

    @classmethod
    def get_current_user(cls) -> str:
        """获取当前系统用户名"""
        return getpass.getuser()

    @classmethod
    def load_authorized_users(cls, filepath: str = None):
        """从授权文件加载白名单用户"""
        if filepath is None:
            filepath = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "authorized_users.txt",
            )
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    name = line.strip()
                    if name and not name.startswith("#"):
                        cls._AUTHORIZED_USERS.add(name)

    @classmethod
    def is_authorized(cls) -> bool:
        """
        综合校验：管理员权限 + 用户白名单
        如果白名单为空，则仅校验管理员权限
        """
        if not cls.check_admin_privilege():
            return False
        if cls._AUTHORIZED_USERS:
            return cls.get_current_user() in cls._AUTHORIZED_USERS
        return True

    @classmethod
    def require_authorization(cls, operation: str = "执行此操作"):
        """
        强制授权检查，未通过则拒绝执行
        用于关键操作（数据导出、密钥访问等）的前置校验
        """
        if not cls.check_admin_privilege():
            raise PermissionError(
                f"权限不足：{operation}需要管理员权限，当前用户为 {cls.get_current_user()}"
            )
        if cls._AUTHORIZED_USERS and cls.get_current_user() not in cls._AUTHORIZED_USERS:
            raise PermissionError(
                f"用户 {cls.get_current_user()} 不在授权白名单中，无法{operation}"
            )
