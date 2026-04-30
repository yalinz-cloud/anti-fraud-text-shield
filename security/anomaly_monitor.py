"""
异常操作监控模块 — 检测并告警批量数据导出等敏感操作
"""
import os
import time
import hashlib
import threading
from datetime import datetime
from collections import defaultdict


class AnomalyMonitor:
    """
    异常操作监控器

    监控策略：
    1. 短时间内高频文件读取 → 可能的数据窃取
    2. 涉诈特征库批量导出 → 触发弹窗告警
    3. 非工作时间异常访问 → 记录可疑行为
    """

    def __init__(self):
        self._access_log = defaultdict(list)          # 文件访问记录
        self._export_attempts = []                     # 导出尝试记录
        self._alert_callbacks = []                     # 告警回调列表
        self._lock = threading.Lock()
        self._suspicious_threshold_file_count = 50     # 短时间读取 >50 个文件视为可疑
        self._suspicious_threshold_export_size = 100   # 单次导出 >100 条特征视为批量
        self._time_window_seconds = 60                 # 监控时间窗口（秒）

    def register_alert_callback(self, callback):
        """注册告警回调函数"""
        self._alert_callbacks.append(callback)

    def _trigger_alert(self, alert_type: str, details: dict):
        """触发告警"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            "timestamp": timestamp,
            "type": alert_type,
            "details": details,
        }
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception:
                pass
        return alert

    def record_file_access(self, filepath: str, operation: str = "read"):
        """记录文件访问行为"""
        with self._lock:
            now = time.time()
            self._access_log[operation].append((now, filepath))
            # 清理过期记录
            self._access_log[operation] = [
                (t, f) for t, f in self._access_log[operation]
                if now - t < self._time_window_seconds
            ]
            # 检查高频访问
            if len(self._access_log[operation]) > self._suspicious_threshold_file_count:
                return self._trigger_alert("high_frequency_access", {
                    "operation": operation,
                    "file_count": len(self._access_log[operation]),
                    "time_window_seconds": self._time_window_seconds,
                    "recent_files": [f for _, f in self._access_log[operation][-10:]],
                })
        return None

    def check_bulk_export(self, export_data: list, export_label: str = "") -> dict:
        """
        检查是否为批量导出操作

        Args:
            export_data: 待导出的数据列表
            export_label: 导出数据标签

        Returns:
            dict: 告警信息，如果未触发告警则返回 None
        """
        if not isinstance(export_data, list):
            return None

        record_count = len(export_data)
        with self._lock:
            self._export_attempts.append({
                "time": time.time(),
                "count": record_count,
                "label": export_label,
            })

        if record_count > self._suspicious_threshold_export_size:
            alert = self._trigger_alert("bulk_export_attempt", {
                "export_label": export_label,
                "record_count": record_count,
                "threshold": self._suspicious_threshold_export_size,
                "data_hash": hashlib.sha256(
                    str(export_data[:10]).encode()
                ).hexdigest()[:16],
            })
            return alert
        return None

    def check_off_hours_access(self) -> bool:
        """检查是否在非工作时间（22:00-06:00）访问"""
        current_hour = datetime.now().hour
        return current_hour >= 22 or current_hour < 6

    def get_access_summary(self) -> dict:
        """获取访问行为摘要"""
        with self._lock:
            return {
                "read_operations": len(self._access_log.get("read", [])),
                "write_operations": len(self._access_log.get("write", [])),
                "export_attempts": len(self._export_attempts),
                "total_alerts": len([e for e in self._export_attempts
                                    if e["count"] > self._suspicious_threshold_export_size]),
            }


# 全局单例
_global_monitor = None


def get_monitor() -> AnomalyMonitor:
    """获取全局异常监控器实例"""
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = AnomalyMonitor()
    return _global_monitor
