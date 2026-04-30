"""
Anti-Fraud Text Shield — Global Configuration
"""
import os

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# 数据存储路径
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")

# 安全操作白名单目录（文件读写仅允许在这些目录内）
ALLOWED_DIRS = [DATA_DIR, LOG_DIR, MODEL_DIR, os.path.join(PROJECT_ROOT, "scripts")]

# 模型参数
MODEL_PARAMS = {
    "vocab_size": 5000,
    "embed_dim": 128,
    "num_filters": 100,
    "filter_sizes": [2, 3, 4],
    "num_classes": 2,
    "dropout": 0.5,
    "max_seq_len": 128,
}

# 模型存储路径
MODEL_SAVE_PATH = os.path.join(MODEL_DIR, "fraud_model.pt")
VOCAB_SAVE_PATH = os.path.join(MODEL_DIR, "vocab.json")

# 加密密钥路径（优先使用环境变量；未设置时写入本地运行文件，不建议纳入版本控制）
ENCRYPTION_KEY_PATH = os.environ.get("AFS_KEY_PATH", os.path.join(DATA_DIR, "demo_runtime.key"))

# 拦截日志路径
INTERCEPT_LOG_PATH = os.path.join(LOG_DIR, "intercept.log")
# 加密日志路径（高敏感检测记录单独加密存储）
INTERCEPT_LOG_ENCRYPTED_PATH = os.path.join(LOG_DIR, "intercept.enc")

# 检测阈值
DETECTION_THRESHOLD = 0.7

# 异常监控配置
ANOMALY_CONFIG = {
    "max_file_access_per_window": 50,       # 时间窗口内最大文件访问数
    "anomaly_time_window_seconds": 60,       # 异常检测时间窗口
    "bulk_export_threshold": 100,            # 批量导出阈值（条）
    "off_hours_start": 22,                   # 非工作时间起始（22:00）
    "off_hours_end": 6,                      # 非工作时间结束（06:00）
}

# 输入安全限制
INPUT_LIMITS = {
    "max_text_length": 10000,
    "max_filename_length": 255,
    "max_batch_size": 500,
}

# 确保必要目录存在
for _dir in [DATA_DIR, PROCESSED_DIR, LOG_DIR, MODEL_DIR]:
    os.makedirs(_dir, exist_ok=True)
