"""
拦截引擎 — 融合规则引擎与模型推理的实时涉诈信息拦截
纯离线运行，所有检测记录加密存储于本地，无网络上报
"""
import os
import json
import logging
from datetime import datetime
from compliance.rules import FraudRuleEngine
from compliance.filter import PrivacyFilter
from interception.inference import FraudDetector
from security.input_validator import InputValidator
from security.anomaly_monitor import get_monitor
import config


class Interceptor:
    """
    涉诈信息实时拦截器

    拦截策略：
    1. 输入安全校验 → 防范代码注入
    2. 规则引擎扫描 → 命中高风险关键词/虚假链接/诈骗账号
    3. 模型推理 → 输出涉诈概率
    4. 综合判定 → 任一命中则触发拦截
    5. 加密记录日志 → 本地加密存储，无明文泄露风险
    """

    def __init__(self, detector: FraudDetector = None, cipher=None):
        self._rule_engine = FraudRuleEngine()
        self._detector = detector
        self._cipher = cipher  # AES 加密器，用于日志加密
        self._monitor = get_monitor()
        self._setup_logging()

    def _setup_logging(self):
        """配置本地日志（仅写入本地文件）"""
        self._logger = logging.getLogger("fraud_interceptor")
        self._logger.setLevel(logging.INFO)
        self._logger.handlers.clear()
        os.makedirs(os.path.dirname(config.INTERCEPT_LOG_PATH), exist_ok=True)
        fh = logging.FileHandler(config.INTERCEPT_LOG_PATH, encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        self._logger.addHandler(fh)

    def _write_encrypted_log(self, report: dict):
        """将高敏感检测报告加密后写入独立日志文件"""
        if self._cipher is None:
            return
        try:
            log_entry = json.dumps(report, ensure_ascii=False) + "\n"
            encrypted_entry = self._cipher.encrypt_bytes(log_entry.encode("utf-8"))
            with open(config.INTERCEPT_LOG_ENCRYPTED_PATH, "ab") as f:
                # 每条记录前写入长度前缀（4字节大端序）
                f.write(len(encrypted_entry).to_bytes(4, "big"))
                f.write(encrypted_entry)
        except Exception:
            pass  # 加密日志写入失败不影响主流程

    def intercept(self, text: str) -> dict:
        """
        对输入文本执行拦截检测

        Returns:
            dict: 包含检测结果、拦截状态、命中详情的完整报告
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Step 0: 输入安全校验
        cleaned_text, input_safe, warnings = InputValidator.validate_and_clean(text)

        # Step 1: 隐私过滤（先脱敏再分析，确保隐私安全）
        safe_text, privacy_stats = PrivacyFilter.filter_all(cleaned_text)

        # Step 2: 规则引擎综合扫描
        rule_result = self._rule_engine.comprehensive_scan(safe_text)

        # Step 3: 模型推理（如检测器已加载）
        model_result = None
        if self._detector is not None:
            try:
                model_result = self._detector.detect_single(safe_text)
            except Exception as e:
                model_result = {"error": str(e)}

        # Step 4: 综合判定
        rule_hit = rule_result["is_suspicious"]
        model_hit = (
            model_result is not None
            and not model_result.get("error")
            and model_result.get("is_fraud", False)
        )
        should_block = rule_hit or model_hit or not input_safe

        # 生成拦截原因
        reasons = []
        if not input_safe:
            reasons.append("输入安全检查未通过，检测到可疑代码注入特征")
        if rule_hit:
            reasons.append(f"规则引擎命中 {rule_result['total_hit_categories']} 类涉诈特征")
            if rule_result["speech_patterns"]:
                reasons.append(f"涉诈话术类别: {', '.join(rule_result['speech_patterns'].keys())}")
            if rule_result["fake_links"]:
                reasons.append(f"虚假链接类型: {', '.join(rule_result['fake_links'].keys())}")
            if rule_result["fraud_accounts"]:
                reasons.append(f"诈骗账号标识: {', '.join(rule_result['fraud_accounts'].keys())}")
        if model_hit:
            reasons.append(f"模型判定涉诈概率 {model_result['fraud_probability']} >= 阈值 {config.DETECTION_THRESHOLD}")

        # Step 5: 构建完整报告
        report = {
            "timestamp": timestamp,
            "input_length": len(text),
            "input_safe": input_safe,
            "privacy_filter": privacy_stats,
            "rule_scan": {
                "risk_level": rule_result["risk_level"],
                "total_hit_categories": rule_result["total_hit_categories"],
                "high_risk_keywords": rule_result["high_risk_keywords"]["found"],
                "speech_categories": list(rule_result["speech_patterns"].keys()),
                "link_types": list(rule_result["fake_links"].keys()),
                "account_types": list(rule_result["fraud_accounts"].keys()),
            },
            "model_scan": model_result,
            "should_block": should_block,
            "block_reasons": reasons,
            "action": "BLOCK" if should_block else "PASS",
        }

        # Step 6: 写入本地日志（明文 + 加密双写）
        self._logger.info(json.dumps(report, ensure_ascii=False))
        self._write_encrypted_log(report)

        # Step 7: 异常操作监控（批量拦截时检测）
        self._monitor.record_file_access(config.INTERCEPT_LOG_PATH, "write")

        return report

    def batch_intercept(self, texts: list) -> list:
        """批量拦截检测（含批量导出监控）"""
        if len(texts) > config.INPUT_LIMITS["max_batch_size"]:
            raise ValueError(f"批量检测数量 {len(texts)} 超过上限 {config.INPUT_LIMITS['max_batch_size']}")
        # 异常监控：检查批量操作
        alert = self._monitor.check_bulk_export(texts, "批量拦截检测")
        if alert:
            self._logger.warning(f"[异常监控] 批量操作告警: {json.dumps(alert, ensure_ascii=False)}")
        return [self.intercept(text) for text in texts]
