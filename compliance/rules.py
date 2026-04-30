"""
反诈特征规则引擎 — 规则策略从 base64 编码的载荷文件解码加载
本地部署时需配套 rules_payload.py 文件置于同目录（该文件已 gitignore）
"""
import ast
import base64
import logging

logger = logging.getLogger(__name__)

try:
    from . import rules_payload
    _HAVE_PAYLOAD = True
except (ImportError, ModuleNotFoundError):
    _HAVE_PAYLOAD = False


def _decode_payload(payload_dict: dict) -> dict:
    """将 base64 编码的规则字典解码为 Python 对象（使用 ast.literal_eval 安全解析）"""
    decoded = {}
    for key, b64_value in payload_dict.items():
        py_str = base64.b64decode(b64_value).decode("utf-8")
        decoded[key] = ast.literal_eval(py_str)
    return decoded


class FraudRuleEngine:
    """涉诈特征规则匹配引擎，规则策略由外部载荷文件提供"""

    def __init__(self):
        if not _HAVE_PAYLOAD:
            raise RuntimeError(
                "规则载荷文件 rules_payload.py 不存在，反诈规则引擎无法启动。"
                "请将本地 rules_payload.py 复制到 compliance/ 目录后重试。"
            )
        self._rules = _decode_payload({
            "speech": rules_payload.SPEECH_PATTERNS_B64,
            "links": rules_payload.FAKE_LINK_PATTERNS_B64,
            "accounts": rules_payload.FRAUD_ACCOUNT_PATTERNS_B64,
            "keywords": rules_payload.HIGH_RISK_KEYWORDS_B64,
        })

    @staticmethod
    def _scan_patterns(lookup: dict, text: str) -> dict:
        """匹配文本中的规则模式"""
        import re
        results = {}
        for category, patterns in lookup.items():
            hits = []
            for pattern in patterns:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    hits.append({
                        "pattern": pattern,
                        "matched": match.group(),
                        "position": match.span(),
                    })
            if hits:
                results[category] = hits
        return results

    def match_speech_patterns(self, text: str) -> dict:
        """匹配涉诈话术特征"""
        return self._scan_patterns(self._rules["speech"], text)

    def detect_fake_links(self, text: str) -> dict:
        """检测虚假链接格式"""
        return self._scan_patterns(self._rules["links"], text)

    def detect_fraud_accounts(self, text: str) -> dict:
        """检测诈骗账号标识"""
        return self._scan_patterns(self._rules["accounts"], text)

    def count_high_risk_keywords(self, text: str) -> tuple:
        """统计高风险关键词命中次数"""
        found = [kw for kw in self._rules["keywords"] if kw in text]
        return found, len(found)

    def comprehensive_scan(self, text: str) -> dict:
        """综合扫描：一次调用完成所有规则匹配"""
        speech = self.match_speech_patterns(text)
        links = self.detect_fake_links(text)
        accounts = self.detect_fraud_accounts(text)
        keywords, kw_count = self.count_high_risk_keywords(text)
        total_hits = len(speech) + len(links) + len(accounts) + kw_count
        return {
            "speech_patterns": speech,
            "fake_links": links,
            "fraud_accounts": accounts,
            "high_risk_keywords": {"found": keywords, "count": kw_count},
            "total_hit_categories": total_hits,
            "is_suspicious": total_hits > 0,
            "risk_level": self._assess_risk_level(total_hits, kw_count),
        }

    def _assess_risk_level(self, total_hits: int, kw_count: int) -> str:
        """评估综合风险等级"""
        if total_hits >= 5 or kw_count >= 4:
            return "高危"
        elif total_hits >= 3 or kw_count >= 2:
            return "中危"
        elif total_hits >= 1:
            return "低危"
        return "正常"
