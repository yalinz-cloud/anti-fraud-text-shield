"""
输入安全校验器 — 防范代码注入、SQL注入、XSS等常见攻击
"""
import re
import html


class InputValidator:
    """用户输入安全校验器，对系统边界数据进行多层清洗"""

    # 允许的文本字符范围（中文、英文、数字、常用标点）
    _SAFE_TEXT_PATTERN = re.compile(
        r"^[一-鿿㐀-䶿a-zA-Z0-9"
        r"\s\.\,\!\?\;\:\@\#\$\%\^\&\*\(\)\-\+\=\[\]\{\}\|\/\<\>"
        r"　-〿＀-￯"
        r"_\"\'\~\`"
        r"]*$"
    )

    # 危险代码特征
    _CODE_INJECTION_PATTERNS = [
        r"(?:__import__|exec|eval|compile)\s*\(",       # Python代码执行
        r"(?:os\.|subprocess|popen|system)\s*\(",        # 系统命令执行
        r"(?:__[a-z]+__)\s*=\s*",                        # 魔术方法赋值
        r"(?:lambda\s+|lambda:)",                         # lambda 表达式
        r"(?:import\s+|from\s+\S+\s+import)",             # import 语句
        r"<\s*(?:script|iframe|object|embed|style)\b",    # HTML标签
        r"(?:onerror|onclick|onload)\s*=",                # 事件处理器
        r"javascript\s*:",                                 # javascript: 协议
        r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+", # SQL 关键字
        r"(?:--|#)\s*$",                                  # SQL 注释
        r"(?:OR|AND)\s+\d+\s*=\s*\d+",                    # SQL 布尔注入
    ]

    # 最大文本长度限制
    MAX_TEXT_LENGTH = 10000
    MAX_FILENAME_LENGTH = 255
    MAX_PATH_LENGTH = 4096

    @classmethod
    def validate_text(cls, text: str, max_length: int = None) -> str:
        """
        校验并清洗用户输入文本

        返回清洗后的文本，校验失败则抛出 ValueError
        """
        if not isinstance(text, str):
            raise ValueError("输入必须为字符串类型")

        if max_length is None:
            max_length = cls.MAX_TEXT_LENGTH

        if len(text) > max_length:
            raise ValueError(f"输入文本长度 {len(text)} 超过限制 {max_length}")

        # 去掉不可打印字符（保留换行符）
        cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", text)

        # 去掉零宽字符（BOM等）
        cleaned = cleaned.replace("﻿", "").replace("​", "")

        return cleaned

    @classmethod
    def detect_code_injection(cls, text: str) -> list:
        """
        检测代码注入特征

        Returns:
            list: 匹配到的危险特征列表，空列表表示安全
        """
        found = []
        lowered = text.lower()
        for pattern in cls._CODE_INJECTION_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                found.append({
                    "pattern": pattern,
                    "matches": matches,
                })
        return found

    @classmethod
    def sanitize_html(cls, text: str) -> str:
        """HTML 实体转义，防止 XSS"""
        return html.escape(text, quote=True)

    @classmethod
    def validate_and_clean(cls, text: str) -> tuple:
        """
        综合校验与清洗，返回 (清洗后文本, 安全标记, 风险列表)
        """
        warnings = []
        try:
            cleaned = cls.validate_text(text)
        except ValueError as e:
            return "", False, [str(e)]

        # 代码注入检测
        injections = cls.detect_code_injection(cleaned)
        if injections:
            warnings.append(f"检测到 {len(injections)} 个可疑代码注入特征")
            for inj in injections[:3]:  # 仅记录前3项
                warnings.append(f"  - 匹配: {inj['matches'][:2]}")

        is_safe = len(warnings) == 0
        # 如果检测到注入特征，文本仍然返回但标记为不安全
        return cleaned, is_safe, warnings

    @classmethod
    def validate_batch(cls, texts: list) -> list:
        """批量校验文本列表"""
        results = []
        for i, text in enumerate(texts):
            cleaned, is_safe, warnings = cls.validate_and_clean(text)
            results.append({
                "index": i,
                "is_safe": is_safe,
                "warnings": warnings,
                "original_length": len(text),
                "cleaned_length": len(cleaned),
            })
        return results
