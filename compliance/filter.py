"""
隐私字段过滤器 — 自动识别并脱敏手机号、身份证号等敏感信息
"""
import re


class PrivacyFilter:
    """识别并脱敏文本中的个人隐私字段，确保数据处理全程合规"""

    # 手机号模式：11位以1开头的数字
    PHONE_PATTERN = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")

    # 带前缀的手机号（+86 / 86- / 0086 等）
    PHONE_WITH_PREFIX_PATTERN = re.compile(
        r"(?:\+?86[-\s]?)?(?:0086[-\s]?)?1[3-9]\d{9}(?!\d)"
    )

    # 身份证号模式：18位（末位可能为X）
    ID_CARD_PATTERN = re.compile(
        r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])"
        r"(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"
    )

    # 银行卡号模式：16-19位数字
    BANK_CARD_PATTERN = re.compile(r"(?<!\d)[1-9]\d{15,18}(?!\d)")

    # 电子邮箱模式
    EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    # IP地址模式
    IP_PATTERN = re.compile(
        r"(?<!\d)(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
        r"\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
        r"\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
        r"\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"
    )

    # 家庭住址模式（粗略匹配）
    ADDRESS_PATTERN = re.compile(
        r"(?:省|自治区|市|区|县|镇|乡|村|路|街|巷|号|栋|单元|室)\s*"
        r"(?:[一-龥\d]+(?:省|自治区|市|区|县|镇|乡|村|路|街|巷|号|栋|单元|室)){2,}"
    )

    @classmethod
    def mask_phone(cls, text: str) -> str:
        """脱敏手机号：保留前3后4，中间用****替换"""
        def _replacer(match):
            phone = match.group()
            # 提取后11位中的手机号部分
            digits = re.sub(r"\D", "", phone)
            if len(digits) >= 11:
                core = digits[-11:]
                return phone.replace(core, f"{core[:3]}****{core[-4:]}")
            return phone[:3] + "****" + phone[-4:]
        return cls.PHONE_WITH_PREFIX_PATTERN.sub(_replacer, text)

    @classmethod
    def mask_id_card(cls, text: str) -> str:
        """脱敏身份证号：保留前6后4，中间用********替换"""
        def _replacer(match):
            id_num = match.group()
            return f"{id_num[:6]}********{id_num[-4:]}"
        return cls.ID_CARD_PATTERN.sub(_replacer, text)

    @classmethod
    def mask_bank_card(cls, text: str) -> str:
        """脱敏银行卡号：保留后4位"""
        def _replacer(match):
            card = match.group()
            return f"****{card[-4:]}"
        return cls.BANK_CARD_PATTERN.sub(_replacer, text)

    @classmethod
    def mask_email(cls, text: str) -> str:
        """脱敏邮箱：保留首字母和域名"""
        def _replacer(match):
            email = match.group()
            local, domain = email.rsplit("@", 1)
            if len(local) > 1:
                return f"{local[0]}***@{domain}"
            return f"*@{domain}"
        return cls.EMAIL_PATTERN.sub(_replacer, text)

    @classmethod
    def mask_ip(cls, text: str) -> str:
        """脱敏IP地址：保留首段"""
        def _replacer(match):
            ip = match.group()
            parts = ip.split(".")
            return f"{parts[0]}.*.*.*"
        return cls.IP_PATTERN.sub(_replacer, text)

    @classmethod
    def filter_all(cls, text: str) -> tuple:
        """执行全部隐私过滤，返回脱敏后文本及脱敏统计"""
        filtered = text
        filtered = cls.mask_phone(filtered)
        filtered = cls.mask_id_card(filtered)
        filtered = cls.mask_bank_card(filtered)
        filtered = cls.mask_email(filtered)
        filtered = cls.mask_ip(filtered)

        # 统计脱敏数量
        phones = len(cls.PHONE_WITH_PREFIX_PATTERN.findall(text))
        id_cards = len(cls.ID_CARD_PATTERN.findall(text))
        bank_cards = len(cls.BANK_CARD_PATTERN.findall(text))
        emails = len(cls.EMAIL_PATTERN.findall(text))
        ips = len(cls.IP_PATTERN.findall(text))

        stats = {
            "phones_masked": phones,
            "id_cards_masked": id_cards,
            "bank_cards_masked": bank_cards,
            "emails_masked": emails,
            "ips_masked": ips,
            "total_masked": phones + id_cards + bank_cards + emails + ips,
        }
        return filtered, stats
