"""
Anti-Fraud Text Shield — Complete Demo Script
展示四大模块协同工作：安全防护 → 合规处理 → 加密防护 → 实时拦截
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.rules import FraudRuleEngine
from compliance.filter import PrivacyFilter
from encryption.aes_crypto import KeyManager, AESCipher
from interception.inference import FraudDetector
from interception.interceptor import Interceptor
from security.access_control import AccessController
from security.path_sanitizer import PathSanitizer
from security.input_validator import InputValidator
from security.anomaly_monitor import get_monitor
import config


# ============================================================
# 演示用涉诈文本样本
# ============================================================
DEMO_TEXTS = [
    # 样本1: 冒充执法部门类
    "您好，我是平台风控中心的工作人员，工号B-2468。您的身份信息疑似异常，"
    "请立即将名下资金转入安全账户888888xxxxxxxx0123进行核验，"
    "否则将影响后续处理。如有疑问请联系电话138****0000。",

    # 样本2: 投资理财诈骗类
    "联系微号：stock_master888，分析师分享内部消息与带单机会，"
    "日收益稳定8%，高回报低风险。已有多位学员加入，点击 https://demo.example.invalid:8080/login 即可注册。",

    # 样本3: 刷单诈骗类
    "招聘手机兼职，不需要任何经验，在家就能获得高额佣金。"
    "每天只需完成几单任务，佣金立结。请联系Q号：9876543了解更多。",

    # 样本4: 正常文本
    "你好，明天下午3点的项目评审会议地点改到B座12层大会议室，"
    "请各位同事准时参加，携带上周的进展报告。如有问题请联系我。",

    # 样本5: 贷款诈骗类
    "急需周转的朋友看过来。无抵押低息贷款，资质较弱也可申请，最高额度50万，"
    "快速审批到账。只需先缴纳2000元保证金解冻账户即可提现，"
    "联系Telegram：@demo_helper 快速办理。",
]


def print_separator(title: str):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def demo_access_control():
    """演示0: 安全访问控制"""
    print_separator("安全模块：访问权限校验")
    user = AccessController.get_current_user()
    is_admin = AccessController.check_admin_privilege()
    print(f"  当前用户: {user}")
    print(f"  管理员权限: {'已获取' if is_admin else '未获取（部分功能受限）'}")
    # 初始化白名单目录
    PathSanitizer.set_allowed_dirs(config.ALLOWED_DIRS)
    print(f"  路径白名单: {len(config.ALLOWED_DIRS)} 个安全目录已锁定")


def demo_input_validation():
    """演示0b: 输入安全校验"""
    print_separator("安全模块：输入安全校验")

    safe_tests = [
        "这是一段正常的文本输入，没有任何问题",
        "SELECT * FROM users WHERE 1=1 --",
        "<script>alert('xss')</script>",
        "eval('__import__(\"os\").system(\"dir\")')",
    ]
    for test in safe_tests:
        _, is_safe, warnings = InputValidator.validate_and_clean(test)
        status = "[安全]" if is_safe else "[拦截]"
        print(f"  {status} {test[:55]}..."
              + (f" -> {warnings[0][:40]}" if warnings else ""))


def demo_path_sanitizer():
    """演示0c: 路径遍历防护"""
    print_separator("安全模块：路径遍历防护")
    attack_paths = [
        "../../etc/passwd",
        "..\\..\\Windows\\System32",
        "data/../secrets/demo_runtime.key",
        "data/fraud_corpus.enc",  # 合法路径
    ]
    for path in attack_paths:
        try:
            safe = PathSanitizer.sanitize(path)
            print(f"  [允许] {path} -> {safe}")
        except ValueError as e:
            print(f"  [阻止] {path} -> {str(e)[:50]}")


def demo_privacy_filter():
    """演示1: 隐私字段脱敏"""
    print_separator("模块一：反诈数据合规处理 — 隐私字段过滤")

    text = ("用户某甲，手机号13800000000，身份证号110101199001010001，"
            "银行卡888888xxxxxxxx0123，邮箱user@example.com，"
            "IP地址198.51.100.1，住址某市某区某路xx号。")

    print(f"  [原始文本] {text}")
    filtered, stats = PrivacyFilter.filter_all(text)
    print(f"  [脱敏文本] {filtered}")
    print(f"  [脱敏统计] 手机号:{stats['phones_masked']} 身份证:{stats['id_cards_masked']} "
          f"银行卡:{stats['bank_cards_masked']} 邮箱:{stats['emails_masked']} "
          f"IP:{stats['ips_masked']} 总计:{stats['total_masked']}")


def demo_rule_engine():
    """演示2: 规则引擎扫描"""
    print_separator("模块一：反诈数据合规处理 — 涉诈特征规则扫描")

    engine = FraudRuleEngine()
    text = DEMO_TEXTS[1]  # 投资理财诈骗样本

    print(f"  [待检测文本] {text[:100]}...")
    result = engine.comprehensive_scan(text)

    print(f"\n  [风险等级] {result['risk_level']}")
    print(f"  [命中类别数] {result['total_hit_categories']}")
    print(f"  [高风险关键词] {result['high_risk_keywords']['found']}")
    if result["speech_patterns"]:
        print(f"  [涉诈话术] {list(result['speech_patterns'].keys())}")
    if result["fake_links"]:
        print(f"  [虚假链接] {list(result['fake_links'].keys())}")
    if result["fraud_accounts"]:
        print(f"  [诈骗账号] {list(result['fraud_accounts'].keys())}")


def demo_encryption():
    """演示3: 加密防护"""
    print_separator("模块二：反诈数据加密防护 — AES-256-GCM")

    key = KeyManager.generate_key()
    cipher = AESCipher(key)

    # 加解密演示
    plaintext = "反诈核心特征库：包含12类涉诈话术词、8种虚假链接格式、6类诈骗账号标识"
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)

    print(f"  原始数据: {plaintext[:50]}...")
    print(f"  密文长度: {len(encrypted)} 字节 (含 nonce+tag)")
    print(f"  解密结果: {decrypted[:50]}...")
    print(f"  一致性: {'通过' if decrypted == plaintext else '失败'}")

    # 防篡改验证
    tampered = bytearray(encrypted)
    tampered[-5] ^= 0xFF
    try:
        cipher.decrypt(bytes(tampered))
        print(f"  防篡改: 未检测到篡改 (FAIL)")
    except Exception:
        print(f"  防篡改: 正确检测到密文篡改")

    return cipher


def demo_model_inference():
    """演示4: 模型推理"""
    print_separator("模块三：涉诈信息实时拦截 — 模型推理")

    detector = FraudDetector().load()

    for i, text in enumerate(DEMO_TEXTS):
        result = detector.detect_single(text)
        status = "[拦截]" if result["is_fraud"] else "[放行]"
        print(f"  {status} 样本{i+1}: 概率={result['fraud_probability']:.4f} | "
              f"内容: {text[:50]}...")


def demo_full_interception(cipher=None):
    """演示5: 完整拦截流程（含安全校验 + 加密日志）"""
    print_separator("模块三：涉诈信息实时拦截 — 完整拦截流程（含加密日志）")

    detector = FraudDetector().load()
    interceptor = Interceptor(detector=detector, cipher=cipher)
    monitor = get_monitor()
    monitor.register_alert_callback(lambda a: print(f"\n  *** [异常告警] {a['type']}: {a['details']}"))

    for i, text in enumerate(DEMO_TEXTS):
        report = interceptor.intercept(text)
        action_icon = "[BLOCK]" if report["should_block"] else "[PASS]"
        print(f"\n  {action_icon} 样本{i+1} (长度{report['input_length']}字)")
        print(f"       输入安全: {'通过' if report['input_safe'] else '未通过'}")
        print(f"       风险等级: {report['rule_scan']['risk_level']}")
        print(f"       隐私脱敏: {report['privacy_filter']['total_masked']}处")
        if report["block_reasons"]:
            for reason in report["block_reasons"]:
                print(f"       -> {reason}")


def demo_anomaly_monitor():
    """演示6: 异常操作监控"""
    print_separator("安全模块：异常操作监控")

    monitor = get_monitor()
    alerts_received = []
    monitor.register_alert_callback(lambda a: alerts_received.append(a))

    # 模拟批量导出告警
    alert = monitor.check_bulk_export(
        [f"特征_{i}" for i in range(150)],
        "涉诈特征库全量导出"
    )
    if alert:
        print(f"  [告警] 批量导出检测: {alert['type']} (count={alert['details']['record_count']})")

    # 模拟高频文件访问
    for i in range(55):
        monitor.record_file_access(f"/data/feature_{i}.txt", "read")

    summary = monitor.get_access_summary()
    print(f"  [监控摘要] 读操作:{summary['read_operations']} "
          f"写操作:{summary['write_operations']} "
          f"导出尝试:{summary['export_attempts']} "
          f"告警数:{summary['total_alerts']}")


def main():
    print("=" * 70)
    print("  Anti-Fraud Text Shield v2.0")
    print("  基于 PyTorch 2.0 + 多维正则规则 + AES-256-GCM 加密")
    print("  四大核心模块：安全防护 | 合规处理 | 加密防护 | 实时拦截")
    print("=" * 70)

    # 安全模块演示
    demo_access_control()
    demo_input_validation()
    demo_path_sanitizer()

    # 模块一：合规处理
    demo_privacy_filter()
    demo_rule_engine()

    # 模块二：加密防护
    cipher = demo_encryption()

    # 模块三：实时拦截
    demo_model_inference()
    demo_full_interception(cipher=cipher)

    # 异常监控
    demo_anomaly_monitor()

    print_separator("演示完成")
    print(f"  拦截日志: logs/intercept.log")
    print(f"  加密日志: logs/intercept.enc")
    print(f"  运行模式: 纯离线 - 所有检测数据仅本地加密留存，无网络上报")


if __name__ == "__main__":
    main()
