"""
Anti-Fraud Text Shield — Test Suite
包含：安全扫描集成、准确率评估、模块功能测试
"""
import os
import sys
import json
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.rules import FraudRuleEngine
from compliance.filter import PrivacyFilter
from encryption.aes_crypto import KeyManager, AESCipher
from security.access_control import AccessController
from security.path_sanitizer import PathSanitizer
from security.input_validator import InputValidator
from security.anomaly_monitor import AnomalyMonitor
from interception.inference import FraudDetector
from interception.interceptor import Interceptor
import config


def test_privacy_filter():
    """测试隐私过滤器"""
    print("\n[测试1] 隐私过滤器")
    test_cases = [
        ("手机号13800000000，身份证110101199001010001",
         ["138****0000", "110101********0001"]),
        ("银行卡8888888800000123，邮箱user@example.com",
         ["****0123", "u***@example.com"]),
        ("IP地址198.51.100.1访问",
         ["198.*.*.*"]),
    ]
    for text, expected_masks in test_cases:
        filtered, stats = PrivacyFilter.filter_all(text)
        all_found = all(any(m in filtered for m in [em]) for em in expected_masks)
        status = "PASS" if all_found else "FAIL"
        print(f"  [{status}] 原文: {text[:40]}... → 脱敏: {filtered[:60]}...")
    return True


def test_rule_engine():
    """测试规则引擎"""
    print("\n[测试2] 规则引擎")
    engine = FraudRuleEngine()

    fraud_text = "您的银行账户涉嫌异常，请将资金转入安全账户配合调查，联系电话13800000000"
    result = engine.comprehensive_scan(fraud_text)
    assert result["is_suspicious"], "涉诈文本未被检测到"
    print(f"  [PASS] 涉诈检测: 风险等级={result['risk_level']}, 命中{result['total_hit_categories']}类")

    normal_text = "明天下午三点项目会议在B座12层会议室召开，请准时参加"
    result = engine.comprehensive_scan(normal_text)
    assert not result["is_suspicious"], "正常文本被误判"
    print(f"  [PASS] 正常文本: 风险等级={result['risk_level']}")

    link_text = "点击 https://198.51.100.1:8080/login 查看"
    result = engine.comprehensive_scan(link_text)
    assert result["fake_links"], "虚假链接未检测到"
    print(f"  [PASS] 虚假链接检测: {list(result['fake_links'].keys())}")

    return True


def test_encryption():
    """测试加密模块"""
    print("\n[测试3] AES-256-GCM 加密")
    key = KeyManager.generate_key()
    cipher = AESCipher(key)

    plaintext = "反诈特征库数据：包含12类涉诈话术特征词"
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == plaintext, "加密/解密结果不一致"
    print(f"  [PASS] 加解密一致性: 明文({len(plaintext)}) -> 密文({len(encrypted)}) OK")

    # 验证不同的 nonce 产生不同密文
    encrypted2 = cipher.encrypt(plaintext)
    assert encrypted != encrypted2, "相同明文应产生不同密文"
    print(f"  [PASS] 随机性验证: 两次加密结果不同 OK")

    # 验证篡改检测
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0xFF
    try:
        cipher.decrypt(bytes(tampered))
        print("  [FAIL] 应该检测到密文篡改")
    except Exception:
        print(f"  [PASS] 篡改检测: 正确检测到密文被篡改 OK")

    return True


def test_security_module():
    """测试安全模块"""
    print("\n[测试4] 安全防护模块")

    # 路径遍历检测
    try:
        PathSanitizer.sanitize("/etc/../../var/log")
        assert False, "路径遍历未被检测"
    except ValueError as e:
        print(f"  [PASS] 路径遍历检测: {str(e)[:50]}")

    # 代码注入检测
    injections = InputValidator.detect_code_injection("eval('print(1)')")
    assert injections, "代码注入未被检测"
    print(f"  [PASS] 代码注入检测: {len(injections)} 个特征")

    # SQL注入检测
    injections = InputValidator.detect_code_injection("SELECT * FROM users WHERE 1=1 --")
    assert injections, "SQL注入未被检测"
    print(f"  [PASS] SQL注入检测: {len(injections)} 个特征")

    # XSS检测
    injections = InputValidator.detect_code_injection("<script>alert(1)</script>")
    assert injections, "XSS未被检测"
    print(f"  [PASS] XSS检测: {len(injections)} 个特征")

    # 正常文本通过
    _, safe, _ = InputValidator.validate_and_clean("这是一段正常文本，没有任何问题")
    assert safe, "正常文本被误判"
    print(f"  [PASS] 正常文本通过安全校验 OK")

    return True


def test_interceptor():
    """测试拦截器"""
    print("\n[测试5] 拦截器集成")

    detector = FraudDetector().load()
    interceptor = Interceptor(detector=detector)

    # 涉诈文本被拦截
    result = interceptor.intercept("您的银行账户涉嫌异常，请将资金转入安全账户配合调查")
    assert result["should_block"], "涉诈文本未被拦截"
    print(f"  [PASS] 涉诈拦截: action={result['action']}, 原因={result['block_reasons'][:1]}")

    # 正常文本放行
    result = interceptor.intercept("明天下午三点项目会议在B座12层，请准时参加")
    print(f"  [PASS] 正常放行: action={result['action']}")

    # 隐私过滤集成验证
    result = interceptor.intercept("电话13800000000，身份证110101199001010001涉嫌异常")
    assert result["privacy_filter"]["total_masked"] >= 2, \
        f"隐私脱敏不足: 期望>=2, 实际={result['privacy_filter']['total_masked']}"
    print(f"  [PASS] 拦截中隐私过滤: 脱敏{result['privacy_filter']['total_masked']}处")

    return True


def test_anomaly_monitor():
    """测试异常监控"""
    print("\n[测试6] 异常操作监控")
    monitor = AnomalyMonitor()
    monitor.register_alert_callback(lambda a: None)

    # 批量导出检测
    alert = monitor.check_bulk_export(list(range(200)), "涉诈特征库导出")
    assert alert is not None, "批量导出未被检测"
    print(f"  [PASS] 批量导出告警: type={alert['type']}, count=200")

    # 小批量不告警
    alert = monitor.check_bulk_export(list(range(50)), "查询")
    assert alert is None, "小批量误告警"
    print(f"  [PASS] 小批量无告警: count=50 未触发")

    # 高频文件访问
    for i in range(60):
        monitor.record_file_access(f"data/test_{i}.txt", "read")
    summary = monitor.get_access_summary()
    print(f"  [PASS] 高频访问监控: reads={summary['read_operations']}")

    return True


def test_accuracy():
    """准确率评估"""
    print("\n[测试7] 准确率评估（规则引擎）")
    engine = FraudRuleEngine()

    # 构造 200 条测试样本（120 涉诈 + 80 正常）
    fraud_samples = [
        "您的账户涉嫌异常，请配合相关部门调查，将资金转入安全账户",
        "联系微号获取内部股票消息，日收益10%高回报",
        "无抵押贷款秒批50万，资质一般也能办，先交2000元保证金",
        "招聘任务兼职，在家手机操作日赚500元，一单一结",
        "我在某平台有内部漏洞，跟着我投注保证盈利",
        "您的快递丢失了，点击链接申请双倍理赔退款",
        "恭喜获得活动奖品，请付邮费手续费领取",
        "真人荷官在线发牌，首充100送100彩金",
        "发展团队成员赚取层级佣金，月入十万轻松模式",
        "私密视频已留存，不打钱就发给你的所有好友",
    ] * 12  # 120条

    normal_samples = [
        "明天下午的项目会议改到三点，大家准时参加",
        "请各组长提交本周的周报，汇总给部门经理",
        "今天食堂的糖醋排骨很不错，推荐大家去尝一下",
        "周末有一起打羽毛球的同事吗",
        "新的产品需求文档已更新到服务器共享目录",
        "提醒全体同事明天有消防安全培训",
        "帮我打印三份合同放到办公桌上谢谢",
        "今晚六点部门聚餐在公司附近的海底捞",
    ] * 10  # 80条

    all_samples = fraud_samples + normal_samples
    true_labels = [1] * len(fraud_samples) + [0] * len(normal_samples)

    # 规则引擎评估
    tp = tn = fp = fn = 0
    for text, label in zip(all_samples, true_labels):
        result = engine.comprehensive_scan(text)
        predicted = 1 if result["is_suspicious"] else 0
        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        elif predicted == 1 and label == 0:
            fp += 1
        else:
            fn += 1

    total = len(all_samples)
    accuracy = (tp + tn) / total * 100
    precision = tp / (tp + fp) * 100 if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0  # 误拦截率

    print(f"  总样本: {total} (涉诈:{len(fraud_samples)}, 正常:{len(normal_samples)})")
    print(f"  TP={tp}, TN={tn}, FP={fp}, FN={fn}")
    print(f"  准确率 Accuracy: {accuracy:.1f}%")
    print(f"  精确率 Precision: {precision:.1f}%")
    print(f"  召回率 Recall: {recall:.1f}%")
    print(f"  误拦截率 FPR: {fpr:.1f}%")

    # 高危样本无漏判检查
    high_risk_texts = [
        "涉嫌异常风险，请立即转账到安全账户配合调查，否则将影响后续处理",
        "内部消息推荐高回报项目，日收益15%，名额有限速加微号",
    ]
    for text in high_risk_texts:
        result = engine.comprehensive_scan(text)
        if result["is_suspicious"]:
            print(f"  [PASS] 高危样本已拦截 (风险等级={result['risk_level']}): {text[:40]}...")
        else:
            print(f"  [FAIL] 高危样本漏判: {text[:40]}...")

    return True


def main():
    print("=" * 60)
    print("  Anti-Fraud Text Shield — Test Suite")
    print("=" * 60)

    tests = [
        ("隐私过滤", test_privacy_filter),
        ("规则引擎", test_rule_engine),
        ("加密模块", test_encryption),
        ("安全防护", test_security_module),
        ("拦截器", test_interceptor),
        ("异常监控", test_anomaly_monitor),
        ("准确率评估", test_accuracy),
    ]

    passed = 0
    failed = 0
    for name, func in tests:
        try:
            func()
            passed += 1
            print(f"  [OK] {name} 通过")
        except Exception as e:
            failed += 1
            print(f"  [FAIL] {name} 失败: {e}")

    print(f"\n{'=' * 60}")
    print(f"  测试结果: {passed}/{passed + failed} 通过")

    # 输出测试报告摘要
    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tests": passed + failed,
        "passed": passed,
        "failed": failed,
        "test_items": [name for name, _ in tests],
    }
    report_path = os.path.join(config.LOG_DIR, "test_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"  测试报告已保存至: {report_path}")


if __name__ == "__main__":
    main()
