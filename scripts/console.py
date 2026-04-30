"""
Anti-Fraud Text Shield — Interactive Console Scanner
Supports: paste text input, local file import, real-time detection
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.filter import PrivacyFilter
from interception.inference import FraudDetector
from interception.interceptor import Interceptor
import config


def scan_text(text: str, interceptor: Interceptor) -> dict:
    """Single text scan"""
    print(f"\n  Input length: {len(text)} chars")
    filtered, privacy_stats = PrivacyFilter.filter_all(text)
    if privacy_stats["total_masked"] > 0:
        print(f"  Privacy masked: {privacy_stats['total_masked']} fields")
        print(f"  Filtered text:  {filtered[:120]}...")
    report = interceptor.intercept(text)
    return report


def scan_file(filepath: str, interceptor: Interceptor) -> list:
    """Import and scan a local text file"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    results = []
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        print(f"\n--- Line {i} ---")
        report = scan_text(line, interceptor)
        results.append(report)
    return results


def print_report(report: dict):
    """Print detection result"""
    action = "[BLOCK]" if report["should_block"] else "[PASS]"
    print(f"\n  ===== {action} =====")
    print(f"  Risk:     {report['rule_scan']['risk_level']}")
    if report["block_reasons"]:
        for r in report["block_reasons"]:
            print(f"  Reason:   {r}")


def main():
    print("=" * 60)
    print("  Anti-Fraud Text Shield — Console Scanner")
    print("  Offline mode | No data uploaded")
    print("=" * 60)

    detector = FraudDetector().load()
    interceptor = Interceptor(detector=detector)

    while True:
        print("\n--- Input Method ---")
        print("  1. Paste text")
        print("  2. Import .txt file")
        print("  3. Run demo samples")
        print("  0. Exit")
        choice = input("\n  Choice: ").strip()

        if choice == "0":
            break
        elif choice == "1":
            print("\n  Paste text below (Ctrl+Z on Win / Ctrl+D on Linux to finish):")
            lines = sys.stdin.read().strip().splitlines()
            text = "\n".join(lines)
            if text:
                report = scan_text(text, interceptor)
                print_report(report)
        elif choice == "2":
            path = input("  File path: ").strip()
            try:
                results = scan_file(path, interceptor)
                print(f"\n  Scanned {len(results)} lines from: {path}")
            except Exception as e:
                print(f"  Error: {e}")
        elif choice == "3":
            samples = [
                "您好，您涉嫌一起洗钱案件，请将资金转入安全账户配合调查，否则将被追究法律责任。",
                "加我微信：inv_master888，金牌导师免费带单，日收益稳定10%，稳赚不赔。",
                "招聘手机兼职刷单，在家日赚500，一单一结，请联系QQ：12345。",
                "明天下午3点项目评审会议改到B座12层大会议室，请准时参加。",
                "急需用钱？无抵押低息贷款，先交2000元保证金即可快速到账。",
                "Telegram：@crypto_helper 免费推荐百倍币，限量名额。",
            ]
            for i, text in enumerate(samples, 1):
                print(f"\n  === Sample {i} ===")
                report = scan_text(text, interceptor)
                print_report(report)
        else:
            print("  Invalid choice")

    print("\n  Goodbye.")


if __name__ == "__main__":
    main()
