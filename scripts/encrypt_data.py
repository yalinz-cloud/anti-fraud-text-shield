"""
反诈数据加密存储脚本 — 使用 AES-256-GCM 对数据文件进行加密保护
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from encryption.aes_crypto import KeyManager, AESCipher
import config


def main():
    # 生成或加载密钥
    if os.path.exists(config.ENCRYPTION_KEY_PATH):
        print(f"[1/4] 加载已有密钥: {config.ENCRYPTION_KEY_PATH}")
        key = KeyManager.load_key(config.ENCRYPTION_KEY_PATH)
    else:
        print("[1/4] 生成新密钥...")
        key = KeyManager.generate_key()
        KeyManager.save_key(key, config.ENCRYPTION_KEY_PATH)
        print(f"      密钥已保存至: {config.ENCRYPTION_KEY_PATH}")

    cipher = AESCipher(key)

    # 示例：加密一段反诈语料文本
    print("\n[2/4] 加密反诈特征数据...")
    sample_data = (
        "【涉诈话术示例库】\n"
        "1. 风险样例A：您的账户疑似异常，请配合核验，将资金转入安全账户。\n"
        "2. 风险样例B：内部消息推荐高回报项目，宣称日收益10%。\n"
        "3. 风险样例C：在家手机操作，完成任务后即可获得返利。\n"
        "4. 风险样例D：无抵押低息贷款，秒批额度，先交保证金解冻。\n"
    )
    encrypted = cipher.encrypt(sample_data)
    print(f"      明文大小: {len(sample_data.encode('utf-8'))} 字节")
    print(f"      密文大小: {len(encrypted)} 字节")

    # 将加密数据写入文件
    encrypted_path = os.path.join(config.DATA_DIR, "fraud_corpus.enc")
    with open(encrypted_path, "wb") as f:
        f.write(encrypted)
    print(f"      加密文件已保存: {encrypted_path}")

    # 解密验证
    print("\n[3/4] 解密验证...")
    with open(encrypted_path, "rb") as f:
        loaded_encrypted = f.read()
    decrypted = cipher.decrypt(loaded_encrypted)
    assert decrypted == sample_data, "解密内容与原文不一致！"
    print(f"      解密成功，内容完整一致")

    # 文件级加密演示
    print("\n[4/4] 文件加密/解密演示...")
    demo_file = os.path.join(config.DATA_DIR, "demo_features.txt")
    enc_file = os.path.join(config.DATA_DIR, "demo_features.txt.enc")
    dec_file = os.path.join(config.DATA_DIR, "demo_features_decrypted.txt")

    with open(demo_file, "w", encoding="utf-8") as f:
        f.write("反诈特征库版本:v2.0\n特征数量:896\n更新日期:2026-04-30\n备注:公开演示样例已脱敏")

    cipher.encrypt_file(demo_file, enc_file)
    print(f"      加密: {demo_file} → {enc_file}")

    cipher.decrypt_file(enc_file, dec_file)
    with open(dec_file, "r", encoding="utf-8") as f:
        dec_content = f.read()
    print(f"      解密: {enc_file} → {dec_file}")
    print(f"      解密内容: {dec_content}")

    # 清理演示文件
    for f in [demo_file, enc_file, dec_file]:
        if os.path.exists(f):
            os.remove(f)
    print("\n[完成] AES-256-GCM 加密链路验证通过")


if __name__ == "__main__":
    main()
