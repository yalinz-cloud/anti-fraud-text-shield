"""
反诈模型训练脚本 — 基于 TextCNN + 中文分词 + 合成语料的轻量训练流程
"""
import os
import sys
import json
import random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import jieba
from models.classifier import FraudTextCNN
import config


# ============================================================
# 合成训练语料（基础涉诈 vs 正常文本模板）
# ============================================================
FRAUD_TEMPLATES = [
    "您的银行账户涉嫌异常，请立即将资金转入安全账户配合调查",
    "加微号获取内部消息，分析师免费带单，日收益稳定10%",
    "无抵押低息贷款，资质较弱也可办理，秒批额度50万，先交保证金",
    "招聘手机兼职任务员，在家日赚800，一单一结，无需经验",
    "我在某平台发现漏洞，跟着我下注保证高回报",
    "您的快递丢失，请点击链接申请理赔退款",
    "恭喜您成为幸运用户，获得活动奖励，请缴纳手续费领取奖品",
    "真人在线发牌，首充赠送彩金大礼包",
    "邀请成员加入团队，按层级获得分红，月入十万不是梦",
    "私密视频已留存，转账5000元否则将内容发给你的通讯录好友",
    "高薪招聘出国打工，月薪3万包吃住，无经验学历要求",
    "扫描二维码下载APP，投资数字项目即将上线",
    "您的医保卡异常停用，请点击链接验证身份信息重新激活",
    "缴纳解冻费即可提现，刷银行流水提升信用额度",
    "内部渠道认购原始股，上市后高额回报，名额有限速联系",
]

NORMAL_TEMPLATES = [
    "明天下午三点的项目会议改到B座12层大会议室",
    "请各位同事在下班前提交本周的工作周报",
    "公司食堂今日供应红烧排骨和西红柿炒鸡蛋",
    "周末有没有同事一起参加羽毛球活动",
    "最新的产品需求文档已更新到共享服务器",
    "提醒大家明天上午十点有全体培训",
    "请帮忙打印三份合同，放到我办公桌上",
    "今天晚上部门聚餐，地点在公司附近的海底捞",
    "系统升级维护通知：周六凌晨2点到6点",
    "新同事入职欢迎会定在周五下午",
    "会议室投影仪坏了，IT部门正在维修",
    "请各组长汇总组员的绩效考核数据",
    "这个月的销售额比上个月增长了12%",
    "午休时间请大家保持安静，不要影响他人",
    "办公用品申购截止到本周五，请尽快提交清单",
]


def build_vocab(texts: list, min_freq: int = 2, max_size: int = 5000) -> dict:
    """基于训练语料构建中文分词词典"""
    vocab = {"<PAD>": 0, "<UNK>": 1}
    token_freq = {}
    for text in texts:
        for token in jieba.lcut(text):
            token_freq[token] = token_freq.get(token, 0) + 1
    for token, freq in sorted(token_freq.items(), key=lambda x: -x[1]):
        if freq >= min_freq and len(vocab) < max_size:
            vocab[token] = len(vocab)
    return vocab


class FraudDataset(Dataset):
    """Fraud text classification dataset"""

    def __init__(self, texts: list, labels: list, vocab: dict, max_len: int = 128):
        self._texts = texts
        self._labels = labels
        self._vocab = vocab
        self._max_len = max_len

    def _tokenize(self, text: str) -> list:
        token_ids = [
            self._vocab.get(t, self._vocab.get("<UNK>", 1))
            for t in jieba.lcut(text)
        ]
        if len(token_ids) >= self._max_len:
            return token_ids[:self._max_len]
        return token_ids + [self._vocab.get("<PAD>", 0)] * (self._max_len - len(token_ids))

    def __len__(self):
        return len(self._texts)

    def __getitem__(self, idx):
        return (
            torch.tensor(self._tokenize(self._texts[idx]), dtype=torch.long),
            torch.tensor(self._labels[idx], dtype=torch.long),
        )


def generate_synthetic_data(num_fraud: int = 600, num_normal: int = 400, seed: int = 42) -> tuple:
    """
    生成合成训练数据

    通过模板组合 + 随机扰动扩充样本多样性
    """
    random.seed(seed)
    texts, labels = [], []

    # 涉诈样本：基于模板扩展
    for _ in range(num_fraud):
        base = random.choice(FRAUD_TEMPLATES)
        # 随机添加扰动词，增加样本多样性
        perturbations = [
            f"【紧急通知】{base}",
            f"{base}，请尽快处理！",
            f"重要提醒：{base}",
            f"{base}（限时活动）",
            f"通知：{base}",
        ]
        texts.append(random.choice(perturbations))
        labels.append(1)

    # 正常样本：基于模板扩展
    for _ in range(num_normal):
        base = random.choice(NORMAL_TEMPLATES)
        perturbations = [
            f"各位同事，{base}",
            f"{base}，谢谢大家",
            f"提醒一下，{base}",
            f"{base}，请注意查收。",
            base,
        ]
        texts.append(random.choice(perturbations))
        labels.append(0)

    # 打乱
    combined = list(zip(texts, labels))
    random.shuffle(combined)
    texts, labels = zip(*combined)
    return list(texts), list(labels)


def train():
    """模型训练主流程"""
    print("=" * 60)
    print("  Fraud Text Classifier — Training Pipeline")
    print("=" * 60)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[设备] {device}")

    # 生成训练/验证数据（80/20 分割）
    print("\n[数据] 生成合成训练语料...")
    all_texts, all_labels = generate_synthetic_data(600, 400)
    split = int(len(all_texts) * 0.8)
    train_texts, train_labels = all_texts[:split], all_labels[:split]
    val_texts, val_labels = all_texts[split:], all_labels[split:]

    print(f"  训练集: {len(train_texts)} 条 (涉诈: {sum(train_labels)}, 正常: {len(train_labels) - sum(train_labels)})")
    print(f"  验证集: {len(val_texts)} 条 (涉诈: {sum(val_labels)}, 正常: {len(val_labels) - sum(val_labels)})")

    # 构建词典
    print("\n[词典] 构建中文分词词典...")
    vocab = build_vocab(train_texts, min_freq=1, max_size=config.MODEL_PARAMS["vocab_size"])
    print(f"  词典大小: {len(vocab)}")

    # 更新模型参数中的词典大小
    model_params = {**config.MODEL_PARAMS}
    model_params["vocab_size"] = len(vocab)

    # 数据加载器
    train_dataset = FraudDataset(train_texts, train_labels, vocab, config.MODEL_PARAMS["max_seq_len"])
    val_dataset = FraudDataset(val_texts, val_labels, vocab, config.MODEL_PARAMS["max_seq_len"])
    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)

    # 模型
    print("\n[模型] 初始化 TextCNN...")
    model = FraudTextCNN(**{k: v for k, v in model_params.items()
                            if k in ("vocab_size", "embed_dim", "num_filters",
                                     "filter_sizes", "num_classes", "dropout")})
    model.to(device)
    # PyTorch 2.0 torch.compile 编译加速
    if hasattr(torch, "compile"):
        model = torch.compile(model)
        print(f"  已启用 torch.compile 编译加速")
    print(f"  参数量: {sum(p.numel() for p in model.parameters()):,}")

    # 训练配置
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    epochs = 10

    print(f"\n[训练] 开始训练 ({epochs} epochs)...")
    best_acc = 0.0
    for epoch in range(1, epochs + 1):
        # 训练阶段
        model.train()
        train_loss, train_correct, train_total = 0.0, 0, 0
        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(device), batch_y.to(device)
            optimizer.zero_grad()
            logits = model(batch_x)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch_x.size(0)
            pred = torch.argmax(logits, dim=1)
            train_correct += (pred == batch_y).sum().item()
            train_total += batch_x.size(0)

        train_acc = train_correct / train_total
        train_loss_avg = train_loss / train_total

        # 验证阶段
        model.eval()
        val_loss, val_correct, val_total = 0.0, 0, 0
        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                logits = model(batch_x)
                loss = criterion(logits, batch_y)
                val_loss += loss.item() * batch_x.size(0)
                pred = torch.argmax(logits, dim=1)
                val_correct += (pred == batch_y).sum().item()
                val_total += batch_x.size(0)

        val_acc = val_correct / val_total
        val_loss_avg = val_loss / val_total

        print(f"  Epoch {epoch:2d}/{epochs}: "
              f"train_loss={train_loss_avg:.4f} train_acc={train_acc:.4f} | "
              f"val_loss={val_loss_avg:.4f} val_acc={val_acc:.4f}")

        if val_acc > best_acc:
            best_acc = val_acc

    # 保存模型
    print(f"\n[保存] 最佳验证准确率: {best_acc:.4f}")
    model.save_model(config.MODEL_SAVE_PATH, vocab=vocab)
    print(f"  模型已保存至: {config.MODEL_SAVE_PATH}")

    # 保存词典
    with open(config.VOCAB_SAVE_PATH, "w", encoding="utf-8") as f:
        json.dump(vocab, f, ensure_ascii=False)
    print(f"  词典已保存至: {config.VOCAB_SAVE_PATH}")

    print("\n[完成] 训练流程结束")
    return model, vocab, best_acc


if __name__ == "__main__":
    train()
