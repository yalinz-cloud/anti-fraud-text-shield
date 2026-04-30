"""
TextCNN 文本分类模型 — 基于 PyTorch 2.0 的轻量级反诈检测网络
"""
import os
import torch
import torch.nn as nn
import torch.nn.functional as F


class FraudTextCNN(nn.Module):
    """
    TextCNN model for Chinese fraud text classification

    架构：Embedding → 多尺度 Conv1d → GlobalMaxPool → Concat → Dropout → FC
    """

    def __init__(
        self,
        vocab_size: int = 5000,
        embed_dim: int = 128,
        num_filters: int = 100,
        filter_sizes: list = None,
        num_classes: int = 2,
        dropout: float = 0.5,
        pad_idx: int = 0,
    ):
        super().__init__()
        if filter_sizes is None:
            filter_sizes = [2, 3, 4]

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=pad_idx)
        self.convs = nn.ModuleList([
            nn.Conv1d(
                in_channels=embed_dim,
                out_channels=num_filters,
                kernel_size=k,
                padding="same",
            )
            for k in filter_sizes
        ])
        self.dropout = nn.Dropout(dropout)
        self.fc = nn.Linear(num_filters * len(filter_sizes), num_classes)

        # 权重初始化
        nn.init.xavier_uniform_(self.embedding.weight)
        for conv in self.convs:
            nn.init.xavier_uniform_(conv.weight)
        nn.init.xavier_uniform_(self.fc.weight)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        前向传播
        Args:
            x: token 索引序列, shape (batch, seq_len)
        Returns:
            logits: shape (batch, num_classes)
        """
        # (batch, seq_len) → (batch, seq_len, embed_dim) → (batch, embed_dim, seq_len)
        embedded = self.embedding(x).transpose(1, 2)

        # 多尺度卷积 + 全局最大池化
        pooled = []
        for conv in self.convs:
            feature_map = F.relu(conv(embedded))        # (batch, num_filters, seq_len_out)
            pooled.append(F.adaptive_max_pool1d(feature_map, 1).squeeze(-1))  # (batch, num_filters)

        # 拼接 → Dropout → 全连接
        concat = torch.cat(pooled, dim=1)  # (batch, num_filters * len(filter_sizes))
        dropped = self.dropout(concat)
        logits = self.fc(dropped)          # (batch, num_classes)
        return logits

    def predict_proba(self, x: torch.Tensor) -> torch.Tensor:
        """预测概率值"""
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            return F.softmax(logits, dim=1)

    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """预测类别索引"""
        proba = self.predict_proba(x)
        return torch.argmax(proba, dim=1)

    def save_model(self, path: str, vocab: dict = None):
        """保存模型权重及词典"""
        checkpoint = {"model_state_dict": self.state_dict(), "model_config": {
            "vocab_size": self.embedding.num_embeddings,
            "embed_dim": self.embedding.embedding_dim,
            "num_filters": self.convs[0].out_channels,
            "filter_sizes": [c.kernel_size[0] for c in self.convs],
            "num_classes": self.fc.out_features,
            "dropout": self.dropout.p,
        }}
        if vocab is not None:
            checkpoint["vocab"] = vocab
        torch.save(checkpoint, path)

    @classmethod
    def compile_model(cls, model: "FraudTextCNN") -> "FraudTextCNN":
        """PyTorch 2.0 torch.compile 即时编译加速推理"""
        if hasattr(torch, "compile"):
            return torch.compile(model)
        return model

    @classmethod
    def load_model(cls, path: str, map_location: str = "cpu"):
        """从文件加载模型并应用 torch.compile（仅加载本地可信路径文件）"""
        abs_path = os.path.abspath(path)
        checkpoint = torch.load(abs_path, map_location=map_location, weights_only=False)  # nosec B614
        config = checkpoint.get("model_config")
        if config is None:
            raise ValueError("模型文件缺少 model_config")
        required_keys = {"vocab_size", "embed_dim", "num_filters", "filter_sizes", "num_classes", "dropout"}
        if not required_keys.issubset(config.keys()):
            raise ValueError("模型配置字段缺失")
        model = cls(**config)
        model.load_state_dict(checkpoint["model_state_dict"])
        vocab = checkpoint.get("vocab", None)
        return model, vocab
