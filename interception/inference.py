"""
推理引擎 — 加载模型、文本预处理、单条/批量推理
"""
import os
import json
import torch
import jieba
from models.classifier import FraudTextCNN
import config


class FraudDetector:
    """Fraud text detector wrapping the full inference pipeline"""

    def __init__(self, model_path: str = None, vocab_path: str = None, threshold: float = None):
        self._model_path = model_path or config.MODEL_SAVE_PATH
        self._vocab_path = vocab_path or config.VOCAB_SAVE_PATH
        self._threshold = threshold or config.DETECTION_THRESHOLD
        self._model = None
        self._vocab = None
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._max_seq_len = config.MODEL_PARAMS["max_seq_len"]

    def load(self):
        """加载模型和词典，应用 PyTorch 2.0 torch.compile 加速推理"""
        if os.path.exists(self._model_path):
            self._model, self._vocab = FraudTextCNN.load_model(self._model_path, map_location=str(self._device))
            self._model.to(self._device)
            self._model = FraudTextCNN.compile_model(self._model)  # torch.compile 加速
            self._model.eval()
        else:
            # 模型文件不存在时，初始化为随机权重模型（演示模式）
            print(f"[提示] 模型文件 {self._model_path} 不存在，初始化为随机权重模型")
            model_args = {k: v for k, v in config.MODEL_PARAMS.items()
                          if k in ("vocab_size", "embed_dim", "num_filters",
                                   "filter_sizes", "num_classes", "dropout")}
            self._model = FraudTextCNN(**model_args)
            self._model.to(self._device)
            self._model.eval()
            self._vocab = {"<PAD>": 0, "<UNK>": 1}
        return self

    def _tokenize(self, text: str) -> list:
        """中文分词并转换为 token 序列"""
        tokens = jieba.lcut(text.strip())
        token_ids = []
        for token in tokens:
            if self._vocab and token in self._vocab:
                token_ids.append(self._vocab[token])
            else:
                token_ids.append(self._vocab.get("<UNK>", 1) if self._vocab else 0)
        return token_ids

    def _build_input(self, texts: list) -> torch.Tensor:
        """批量构建模型输入张量"""
        batch_ids = []
        for text in texts:
            token_ids = self._tokenize(text)
            if len(token_ids) >= self._max_seq_len:
                token_ids = token_ids[:self._max_seq_len]
            else:
                pad_id = self._vocab.get("<PAD>", 0) if self._vocab else 0
                token_ids += [pad_id] * (self._max_seq_len - len(token_ids))
            batch_ids.append(token_ids)
        return torch.tensor(batch_ids, dtype=torch.long, device=self._device)

    def detect_single(self, text: str) -> dict:
        """单条文本检测"""
        input_tensor = self._build_input([text])
        proba = self._model.predict_proba(input_tensor)
        fraud_prob = float(proba[0, 1])  # 第1类为"涉诈"
        is_fraud = fraud_prob >= self._threshold
        return {
            "text": text[:200],
            "fraud_probability": round(fraud_prob, 4),
            "is_fraud": is_fraud,
            "threshold": self._threshold,
        }

    def detect_batch(self, texts: list) -> list:
        """批量文本检测"""
        if not texts:
            return []
        input_tensor = self._build_input(texts)
        proba = self._model.predict_proba(input_tensor)
        results = []
        for i, text in enumerate(texts):
            fraud_prob = float(proba[i, 1])
            results.append({
                "text": text[:200],
                "fraud_probability": round(fraud_prob, 4),
                "is_fraud": fraud_prob >= self._threshold,
                "threshold": self._threshold,
            })
        return results
