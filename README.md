# Anti-Fraud Text Shield

基于 PyTorch 2.0 + 多维正则规则引擎 + AES-256-GCM 加密的文本安全检测系统。

## 项目概述

系统围绕文本安全检测与数据保护两大核心，由四个协同工作的模块组成：

| 模块 | 功能 |
|------|------|
| 安全防护 | 访问权限校验、路径遍历防护、代码注入检测、异常操作监控 |
| 合规处理 | 12类涉诈话术正则规则库、隐私字段自动脱敏 |
| 加密防护 | AES-256-GCM 文件级加密存储、密钥外部化管理 |
| 实时拦截 | TextCNN 模型推理 + 规则融合判决、本地加密日志 |

## 项目结构

```
anti-fraud-text-shield/
├── config.py                    # 全局配置
├── compliance/                  # 合规处理模块
│   ├── rules.py                 # 涉诈特征正则规则引擎
│   └── filter.py                # 隐私字段脱敏过滤器
├── encryption/                  # 加密防护模块
│   └── aes_crypto.py            # AES-256-GCM 加解密工具
├── models/                      # 模型定义
│   └── classifier.py            # TextCNN 文本分类网络
├── interception/                # 实时拦截模块
│   ├── inference.py             # 模型推理引擎
│   └── interceptor.py           # 拦截判决与日志记录
├── security/                    # 安全防护模块
│   ├── access_control.py        # 管理员权限校验
│   ├── input_validator.py       # 输入安全清洗（注入/XSS/SQL检测）
│   ├── path_sanitizer.py        # 路径遍历防护
│   └── anomaly_monitor.py       # 异常操作监控告警
├── scripts/                     # 可执行脚本
│   ├── demo.py                  # 完整功能演示
│   ├── train.py                 # 模型训练流程
│   └── encrypt_data.py          # 数据加密存储演示
├── tests/
│   └── run_tests.py             # 综合测试套件
└── requirements.txt             # 依赖清单
```

## 环境要求

- Python >= 3.8
- PyTorch >= 2.0.0
- pycryptodome >= 3.15.0
- jieba >= 0.42.1
- numpy >= 1.24.0

## 快速使用

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 运行完整演示

```bash
python scripts/demo.py
```

演示内容依次展示：安全访问校验 → 输入注入检测 → 路径遍历防护 → 隐私字段脱敏 → 涉诈规则扫描 → AES 加解密 → 模型推理 → 实时拦截判决 → 异常操作监控告警。

### 3. 运行综合测试

```bash
python tests/run_tests.py
```

测试覆盖：隐私过滤、规则引擎、加密模块、安全防护、拦截器集成、异常监控、准确率评估（7项）。

### 4. 模型训练

```bash
python scripts/train.py
```

使用 TextCNN 网络在合成语料上进行训练，模型自动保存至 `models/fraud_model.pt`。

### 5. 数据加密

```bash
python scripts/encrypt_data.py
```

演示 AES-256-GCM 对反诈特征数据的加密存储与解密验证。

## 公开仓库说明

- 本仓库面向公开演示，示例文本中的手机号、证件号、邮箱、IP 与高风险话术均已做脱敏或占位处理
- 运行生成的密钥、日志、模型文件、缓存文件默认不纳入版本控制
- 如需运行加密演示，建议通过环境变量 `AFS_KEY_PATH` 指定本地未托管的密钥路径

## 系统特点

- **纯离线运行**：所有检测仅在本地执行，无网络上报请求
- **数据加密存储**：涉诈特征库、检测日志均支持 AES-256-GCM 加密
- **多层检测机制**：正则规则引擎 + TextCNN 模型融合判决
- **安全开发实践**：通过 OWASP 安全编码指南校验，无硬编码密钥，无路径遍历风险
- **隐私合规**：自动识别并脱敏手机号、身份证号、银行卡号等敏感字段

## 安全扫描

```bash
pip install bandit
bandit -r . -x ".git,__pycache__,data,logs" -ll
```

当前扫描结果：0 高危、0 中危漏洞。
