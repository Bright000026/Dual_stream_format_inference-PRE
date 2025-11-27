# Protocol Boundary Detection with Dual-Stream Architecture

[English](README.md) | [中文](README_zh-CN.md)

协议边界检测双流架构模型 - 用于协议报文字段边界识别，适用于IoT和工业协议

## 项目简介

本项目实现了一个基于深度学习的协议边界检测模型，能够自动识别未知协议的报文字段边界。适用于IoT和工业协议场景。采用双流架构设计，通过水平流和垂直流分别建模单条报文内的序列依赖和跨报文的统计共性。

## 核心特性

- ✅ **双流架构**: 水平流(Transformer) + 垂直流(VerticalAttention)
- ✅ **FiLM特征调制**: 基于字节统计先验的自适应特征调制
- ✅ **动态融合**: 门控机制融合双流特征
- ✅ **难例挖掘**: 动态难例重采样提升模型泛化能力
- ✅ **跨协议泛化**: 支持在多种协议上训练和测试

## 项目结构

```
opensource_release/
├── base_model.py              # 基础模型架构
├── dual_stream_model.py       # 双流模型(核心)
├── train.py                   # 训练脚本
├── test.py                    # 测试脚本
├── batch_test.py              # 批量测试脚本
├── config.py                  # 配置文件
├── data_process.py            # 数据处理模块
├── ensemble_prediction.py     # 集成预测模块
├── merge_csv.py               # CSV合并工具
└── requirements.txt           # 依赖包列表
```

## 文件说明

### 核心模型文件

- **base_model.py**: 基础模型架构，包含所有核心组件
- **dual_stream_model.py**: 双流模型主文件，实现双流架构

### 训练和测试文件

- **train.py**: 训练脚本，支持:

  - 跨协议泛化训练
  - 动态难例重采样
  - 早停机制
  - 多种损失函数(CRF, Focal, Dice)
- **test.py**: 测试脚本，支持:

  - 单协议测试
  - 多样性评估
  - 结果JSON输出
- **batch_test.py**: 批量测试脚本，支持:

  - 多协议自动化测试
  - 结果汇总和CSV导出

### 配置和工具文件

- **config.py**: 配置文件，包含:

  - 训练参数(学习率、batch size、epoch数等)
  - 模型参数(维度、层数、窗口大小等)
  - 数据参数(协议列表、序列长度等)
- **data_process.py**: 数据处理模块，负责:

  - CSV数据加载
  - 协议报文分组
  - 训练样本生成
  - 多样性评估

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 准备数据

将协议数据CSV文件放置在相应目录，CSV格式要求:

- `Segment`: 报文字节序列(空格分隔的十六进制)
- `Field Names`: 字段名称列表

### 3. 配置参数

修改 `config.py` 中的配置:

```python
# 训练协议
TRAIN_PROTOCOLS = ['tcp', 'udp', 'arp', 'dns', 'bgp', 'icmp', 'radius']

# 测试协议
TEST_PROTOCOLS = ['s7comm']

# 训练参数
NUM_EPOCHS = 10
BATCH_SIZE = 4
LEARNING_RATE = 1e-4
```

### 4. 训练模型

```bash
python train.py
```

训练完成后，模型将保存在 `checkpoints/` 目录。

### 5. 测试模型

单协议测试:

```bash
python test.py
```

批量测试:

```bash
python batch_test.py
```

## 模型架构

### 双流架构设计

本模型采用双流架构，结合水平流、垂直流和FiLM融合机制捕获协议报文的不同特征。详细架构参见framework.pdf。

**水平流 (Horizontal Stream)**:

- 使用Transformer编码器建模单条报文内的序列依赖关系
- 捕获字节序列的上下文信息
- 提取局部特征模式
- 通过多头自注意力机制捕获长距离依赖

**垂直流 (Vertical Stream)**:

- 使用垂直注意力机制建模跨报文的统计共性
- 捕获多条相似报文间的对应关系
- 提取全局统计特征
- 利用批次内报文的对齐特性识别字段边界模式

**FiLM特征融合 (Feature-wise Linear Modulation)**:

- 基于字节统计特征(熵、直方图、频率分布等)的自适应特征调制
- 对双流特征进行动态缩放和偏移，增强模型对不同协议的适应性
- 将统计先验知识注入深度特征空间
- 通过门控机制自适应控制调制强度

**动态融合**:

- 门控机制自适应融合水平流和垂直流特征
- 根据输入特征动态调整双流的权重分配

### 关键组件

1. **水平流(Horizontal Stream)**: Transformer编码器，建模单条报文内的序列依赖
2. **垂直流(Vertical Stream)**: 垂直注意力机制，捕获跨报文的统计共性
3. **FiLM特征融合**: 基于字节统计特征的自适应调制，将统计先验注入特征空间
4. **动态融合**: 门控机制自适应融合双流特征

## 训练策略

### 难例挖掘

训练过程采用动态难例重采样策略:

- 前5个epoch正常训练
- 从第6个epoch开始，每2个epoch执行一次难例重采样
- 难样本(F1低于均值)获得更高采样权重

### 损失函数

组合多种损失函数:

- **CRF Loss**: 序列标注损失
- **Focal Loss**: 处理类别不平衡
- **Dice Loss**: 提高边界重叠度

## 评估指标

- **Precision**: 预测边界的准确率
- **Recall**: 真实边界的召回率
- **F1 Score**: Precision和Recall的调和平均
- **Field Accuracy**: 完整字段的准确率(Perfection)

## 📄 引用

如果您在研究中使用了本代码，请引用我们的论文：

> **论文审稼中，引用信息将在论文发表后更新。**

目前请引用本仓库

## 📬 联系方式

如有问题或建议，请：

- 在 [GitHub Issues](../../issues) 提交问题
- 联系方式将在论文发表后更新

## 📜 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

**引用要求**：如果您在研究或项目中使用了本代码，请引用本仓库和我们的论文（引用信息将在论文发表后更新）。
