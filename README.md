# Protocol Boundary Identification with Dual-Stream Architecture

[English](README.md) | [中文](README_zh-CN.md)

Deep learning model for format inference in protocol reverse engineering, applicable to IoT and industrial protocols

## Introduction

This project implements a deep learning-based protocol boundary detection model that can automatically identify field boundaries in unknown protocol messages. Applicable to IoT and industrial protocol scenarios. It adopts a dual-stream architecture design, modeling intra-message sequential dependencies and cross-message statistical commonalities through horizontal and vertical streams.

## Core Features

- ✅ **Dual-Stream Architecture**: Horizontal Stream (Transformer) + Vertical Stream (VerticalAttention)
- ✅ **FiLM Feature Modulation**: Adaptive feature modulation based on byte-level statistics
- ✅ **Dynamic Fusion**: Gate-controlled fusion of dual-stream features
- ✅ **Hard Example Mining**: Dynamic hard example resampling for improved generalization
- ✅ **Cross-Protocol Generalization**: Support for training and testing on multiple protocols

## Project Structure

```
opensource_release/
├── base_model.py              # Base model architecture
├── dual_stream_model.py       # Dual-stream model (core)
├── train.py                   # Training script
├── test.py                    # Testing script
├── batch_test.py              # Batch testing script
├── config.py                  # Configuration file
├── data_process.py            # Data processing module
├── ensemble_prediction.py     # Ensemble prediction module
├── merge_csv.py               # CSV merging utility
├── requirements.txt           # Dependency list
├── generate/                  # Protocol dataset generators
│   ├── README.md              # Generator documentation
│   ├── *_generator.py         # Protocol generators (TCP, UDP, ARP, DNS, etc.)
│   └── csv/                   # Generated protocol datasets
└── backup/                    # Pre-trained model weights
    ├── model_epoch_10_cross_protocol.pth                      # Full model
    ├── model_epoch_10_cross_protocol_horizontal_ablation.pth  # Horizontal-only ablation
    └── model_epoch_10_cross_protocol_nofilm.pth               # No-FiLM ablation
```

## File Descriptions

### Core Model Files

- **base_model.py**: Base model architecture containing all core components
- **dual_stream_model.py**: Dual-stream model main file implementing the dual-stream architecture

### Training and Testing Files

- **train.py**: Training script with support for:

  - Cross-protocol generalization training
  - Dynamic hard example resampling
  - Early stopping mechanism
  - Multiple loss functions (CRF, Focal, Dice)
- **test.py**: Testing script with support for:

  - Single protocol testing
  - Diversity evaluation
  - JSON result output
- **batch_test.py**: Batch testing script with support for:

  - Multi-protocol automated testing
  - Result aggregation and CSV export

### Configuration and Utility Files

- **config.py**: Configuration file containing:

  - Training parameters (learning rate, batch size, epochs, etc.)
  - Model parameters (dimensions, layers, window size, etc.)
  - Data parameters (protocol list, sequence length, etc.)
- **data_process.py**: Data processing module responsible for:

  - CSV data loading
  - Protocol message grouping
  - Training sample generation
  - Diversity evaluation

### Dataset Generation

- **generate/**: Protocol dataset generator collection
  - Contains 12 protocol generators (TCP, UDP, ARP, DNS, MQTT, CoAP, BGP, RADIUS, Modbus, S7Comm, OMRON FINS, HART-IP)
  - Automatically generates protocol message datasets with field boundary annotations
  - See [generate/README.md](generate/README.md) for detailed documentation

### Pre-trained Models

- **backup/**: Pre-trained model weights
  - **model_epoch_10_cross_protocol.pth**: Complete dual-stream model trained on 6 protocols (tcp, udp, arp, dns, bgp, radius)
  - **model_epoch_10_cross_protocol_horizontal_ablation.pth**: Horizontal-only ablation model (without vertical stream)
  - **model_epoch_10_cross_protocol_nofilm.pth**: No-FiLM ablation model (without FiLM feature modulation)
  - These models can be directly used for testing or fine-tuning

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Prepare Data

Place protocol data CSV files in the appropriate directory. CSV format requirements:

- `Segment`: Message byte sequence (space-separated hexadecimal)
- `Field Names`: List of field names

### 3. Configure Parameters

Modify configuration in `config.py`:

```python
# Training protocols
TRAIN_PROTOCOLS = ['tcp', 'udp', 'arp', 'dns', 'bgp', 'icmp', 'radius']

# Testing protocols
TEST_PROTOCOLS = ['s7comm']

# Training parameters
NUM_EPOCHS = 10
BATCH_SIZE = 4
LEARNING_RATE = 1e-4
```

### 4. Train Model

```bash
python train.py
```

After training completes, the model will be saved in the `checkpoints/` directory.

### 5. Test Model

Single protocol testing:

```bash
python test.py
```

Batch testing:

```bash
python batch_test.py
```

## Model Architecture

### Dual-Stream Architecture Design

The model adopts a dual-stream architecture that combines horizontal stream, vertical stream, and FiLM fusion mechanism to capture different features of protocol messages. For detailed architecture, see framework.pdf.

**Horizontal Stream**:

- Uses Transformer encoder to model sequential dependencies within individual messages
- Captures contextual information in byte sequences
- Extracts local feature patterns
- Captures long-range dependencies through multi-head self-attention mechanism

**Vertical Stream**:

- Uses vertical attention mechanism to model statistical commonalities across messages
- Captures correspondence relationships between similar messages
- Extracts global statistical features
- Leverages alignment characteristics of messages within a batch to identify field boundary patterns

**FiLM Feature Fusion (Feature-wise Linear Modulation)**:

- Adaptive feature modulation based on byte-level statistics (entropy, histogram, frequency distribution, etc.)
- Performs dynamic scaling and shifting on dual-stream features to enhance model adaptability to different protocols
- Injects statistical prior knowledge into deep feature space
- Adaptively controls modulation intensity through gating mechanism

**Dynamic Fusion**:

- Gate-controlled adaptive fusion of horizontal and vertical stream features
- Dynamically adjusts weight allocation of dual streams based on input features

### Key Components

1. **Horizontal Stream**: Transformer encoder modeling sequential dependencies within messages
2. **Vertical Stream**: Vertical attention mechanism capturing cross-message statistical commonalities
3. **FiLM Feature Fusion**: Adaptive modulation based on byte-level statistics, injecting statistical priors into feature space
4. **Dynamic Fusion**: Gate-controlled adaptive fusion of dual-stream features

## Training Strategy

### Hard Example Mining

The training process employs a dynamic hard example resampling strategy:

- Normal training for the first 5 epochs
- Starting from epoch 6, hard example resampling is performed every 2 epochs
- Hard samples (F1 below average) receive higher sampling weights

### Loss Functions

Combination of multiple loss functions:

- **CRF Loss**: Sequence labeling loss
- **Focal Loss**: Handling class imbalance
- **Dice Loss**: Improving boundary overlap

## Evaluation Metrics

- **Precision**: Accuracy of predicted boundaries
- **Recall**: Recall rate of true boundaries
- **F1 Score**: Harmonic mean of Precision and Recall
- **Field Accuracy**: Accuracy of complete fields (Perfection)

## 📄 Citation

If you use this code in your research, please cite our paper:

> **Paper is under review. Citation information will be updated upon publication.**

For now, please reference this repository

## 📬 Contact

For questions or issues, please:

- Open an issue on [GitHub Issues](../../issues)
- Contact information will be updated upon paper publication

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Citation Requirement**: If you use this code in your research or project, please cite this repository and our paper (citation information will be updated upon publication).
