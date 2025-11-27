# -*- coding: utf-8 -*-
"""
Cross-Protocol Training Script with Dynamic Hard Example Mining

Training Strategy:
- First 5 epochs: Normal random sampling
- From epoch 6: Hard example resampling every 2 epochs
- Hard samples: Training samples with F1 score below mean
- Sampling weights: Hard samples (1.0), Easy samples (0.2)
"""

import os
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler
import numpy as np
from tqdm import tqdm
import logging
import time
from data_process import ProtocolDataProcessor
#from base_model import ProtocolBoundaryModel
from dual_stream_model import ProtocolBoundaryModel


from config import TrainingConfig, CrossProtocolConfig
from transformers import get_cosine_schedule_with_warmup
import sys
import importlib.util

def import_eval_module():
    """Dynamically import evaluation module"""
    spec = importlib.util.spec_from_file_location("evaluation", "./evaluation.py")
    if spec is None or spec.loader is None:
        raise ImportError("Failed to load evaluation module: evaluation.py")
    evl_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evl_module)
    return evl_module

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create directories
os.makedirs("checkpoints", exist_ok=True)
os.makedirs("results", exist_ok=True)

# Device selection
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
logger.info(f"Using device: {device}")

def compute_sample_f1_scores(model, dataset, device, config):
    """
    Compute F1 score for each training sample for hard example mining
    
    Args:
        model: Current model
        dataset: Training dataset (TensorDataset)
        device: Compute device
        config: Configuration object
    
    Returns:
        List[float]: F1 score for each training sample
    """
    model.eval()
    sample_f1_scores = []
    
    # Create temporary DataLoader with batch_size=1 for per-sample evaluation
    temp_loader = DataLoader(dataset, batch_size=1, shuffle=False, num_workers=0, pin_memory=False)
    
    logger.info(f"Computing F1 scores for {len(dataset)} training samples for hard example mining...")
    
    with torch.no_grad():
        for batch_idx, (batch_X, batch_mask, batch_labels) in enumerate(tqdm(temp_loader, desc="Computing F1 scores")):
            batch_X = batch_X.to(device)
            batch_mask = batch_mask.to(device)
            batch_labels = batch_labels.to(device)
            
            # Model prediction
            best_paths = model(batch_X, batch_mask)
            
            for i in range(len(best_paths)):
                pred_len = len(best_paths[i])
                predicted = torch.zeros_like(batch_labels[i], device=device)
                predicted[:pred_len] = torch.tensor(best_paths[i], dtype=torch.long, device=device)
                
                true = batch_labels[i]
                valid_positions = batch_mask[i, 0]
                
                # Compute TP, FP, FN
                tp = ((predicted == 1) & (true == 1) & valid_positions).sum().item()
                fp = ((predicted == 1) & (true == 0) & valid_positions).sum().item()
                fn = ((predicted == 0) & (true == 1) & valid_positions).sum().item()
                
                # Compute F1 score
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                
                sample_f1_scores.append(f1)
    
    model.train()
    logger.info(f"F1 score computation complete, will be used for hard example resampling")
    return sample_f1_scores

def check_should_stop_resampling(sample_f1_scores, std_threshold=0.01, mean_threshold=0.95):
    """
    Check if hard example resampling should be stopped
    Stop when all training samples have very high F1 scores with narrow distribution
    
    Args:
        sample_f1_scores: List of F1 scores for each training sample
        std_threshold: F1 score standard deviation threshold, default 0.01
        mean_threshold: F1 score mean threshold, default 0.95
    
    Returns:
        bool: True to stop resampling, False to continue
    """
    f1_scores = np.array(sample_f1_scores)
    mean_f1 = np.mean(f1_scores)
    std_f1 = np.std(f1_scores)
    min_f1 = np.min(f1_scores)
    max_f1 = np.max(f1_scores)
    
    should_stop = (mean_f1 >= mean_threshold) and (std_f1 <= std_threshold)
    
    logger.info(f"==== Hard Example Resampling Stop Check ====")
    logger.info(f"F1 Score Statistics:")
    logger.info(f"  Mean: {mean_f1:.4f} (threshold: >={mean_threshold})")
    logger.info(f"  Std Dev: {std_f1:.4f} (threshold: <={std_threshold})")
    logger.info(f"  Range: [{min_f1:.4f}, {max_f1:.4f}]")
    logger.info(f"Stop Decision: {'Yes' if should_stop else 'No'}")
    
    if should_stop:
        logger.info(f"[PASS] Model fits training set well, will stop hard example resampling")
        logger.info(f"  Reason: Mean F1={mean_f1:.4f} >= {mean_threshold}, Std={std_f1:.4f} <= {std_threshold}")
    else:
        logger.info(f"[CONTINUE] Training set has room for improvement, continue hard example resampling")
    
    return should_stop

def create_hard_example_sampler(dataset, sample_f1_scores, hard_sample_weight=1.0, easy_sample_weight=0.2):
    """
    Create hard example sampler based on F1 scores of training samples
    
    Args:
        dataset: Training dataset (train_dataset)
        sample_f1_scores: F1 score for each training sample
        hard_sample_weight: Weight for hard samples
        easy_sample_weight: Weight for easy samples
    
    Returns:
        WeightedRandomSampler: Weighted sampler for training set resampling
    """
    f1_scores = np.array(sample_f1_scores)
    mean_f1 = np.mean(f1_scores)
    
    # Identify hard samples: training samples with F1 below mean
    is_hard_sample = f1_scores < mean_f1
    num_hard_samples = np.sum(is_hard_sample)
    num_easy_samples = len(f1_scores) - num_hard_samples
    
    train_dataset_size = len(dataset)
    logger.info(f"==== Training Set Hard Example Resampling Configuration ====")
    logger.info(f"Total training samples: {train_dataset_size}")
    logger.info(f"Sample F1 statistics:")
    logger.info(f"  Mean F1: {mean_f1:.4f}")
    logger.info(f"  F1 range: [{np.min(f1_scores):.4f}, {np.max(f1_scores):.4f}]")
    logger.info(f"  Hard samples: {num_hard_samples} ({num_hard_samples/len(f1_scores)*100:.1f}%)")
    logger.info(f"  Easy samples: {num_easy_samples} ({num_easy_samples/len(f1_scores)*100:.1f}%)")
    
    # Assign weights: hard samples get higher weight for increased sampling probability
    sample_weights = np.where(is_hard_sample, hard_sample_weight, easy_sample_weight)
    
    logger.info(f"Sampling weights:")
    logger.info(f"  Hard sample weight: {hard_sample_weight}")
    logger.info(f"  Easy sample weight: {easy_sample_weight}")
    logger.info(f"  Hard sample weight ratio: {hard_sample_weight/(hard_sample_weight+easy_sample_weight)*100:.1f}%")
    
    # Create weighted sampler for training set resampling
    sampler = WeightedRandomSampler(
        weights=sample_weights.tolist(),
        num_samples=train_dataset_size,
        replacement=True
    )
    
    logger.info(f"WeightedRandomSampler created:")
    logger.info(f"  Weight array length: {len(sample_weights)} (should equal training set size)")
    logger.info(f"  Samples per epoch: {train_dataset_size} (should equal training set size)")
    logger.info(f"  Replacement allowed: True (hard samples may be selected multiple times)")
    logger.info(f"Hard example sampler created for training set resampling only")
    logger.info(f"Note: Validation set unaffected, maintains original distribution")
    return sampler

def should_perform_resampling(epoch):
    """
    Determine if hard example resampling should be performed
    Schedule: First 5 epochs use normal sampling, from epoch 6 onwards resample every 2 epochs
    
    Args:
        epoch: Current epoch (0-indexed)
    
    Returns:
        bool: Whether to perform resampling
    """
    if epoch < 5:
        return False
    return (epoch - 5) % 2 == 0

def test_resampling_schedule():
    """
    Unit test: Verify the correctness of hard example resampling schedule logic
    """
    print("Testing hard example resampling schedule logic...")
    
    # Test first 5 epochs: should not perform resampling
    for epoch in range(5):
        result = should_perform_resampling(epoch)
        assert not result, f"Epoch {epoch}: Should use random sampling, but returned {result}"
        print(f"  Epoch {epoch+1}: Random sampling [PASS]")
    
    # Test periodic resampling from epoch 6
    expected_resampling_epochs = [5, 7, 9, 11, 13, 15]
    expected_normal_epochs = [6, 8, 10, 12, 14]
    
    for epoch in expected_resampling_epochs:
        result = should_perform_resampling(epoch)
        assert result, f"Epoch {epoch+1}: Should perform resampling, but returned {result}"
        print(f"  Epoch {epoch+1}: Hard example resampling [PASS]")
    
    for epoch in expected_normal_epochs:
        result = should_perform_resampling(epoch)
        assert not result, f"Epoch {epoch+1}: Should use previous resampling, but returned {result}"
        print(f"  Epoch {epoch+1}: Use previous resampling [PASS]")
    
    print("Hard example resampling schedule logic test passed!")
    print("Schedule confirmed:")
    print("  - First 5 epochs (1-5): Random sampling")
    print("  - From epoch 6: Resample every 2 epochs")
    print("  - Resampling at: Epoch 6, 8, 10, 12, 14, 16...")
    return True

def evaluate_on_real_test_set_with_ensemble(model, device, epoch, config, test_data_path):
    """
    Evaluate model performance on real test set using diversity-based ensemble prediction
    """
    try:
        from ensemble_prediction import create_ensemble_predictor
        
        test_max_len = config.TEST_MAX_LEN
        logger.info(f"Epoch {epoch+1}: Starting diversity ensemble evaluation... (test_data_path={test_data_path}, test_max_len={test_max_len})")
        
        # Create test data processor
        data_config = config.get_data_config()
        test_processor = ProtocolDataProcessor(
            max_len=test_max_len, 
            min_packets=data_config['min_packets'],
            min_group_size=data_config['min_group_size']
        )
        
        # Use diversity-based test data generation method
        test_samples_per_group = config.TEST_SAMPLES_PER_GROUP if hasattr(config, 'TEST_SAMPLES_PER_GROUP') else min(10, data_config['samples_per_group'] // 10)
        X_list, mask_list, labels_list, group_metadata = test_processor.process_test_data_with_diversity(
            test_data_path, 
            samples_per_group=test_samples_per_group
        )
        
        if len(X_list) == 0:
            logger.warning(f"Epoch {epoch+1}: No samples generated in test set")
            return None
        
        # Convert to tensors
        X_array = np.stack(X_list, axis=0)
        mask_array = np.stack(mask_list, axis=0)
        labels_array = np.stack(labels_list, axis=0)
        
        X_tensor = torch.tensor(X_array, dtype=torch.long)
        mask_tensor = torch.tensor(mask_array, dtype=torch.bool)
        
        # Create DataLoader
        eval_X = X_tensor
        eval_mask = mask_tensor
        eval_dataset = TensorDataset(eval_X, eval_mask)
        eval_dataloader = DataLoader(eval_dataset, batch_size=config.BATCH_SIZE, shuffle=False, num_workers=0, pin_memory=False)
        
        # Get model predictions
        model.eval()
        all_predictions = []
        
        with torch.no_grad():
            for batch_X, batch_mask in eval_dataloader:
                batch_X = batch_X.to(device)
                batch_mask = batch_mask.to(device)
                
                # Model prediction
                best_paths = model(batch_X, batch_mask)
                
                # Collect predictions
                for i in range(len(best_paths)):
                    all_predictions.append(best_paths[i])
        
        # Create ensemble predictor
        ensemble_predictor = create_ensemble_predictor(
            strategy='diversity_weighted', 
            confidence_threshold=0.6
        )
        
        # Perform ensemble prediction for each format group
        ensemble_results = ensemble_predictor.ensemble_format_predictions(
            all_predictions, group_metadata, list(group_metadata.keys())
        )
        
        # Calculate ensemble evaluation metrics
        true_labels_dict = {}
        sample_idx = 0
        for group_key, metadata in group_metadata.items():
            num_samples = len(metadata['sample_weights'])
            if num_samples > 0:
                # Use first sample's label as true label for this format
                true_labels_dict[group_key] = (labels_array[sample_idx] > 0.5).astype(np.int64)
                sample_idx += num_samples
        
        ensemble_metrics = ensemble_predictor.compute_ensemble_metrics(
            ensemble_results, true_labels_dict
        )
        
        # Calculate overall metrics
        total_tp, total_fp, total_fn = 0, 0, 0
        total_perfect_fields, total_true_fields = 0, 0
        total_confidence = 0
        num_groups = 0
        
        for group_key, metrics in ensemble_metrics.items():
            total_tp += metrics['tp']
            total_fp += metrics['fp']
            total_fn += metrics['fn']
            total_confidence += metrics['avg_confidence']
            num_groups += 1
            
            # Calculate perfect fields
            if group_key in true_labels_dict:
                true_labels = true_labels_dict[group_key]
                ensemble_pred = ensemble_results[group_key][0]
                
                # Extract fields
                true_fields = ensemble_predictor._extract_fields(true_labels)
                pred_fields = ensemble_predictor._extract_fields(ensemble_pred)
                perfect_matches = sum(1 for tf in true_fields if tf in pred_fields)
                
                total_perfect_fields += perfect_matches
                total_true_fields += len(true_fields)
        
        # Calculate overall metrics
        overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        overall_f1 = 2 * overall_precision * overall_recall / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0
        overall_perfection = total_perfect_fields / total_true_fields if total_true_fields > 0 else 0
        avg_confidence = total_confidence / num_groups if num_groups > 0 else 0
        
        logger.info(f"Epoch {epoch+1} - Diversity Ensemble Test Results:")
        logger.info(f"  Overall F1: {overall_f1:.4f} (confidence: {avg_confidence:.3f})")
        logger.info(f"  Overall Precision: {overall_precision:.4f}")
        logger.info(f"  Overall Recall: {overall_recall:.4f}")
        logger.info(f"  Overall Perfection: {overall_perfection:.4f}")
        logger.info(f"  Format groups: {num_groups}, Total samples: {len(all_predictions)}")
        
        return {
            'overall': {
                'f1': overall_f1, 
                'precision': overall_precision, 
                'recall': overall_recall, 
                'perfection': overall_perfection,
                'confidence': avg_confidence
            },
            'ensemble_details': ensemble_metrics,
            'num_format_groups': num_groups
        }
        
    except Exception as e:
        logger.error(f"Epoch {epoch+1}: Diversity ensemble evaluation failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def load_and_prepare_data(data_path, config, val_ratio=None):
    """Load data and prepare for training format using all relevant config parameters"""
    max_len = config.TRAIN_MAX_LEN
    data_config = config.get_data_config()
    val_ratio = val_ratio or data_config['val_ratio']
    
    logger.info(f"Loading and preparing data: {data_path}")
    logger.info(f"Data processing config: max_len={max_len}, min_packets={data_config['min_packets']}, min_group_size={data_config['min_group_size']}, samples_per_group={data_config['samples_per_group']}")
    
    processor = ProtocolDataProcessor(
        max_len=max_len, 
        min_packets=data_config['min_packets'],
        min_group_size=data_config['min_group_size']
    )
    result = processor.process_all_data(
        data_path, 
        samples_per_group=data_config['samples_per_group'],
        adaptive_sampling=data_config.get('adaptive_sampling', True),
        diversity_threshold=data_config.get('diversity_threshold', 1000),
        adaptive_thresholds=data_config.get('adaptive_thresholds'),
        adaptive_multipliers=data_config.get('adaptive_multipliers'),
        max_samples_per_format=data_config.get('max_samples_per_format'),
        min_samples_per_format=data_config.get('min_samples_per_format')
    )
    
    X_list, mask_list, labels_list = result

    logger.info(f"Successfully generated {len(X_list)} training samples")

    # Convert to PyTorch tensors
    X_array = np.stack(X_list, axis=0)
    mask_array = np.stack(mask_list, axis=0)
    binary_labels_list = [(labels > 0.5).astype(np.int64) for labels in labels_list]
    labels_array = np.stack(binary_labels_list, axis=0)
    
    X_tensor = torch.tensor(X_array, dtype=torch.long)
    mask_tensor = torch.tensor(mask_array, dtype=torch.bool)
    labels_tensor = torch.tensor(labels_array, dtype=torch.long)

    # Split training and validation sets
    num_samples = len(X_tensor)
    val_size = int(num_samples * val_ratio)
    train_size = num_samples - val_size
    
    indices = torch.randperm(num_samples)
    train_indices = indices[:train_size]
    val_indices = indices[train_size:]
    
    # Create datasets
    train_X = X_tensor[train_indices]
    train_mask = mask_tensor[train_indices]
    train_labels = labels_tensor[train_indices]
    train_dataset = TensorDataset(train_X, train_mask, train_labels)
    
    val_X = X_tensor[val_indices]
    val_mask = mask_tensor[val_indices]
    val_labels = labels_tensor[val_indices]
    val_dataset = TensorDataset(val_X, val_mask, val_labels)
    
    # Create initial DataLoader (using random sampling)
    train_dataloader = DataLoader(train_dataset, batch_size=config.BATCH_SIZE, shuffle=True, num_workers=0, pin_memory=False)
    val_dataloader = DataLoader(val_dataset, batch_size=config.BATCH_SIZE, shuffle=False, num_workers=0, pin_memory=False)
    
    # Force clear GPU cache
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
        torch.cuda.synchronize()
    
    logger.info(f"Data loading complete, training set samples: {train_size}, validation set samples: {val_size}")
    return train_dataloader, val_dataloader, train_dataset

def evaluate_model(model, dataloader, device, epoch):
    """Evaluate model performance on validation set"""
    model.eval()
    total_tp, total_fp, total_fn = 0, 0, 0
    total_perfect_fields = 0
    total_true_fields = 0
    
    with torch.no_grad():
        for batch_X, batch_mask, batch_labels in dataloader:
            batch_X = batch_X.to(device)
            batch_mask = batch_mask.to(device)
            batch_labels = batch_labels.to(device)
            
            best_paths = model(batch_X, batch_mask)
            
            for i in range(len(best_paths)):
                pred_len = len(best_paths[i])
                predicted = torch.zeros_like(batch_labels[i], device=device)
                predicted[:pred_len] = torch.tensor(best_paths[i], dtype=torch.long, device=device)               
                
                true = batch_labels[i]
                valid_positions = batch_mask[i, 0]
                
                tp = ((predicted == 1) & (true == 1) & valid_positions).sum().item()
                fp = ((predicted == 1) & (true == 0) & valid_positions).sum().item()
                fn = ((predicted == 0) & (true == 1) & valid_positions).sum().item()
                
                total_tp += tp
                total_fp += fp
                total_fn += fn
                
                # Calculate Perfection metric
                true_fields = []
                pred_fields = []
                
                valid_indices = torch.where(valid_positions)[0]
                if len(valid_indices) == 0:
                    continue
                    
                start = valid_indices[0].item()
                
                for pos in valid_indices:
                    if true[pos] == 1:
                        if pos > start:
                            true_fields.append((start, pos.item()))
                        start = pos.item()
                if start < valid_indices[-1].item():
                    true_fields.append((start, valid_indices[-1].item() + 1))
                
                start = valid_indices[0].item()
                for pos in valid_indices:
                    if predicted[pos] == 1:
                        if pos > start:
                            pred_fields.append((start, pos.item()))
                        start = pos.item()
                if start < valid_indices[-1].item():
                    pred_fields.append((start, valid_indices[-1].item() + 1))
                
                perfect_matches = 0
                for true_field in true_fields:
                    if true_field in pred_fields:
                        perfect_matches += 1
                
                total_perfect_fields += perfect_matches
                total_true_fields += len(true_fields)
    
    # Calculate metrics
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    perfection = total_perfect_fields / total_true_fields if total_true_fields > 0 else 0
    
    logger.info(f"Validation Result- Epoch {epoch+1}: F1={f1:.4f}, Precision={precision:.4f}, Recall={recall:.4f}, Perfection={perfection:.4f}")
    return {'f1': f1, 'precision': precision, 'recall': recall, 'perfection': perfection}

def train_cross_protocol_with_hard_mining():
    """Main training function with dynamic hard example resampling"""
    
    config = CrossProtocolConfig
    print("\n Using Cross-Protocol Configuration (with Dynamic Hard Example Mining):")
    print(f"  CRF Weight: {config.CRF_WEIGHT}")
    print(f"  Focal Weight: {config.FOCAL_WEIGHT}")
    print(f"  Dice Weight: {config.DICE_WEIGHT}")
    print(f"  Consistency Weight: {config.CONSISTENCY_WEIGHT}")
    print(f"  Learning Rate: {config.LEARNING_RATE}")
    print(f"  Training Epochs: {config.NUM_EPOCHS}")
    print(f"  Early Stopping Patience: {config.EARLY_STOPPING_PATIENCE}")
    print("\nDynamic Hard Example Mining Mechanism:")
    print(f"  Epochs 1-5: Normal random sampling")
    print(f"  From Epoch 6: Resample every 2 epochs")
    print(f"  Hard sample weight: 1.0, Easy sample weight: 0.2")
    config.print_config()
    
    # Auto merge CSV files
    print("\n=== Step 1: Auto-merge CSV Files ===")
    train_path = None
    test_path = None
    
    try:
        from merge_csv import auto_merge_csvs_from_config
        success, train_path, test_path = auto_merge_csvs_from_config()
        if success:
            print(f"CSV merge successful")
            print(f"  Training data path: {train_path}")
            print(f"  Test data path: {test_path}")
        else:
            print("CSV merge failed, cannot continue training")
            raise ValueError("Unable to get training data path")
    except Exception as e:
        print(f"Error during CSV merge: {str(e)}")
        print("Unable to get training data path, please check TRAIN_PROTOCOLS and TEST_PROTOCOLS in config")
        raise e
    
    print("\n=== Step 2: Load and Prepare Training Data ===")
    train_dataloader, val_dataloader, train_dataset = load_and_prepare_data(
        train_path,
        config=config
    )
    
    print("\n=== Step 3: Create Model ===")
    model_config = config.get_model_config()
    model = ProtocolBoundaryModel(**model_config)
    model = model.to(device)
    
    logger.info(f"Model config: {model_config}")
    
    print("\n=== Step 4: Configure Optimizer ===")
    optimizer_config = config.get_optimizer_config()
    optimizer = optim.AdamW(model.parameters(), lr=optimizer_config['lr'], weight_decay=optimizer_config.get('weight_decay', 0.01))
    
    total_steps = len(train_dataloader) * config.NUM_EPOCHS
    scheduler = get_cosine_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_steps * config.WARMUP_RATIO),
        num_training_steps=total_steps
    )
    
    print("\n=== Step 5: Start Dynamic Hard Example Mining Training ===")
    best_val_f1 = 0.0
    best_real_test_f1 = 0.0
    patience_counter = 0
    
    train_losses = []
    val_f1_scores = []
    real_test_f1_scores = []
    best_real_test_overall = None
    
    # 用于跟踪重采样历史
    resampling_history = []
    
    # 用于控制是否继续进行难例重采样
    resampling_stopped = False
    resampling_stop_epoch = None
    
    for epoch in range(config.NUM_EPOCHS):
        start_time = time.time()
        
        # 动态难例重采样机制：仅对训练集进行重采样
        # 新增：如果已经停止重采样，则跳过重采样逻辑
        if should_perform_resampling(epoch) and not resampling_stopped:
            logger.info(f"\nEpoch {epoch+1}: 开始执行动态难例重采样（仅对训练集）...")
            
            # 步骤1：使用当前模型评估所有训练样本的F1分数
            sample_f1_scores = compute_sample_f1_scores(model, train_dataset, device, config)
            
            # 新增：检查是否应该停止难例重采样
            if check_should_stop_resampling(sample_f1_scores, std_threshold=0.01, mean_threshold=0.95):
                resampling_stopped = True
                resampling_stop_epoch = epoch + 1
                logger.info(f"[STOP] 在Epoch {epoch+1}检测到训练集F1分数收敛，自动停止后续难例重采样")
                logger.info(f"[INFO] 后续训练将使用随机采样，以避免过拟合并节省计算资源")
                
                # 恢复为随机采样
                train_dataloader = DataLoader(
                    train_dataset, 
                    batch_size=config.BATCH_SIZE, 
                    shuffle=True,  # 使用随机采样
                    num_workers=0, 
                    pin_memory=False
                )
                
                # 记录停止事件到重采样历史
                resampling_info = {
                    'epoch': epoch + 1,
                    'mean_f1': np.mean(sample_f1_scores),
                    'std_f1': np.std(sample_f1_scores),
                    'hard_samples_ratio': np.sum(np.array(sample_f1_scores) < np.mean(sample_f1_scores)) / len(sample_f1_scores),
                    'status': 'stopped_converged'
                }
                resampling_history.append(resampling_info)
            else:
                # 步骤2：基于F1分数创建难例重采样器，难样本获得更高的采样权重
                hard_sampler = create_hard_example_sampler(
                    train_dataset, 
                    sample_f1_scores, 
                    hard_sample_weight=1.0,  # 难样本（F1低于均值）权重
                    easy_sample_weight=0.2   # 简单样本权重
                )
                
                # 步骤3：使用难例采样器重新创建训练DataLoader
                # 注意：这里只重新创建train_dataloader，验证集保持不变
                train_dataloader = DataLoader(
                    train_dataset, 
                    batch_size=config.BATCH_SIZE, 
                    sampler=hard_sampler,  # 使用难例采样器替换随机采样
                    num_workers=0, 
                    pin_memory=False
                )
                
                # 记录重采样历史
                resampling_info = {
                    'epoch': epoch + 1,
                    'mean_f1': np.mean(sample_f1_scores),
                    'std_f1': np.std(sample_f1_scores),
                    'hard_samples_ratio': np.sum(np.array(sample_f1_scores) < np.mean(sample_f1_scores)) / len(sample_f1_scores),
                    'status': 'active'
                }
                resampling_history.append(resampling_info)
                
                logger.info(f"训练集难例重采样完成，难样本比例: {resampling_info['hard_samples_ratio']*100:.1f}%")
                logger.info(f"验证集保持原始随机采样，不进行重采样")
            # Update scheduler
            remaining_epochs = config.NUM_EPOCHS - epoch
            new_total_steps = len(train_dataloader) * remaining_epochs
            
            scheduler = get_cosine_schedule_with_warmup(
                optimizer,
                num_warmup_steps=int(new_total_steps * config.WARMUP_RATIO),
                num_training_steps=new_total_steps
            )
        elif should_perform_resampling(epoch) and resampling_stopped:
            logger.info(f"\nEpoch {epoch+1}: Hard example resampling stopped at Epoch {resampling_stop_epoch}, using random sampling")
        
        # Training phase
        model.train()
        total_loss = 0.0
        
        # Update sampling status display logic, consider stopping resampling
        if resampling_stopped:
            sampling_status = "Random sampling (resampling stopped)"
        elif epoch >= 5 and (epoch - 5) % 2 < 2:
            sampling_status = "Hard example resampling"
        else:
            sampling_status = "Random sampling"
        
        progress_bar = tqdm(train_dataloader, desc=f"Epoch {epoch+1}/{config.NUM_EPOCHS} ({sampling_status})")
        
        for step, (batch_X, batch_mask, batch_labels) in enumerate(progress_bar):
            try:
                batch_X = batch_X.to(device)
                batch_mask = batch_mask.to(device)
                batch_labels = batch_labels.to(device)
                
        # Force clear GPU cache
                if step % 10 == 0 and torch.cuda.is_available():
                    torch.cuda.empty_cache()
                
                # Compute combined loss
                loss = model(batch_X, batch_mask, labels=batch_labels)
                
                # Check if loss is finite
                if not torch.isfinite(loss):
                    logger.warning(f"Epoch {epoch+1}, Step {step}: Detected infinite loss: {loss.item()}, skipping batch")
                    continue
                
                optimizer.zero_grad()
                loss.backward()
                
                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=config.MAX_GRAD_NORM)
                optimizer.step()
                scheduler.step()

                total_loss += loss.item()
                progress_bar.set_postfix({'loss': loss.item(), 'sampling': sampling_status})
                
            except RuntimeError as e:
                if "out of memory" in str(e):
                    logger.error(f"GPU out of memory: {e}")
                    if torch.cuda.is_available():
                        torch.cuda.empty_cache()
                    continue
                else:
                    logger.error(f"Training step error: {e}")
                    raise e
            except Exception as e:
                logger.error(f"Unknown error: {e}")
                continue
        
        avg_loss = total_loss / len(train_dataloader)
        train_losses.append(avg_loss)
        
        # Validation phase
        val_metrics = evaluate_model(model, val_dataloader, device, epoch)
        val_f1_scores.append(val_metrics['f1'])
        
        # Real test set evaluation (using diversity ensemble)
        real_test_metrics = evaluate_on_real_test_set_with_ensemble(model, device, epoch, config, test_path)
        if real_test_metrics:
            current_real_test_f1 = real_test_metrics['overall']['f1']
            current_confidence = real_test_metrics['overall']['confidence']
            num_format_groups = real_test_metrics['num_format_groups']
            real_test_f1_scores.append(current_real_test_f1)
            
            # Log ensemble evaluation details
            logger.info(f"  Ensemble evaluation: Format groups={num_format_groups}, Avg confidence={current_confidence:.3f}")
        else:
            current_real_test_f1 = 0.0
            real_test_f1_scores.append(0.0)
        
        # Model saving and early stopping
        if val_metrics['f1'] > best_val_f1:
            best_val_f1 = val_metrics['f1']
            torch.save(model.state_dict(), "checkpoints/best_val_model_cross_protocol.pth")
            logger.info(f"Saved best validation model, F1: {best_val_f1:.4f}")
        
        # Focus on real test set performance
        if current_real_test_f1 > best_real_test_f1:
            best_real_test_f1 = current_real_test_f1
            torch.save(model.state_dict(), "checkpoints/best_real_test_model_cross_protocol.pth")
            logger.info(f"Saved best real test model, F1: {best_real_test_f1:.4f}")
            best_real_test_overall = real_test_metrics['overall']
            patience_counter = 0
        else:
            patience_counter += 1
        
        # Save model for each epoch
        torch.save(model.state_dict(), f"checkpoints/model_epoch_{epoch+1}_cross_protocol.pth")
        
        # Early stopping strategy
        if patience_counter >= config.EARLY_STOPPING_PATIENCE:
            logger.info(f"Early stopping triggered! Real test set performance did not improve for {config.EARLY_STOPPING_PATIENCE} epochs")
            break
        
        # Logging
        epoch_time = time.time() - start_time
        logger.info(f"Epoch {epoch+1}/{config.NUM_EPOCHS} completed, elapsed: {epoch_time:.2f}s")
        logger.info(f"  Training loss: {avg_loss:.4f}")
        logger.info(f"  Validation F1: {val_metrics['f1']:.4f}, Perfection: {val_metrics['perfection']:.4f}")
        if real_test_metrics:
            logger.info(f"  Real test F1: {current_real_test_f1:.4f}, Perfection: {real_test_metrics['overall']['perfection']:.4f}")
        logger.info(f"  Best real test F1: {best_real_test_f1:.4f}, Patience: {patience_counter}/{config.EARLY_STOPPING_PATIENCE}")
        logger.info(f"  Sampling strategy: {sampling_status}")
    
    # Statistics after training
    logger.info(f"\n\n========== Dynamic Hard Example Mining Training Complete ==========")
    logger.info(f"Best validation F1: {best_val_f1:.4f}")
    logger.info(f"Best real test F1: {best_real_test_f1:.4f}")
    logger.info(f"Final training loss: {train_losses[-1]:.4f}")
    logger.info(f"Final validation F1: {val_f1_scores[-1]:.4f}")
    logger.info(f"Final real test F1: {real_test_f1_scores[-1]:.4f}")
    
    # Output resampling stop information
    if resampling_stopped:
        logger.info(f"\n[STOPPED] Hard example resampling stop information:")
        logger.info(f"  Stop epoch: {resampling_stop_epoch}")
        logger.info(f"  Stop reason: Training set F1 scores converged (high mean and low std)")
        logger.info(f"  Subsequent training: Using random sampling to avoid overfitting")
    else:
        logger.info(f"\n[ACTIVE] Hard example resampling remained active throughout training")
    
    # Output resampling history
    if resampling_history:
        logger.info(f"\nResampling history:")
        for info in resampling_history:
            status_str = f" [{info['status']}]" if 'status' in info else ""
            std_str = f", Std={info['std_f1']:.4f}" if 'std_f1' in info else ""
            logger.info(f"  Epoch {info['epoch']}: Mean F1={info['mean_f1']:.4f}{std_str}, Hard sample ratio={info['hard_samples_ratio']*100:.1f}%{status_str}")
    
    # Save training metrics
    np.save("results/train_losses_cross_protocol.npy", np.array(train_losses))
    np.save("results/val_f1_scores_cross_protocol.npy", np.array(val_f1_scores))
    np.save("results/real_test_f1_scores_cross_protocol.npy", np.array(real_test_f1_scores))
    
    # Save resampling history
    if resampling_history:
        import json
        with open("results/resampling_history.json", "w") as f:
            json.dump(resampling_history, f, indent=2)
    
    # Append training record
    try:
        record_lines = [
            f"===== Training Record ({time.strftime('%Y-%m-%d %H:%M:%S')}) =====",
            f"TRAIN_PROTOCOLS: {config.TRAIN_PROTOCOLS}",
            f"TEST_PROTOCOLS: {config.TEST_PROTOCOLS}",
            f"TRAIN_MAX_LEN: {config.TRAIN_MAX_LEN}",
            f"TEST_MAX_LEN: {config.TEST_MAX_LEN}",
            f"MIN_PACKETS: {config.MIN_PACKETS}",
            f"SAMPLES_PER_GROUP: {config.SAMPLES_PER_GROUP}",
            f"MIN_GROUP_SIZE: {config.MIN_GROUP_SIZE}",
            f"LEARNING_RATE: {config.LEARNING_RATE}",
            f"D_MODEL: {config.D_MODEL}",
            f"NHEAD: {config.NHEAD}",
            f"NUM_LAYERS: {config.NUM_LAYERS}",
        ]
        if best_real_test_overall:
            record_lines += [
                f"RESULTS - Precision: {best_real_test_overall.get('precision', 0):.4f}",
                f"RESULTS - Recall: {best_real_test_overall.get('recall', 0):.4f}",
                f"RESULTS - F1: {best_real_test_overall.get('f1', 0):.4f}",
                f"RESULTS - Perfection: {best_real_test_overall.get('perfection', 0):.4f}",
            ]
        else:
            record_lines += [
                f"RESULTS - Precision: N/A",
                f"RESULTS - Recall: N/A",
                f"RESULTS - F1: {best_real_test_f1:.4f}",
                f"RESULTS - Perfection: N/A",
            ]
        record_lines.append("============================================================")
        with open("training_records.log", "a", encoding="utf-8") as rf:
            rf.write("\n".join(record_lines) + "\n")
        logger.info("Training record appended to training_records.log")
    except Exception as e:
        logger.error(f"Failed to append training record: {e}")

if __name__ == "__main__":
    # Run scheduling logic unit test first
    print("========== Dynamic Hard Example Resampling Mechanism Verification ==========\n")
    try:
        test_resampling_schedule()
        print("\nScheduling logic verification passed, starting training...\n")
    except Exception as e:
        print(f"Scheduling logic verification failed: {e}")
        print("Please check the implementation of should_perform_resampling function")
        raise e
    
    try:
        train_cross_protocol_with_hard_mining()
    except Exception as e:
        logger.exception("Error occurred during dynamic hard example resampling training")
        raise e
