# -*- coding: utf-8 -*-
"""
Boundary prediction test script
Used to output boundary prediction results and compare with true labels on real test set
"""

import os
import torch
import numpy as np
from torch.utils.data import DataLoader, TensorDataset
import logging
from data_process import ProtocolDataProcessor
#from base_model import ProtocolBoundaryModel
from dual_stream_model import ProtocolBoundaryModel

from config import CrossProtocolConfig
from ensemble_prediction import create_ensemble_predictor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Select device
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
logger.info(f"Using device: {device}")

# ===================
# Ensemble strategy configuration
# ===================
# Optional values: None, 'weighted_majority', 'diversity_weighted', 'adaptive'
# None: Don't use ensemble, predict each sample individually (default)
# 'weighted_majority': Weighted majority voting
# 'diversity_weighted': Diversity-weighted voting (recommended)
# 'adaptive': Adaptive voting
ENSEMBLE_STRATEGY = None  # Modify here to select different strategies
ENSEMBLE_CONFIDENCE_THRESHOLD = 0.6  # Confidence threshold

def extract_fields_from_boundaries(boundary_sequence, max_len):
    """
    Extract field ranges from boundary sequence
    
    Args:
        boundary_sequence: 0/1 sequence, 1 indicates field boundary
        max_len: Maximum sequence length
    
    Returns:
        list: [(start, end), ...] list of field ranges
    """
    fields = []
    start = 0
    
    for i, is_boundary in enumerate(boundary_sequence):
        if is_boundary == 1:  # Encounter boundary
            if i > start:  # Ensure field has length
                fields.append((start, i))
            start = i
    
    # Handle the last field
    if start < max_len:
        fields.append((start, max_len))
    
    return fields

def load_trained_model(model_path, config):
    """Load trained model (compatible with different max_len)"""
    # First try loading with normal config
    try:
        model_config = config.get_model_config()
        model = ProtocolBoundaryModel(**model_config)
        
        if os.path.exists(model_path):
            model.load_state_dict(torch.load(model_path, map_location=device))
            logger.info(f"Successfully loaded model: {model_path}")
        else:
            logger.error(f"Model file does not exist: {model_path}")
            return None
        
        model = model.to(device)
        model.eval()
        return model
        
    except RuntimeError as e:
        if "size mismatch" in str(e):
            logger.warning(f"Model size mismatch: {e}")
            logger.info("Trying to load with training config...")
            
            # Try loading with training max_len config
            train_config = config.get_model_config()
            train_config['max_len'] = 64  # Possible value used during training
            
            try:
                model = ProtocolBoundaryModel(**train_config)
                model.load_state_dict(torch.load(model_path, map_location=device))
                logger.info(f"Successfully loaded model with max_len=64: {model_path}")
                model = model.to(device)
                model.eval()
                return model
            except Exception as e2:
                logger.error(f"Failed to load with training config: {e2}")
                return None
        else:
            logger.error(f"Model loading failed: {e}")
            return None

def load_all_test_data(config):
    """Load all test data (no sampling, test all samples)"""
    # First perform CSV merge operation to get real test data path
    logger.info("Performing CSV merge operation...")
    try:
        from merge_csv import auto_merge_csvs_from_config
        success, train_path, test_path = auto_merge_csvs_from_config()
        if success:
            test_data_path = test_path
            logger.info(f"[PASS] CSV merge successful, test data path: {test_data_path}")
        else:
            logger.error("[ERROR] CSV merge failed, unable to get test data path")
            raise RuntimeError("CSV merge failed, please check TEST_PROTOCOLS config in config.py")
    except Exception as e:
        logger.error(f"[ERROR] Error during CSV merge: {str(e)}")
        raise RuntimeError(f"CSV merge failed: {str(e)}")
    
    test_max_len = config.TEST_MAX_LEN
    
    logger.info(f"Loading test data: {test_data_path}")
    logger.info(f"Test sequence length: {test_max_len}")
    
    # Create data processor for testing
    data_config = config.get_data_config()
    test_processor = ProtocolDataProcessor(
        max_len=test_max_len,
        min_packets=data_config['min_packets'],
        min_group_size=data_config['min_group_size']
    )
    
    # Load all data (no sample limit)
    logger.info("Loading all test samples...")
    try:
        # Read CSV data
        df = test_processor.load_data(test_data_path)
        logger.info(f"Loaded {len(df)} raw CSV records")
        
        # Group strictly by truncated Segments and Field Names
        groups = test_processor.group_by_segments_and_fields(df)
        logger.info(f"Grouping result: {len(groups)} different format types")
        
        # Generate test samples for all groups (no sample limit per group)
        X_list = []
        mask_list = []
        labels_list = []
        group_metadata = {}
        
        total_csv_records = 0
        total_test_samples = 0
        
        for seg_key, data in groups.items():
            packets = data['packets']
            labels = data['labels']
            num_original_packets = len(packets)
            total_csv_records += num_original_packets
            
            # Skip groups with too few samples
            if num_original_packets < test_processor.min_group_size:
                logger.info(f"Skipping group {seg_key}: too few samples ({num_original_packets} < {test_processor.min_group_size})")
                continue
            
            logger.info(f"Processing group {seg_key}: {num_original_packets} original packets")
            
            # Calculate maximum possible samples (each sample needs min_packets packets)
            max_possible_samples = max(1, num_original_packets // test_processor.min_packets)
            
            # To fully test, we generate as many samples as possible
            # But ensure each sample has enough diversity
            num_samples = min(max_possible_samples, num_original_packets)
            
            logger.info(f"  Will generate {num_samples} test samples")
            
            # Calculate packet diversity
            diversity_scores = test_processor.compute_packet_diversity(packets)
            
            # Generate all possible sample combinations (using diversity selection)
            selected_combinations = test_processor.select_diverse_packets(packets, num_samples, diversity_scores)
            
            # Record group metadata
            group_metadata[seg_key] = {
                'diversity_scores': diversity_scores,
                'selected_combinations': selected_combinations,
                'sample_weights': [],
                'num_original_packets': num_original_packets,
                'num_generated_samples': len(selected_combinations)
            }
            
            # Generate sample for each selected combination
            for i, selected_indices in enumerate(selected_combinations):
                sampled_packets = [packets[idx] for idx in selected_indices]
                sampled_labels = [labels[idx] for idx in selected_indices]
                
                # Calculate current sample's weight (based on average diversity of selected packets)
                sample_diversity = np.mean([diversity_scores[idx] for idx in selected_indices])
                group_metadata[seg_key]['sample_weights'].append(sample_diversity)
                
                # Build byte matrix and mask
                X, mask = test_processor.build_matrix(sampled_packets)
                
                # Generate labels
                stacked_labels = np.stack(sampled_labels, axis=0)
                avg_labels = np.mean(stacked_labels, axis=0)
                
                # Add to test set
                X_list.append(X)
                mask_list.append(mask)
                labels_list.append(avg_labels)
                total_test_samples += 1
        
        if len(X_list) == 0:
            logger.error("Test set did not generate any samples")
            return None, None, None, None
        
        # Convert to tensors
        X_array = np.stack(X_list, axis=0)
        mask_array = np.stack(mask_list, axis=0)
        labels_array = np.stack(labels_list, axis=0)
        
        X_tensor = torch.tensor(X_array, dtype=torch.long)
        mask_tensor = torch.tensor(mask_array, dtype=torch.bool)
        labels_tensor = torch.tensor(labels_array, dtype=torch.long)
        
        logger.info(f"Test data loading completed:")
        logger.info(f"  Raw CSV records: {len(df)}")
        logger.info(f"  Generated test samples: {total_test_samples}")
        logger.info(f"  Test format types: {len(group_metadata)}")
        logger.info(f"  Data shapes: X{X_tensor.shape}, mask{mask_tensor.shape}, labels{labels_tensor.shape}")
        
        return X_tensor, mask_tensor, labels_tensor, group_metadata
        
    except Exception as e:
        logger.error(f"Failed to load test data: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None

def load_test_data(config, max_samples=None):
    """Load test data (using the same way as train_cross_protocol)"""
    # First perform CSV merge operation to get real test data path
    logger.info("Performing CSV merge operation...")
    try:
        from merge_csv import auto_merge_csvs_from_config
        success, train_path, test_path = auto_merge_csvs_from_config()
        if success:
            test_data_path = test_path
            logger.info(f"[PASS] CSV merge successful, test data path: {test_data_path}")
        else:
            logger.error("[ERROR] CSV merge failed, unable to get test data path")
            raise RuntimeError("CSV merge failed, please check TEST_PROTOCOLS config in config.py")
    except Exception as e:
        logger.error(f"[ERROR] Error during CSV merge: {str(e)}")
        raise RuntimeError(f"CSV merge failed: {str(e)}")
    
    test_max_len = config.TEST_MAX_LEN
    
    logger.info(f"Loading test data: {test_data_path}")
    logger.info(f"Test sequence length: {test_max_len}")
    
    # Create data processor for testing
    data_config = config.get_data_config()
    test_processor = ProtocolDataProcessor(
        max_len=test_max_len,
        min_packets=data_config['min_packets'],
        min_group_size=data_config['min_group_size']
    )
    
    # Process test data
    test_samples_per_group = min(5, data_config['samples_per_group'] // 4)  # Reduce test sample count
    X_list, mask_list, labels_list, group_metadata = test_processor.process_test_data_with_diversity(
        test_data_path,
        samples_per_group=test_samples_per_group
    )
    
    if len(X_list) == 0:
        logger.error("Test set did not generate any samples")
        return None, None, None, None
    
    # Limit sample count (if specified)
    if max_samples and max_samples < len(X_list):
        X_list = X_list[:max_samples]
        mask_list = mask_list[:max_samples]
        labels_list = labels_list[:max_samples]
        logger.info(f"Limiting test sample count to: {max_samples}")
    
    # Convert to tensors
    X_array = np.stack(X_list, axis=0)
    mask_array = np.stack(mask_list, axis=0)
    labels_array = np.stack(labels_list, axis=0)
    
    X_tensor = torch.tensor(X_array, dtype=torch.long)
    mask_tensor = torch.tensor(mask_array, dtype=torch.bool)
    labels_tensor = torch.tensor(labels_array, dtype=torch.long)
    
    logger.info(f"Test data loading completed, sample count: {len(X_list)}")
    logger.info(f"Data shapes: X{X_tensor.shape}, mask{mask_tensor.shape}, labels{labels_tensor.shape}")
    
    return X_tensor, mask_tensor, labels_tensor, group_metadata

def predict_boundaries(model, X_tensor, mask_tensor, batch_size=4):
    """Use model for boundary prediction"""
    model.eval()
    predictions = []
    
    # Create DataLoader
    dataset = TensorDataset(X_tensor, mask_tensor)
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=False, num_workers=0)
    
    with torch.no_grad():
        for batch_X, batch_mask in dataloader:
            batch_X = batch_X.to(device)
            batch_mask = batch_mask.to(device)
            
            # Model prediction (inference mode)
            try:
                best_paths = model(batch_X, batch_mask)
                predictions.extend(best_paths)
            except Exception as e:
                logger.error(f"Error during prediction: {e}")
                # Add default prediction (all 0)
                for _ in range(len(batch_X)):
                    predictions.append([0] * batch_X.shape[-1])
    
    return predictions

def ensemble_predictions_by_group(predictions, group_metadata, strategy='diversity_weighted', confidence_threshold=0.6):
    """
    Ensemble and merge multiple prediction results for the same format group
    
    Args:
        predictions: List of prediction results for all samples
        group_metadata: Group metadata (contains weight information)
        strategy: Ensemble strategy ('weighted_majority', 'diversity_weighted', 'adaptive')
        confidence_threshold: Confidence threshold
        
    Returns:
        ensemble_results: Dict[Format group -> (ensemble prediction, metadata)]
        sample_to_group: Mapping from sample index to format group
    """
    if strategy is None:
        logger.info("Ensemble merging not enabled, keeping original prediction results")
        return None, None
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Starting ensemble merging - Strategy: {strategy}")
    logger.info(f"{'='*60}")
    
    # Create ensemble predictor
    ensemble_predictor = create_ensemble_predictor(strategy, confidence_threshold)
    
    # Organize prediction results by format group
    ensemble_results = {}
    sample_to_group = {}
    sample_idx = 0
    
    for group_key, metadata in group_metadata.items():
        num_samples = metadata['num_generated_samples']
        group_predictions = []
        group_weights = metadata['sample_weights']
        
        logger.info(f"\nProcessing format group: {group_key}")
        logger.info(f"  Sample count: {num_samples}")
        logger.info(f"  Sample weights: {[f'{w:.3f}' for w in group_weights]}")
        
        # Collect all prediction results for this format group
        for i in range(num_samples):
            if sample_idx < len(predictions):
                pred_array = np.array(predictions[sample_idx])
                group_predictions.append(pred_array)
                sample_to_group[sample_idx] = group_key
                sample_idx += 1
        
        # Ensemble prediction for this format group
        if len(group_predictions) > 0:
            ensemble_pred, pred_metadata = ensemble_predictor.ensemble_predictions(
                group_predictions,
                group_weights,
                group_key
            )
            ensemble_results[group_key] = (ensemble_pred, pred_metadata)
            
            logger.info(f"  Ensemble merging completed - average confidence: {pred_metadata['avg_confidence']:.3f}")
            logger.info(f"  Low confidence positions: {len(pred_metadata['low_confidence_positions'])}")
        else:
            logger.warning(f"Format group {group_key} has no valid prediction results")
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Ensemble merging completed - processed {len(ensemble_results)} format groups")
    logger.info(f"{'='*60}\n")
    
    return ensemble_results, sample_to_group

def analyze_boundary_predictions(X_tensor, mask_tensor, labels_tensor, predictions, group_metadata, max_display=5, save_results=True, ensemble_results=None, sample_to_group=None):
    """Analyze and display boundary prediction results (comprehensive testing for all samples)"""
    logger.info(f"\n{'='*80}")
    if ensemble_results is not None:
        logger.info(f"Boundary prediction result analysis - Comprehensive testing mode (using ensemble merging)")
    else:
        logger.info(f"Boundary prediction result analysis - Comprehensive testing mode (single sample prediction)")
    logger.info(f"{'='*80}")
    
    total_samples = len(predictions)
    display_count = min(max_display, total_samples)
    
    logger.info(f"Total sample count: {total_samples}")
    logger.info(f"Display details for first {display_count} samples:")
    
    # For statistics of overall metrics across all samples
    all_correct_predictions = 0
    all_total_boundaries_correct = 0
    all_total_boundaries_pred = 0
    all_total_boundaries_true = 0
    all_perfect_field_matches = 0
    all_total_true_fields = 0
    
    # For saving results
    results_data = []
    
    # Collect ensemble performance metrics if using ensemble merging
    ensemble_metrics = {}
    if ensemble_results is not None and sample_to_group is not None:
        logger.info(f"\n{'='*60}")
        logger.info(f"Ensemble merging result performance evaluation")
        logger.info(f"{'='*60}")
        
        for group_key, (ensemble_pred, pred_metadata) in ensemble_results.items():
            # Find the first sample of this group to get true labels
            group_sample_idx = None
            for idx, g_key in sample_to_group.items():
                if g_key == group_key:
                    group_sample_idx = idx
                    break
            
            if group_sample_idx is not None:
                valid_mask = mask_tensor[group_sample_idx].any(dim=0)
                valid_length = valid_mask.sum().item()
                true_labels = labels_tensor[group_sample_idx][:valid_length].cpu().numpy()
                
                # Align ensemble prediction to valid length
                ensemble_pred_aligned = ensemble_pred[:valid_length] if len(ensemble_pred) >= valid_length else np.pad(ensemble_pred, (0, valid_length - len(ensemble_pred)))
                
                # Calculate metrics
                is_exact_match = (true_labels == ensemble_pred_aligned).all()
                
                # Boundary statistics
                true_boundary_positions = set([j for j, val in enumerate(true_labels) if val == 1])
                pred_boundary_positions = set([j for j, val in enumerate(ensemble_pred_aligned) if val == 1])
                correct_boundary_positions = true_boundary_positions & pred_boundary_positions
                
                precision = len(correct_boundary_positions) / max(len(pred_boundary_positions), 1)
                recall = len(correct_boundary_positions) / max(len(true_boundary_positions), 1)
                f1 = 2 * precision * recall / max(precision + recall, 1e-8)
                
                # Field-level matching
                true_fields = extract_fields_from_boundaries(true_labels, valid_length)
                pred_fields = extract_fields_from_boundaries(ensemble_pred_aligned, valid_length)
                perfect_matches = sum(1 for tf in true_fields if tf in pred_fields)
                field_accuracy = perfect_matches / max(len(true_fields), 1)
                
                ensemble_metrics[group_key] = {
                    'exact_match': is_exact_match,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1,
                    'field_accuracy': field_accuracy,
                    'avg_confidence': pred_metadata['avg_confidence'],
                    'num_samples_used': pred_metadata['num_predictions']
                }
                
                logger.info(f"\nFormat group: {group_key}")
                logger.info(f"  Exact match: {'Yes' if is_exact_match else 'No'}")
                logger.info(f"  Precision: {precision:.4f}, Recall: {recall:.4f}, F1: {f1:.4f}")
                logger.info(f"  Field accuracy: {field_accuracy:.4f}")
                logger.info(f"  Average confidence: {pred_metadata['avg_confidence']:.4f}")
                logger.info(f"  Samples used for fusion: {pred_metadata['num_predictions']}")
        
        logger.info(f"\n{'='*60}\n")
    
    for i in range(total_samples):
        # Get valid length (based on mask)
        valid_mask = mask_tensor[i].any(dim=0)  # [L]
        valid_length = valid_mask.sum().item()
        
        # True labels
        true_labels = labels_tensor[i][:valid_length].cpu().numpy()
        true_fields = extract_fields_from_boundaries(true_labels, valid_length)
        
        # Prediction results
        pred_labels = predictions[i][:valid_length] if len(predictions[i]) >= valid_length else predictions[i] + [0] * (valid_length - len(predictions[i]))
        pred_fields = extract_fields_from_boundaries(pred_labels, valid_length)
        
        # Original data (show first few bytes)
        first_packet = X_tensor[i][0][:valid_length].cpu().numpy()
        hex_data = ' '.join([f'{b:02x}' for b in first_packet[:min(32, valid_length)]])
        
        # Only show details for first few samples
        if i < display_count:
            logger.info(f"\n{'-'*50}")
            logger.info(f"Sample {i+1}:")
            logger.info(f"  Valid length: {valid_length}")
            logger.info(f"  Raw data (all {valid_length} bytes): {hex_data}{'...' if valid_length > 32 else ''}")
            logger.info(f"  True boundary sequence: {true_labels.tolist()}")
            logger.info(f"  Predicted boundary sequence: {pred_labels}")
            logger.info(f"  True field boundaries: {true_fields}")
            logger.info(f"  Predicted field boundaries: {pred_fields}")
            
            # Detailed field comparison
            logger.info(f"  \n  Field comparison analysis:")
            logger.info(f"    True field count: {len(true_fields)}")
            logger.info(f"    Predicted field count: {len(pred_fields)}")
            
            # Field matching situation
            perfect_matches = 0
            for j, true_field in enumerate(true_fields):
                if true_field in pred_fields:
                    logger.info(f"    [PASS] Field {j+1}: {true_field} - Perfect match")
                    perfect_matches += 1
                else:
                    logger.info(f"    [FAIL] Field {j+1}: {true_field} - No match")
            
            logger.info(f"    Perfectly matched fields: {perfect_matches}/{len(true_fields)}")
            
            # Calculate accuracy
            is_exact_match = (true_labels == np.array(pred_labels[:len(true_labels)])).all()
            if is_exact_match:
                logger.info(f"  [PASS] Perfect match!")
            else:
                logger.info(f"  [FAIL] No match")
        
        # Statistics for all samples
        is_exact_match = (true_labels == np.array(pred_labels[:len(true_labels)])).all()
        if is_exact_match:
            all_correct_predictions += 1
        
        # Count boundary accuracy
        all_total_boundaries_true += sum(true_labels)
        all_total_boundaries_pred += sum(pred_labels[:len(true_labels)])
        
        # Calculate intersection of boundary positions
        true_boundary_positions = set([j for j, val in enumerate(true_labels) if val == 1])
        pred_boundary_positions = set([j for j, val in enumerate(pred_labels[:len(true_labels)]) if val == 1])
        correct_boundary_positions = true_boundary_positions & pred_boundary_positions
        all_total_boundaries_correct += len(correct_boundary_positions)
        
        # Count field matching
        perfect_matches = 0
        for true_field in true_fields:
            if true_field in pred_fields:
                perfect_matches += 1
        all_perfect_field_matches += perfect_matches
        all_total_true_fields += len(true_fields)
        
        # Save result data (only save first few as examples)
        if i < display_count:
            sample_result = {
                'sample_id': int(i+1),
                'valid_length': int(valid_length),
                'hex_data': hex_data,
                'true_boundaries': [int(x) for x in true_labels.tolist()],
                'pred_boundaries': pred_labels,
                'true_fields': true_fields,
                'pred_fields': pred_fields,
                'perfect_matches': int(perfect_matches),
                'total_true_fields': int(len(true_fields)),
                'exact_match': bool(is_exact_match),
                'boundary_stats': {
                    'true_count': int(len(true_boundary_positions)),
                    'pred_count': int(len(pred_boundary_positions)),
                    'correct_count': int(len(correct_boundary_positions))
                }
            }
            results_data.append(sample_result)
    
    # Initialize metric variables
    boundary_precision = 0.0
    boundary_recall = 0.0
    boundary_f1 = 0.0
    field_accuracy = 0.0
    
    if all_total_boundaries_true > 0:
        boundary_precision = all_total_boundaries_correct / max(all_total_boundaries_pred, 1)
        boundary_recall = all_total_boundaries_correct / all_total_boundaries_true
        boundary_f1 = 2 * boundary_precision * boundary_recall / max(boundary_precision + boundary_recall, 1e-8)
    
    if all_total_true_fields > 0:
        field_accuracy = all_perfect_field_matches / all_total_true_fields
    
    # By-group statistics (if metadata is available) - display first
    if group_metadata:
        logger.info(f"\n{'='*50}")
        logger.info(f"Statistics by format type:")
        logger.info(f"{'='*50}")
        sample_idx = 0
        for group_key, metadata in group_metadata.items():
            group_samples = metadata['num_generated_samples']
            group_correct = 0
            group_total_boundaries_true = 0
            group_total_boundaries_pred = 0
            group_total_boundaries_correct = 0
            
            for i in range(sample_idx, sample_idx + group_samples):
                if i >= len(predictions):
                    break
                    
                valid_mask = mask_tensor[i].any(dim=0)
                valid_length = valid_mask.sum().item()
                true_labels = labels_tensor[i][:valid_length].cpu().numpy()
                pred_labels = predictions[i][:valid_length] if len(predictions[i]) >= valid_length else predictions[i] + [0] * (valid_length - len(predictions[i]))
                
                is_exact_match = (true_labels == np.array(pred_labels[:len(true_labels)])).all()
                if is_exact_match:
                    group_correct += 1
                
                group_total_boundaries_true += sum(true_labels)
                group_total_boundaries_pred += sum(pred_labels[:len(true_labels)])
                
                true_boundary_positions = set([j for j, val in enumerate(true_labels) if val == 1])
                pred_boundary_positions = set([j for j, val in enumerate(pred_labels[:len(true_labels)]) if val == 1])
                correct_boundary_positions = true_boundary_positions & pred_boundary_positions
                group_total_boundaries_correct += len(correct_boundary_positions)
            
            group_accuracy = group_correct / group_samples if group_samples > 0 else 0
            group_precision = group_total_boundaries_correct / max(group_total_boundaries_pred, 1)
            group_recall = group_total_boundaries_correct / max(group_total_boundaries_true, 1)
            group_f1 = 2 * group_precision * group_recall / max(group_precision + group_recall, 1e-8)
            
            logger.info(f"  {group_key}: {group_samples} samples, accuracy={group_accuracy:.3f}, F1={group_f1:.3f}")
            sample_idx += group_samples
    
    # Overall statistics (all samples) - display after
    logger.info(f"\n{'='*50}")
    logger.info(f"Overall statistics (based on all {total_samples} test samples):")
    logger.info(f"{'='*50}")
    logger.info(f"Perfectly matched samples: {all_correct_predictions}/{total_samples} ({100*all_correct_predictions/total_samples:.2f}%)")
    logger.info(f"Boundary-level precision: {boundary_precision:.4f}")
    logger.info(f"Boundary-level recall: {boundary_recall:.4f}")
    logger.info(f"Boundary-level F1: {boundary_f1:.4f}")
    logger.info(f"Field-level accuracy: {field_accuracy:.4f}")
    logger.info(f"Total boundaries - True: {all_total_boundaries_true}, Predicted: {all_total_boundaries_pred}, Correct: {all_total_boundaries_correct}")
    logger.info(f"Total fields - True: {all_total_true_fields}, Perfectly matched: {all_perfect_field_matches}")
    logger.info(f"{'='*50}")
    
    # Save results to file
    if save_results:
        import json
        results_file = 'boundary_prediction_results_full_test.json'
        
        summary_data = {
            'total_samples': int(total_samples),
            'analyzed_samples': int(display_count),
            'exact_matches': int(all_correct_predictions),
            'exact_match_rate': float(all_correct_predictions/total_samples),
            'boundary_precision': float(boundary_precision),
            'boundary_recall': float(boundary_recall),
            'boundary_f1': float(boundary_f1),
            'field_accuracy': float(field_accuracy),
            'total_boundaries_true': int(all_total_boundaries_true),
            'total_boundaries_pred': int(all_total_boundaries_pred),
            'total_boundaries_correct': int(all_total_boundaries_correct),
            'total_fields_true': int(all_total_true_fields),
            'total_fields_matched': int(all_perfect_field_matches)
        }
        
        # If ensemble merging is used, add ensemble results to summary
        if ensemble_results is not None and len(ensemble_metrics) > 0:
            summary_data['ensemble_enabled'] = True
            summary_data['ensemble_strategy'] = ENSEMBLE_STRATEGY
            summary_data['ensemble_group_metrics'] = {}
            for group_key, metrics in ensemble_metrics.items():
                summary_data['ensemble_group_metrics'][group_key] = {
                    k: (bool(v) if isinstance(v, (bool, np.bool_)) else float(v))
                    for k, v in metrics.items()
                }
        else:
            summary_data['ensemble_enabled'] = False
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'summary': summary_data,
                'detailed_results': results_data  # Only include first few samples as examples
            }, f, ensure_ascii=False, indent=2)
        logger.info(f"\n{'='*50}")
        logger.info(f"Results saved to: {results_file}")
        logger.info(f"{'='*50}")

def analyze_boundary_predictions_old(X_tensor, mask_tensor, labels_tensor, predictions, max_display=10, save_results=True):
    """Analyze and display boundary prediction results"""
    logger.info(f"\n{'='*80}")
    logger.info(f"Boundary prediction result analysis")
    logger.info(f"{'='*80}")
    
    total_samples = len(predictions)
    display_count = min(max_display, total_samples)
    
    logger.info(f"Total sample count: {total_samples}")
    logger.info(f"Display detailed results for first {display_count} samples:")
    
    correct_predictions = 0
    total_boundaries_correct = 0
    total_boundaries_pred = 0
    total_boundaries_true = 0
    
    # For saving results
    results_data = []
    
    for i in range(display_count):
        logger.info(f"\n{'-'*50}")
        logger.info(f"Sample {i+1}:")
        
        # Get valid length (based on mask)
        valid_mask = mask_tensor[i].any(dim=0)  # [L]
        valid_length = valid_mask.sum().item()
        
        # True labels
        true_labels = labels_tensor[i][:valid_length].cpu().numpy()
        true_fields = extract_fields_from_boundaries(true_labels, valid_length)
        
        # Prediction results
        pred_labels = predictions[i][:valid_length] if len(predictions[i]) >= valid_length else predictions[i] + [0] * (valid_length - len(predictions[i]))
        pred_fields = extract_fields_from_boundaries(pred_labels, valid_length)
        
        # Original data (show first few bytes)
        first_packet = X_tensor[i][0][:valid_length].cpu().numpy()
        hex_data = ' '.join([f'{b:02x}' for b in first_packet[:min(32, valid_length)]])
        
        logger.info(f"  Valid length: {valid_length}")
        logger.info(f"  Raw data (all {valid_length} bytes): {hex_data}{'...' if valid_length > 32 else ''}")
        logger.info(f"  True boundary sequence: {true_labels.tolist()}")
        logger.info(f"  Predicted boundary sequence: {pred_labels}")
        logger.info(f"  True field boundaries: {true_fields}")
        logger.info(f"  Predicted field boundaries: {pred_fields}")
        
        # Detailed field comparison
        logger.info(f"  \n  Field comparison analysis:")
        logger.info(f"    True field count: {len(true_fields)}")
        logger.info(f"    Predicted field count: {len(pred_fields)}")
        
        # Field matching
        perfect_matches = 0
        for j, true_field in enumerate(true_fields):
            if true_field in pred_fields:
                logger.info(f"    ✓ Field {j+1}: {true_field} - Perfect match")
                perfect_matches += 1
            else:
                logger.info(f"    ✗ Field {j+1}: {true_field} - No match")
        
        logger.info(f"    Perfectly matched fields: {perfect_matches}/{len(true_fields)}")
        
        # Calculate accuracy
        is_exact_match = (true_labels == np.array(pred_labels[:len(true_labels)])).all()
        if is_exact_match:
            correct_predictions += 1
            logger.info(f"  ✓ Perfect match!")
        else:
            logger.info(f"  ✗ No match")
        
        # Count boundary accuracy
        total_boundaries_true += sum(true_labels)
        total_boundaries_pred += sum(pred_labels[:len(true_labels)])
        
        # Calculate intersection of boundary positions
        true_boundary_positions = set([j for j, val in enumerate(true_labels) if val == 1])
        pred_boundary_positions = set([j for j, val in enumerate(pred_labels[:len(true_labels)]) if val == 1])
        correct_boundary_positions = true_boundary_positions & pred_boundary_positions
        total_boundaries_correct += len(correct_boundary_positions)
        
        logger.info(f"  Boundary statistics: true {len(true_boundary_positions)}, predicted {len(pred_boundary_positions)}, correct {len(correct_boundary_positions)}")
        
        # Save result data
        sample_result = {
            'sample_id': int(i+1),
            'valid_length': int(valid_length),
            'hex_data': hex_data,
            'true_boundaries': [int(x) for x in true_labels.tolist()],
            'pred_boundaries': pred_labels,
            'true_fields': true_fields,
            'pred_fields': pred_fields,
            'perfect_matches': int(perfect_matches),
            'total_true_fields': int(len(true_fields)),
            'exact_match': bool(is_exact_match),
            'boundary_stats': {
                'true_count': int(len(true_boundary_positions)),
                'pred_count': int(len(pred_boundary_positions)),
                'correct_count': int(len(correct_boundary_positions))
            }
        }
        results_data.append(sample_result)
    
    # Overall statistics
    logger.info(f"\n{'='*50}")
    logger.info(f"Overall statistics result:")
    logger.info(f"Perfectly matched samples: {correct_predictions}/{display_count} ({100*correct_predictions/display_count:.2f}%)")
    
    # Initialize metrics variables
    boundary_precision = 0.0
    boundary_recall = 0.0
    boundary_f1 = 0.0
    
    if total_boundaries_true > 0:
        boundary_precision = total_boundaries_correct / max(total_boundaries_pred, 1)
        boundary_recall = total_boundaries_correct / total_boundaries_true
        boundary_f1 = 2 * boundary_precision * boundary_recall / max(boundary_precision + boundary_recall, 1e-8)
        
        logger.info(f"Boundary-level precision: {boundary_precision:.4f}")
        logger.info(f"Boundary-level recall: {boundary_recall:.4f}")
        logger.info(f"Boundary-level F1: {boundary_f1:.4f}")
    
    logger.info(f"Total boundaries - True: {total_boundaries_true}, Predicted: {total_boundaries_pred}, Correct: {total_boundaries_correct}")
    
    # Save results to file
    if save_results:
        import json
        results_file = 'boundary_prediction_results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'summary': {
                    'total_samples': int(total_samples),
                    'analyzed_samples': int(display_count),
                    'exact_matches': int(correct_predictions),
                    'exact_match_rate': float(correct_predictions/display_count),
                    'boundary_precision': float(boundary_precision),
                    'boundary_recall': float(boundary_recall),
                    'boundary_f1': float(boundary_f1),
                    'total_boundaries_true': int(total_boundaries_true),
                    'total_boundaries_pred': int(total_boundaries_pred),
                    'total_boundaries_correct': int(total_boundaries_correct)
                },
                'detailed_results': results_data
            }, f, ensure_ascii=False, indent=2)
        logger.info(f"\nResults saved to: {results_file}")

def main():
    """Main function"""
    # Configuration
    config = CrossProtocolConfig
    
    # Display test configuration information
    logger.info(f"\n{'='*60}")
    logger.info(f"Boundary prediction test script")
    logger.info(f"{'='*60}")
    
    # Display test protocol configuration
    test_is_file, test_source = config.get_test_data_info()
    test_type_text = "file path" if test_is_file else "protocol list"
    logger.info(f"Test data configuration: {test_type_text} - {test_source}")
    
    if not test_is_file:
        logger.info(f"Test protocols: {test_source if isinstance(test_source, list) else [test_source]}")
    else:
        logger.info(f"Test file: {test_source}")
    
    # Model paths (try multiple possible paths)
    model_paths = [
        "checkpoints/model_epoch_10_cross_protocol.pth",  # Prefer latest trained model
        "checkpoints/best_val_model_cross_protocol.pth",
        "checkpoints/best_real_test_model_cross_protocol.pth",
        "checkpoints/model_epoch_1_cross_protocol.pth"
    ]
    
    model = None
    for model_path in model_paths:
        if os.path.exists(model_path):
            model = load_trained_model(model_path, config)
            if model is not None:
                logger.info(f"Using model: {model_path}")
                break
    
    if model is None:
        logger.error("No available trained model found, please run train_cross_protocol.py first")
        return
    
    # Load test data
    logger.info("Loading all test data...")
    X_tensor, mask_tensor, labels_tensor, group_metadata = load_all_test_data(config)
    
    if X_tensor is None:
        logger.error("Test data loading failed")
        return
    
    # Predict boundaries
    logger.info("Performing boundary prediction...")
    try:
        predictions = predict_boundaries(model, X_tensor, mask_tensor, batch_size=2)
        logger.info(f"Prediction complete, obtained {len(predictions)} prediction results")
    except Exception as e:
        logger.error(f"Prediction process failed: {e}")
        return
    
    # Ensemble merging (optional)
    ensemble_results = None
    sample_to_group = None
    if ENSEMBLE_STRATEGY is not None:
        logger.info(f"\nEnable ensemble merging strategy: {ENSEMBLE_STRATEGY}")
        ensemble_results, sample_to_group = ensemble_predictions_by_group(
            predictions, 
            group_metadata, 
            strategy=ENSEMBLE_STRATEGY,
            confidence_threshold=ENSEMBLE_CONFIDENCE_THRESHOLD
        )
    else:
        logger.info("\nEnsemble merging not enabled, using single sample prediction results")
    
    # Analyze results
    analyze_boundary_predictions(
        X_tensor, mask_tensor, labels_tensor, predictions, group_metadata, 
        max_display=5, ensemble_results=ensemble_results, sample_to_group=sample_to_group
    )
    
    logger.info(f"\n{'='*80}")
    logger.info("Boundary prediction analysis complete!")
    logger.info(f"{'='*80}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception("An error occurred during script execution")
        raise e