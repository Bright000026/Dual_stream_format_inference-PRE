# -*- coding: utf-8 -*-
"""
Ensemble Prediction Module
Implements voting mechanism based on diversity-weighted scheme
to merge multiple prediction results for the same format semantic
"""

import numpy as np
import torch
from typing import List, Dict, Tuple, Any, Optional
from collections import Counter
import logging

logger = logging.getLogger(__name__)

class EnsembleBoundaryPredictor:
    """
    Ensemble Boundary Predictor
    Performs weighted voting on multiple prediction results for the same format semantic
    according to diversity weights of input samples
    """
    
    def __init__(self, voting_strategy='weighted_majority', confidence_threshold=0.6):
        """
        Initialize ensemble predictor
        
        Args:
            voting_strategy: Voting strategy ('weighted_majority', 'diversity_weighted', 'adaptive')
            confidence_threshold: Confidence threshold, predictions below this will be marked uncertain
        """

    def ensemble_predictions(self, predictions: List[np.ndarray], 
                           weights: List[float],
                           group_key: Optional[str] = None) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Ensemble multiple prediction results for the same format semantic
        
        Args:
            predictions: List of prediction results, each is a 0/1 array of [seq_len]
            weights: Corresponding sample weights (based on diversity)
            group_key: Format group identifier for logging
            
        Returns:
            (ensemble_pred, metadata): Ensemble prediction result and metadata
        """
        if not predictions or not weights:
            return np.array([]), {}
        
        if len(predictions) != len(weights):
            raise ValueError("Number of predictions does not match number of weights")
        
        # Handle predictions with different lengths
        seq_len = self._get_target_length(predictions)
        predictions = self._align_predictions(predictions, seq_len)
        
        # Normalize weights
        weights_array = np.array(weights)
        weights_array = weights_array / weights_array.sum()
        
        # Execute weighted voting
        if self.voting_strategy == 'weighted_majority':
            ensemble_pred, confidence = self._weighted_majority_vote(predictions, weights_array)
        elif self.voting_strategy == 'diversity_weighted':
            ensemble_pred, confidence = self._diversity_weighted_vote(predictions, weights_array)
        elif self.voting_strategy == 'adaptive':
            ensemble_pred, confidence = self._adaptive_vote(predictions, weights_array)
        else:
            raise ValueError(f"Unsupported voting strategy: {self.voting_strategy}")
        
        # Calculate metadata
        metadata = {
            'num_predictions': len(predictions),
            'weights': weights_array.tolist(),
            'confidence_scores': confidence.tolist(),
            'avg_confidence': np.mean(confidence),
            'low_confidence_positions': np.where(confidence < self.confidence_threshold)[0].tolist(),
            'voting_strategy': self.voting_strategy,
            'group_key': group_key
        }
        
        # Log information
        if group_key:
            logger.info(f"Format {group_key}: ensemble {len(predictions)} predictions, "
                       f"average confidence: {metadata['avg_confidence']:.3f}, "
                       f"low confidence positions: {len(metadata['low_confidence_positions'])}")
        
        return ensemble_pred, metadata
    
    def _weighted_majority_vote(self, predictions: List[np.ndarray], 
                               weights: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Weighted majority voting
        
        Returns:
            (ensemble_pred, confidence): Ensemble prediction result and confidence at each position
        """
        seq_len = len(predictions[0])
        ensemble_pred = np.zeros(seq_len, dtype=int)
        confidence = np.zeros(seq_len)
        
        for pos in range(seq_len):
            # Calculate weighted voting at each position
            votes_for_1 = sum(weights[i] for i in range(len(predictions)) 
                             if predictions[i][pos] == 1)
            votes_for_0 = sum(weights[i] for i in range(len(predictions)) 
                             if predictions[i][pos] == 0)
            
            # Majority voting determines prediction result
            if votes_for_1 > votes_for_0:
                ensemble_pred[pos] = 1
                confidence[pos] = votes_for_1 / (votes_for_1 + votes_for_0)
            else:
                ensemble_pred[pos] = 0
                confidence[pos] = votes_for_0 / (votes_for_1 + votes_for_0)
        
        return ensemble_pred, confidence
    
    def _diversity_weighted_vote(self, predictions: List[np.ndarray], 
                                weights: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Diversity-weighted voting
        Assigns higher voting weights to samples with higher diversity
        """
        # Calculate diversity-enhanced weights
        diversity_weights = weights ** 1.5  # Amplify impact of diversity weights
        diversity_weights = diversity_weights / diversity_weights.sum()
        
        return self._weighted_majority_vote(predictions, diversity_weights)
    
    def _get_target_length(self, predictions: List[np.ndarray]) -> int:
        """
        Determine target length using length-oriented weighted average strategy
        """
        if not predictions:
            return 0
        
        lengths = [len(pred) for pred in predictions]
        
        # Strategy 1: Use maximum length (conservative strategy)
        return max(lengths)
    
    def _align_predictions(self, predictions: List[np.ndarray], target_len: int) -> List[np.ndarray]:
        """
        Align all predictions to target length
        
        Strategy:
        - For shorter predictions: Pad with 0 (non-boundary)
        - For longer predictions: Truncate to target length
        """
        aligned_predictions = []
        
        for pred in predictions:
            if len(pred) == target_len:
                aligned_predictions.append(pred.copy())
            elif len(pred) < target_len:
                # Padding strategy: Pad with 0 at the end
                padded = np.zeros(target_len, dtype=pred.dtype)
                padded[:len(pred)] = pred
                aligned_predictions.append(padded)
            else:
                # Truncation strategy: Keep first target_len elements
                aligned_predictions.append(pred[:target_len])
        
        return aligned_predictions
    
    def _adjust_weights_for_length(self, predictions: List[np.ndarray], 
                                  weights: np.ndarray, 
                                  target_len: int) -> np.ndarray:
        """
        Adjust weights based on prediction length
        Give higher weights to predictions closer to target length
        """
        length_factors = []
        for pred in predictions:
            # Calculate length conformity: Higher score for predictions closer to target length
            length_diff = abs(len(pred) - target_len)
            length_factor = 1.0 / (1.0 + length_diff * 0.1)  # Larger length difference = lower weight
            length_factors.append(length_factor)
        
        length_factors = np.array(length_factors)
        # Combine original weights and length factors
        adjusted_weights = weights * length_factors
        # Re-normalize
        return adjusted_weights / adjusted_weights.sum()
    
    def _adaptive_vote(self, predictions: List[np.ndarray], 
                      weights: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Adaptive voting strategy
        Dynamically adjust weights based on prediction consistency
        """
        seq_len = len(predictions[0])
        ensemble_pred = np.zeros(seq_len, dtype=int)
        confidence = np.zeros(seq_len)
        
        for pos in range(seq_len):
            # Calculate consistency of predictions at this position
            pos_predictions = [pred[pos] for pred in predictions]
            consistency = 1.0 - (np.std(pos_predictions) if len(set(pos_predictions)) > 1 else 0.0)
            
            # Adjust weights based on consistency
            if consistency > 0.8:  # High consistency: Use uniform weights
                adjusted_weights = np.ones(len(weights)) / len(weights)
            else:  # Low consistency: Rely more on diversity weights
                adjusted_weights = weights ** 2
                adjusted_weights = adjusted_weights / adjusted_weights.sum()
            
            # Execute weighted voting
            votes_for_1 = sum(adjusted_weights[i] for i in range(len(predictions)) 
                             if predictions[i][pos] == 1)
            votes_for_0 = sum(adjusted_weights[i] for i in range(len(predictions)) 
                             if predictions[i][pos] == 0)
            
            if votes_for_1 > votes_for_0:
                ensemble_pred[pos] = 1
                confidence[pos] = votes_for_1 / (votes_for_1 + votes_for_0)
            else:
                ensemble_pred[pos] = 0
                confidence[pos] = votes_for_0 / (votes_for_1 + votes_for_0)
        
        return ensemble_pred, confidence
    
    def ensemble_format_predictions(self, model_predictions: List[List[int]], 
                                  group_metadata: Dict[str, Dict],
                                  group_mapping: List[str]) -> Dict[str, Tuple[np.ndarray, Dict]]:
        """
        Ensemble prediction results for all format types
        
        Args:
            model_predictions: List of model prediction results (each element is a prediction sequence)
            group_metadata: Group metadata containing weight information
            group_mapping: Mapping from samples to format groups
            
        Returns:
            Dict[format group -> (ensemble prediction, metadata)]
        """
        ensemble_results = {}
        
        # Organize predictions by format group
        format_predictions = {}
        sample_idx = 0
        
        for group_key, metadata in group_metadata.items():
            num_samples = len(metadata['sample_weights'])
            format_predictions[group_key] = {
                'predictions': [],
                'weights': metadata['sample_weights']
            }
            
            # Collect all predictions for this format group
            for i in range(num_samples):
                if sample_idx < len(model_predictions):
                    pred_array = np.array(model_predictions[sample_idx])
                    format_predictions[group_key]['predictions'].append(pred_array)
                    sample_idx += 1
        
        # Ensemble predictions for each format group
        for group_key, data in format_predictions.items():
            if len(data['predictions']) > 0:
                ensemble_pred, metadata = self.ensemble_predictions(
                    data['predictions'], 
                    data['weights'],
                    group_key
                )
                ensemble_results[group_key] = (ensemble_pred, metadata)
            else:
                logger.warning(f"Format group {group_key} has no valid predictions")
        
        return ensemble_results
    
    def compute_ensemble_metrics(self, ensemble_results: Dict[str, Tuple[np.ndarray, Dict]],
                               true_labels: Dict[str, np.ndarray]) -> Dict[str, Dict]:
        """
        Compute evaluation metrics for ensemble predictions
        
        Args:
            ensemble_results: Ensemble prediction results
            true_labels: Ground truth labels (format group -> label array)
            
        Returns:
            Evaluation metrics for each format group
        """
        metrics = {}
        
        for group_key, (ensemble_pred, pred_metadata) in ensemble_results.items():
            if group_key not in true_labels:
                continue
                
            true_label = true_labels[group_key]
            
            # Ensure consistent length
            min_len = min(len(ensemble_pred), len(true_label))
            pred = ensemble_pred[:min_len]
            true = true_label[:min_len]
            
            # Calculate basic metrics
            tp = np.sum((pred == 1) & (true == 1))
            fp = np.sum((pred == 1) & (true == 0))
            fn = np.sum((pred == 0) & (true == 1))
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            # Calculate field-level perfect match
            true_fields = self._extract_fields(true)
            pred_fields = self._extract_fields(pred)
            perfect_matches = sum(1 for tf in true_fields if tf in pred_fields)
            perfection = perfect_matches / len(true_fields) if len(true_fields) > 0 else 1.0
            
            metrics[group_key] = {
                'f1': f1,
                'precision': precision,
                'recall': recall,
                'perfection': perfection,
                'tp': tp,
                'fp': fp,
                'fn': fn,
                'avg_confidence': pred_metadata['avg_confidence'],
                'num_predictions_used': pred_metadata['num_predictions'],
                'low_confidence_ratio': len(pred_metadata['low_confidence_positions']) / len(pred)
            }
        
        return metrics
    
    def _extract_fields(self, boundary_labels: np.ndarray) -> List[Tuple[int, int]]:
        """Extract field intervals from boundary labels"""
        fields = []
        start = 0
        
        for i, label in enumerate(boundary_labels):
            if label == 1:  # Encounter a boundary
                if i > start:
                    fields.append((start, i))
                start = i
        
        # Add the last field
        if start < len(boundary_labels):
            fields.append((start, len(boundary_labels)))
        
        return fields

def create_ensemble_predictor(strategy='diversity_weighted', confidence_threshold=0.6):
    """
    Factory function to create ensemble predictor
    
    Args:
        strategy: Voting strategy
        confidence_threshold: Confidence threshold
        
    Returns:
        EnsembleBoundaryPredictor instance
    """
    return EnsembleBoundaryPredictor(
        voting_strategy=strategy,
        confidence_threshold=confidence_threshold
    )

# Usage example
def demo_ensemble_prediction():
    """Demonstrate how to use ensemble prediction"""
    # Simulate 3 predictions and corresponding weights
    predictions = [
        np.array([0, 1, 0, 1, 1]),  # Prediction 1
        np.array([0, 1, 1, 1, 0]),  # Prediction 2  
        np.array([0, 1, 0, 1, 0])   # Prediction 3
    ]
    weights = [0.5, 0.3, 0.2]  # Weights based on diversity
    
    # Create ensemble predictor
    ensemble_predictor = create_ensemble_predictor('diversity_weighted')
    
    # Execute ensemble prediction
    ensemble_pred, metadata = ensemble_predictor.ensemble_predictions(
        predictions, weights, "Example format"
    )
    
    print(f"Ensemble prediction result: {ensemble_pred}")
    print(f"Average confidence: {metadata['avg_confidence']:.3f}")
    print(f"Low confidence positions: {metadata['low_confidence_positions']}")
    
    return ensemble_pred, metadata

if __name__ == "__main__":
    demo_ensemble_prediction()
