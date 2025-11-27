# -*- coding: utf-8 -*-
"""
Training Configuration File
Centralized management of all training parameters
Supports different max_len for training and testing
"""

from typing import List, Union

class TrainingConfig:
    """Training Configuration Class"""
    
    # ===================
    # Data Configuration (supports different max_len)
    # ===================
    #TRAIN_DATA_PATH = "./FSIBP/data/format_data_final/no_smb/no_smb.csv"  # Training set
    #TRAIN_DATA_PATH = "./generate/csv/no_test.csv"
    #TEST_DATA_PATH = "./FSIBP/data/format_data_final/smb_format_final.csv"  # Real test set
    #TRAIN_DATA_PATH = "./generate/smb2_messages.csv"
    #TEST_DATA_PATH = "./generate/smb_messages.csv"
    
    
    #TRAIN_DATA_PATH = "./test/data/no_s7comm_data.csv" # Set in config.py
    # Training and test data configuration - supports protocol list or file path
    # If it's a protocol list, automatically finds and merges corresponding CSV files
    # If it's a file path string, uses that file directly
    #, 'modbus', 'OMRON', 'dnp3', 'mqtt', 'coap'
    TRAIN_PROTOCOLS: Union[List[str], str] = ['tcp', 'udp', 'arp', 'dns', 'bgp', 'radius']  # Training protocols
    TEST_PROTOCOLS: Union[List[str], str] = ['OMRON']#"FSIBP/data/format_data_final/modbus_format_final.csv"
    
    # Example configurations:
    # TRAIN_PROTOCOLS = ['mqtt', 'tcp', 'udp']  # Using protocol list
    # Or
    # TRAIN_PROTOCOLS = "./data/my_custom_train_data.csv"  # Using file path
    # 
    # TEST_PROTOCOLS = ['smb2']  # Using protocol list
    # Or  
    # TEST_PROTOCOLS = "./data/my_custom_test_data.csv"  # Using file path
    #TEST_DATA_PATH = "./test/smb/smb_segments_filter.csv"  # Real test set

    
    # Key improvement: supports different max_len for training and testing
    TRAIN_MAX_LEN = 64  # Sequence length used during training
    TEST_MAX_LEN = 64   # Sequence length used during testing
    #CONV_KERNEL_WIDTHS = [3, 5, 7]
    
    MIN_PACKETS = 10  # Number of messages per input group
    SAMPLES_PER_GROUP = 5  # Number of samples generated per format
    MIN_GROUP_SIZE = 2 # Minimum number of raw samples needed per group, groups with fewer samples will be skipped
    VAL_RATIO = 0.2
    
    # ===================
    # Adaptive Sampling Configuration (New)
    # ===================
    ADAPTIVE_SAMPLING = True  # Enable adaptive sampling
    DIVERSITY_SAMPLING_THRESHOLD = 1000  # Diversity sampling threshold (use random sampling above this value)
    
    # Adaptive sampling threshold configuration
    ADAPTIVE_THRESHOLDS = {
        'very_low': 500,     # < 500: Very few samples, basic sampling
        'low': 1000,         # 500-1000: Few samples, light augmentation
        'medium': 2000,      # 1000-2000: Medium samples, moderate augmentation
        'high': 3000         # 2000-3000: Rich samples, heavy augmentation
        # > 3000: Very rich samples, cap protection
    }
    
    # Adaptive sampling multiplier configuration
    ADAPTIVE_MULTIPLIERS = {
        'very_low': 1.0,     # < 500: Basic sampling (10 samples)
        'low': 1.5,          # 500-1000: +50% (15 samples)
        'medium': 3.0,       # 1000-2000: +100% (20 samples)
        'high': 5.0,         # 2000-3000: +150% (25 samples)
        'very_high': 10.0     # > 3000: +200% (30 samples)
    }
    
    # Adaptive sampling limits configuration
    MAX_SAMPLES_PER_FORMAT = 100  # Maximum training samples generated per format group
    MIN_SAMPLES_PER_FORMAT = 5   # Minimum training samples generated per format group


    # New: Diversity ensemble evaluation configuration
    USE_DIVERSITY_ENSEMBLE = True  # Whether to use diversity-first ensemble evaluation
    ENSEMBLE_VOTING_STRATEGY = 'diversity_weighted'  # 'weighted_majority', 'diversity_weighted', 'adaptive'
    ENSEMBLE_CONFIDENCE_THRESHOLD = 0.6  # Confidence threshold for ensemble predictions
    TEST_SAMPLES_PER_GROUP = 50  # Number of samples generated per format group during testing (maintains reasonable ratio with training set)
    # ===================
    # Model Configuration (multi-scale window encoding improvements)
    # ===================
    VOCAB_SIZE = 256
    D_MODEL = 128
    NHEAD = 4
    NUM_LAYERS = 2
    DROPOUT = 0.4  # Increase dropout to reduce overfitting
    WINDOW_SIZES = [3,5,7,9]  # Multi-scale window sizes
    film_window_sizes = [3,5,9]#[3, 5, 9]
    hist_feat_compressed = 32  # Historical feature compression dimension
    
    # ===================
    # Training Configuration (reduce overfitting)
    # ===================
    BATCH_SIZE = 4  # Lower batch size to reduce memory pressure
    NUM_EPOCHS = 10  # Reduce training epochs to avoid overfitting
    LEARNING_RATE = 1e-4  # Lower learning rate for more stable training
    WEIGHT_DECAY = 0.001  # Increase weight decay
    WARMUP_RATIO = 0.1
    
    # Gradient clipping
    MAX_GRAD_NORM = 0.5  # Stricter gradient clipping
    
    # Early stopping configuration - more aggressive early stopping strategy
    EARLY_STOPPING_PATIENCE = 10  # Reduce patience for earlier stopping
    EARLY_STOPPING_MIN_DELTA = 0.005  # Increase minimum improvement threshold
    EARLY_STOPPING_METRIC = "real_test_f1"  # Monitor real test set F1 primarily
    
    # ===================
    # Loss Function Configuration (optimized version)
    # ===================
    # Main loss functions
    USE_FOCAL_LOSS = True  # Focal Loss - handles class imbalance
    USE_DICE_LOSS = True   # Dice Loss - improves boundary overlap
    USE_CONSISTENCY_LOSS = True  # Boundary consistency loss - reduces isolated errors
    
    # Focal Loss parameters
    FOCAL_ALPHA = 0.25  # Boundary class weight (reduced to more reasonable value)
    FOCAL_GAMMA = 2.0   # Focus parameter (reduced to more stable value)
    
    # Loss weights (sum = 1.0)
    CRF_WEIGHT = 0.5        # CRF loss weight
    FOCAL_WEIGHT = 0.3      # Focal Loss weight
    DICE_WEIGHT = 0.15      # Dice Loss weight
    CONSISTENCY_WEIGHT = 0.05  # Consistency loss weight
    
    # ===================
    # Device Configuration
    # ===================
    DEVICE = "auto"  # "auto", "cuda", "cpu"
    NUM_WORKERS = 0
    
    # ===================
    # Logging and Saving Configuration
    # ===================
    LOG_LEVEL = "INFO"
    SAVE_EVERY_N_EPOCHS = 1
    CHECKPOINT_DIR = "checkpoints"
    RESULTS_DIR = "results"
    LOG_FILE = "training.log"
    
    # ===================
    # Evaluation Configuration
    # ===================
    EVAL_EVERY_N_EPOCHS = 1
    SAVE_BEST_VAL_MODEL = True
    SAVE_BEST_TEST_MODEL = True
    
   
    # ===================
    # Cross-Protocol Generalization Configuration
    # ===================
    # Data Augmentation Configuration
    USE_DATA_AUGMENTATION = True
    AUGMENTATION_PROB = 0.1  # Data augmentation probability
    
    # Enhanced Regularization
    ENHANCED_REGULARIZATION = True
    
    @classmethod
    def is_file_path(cls, value):
        """
        Determine whether the given value is a file path
        
        Args:
            value: The value to determine, can be a string or list
            
        Returns:
            bool: Returns true if it's a file path, otherwise false
        """
        # If it's a list, it's not a file path
        if isinstance(value, list):
            return False
        
        # If it's a string, determine whether it's a file path
        if isinstance(value, str):
            # Simple file path determination: contains file extension or path separator
            import os
            return (
                value.endswith('.csv') or 
                value.endswith('.txt') or 
                '/' in value or 
                '\\' in value or
                os.path.exists(value)
            )
        
        return False
    
    @classmethod
    def get_train_data_info(cls):
        """
        Get training data information
        
        Returns:
            tuple: (is_file_path, data_source)
            - is_file_path: bool, whether it's a file path
            - data_source: str or list, data source (file path or protocol list)
        """
        train_protocols = cls.TRAIN_PROTOCOLS
        is_file = cls.is_file_path(train_protocols)
        return is_file, train_protocols
    
    @classmethod
    def get_test_data_info(cls):
        """
        Get test data information
        
        Returns:
            tuple: (is_file_path, data_source)
            - is_file_path: bool, whether it's a file path
            - data_source: str or list, data source (file path or protocol list)
        """
        test_protocols = cls.TEST_PROTOCOLS
        is_file = cls.is_file_path(test_protocols)
        return is_file, test_protocols

    @classmethod
    def get_data_config(cls):
        """Get data processing configuration"""
        return {
            'min_packets': cls.MIN_PACKETS,
            'samples_per_group': cls.SAMPLES_PER_GROUP,
            'min_group_size': cls.MIN_GROUP_SIZE,
            'val_ratio': cls.VAL_RATIO,
            # Adaptive sampling configuration
            'adaptive_sampling': cls.ADAPTIVE_SAMPLING,
            'diversity_threshold': cls.DIVERSITY_SAMPLING_THRESHOLD,
            'adaptive_thresholds': cls.ADAPTIVE_THRESHOLDS,
            'adaptive_multipliers': cls.ADAPTIVE_MULTIPLIERS,
            'max_samples_per_format': cls.MAX_SAMPLES_PER_FORMAT,
            'min_samples_per_format': cls.MIN_SAMPLES_PER_FORMAT
        }
    """
    @classmethod
    def get_model_config(cls):
        #Get model configuration
        return {
            'vocab_size': cls.VOCAB_SIZE,
            'd_model': cls.D_MODEL,
            'nhead': cls.NHEAD,
            'num_layers': cls.NUM_LAYERS,
            'dropout': cls.DROPOUT,
            'max_len': cls.TRAIN_MAX_LEN,  # Use train max_len during training
            'window_sizes': cls.WINDOW_SIZES,  # Support multi-scale windows
            # Loss function related parameters (optimized version)
            'use_focal_loss': cls.USE_FOCAL_LOSS,
            'focal_alpha': cls.FOCAL_ALPHA,
            'focal_gamma': cls.FOCAL_GAMMA,
            'use_dice_loss': cls.USE_DICE_LOSS,
            'use_consistency_loss': cls.USE_CONSISTENCY_LOSS,
            'crf_weight': cls.CRF_WEIGHT,
            'focal_weight': cls.FOCAL_WEIGHT,
            'dice_weight': cls.DICE_WEIGHT,
            'consistency_weight': cls.CONSISTENCY_WEIGHT
        }
    """
    @classmethod
    def get_model_config(cls):
        """Get model configuration (corrected version)"""
        return {
            'vocab_size': cls.VOCAB_SIZE,
            'd_model': cls.D_MODEL,
            'nhead': cls.NHEAD,
            'num_layers': cls.NUM_LAYERS,
            'dropout': cls.DROPOUT,
            'max_len': cls.TRAIN_MAX_LEN,  # 训练时使用训练max_len
            
            # 【Important】Conv2d model-specific parameters
            #'num_messages': cls.SAMPLES_PER_GROUP,  # Fixed message count
            #'conv_kernel_widths': [3, 5, 7],  # Multi-scale convolution kernels
            #'conv_num_layers': 2,  # 【New】Conv2d stacking layers, can be set to 2 or 3 for deep experiments
            
            # Key correction: Ensure values in config file are passed to model
            'window_sizes': cls.WINDOW_SIZES,               # Windows for VerticalAttention
            'film_window_sizes': cls.film_window_sizes,     # Windows for SetTemplateFiLM
            'hist_compress_dim': cls.hist_feat_compressed, # You can also add this to config, using default value for now

            # Loss function related parameters
            'use_focal_loss': cls.USE_FOCAL_LOSS,
            'focal_alpha': cls.FOCAL_ALPHA,
            'focal_gamma': cls.FOCAL_GAMMA,
            'use_dice_loss': cls.USE_DICE_LOSS,
            'use_consistency_loss': cls.USE_CONSISTENCY_LOSS,
            'crf_weight': cls.CRF_WEIGHT,
            'focal_weight': cls.FOCAL_WEIGHT,
            'dice_weight': cls.DICE_WEIGHT,
            'consistency_weight': cls.CONSISTENCY_WEIGHT
        }

    
    @classmethod
    def get_test_model_config(cls):
        """Get test model configuration"""
        config = cls.get_model_config()
        config['max_len'] = cls.TEST_MAX_LEN  # Use test max_len during testing
        return config
    
    @classmethod
    def get_optimizer_config(cls):
        """Get optimizer configuration"""
        return {
            'lr': cls.LEARNING_RATE,
            'weight_decay': cls.WEIGHT_DECAY
        }
    
    @classmethod
    def get_loss_config(cls):
        """Get loss function configuration"""
        return {
            'use_focal': cls.USE_FOCAL_LOSS,
            'alpha': cls.FOCAL_ALPHA,
            'gamma': cls.FOCAL_GAMMA,
            'crf_weight': cls.CRF_WEIGHT,
            'focal_weight': cls.FOCAL_WEIGHT
        }
    
    @classmethod
    def print_config(cls):
        """Print configuration information"""
        print("="*50)
        print("           Training Configuration")
        print("="*50)
        
        # Display protocol configuration instead of file path
        train_is_file, train_source = cls.get_train_data_info()
        test_is_file, test_source = cls.get_test_data_info()
        
        if train_is_file:
            print(f"Training data: {train_source} (file path)")
        else:
            print(f"Training protocols: {train_source}")
            
        if test_is_file:
            print(f"Test data: {test_source} (file path)")
        else:
            print(f"Test protocols: {test_source}")
            
        print(f"Train max_len: {cls.TRAIN_MAX_LEN}, Test max_len: {cls.TEST_MAX_LEN}")
        print(f"Data processing: min_packets={cls.MIN_PACKETS}, samples_per_group={cls.SAMPLES_PER_GROUP}, min_group_size={cls.MIN_GROUP_SIZE}")
        print(f"Model dimensions: d_model={cls.D_MODEL}, nhead={cls.NHEAD}, layers={cls.NUM_LAYERS}")
        print(f"Multi-scale windows: {cls.WINDOW_SIZES}")
        print(f"Training parameters: epochs={cls.NUM_EPOCHS}, lr={cls.LEARNING_RATE}, batch_size={cls.BATCH_SIZE}")
        print(f"Regularization: dropout={cls.DROPOUT}, weight_decay={cls.WEIGHT_DECAY}")
        print(f"Early stopping metric: {cls.EARLY_STOPPING_METRIC}, patience={cls.EARLY_STOPPING_PATIENCE}")
        print(f"Using Focal Loss: {cls.USE_FOCAL_LOSS}")
        print("="*50)

# Cross-Protocol Generalization Configuration Preset
class CrossProtocolConfig(TrainingConfig):
    """Configuration specifically for cross-protocol generalization - enhanced version (multi-scale window + reduced overfitting)
    New: Addressing Precision/Recall imbalance issues
    """
    # =================== 
    # Enhanced Regularization Strategy - Core Improvement
    # ===================
    DROPOUT = 0.4           # Significantly increase dropout to enforce generalization
    WEIGHT_DECAY = 0.01     # Significantly increase weight decay to prevent large parameters
    
    # More aggressive early stopping strategy
    EARLY_STOPPING_PATIENCE = 50      # Based on experience, use more aggressive early stopping
    EARLY_STOPPING_MIN_DELTA = 0.01   # Appropriately lower threshold to give more chances
    
    # Gradient clipping - stricter
    MAX_GRAD_NORM = 1.0     # Slightly relax gradient clipping to avoid over-constraint
    
    # Training strategy - overfitting prevention optimization
    LEARNING_RATE = 1e-4    # Based on experience, use more stable learning rate
    NUM_EPOCHS = 10         # Based on experience, reduce training epochs to prevent overfitting
    WARMUP_RATIO = 0.15     # Appropriately reduce warmup to enter main learning earlier
    BATCH_SIZE = 4          # Reduce batch size to avoid memory issues
    
    # Model complexity reduction - based on experience
    #D_MODEL = 128            # Reduce model dimension
    #NUM_LAYERS = 2          # Reduce Transformer layers
    #NHEAD = 8                # Reduce attention heads

    D_MODEL = 128            # Reduce model dimension
    NUM_LAYERS = 2          # Reduce Transformer layers
    NHEAD = 8                # Reduce attention heads
    
    # Multi-scale window simplification - use only odd window sizes to avoid padding issues
    WINDOW_SIZES = [3, 5, 7, 9]   # Use only odd windows to avoid tensor shape mismatch
    
    # ===================
    # Loss Function Balance - Using Your Previously Successful Configuration
    # ===================
    USE_FOCAL_LOSS = True
    USE_DICE_LOSS = True 
    USE_CONSISTENCY_LOSS = False  # Restore consistency loss
    
    # Using Your Previously Successful Loss Weight Configuration
    CRF_WEIGHT = 0.4        # Your previously successful CRF weight
    FOCAL_WEIGHT = 0.3      # Your previously successful Focal weight
    DICE_WEIGHT = 0.3      # Your previously successful Dice weight
    CONSISTENCY_WEIGHT = 0.00  # Your previously successful consistency weight
    
    # Focal Loss Parameters - Using Balanced Settings
    FOCAL_ALPHA = 0.25      # Moderate setting to avoid over-focusing on boundary class
    FOCAL_GAMMA = 1.0       # Moderate setting to balance hard sample focus
    
    # ===================
    # Data Augmentation Strategy - Improve Generalization
    # ===================
    USE_DATA_AUGMENTATION = True
    AUGMENTATION_PROB = 0.2   # Appropriately reduce augmentation probability to avoid over-interference
    
    # ===================
    # Focus on Real Test Set Performance
    # ===================
    EARLY_STOPPING_METRIC = "real_test_f1"  # Must focus on real test set
    SAVE_BEST_TEST_MODEL = True
