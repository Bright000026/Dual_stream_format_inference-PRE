#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSV File Merge Script
Merge corresponding CSV files based on training and test protocols in config
Support merging specified CSV files to specified paths
"""

import os
import sys
import pandas as pd
from pathlib import Path
from typing import List, Optional
import argparse
import config  # Import configuration file

def merge_specific_csvs(csv_files: List[str], output_path: str, csv_dir: str = "./generate/csv") -> bool:
    """
    Merge specified CSV files to specified path
    
    Args:
        csv_files: List of CSV file names to merge
        output_path: Output file path
        csv_dir: CSV file directory
    
    Returns:
        bool: Whether merge was successful
    """
    if not csv_files:
        print("Warning: No CSV files specified for merge")
        return False
    
    csv_directory = Path(csv_dir)
    if not csv_directory.exists():
        print(f"Error: CSV directory does not exist: {csv_directory}")
        return False
    
    all_dfs = []
    successful_files = []
    
    for csv_file in csv_files:
        file_path = csv_directory / csv_file
        if file_path.exists():
            try:
                df = pd.read_csv(file_path)
                # Add source file column to distinguish sources
                df['source_file'] = csv_file
                all_dfs.append(df)
                successful_files.append(csv_file)
                print(f"[OK] Successfully loaded {csv_file}: {len(df)} records")
            except Exception as e:
                print(f"Error: Failed to read {file_path}: {str(e)}")
        else:
            print(f"Warning: File not found: {file_path}")
    
    if not all_dfs:
        print("Error: No CSV files loaded successfully")
        return False
    
    # Merge all data
    merged_df = pd.concat(all_dfs, ignore_index=True)
    print(f"Merge completed: {len(merged_df)} total records from {len(successful_files)} files")
    
    # Ensure output directory exists
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Save merged file
    try:
        merged_df.to_csv(output_path, index=False)
        print(f"[OK] Successfully saved merged file: {output_path}")
        return True
    except Exception as e:
        print(f"Error: Failed to save file: {str(e)}")
        return False

def merge_protocol_csvs(protocols: List[str], output_path: str, csv_dir: str = "./generate/csv") -> bool:
    """
    Merge CSV files for specified protocols
    
    Args:
        protocols: List of protocols to merge
        output_path: Output file path
        csv_dir: CSV file directory
    
    Returns:
        bool: Whether merge was successful
    """
    if not protocols:
        print("Warning: No protocols specified for merge")
        return False
    
    csv_directory = Path(csv_dir)
    if not csv_directory.exists():
        print(f"Error: CSV directory does not exist: {csv_directory}")
        return False
    
    all_dfs = []
    successful_protocols = []
    
    for protocol in protocols:
        # Build possible file name patterns
        possible_filenames = [
            f"{protocol}_messages.csv",
            f"{protocol.lower()}_messages.csv",
            f"{protocol.upper()}_messages.csv",
            f"{protocol}_segments.csv",
            f"{protocol.lower()}_segments.csv",
            f"{protocol.upper()}_segments.csv"
        ]
        
        file_found = False
        for filename in possible_filenames:
            file_path = csv_directory / filename
            if file_path.exists():
                try:
                    df = pd.read_csv(file_path)
                    # Add protocol column to distinguish sources
                    df['protocol'] = protocol
                    all_dfs.append(df)
                    successful_protocols.append(protocol)
                    print(f"[OK] Successfully loaded {protocol} data: {len(df)} records")
                    file_found = True
                    break
                except Exception as e:
                    print(f"Error: Failed to read {file_path}: {str(e)}")
                    
        if not file_found:
            print(f"Warning: CSV file for {protocol} not found, supported naming patterns: {possible_filenames}")
    
    if not all_dfs:
        print("Error: No CSV files loaded successfully")
        return False
    
    # Merge all data
    merged_df = pd.concat(all_dfs, ignore_index=True)
    print(f"Merge completed: {len(merged_df)} total records from {len(successful_protocols)} protocols")
    
    # Ensure output directory exists
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Save merged file
    try:
        merged_df.to_csv(output_path, index=False)
        print(f"[OK] Successfully saved merged file: {output_path}")
        return True
    except Exception as e:
        print(f"Error: Failed to save file: {str(e)}")
        return False

def auto_merge_csvs_from_config() -> tuple[bool, str, str]:
    """
    Automatically merge CSV files based on config file
    Support mixed matching mode
    Support protocol list or directly specify file path
    
    Returns:
        tuple: (success, train_data_path, test_data_path)
    """
    try:
        # Get training data configuration
        train_is_file, train_source = config.TrainingConfig.get_train_data_info()
        test_is_file, test_source = config.TrainingConfig.get_test_data_info()
        
        print(f"Starting data processing based on config...")
        
        # Handle Chinese display in f-string
        train_type_text = "file path" if train_is_file else "protocol list"
        test_type_text = "file path" if test_is_file else "protocol list"
        
        print(f"Training data config: {train_type_text} - {train_source}")
        print(f"Test data config: {test_type_text} - {test_source}")
        
        # Process training data
        train_csv_path: str
        if train_is_file:
            # Use specified file path directly
            if not isinstance(train_source, str):
                print(f"Error: Training data config error, expected string path, got: {type(train_source)}")
                return False, "", ""
            train_csv_path = train_source
            if not os.path.exists(train_csv_path):
                print(f"Error: Specified training data file does not exist: {train_csv_path}")
                return False, "", ""
            print(f"[OK] Using specified training data file: {train_csv_path}")
        else:
            # Use protocol list for merge
            if not train_source:
                print(f"Error: No training protocols specified in config (TRAIN_PROTOCOLS)")
                return False, "", ""
            
            if not isinstance(train_source, list):
                print(f"Error: Training protocol config error, expected list, got: {type(train_source)}")
                return False, "", ""
            
            # Merge training protocol CSVs
            train_output_path = "./data/merged_train_data.csv"
            train_success = merge_protocol_csvs(train_source, train_output_path)
            
            if not train_success:
                print(f"Training data merge failed")
                return False, "", ""
            
            train_csv_path = train_output_path
        
        # Process test data
        if test_is_file:
            # Use specified file path directly
            if not isinstance(test_source, str):
                print(f"Error: Test data config error, expected string path, got: {type(test_source)}")
                return False, "", ""
            test_csv_path = test_source
            if not os.path.exists(test_csv_path):
                print(f"Error: Specified test data file does not exist: {test_csv_path}")
                return False, "", ""
            print(f"[OK] Using specified test data file: {test_csv_path}")
        else:
            # Use protocol list to find files
            if not test_source:
                print(f"Error: No test protocols specified in config (TEST_PROTOCOLS)")
                return False, "", ""
            
            # Test protocol usually has only one, use its CSV file directly
            if isinstance(test_source, list):
                test_protocol = test_source[0]
            else:
                test_protocol = test_source
            
            # Find CSV file for test protocol
            csv_directory = Path("./generate/csv")
            possible_filenames = [
                f"{test_protocol}_messages.csv",
                f"{test_protocol.lower()}_messages.csv",
                f"{test_protocol.upper()}_messages.csv",
                f"{test_protocol}_segments.csv",
                f"{test_protocol.lower()}_segments.csv",
                f"{test_protocol.upper()}_segments.csv"
            ]
            
            test_csv_path: str = ""  # Initial value
            for filename in possible_filenames:
                file_path = csv_directory / filename
                if file_path.exists():
                    test_csv_path = str(file_path)
                    print(f"[OK] Found CSV file for test protocol {test_protocol}: {test_csv_path}")
                    break
            
            if not test_csv_path:
                print(f"Error: CSV file for test protocol {test_protocol} not found")
                return False, "", ""
        
        # Update config paths
        update_config_paths(train_csv_path, test_csv_path)
        
        print(f"[OK] Data processing completed!")
        if train_is_file:
            print(f"  Training data: {train_csv_path} (directly specified file)")
        else:
            protocol_text = '+'.join(train_source) if isinstance(train_source, list) else str(train_source)
            print(f"  Training data: {train_csv_path} ({protocol_text})")
        
        if test_is_file:
            print(f"  Test data: {test_csv_path} (directly specified file)")
        else:
            test_protocol_text = test_source[0] if isinstance(test_source, list) else str(test_source)
            print(f"  Test data: {test_csv_path} ({test_protocol_text})")
        
        return True, train_csv_path, test_csv_path
        
    except Exception as e:
        print(f"Error: Automatic data processing failed: {str(e)}")
        return False, "", ""

def update_config_paths(train_csv_path: str, test_csv_path: str):
    """
    Update data paths in config file
    
    Args:
        train_csv_path: Training data CSV path
        test_csv_path: Test data CSV path
    """
    try:
        # Directly modify config module attributes
        # Update class attributes
        setattr(config.TrainingConfig, 'TRAIN_DATA_PATH', train_csv_path)
        setattr(config.TrainingConfig, 'TEST_DATA_PATH', test_csv_path)
        print(f"Config updated:")
        print(f"  TRAIN_DATA_PATH = {train_csv_path}")
        print(f"  TEST_DATA_PATH = {test_csv_path}")
        return True
    except Exception as e:
        print(f"Error: Failed to update config: {str(e)}")
        return False

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='CSV file merge tool')
    parser.add_argument('--csv_files', nargs='+', help='Specify CSV file names to merge')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--csv_dir', default='./generate/csv', help='CSV file directory')
    
    args = parser.parse_args()
    
    # If command-line parameters specified, execute specified merge
    if args.csv_files and args.output:
        success = merge_specific_csvs(args.csv_files, args.output, args.csv_dir)
        if success:
            print(f"[OK] Specified files merge successful!")
        else:
            print(f"✗ Specified files merge failed!")
            sys.exit(1)
        return
    # Get protocol list from config
    # Get protocol list from config
    train_protocols = getattr(config.TrainingConfig, 'TRAIN_PROTOCOLS', [])
    test_protocols = getattr(config.TrainingConfig, 'TEST_PROTOCOLS', ['smb'])
    
    if not train_protocols:
        print("Error: No training protocols specified in config (TRAIN_PROTOCOLS)")
        print("Please set TRAIN_PROTOCOLS in config.py first")
        sys.exit(1)
    
    if not test_protocols:
        print("Error: No test protocols specified in config (TEST_PROTOCOLS)")
        print("Please set TEST_PROTOCOLS in config.py first")
        sys.exit(1)
    
    print(f"Starting to merge protocol CSV files...")
    print(f"Training protocols: {train_protocols}")
    print(f"Test protocols: {test_protocols}")
    
    # Merge training protocol CSVs
    train_output_path = "./data/merged_train_data.csv"
    train_success = merge_protocol_csvs(train_protocols, train_output_path)
    
    if not train_success:
        print("Training data merge failed, program exiting")
        sys.exit(1)
    
    # Test protocol usually has only one, use its CSV file directly
    test_protocol = test_protocols[0]  # Assuming only test one protocol
    test_csv_path = None
    
    # Find CSV file for test protocol
    csv_directory = Path("./generate/csv")
    possible_filenames = [
        f"{test_protocol}_messages.csv",
        f"{test_protocol.lower()}_messages.csv",
        f"{test_protocol.upper()}_messages.csv",
        f"{test_protocol}_segments.csv",
        f"{test_protocol.lower()}_segments.csv",
        f"{test_protocol.upper()}_segments.csv"
    ]
    
    for filename in possible_filenames:
        file_path = csv_directory / filename
        if file_path.exists():
            test_csv_path = str(file_path)
            print(f"✓ Found CSV file for test protocol {test_protocol}: {test_csv_path}")
            break
    
    if test_csv_path is None:
        print(f"Error: CSV file for test protocol {test_protocol} not found")
        sys.exit(1)
    
    # Update config paths
    config_updated = update_config_paths(train_output_path, test_csv_path)
    
    if config_updated:
        print("\nAll operations completed!")
        print(f"Training data: {train_output_path} ({'+'.join(train_protocols)})")
        print(f"Test data: {test_csv_path} ({test_protocol})")
        print("Subsequent training will use data from these new paths")
    else:
        print("\nWarning: Config update failed, you need to manually set TRAIN_DATA_PATH and TEST_DATA_PATH")
        print(f"Training data path: {train_output_path}")
        print(f"Test data path: {test_csv_path}")

if __name__ == "__main__":
    main()
