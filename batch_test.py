# -*- coding: utf-8 -*-
"""
Batch Test Script
Automatically run tests on multiple protocols/files and collect statistics
"""

import os
import sys
import subprocess
import json
import csv
import re
from datetime import datetime
import shutil

# Test configuration list
TEST_CONFIGS = [
    # Single protocol tests
    {'name': 'S7Comm', 'config': ['s7comm']},
    {'name': 'Modbus', 'config': ['modbus']},
    {'name': 'MQTT', 'config': ['mqtt']},
    {'name': 'OMRON FINS', 'config': ['omron']},
    {'name': 'CoAP', 'config': ['coap']},
    {'name': 'HART IP', 'config': ['hart_ip_hart_ip']},
    
    # Specific file tests
    {'name': 'S7Comm(public)', 'config': 'public/s7comm_public_messages.csv'},
    {'name': 'Modbus(public)', 'config': 'public/modbus_public_messages.csv'},
    {'name': 'OMRON FINS(public)', 'config':'public/omron_public_messages.csv'},
]

# Result collector
class TestResultCollector:
    def __init__(self):
        self.results = []
        
    def add_result(self, test_name, metrics):
        """Add test results"""
        result = {
            'test_name': test_name,
            'precision': metrics.get('boundary_precision', 0.0),
            'recall': metrics.get('boundary_recall', 0.0),
            'f1': metrics.get('boundary_f1', 0.0),
            'perfection': metrics.get('field_accuracy', 0.0)
        }
        self.results.append(result)
        
    def print_summary(self):
        """Print summary table"""
        print("\n" + "="*80)
        print("Batch Test Results Summary")
        print("="*80)
        print(f"{'Protocol/File':<20} {'Precision':<12} {'Recall':<12} {'F1':<12} {'Perfection':<12}")
        print("-"*80)
        
        for result in self.results:
            print(f"{result['test_name']:<20} {result['precision']:<12.2f} "
                  f"{result['recall']:<12.2f} {result['f1']:<12.2f} "
                  f"{result['perfection']:<12.2f}")
        
        # Calculate average values
        if self.results:
            avg_precision = sum(r['precision'] for r in self.results) / len(self.results)
            avg_recall = sum(r['recall'] for r in self.results) / len(self.results)
            avg_f1 = sum(r['f1'] for r in self.results) / len(self.results)
            avg_perfection = sum(r['perfection'] for r in self.results) / len(self.results)
            
            print("-"*80)
            print(f"{'Average':<20} {avg_precision:<12.2f} {avg_recall:<12.2f} "
                  f"{avg_f1:<12.2f} {avg_perfection:<12.2f}")
        
        print("="*80)
        
    def save_to_csv(self, filename='batch_test_results.csv'):
        """Save results to CSV file"""
        if not self.results:
            print("No results to save")
            return
            
        # Add timestamp to filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"batch_test_results_{timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['test_name', 'precision', 'recall', 'f1', 'perfection'])
            writer.writeheader()
            
            # Format data to two decimal places before writing
            for result in self.results:
                formatted_row = {
                    'test_name': result['test_name'],
                    'precision': f"{result['precision']:.2f}",
                    'recall': f"{result['recall']:.2f}",
                    'f1': f"{result['f1']:.2f}",
                    'perfection': f"{result['perfection']:.2f}"
                }
                writer.writerow(formatted_row)
            
            # Add average row
            if self.results:
                avg_precision = sum(r['precision'] for r in self.results) / len(self.results)
                avg_recall = sum(r['recall'] for r in self.results) / len(self.results)
                avg_f1 = sum(r['f1'] for r in self.results) / len(self.results)
                avg_perfection = sum(r['perfection'] for r in self.results) / len(self.results)
                
                avg_row = {
                    'test_name': 'Average',
                    'precision': f"{avg_precision:.2f}",
                    'recall': f"{avg_recall:.2f}",
                    'f1': f"{avg_f1:.2f}",
                    'perfection': f"{avg_perfection:.2f}"
                }
                writer.writerow(avg_row)
        
        print(f"\nResults saved to: {filename}")

def backup_config():
    """Backup original configuration file"""
    config_path = 'config.py'
    backup_path = f'config_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.py'
    shutil.copy(config_path, backup_path)
    print(f"Configuration file backed up to: {backup_path}")
    return backup_path

def restore_config(backup_path):
    """Restore original configuration file"""
    config_path = 'config.py'
    shutil.copy(backup_path, config_path)
    print(f"Configuration file restored")
    
def modify_config(test_config):
    """Modify TEST_PROTOCOLS configuration in config.py"""
    config_path = 'config.py'
    
    # Read configuration file
    with open(config_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Build new TEST_PROTOCOLS configuration line
    if isinstance(test_config, str):
        # File path
        new_line = f'    TEST_PROTOCOLS: Union[List[str], str] = "{test_config}"'
    else:
        # Protocol list
        new_line = f'    TEST_PROTOCOLS: Union[List[str], str] = {test_config}'
    
    # Use regular expression to replace TEST_PROTOCOLS line
    pattern = r'    TEST_PROTOCOLS: Union\[List\[str\], str\] = .*'
    content = re.sub(pattern, new_line, content)
    
    # Write back to configuration file
    with open(config_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Updated TEST_PROTOCOLS configuration to: {test_config}")

def run_test():
    """Run test script"""
    print("Running test script...")
    
    # Use Python to run test script
    python_path = r"D:\Anaconda\envs\pytorch\python.exe"
    test_script = "test.py"
    
    try:
        result = subprocess.run(
            [python_path, test_script],
            capture_output=True,
            text=True,
            encoding='gbk',  # Use gbk encoding on Windows Chinese systems
            errors='ignore',  # Ignore encoding errors
            timeout=600  # 10 minute timeout
        )
        
        # No longer strictly check returncode, as the test script may have warnings but still complete successfully
        # Only consider it successful if JSON results file is generated
        print("Test script execution completed")
        return result.stdout
        
    except subprocess.TimeoutExpired:
        print("Test script execution timeout")
        return None
    except Exception as e:
        print(f"Error occurred while running test script: {e}")
        return None

def extract_metrics_from_json():
    """Extract metrics from JSON results file"""
    json_file = 'boundary_prediction_results_full_test.json'
    
    if not os.path.exists(json_file):
        print(f"Results file does not exist: {json_file}")
        return None
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        summary = data.get('summary', {})
        metrics = {
            'boundary_precision': summary.get('boundary_precision', 0.0),
            'boundary_recall': summary.get('boundary_recall', 0.0),
            'boundary_f1': summary.get('boundary_f1', 0.0),
            'field_accuracy': summary.get('field_accuracy', 0.0)
        }
        
        return metrics
        
    except Exception as e:
        print(f"Failed to read results file: {e}")
        return None

def main():
    """Main function"""
    print("="*80)
    print("Batch Protocol Test Script")
    print("="*80)
    print(f"Number of test configurations: {len(TEST_CONFIGS)}")
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80)
    
    # Backup original configuration
    backup_path = backup_config()
    
    # Result collector
    collector = TestResultCollector()
    
    try:
        # Iterate through each test configuration
        for i, test_config in enumerate(TEST_CONFIGS, 1):
            test_name = test_config['name']
            test_value = test_config['config']
            
            print(f"\n{'='*80}")
            print(f"Test {i}/{len(TEST_CONFIGS)}: {test_name}")
            print(f"{'='*80}")
            
            # Modify configuration
            modify_config(test_value)
            
            # Run test
            output = run_test()
            
            if output is None:
                print(f"Test {test_name} failed, skipping...")
                continue
            
            # Extract metrics
            metrics = extract_metrics_from_json()
            
            if metrics is None:
                print(f"Unable to extract metrics for test {test_name}, skipping...")
                continue
            
            # Add to results
            collector.add_result(test_name, metrics)
            
            # Display current test results
            print(f"\nCurrent test results:")
            print(f"  Precision: {metrics['boundary_precision']:.4f}")
            print(f"  Recall: {metrics['boundary_recall']:.4f}")
            print(f"  F1: {metrics['boundary_f1']:.4f}")
            print(f"  Perfection: {metrics['field_accuracy']:.4f}")
        
        # Print summary table
        collector.print_summary()
        
        # Save to CSV
        collector.save_to_csv()
        
    finally:
        # Restore original configuration
        restore_config(backup_path)
        
        # Delete backup file (optional)
        # os.remove(backup_path)
        
        print(f"\n{'='*80}")
        print(f"Batch test completed!")
        print(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\nError occurred during script execution: {e}")
        import traceback
        traceback.print_exc()
