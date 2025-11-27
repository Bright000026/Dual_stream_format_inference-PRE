#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
消息过滤脚本
从生成器产生的5000条消息中筛选出1000条高质量消息
确保每种格式至少有5条消息，保持格式分布和多样性
同步处理CSV和PCAP文件
"""

import csv
import sys
import os
from collections import defaultdict
from pathlib import Path
import random
import argparse

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import TrainingConfig

try:
    from scapy.all import rdpcap, wrpcap
except ImportError:
    print("警告: scapy库未安装，PCAP文件处理功能不可用")
    print("请运行: pip install scapy")
    sys.exit(1)


def truncate_segment(segment_str, max_len):
    """
    截断Segment到指定的最大长度
    
    Args:
        segment_str: Segment字符串，格式如 "[(0, 1), (1, 2), ...]"
        max_len: 最大长度
        
    Returns:
        str: 截断后的Segment字符串
    """
    try:
        # 解析segment字符串为列表
        segment_list = eval(segment_str)
        
        # 过滤掉结束位置大于max_len的元组
        filtered_segment = [seg for seg in segment_list if seg[1] <= max_len]
        
        return str(filtered_segment)
    except:
        return segment_str


def analyze_format_distribution(csv_file, max_len):
    """
    分析CSV文件中的格式分布
    
    Args:
        csv_file: CSV文件路径
        max_len: Segment最大长度
        
    Returns:
        dict: {segment: [row_indices]}
    """
    segment_to_indices = defaultdict(list)
    
    print(f"正在分析文件: {csv_file}")
    
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for idx, row in enumerate(reader):
            segment = truncate_segment(row['Segment'], max_len)
            segment_to_indices[segment].append(idx)
    
    return segment_to_indices


def filter_by_min_count(segment_to_indices, min_count=5):
    """
    过滤掉消息数量少于min_count的格式
    
    Args:
        segment_to_indices: {segment: [row_indices]}
        min_count: 最小消息数量
        
    Returns:
        dict: 过滤后的{segment: [row_indices]}
    """
    filtered = {
        segment: indices 
        for segment, indices in segment_to_indices.items() 
        if len(indices) >= min_count
    }
    
    excluded_count = len(segment_to_indices) - len(filtered)
    excluded_msgs = sum(len(indices) for segment, indices in segment_to_indices.items() 
                       if len(indices) < min_count)
    
    print(f"\n过滤统计:")
    print(f"  原始格式总数: {len(segment_to_indices)}")
    print(f"  保留格式总数: {len(filtered)}")
    print(f"  排除格式数量: {excluded_count}")
    print(f"  排除消息数量: {excluded_msgs}")
    
    return filtered


def select_messages_proportionally(segment_to_indices, target_count=1000, min_count=5):
    """
    按比例从每种格式中选择消息
    
    Args:
        segment_to_indices: {segment: [row_indices]}
        target_count: 目标消息总数
        min_count: 每种格式的最小消息数
        
    Returns:
        list: 选中的消息索引列表（已排序）
    """
    total_messages = sum(len(indices) for indices in segment_to_indices.values())
    num_formats = len(segment_to_indices)
    min_possible = num_formats * min_count
    
    if total_messages <= target_count:
        print(f"警告: 可用消息数({total_messages})少于目标数({target_count})")
        # 返回所有消息
        all_indices = []
        for indices in segment_to_indices.values():
            all_indices.extend(indices)
        return sorted(all_indices)
    
    # 检查是否即使每种格式只保留min_count条也会超过目标
    if min_possible > target_count:
        print(f"警告: {num_formats}种格式各保留{min_count}条需要{min_possible}条消息，超过目标{target_count}条")
        print(f"      将优先保留消息数量较多的格式，以精确达到目标数")
        
        # 按原始消息数量排序格式（降序）
        sorted_formats = sorted(
            segment_to_indices.items(), 
            key=lambda x: len(x[1]), 
            reverse=True
        )
        
        # 计算可以选择多少种格式
        max_formats = target_count // min_count  # 最多能选择的格式数
        
        # 选择前max_formats种格式
        selected_formats = {}
        for i in range(min(max_formats, len(sorted_formats))):
            segment, indices = sorted_formats[i]
            selected_formats[segment] = min_count
        
        current_total = sum(selected_formats.values())
        
        print(f"      选择了{len(selected_formats)}种格式（各{min_count}条），共{current_total}条消息")
        
        # 随机选择消息
        selected_indices = []
        for segment, count in selected_formats.items():
            indices = segment_to_indices[segment]
            selected = random.sample(indices, count)
            selected_indices.extend(selected)
        
        print(f"\n选择统计:")
        print(f"  目标消息数: {target_count}")
        print(f"  实际选择数: {len(selected_indices)}")
        print(f"  选择格式数: {len(selected_formats)} / {num_formats}")
        print(f"  格式分布:")
        
        for segment, count in sorted(selected_formats.items(), key=lambda x: len(segment_to_indices[x[0]]), reverse=True)[:10]:
            original_count = len(segment_to_indices[segment])
            print(f"    格式(原{original_count}条) -> 选{count}条")
        
        if len(selected_formats) > 10:
            print(f"    ... 还有 {len(selected_formats) - 10} 种格式")
        
        return sorted(selected_indices)
    
    # 正常情况：可以通过调整每种格式的数量来达到目标
    selected_indices = []
    
    # 第一轮：按比例分配
    format_counts = {}
    for segment, indices in segment_to_indices.items():
        proportion = len(indices) / total_messages
        count = max(min_count, int(target_count * proportion))  # 至少保留min_count条
        format_counts[segment] = min(count, len(indices))
    
    # 调整到目标总数
    current_total = sum(format_counts.values())
    
    # 如果超过目标，按比例减少（但每种至少保留min_count条）
    while current_total > target_count:
        # 找出可以减少的格式（大于min_count条的）
        reducible = {seg: cnt for seg, cnt in format_counts.items() if cnt > min_count}
        if not reducible:
            break
        
        # 从数量最多的格式中减1
        max_segment = max(reducible, key=lambda x: reducible[x])
        format_counts[max_segment] -= 1
        current_total -= 1
    
    # 如果不足目标，按比例增加（但不超过每种格式的实际数量）
    while current_total < target_count:
        # 找出可以增加的格式
        increasable = {
            seg: cnt for seg, cnt in format_counts.items() 
            if cnt < len(segment_to_indices[seg])
        }
        if not increasable:
            break
        
        # 优先增加数量较少的格式（增加多样性）
        min_segment = min(increasable, key=lambda x: increasable[x])
        format_counts[min_segment] += 1
        current_total += 1
    
    # 从每种格式中随机选择指定数量的消息
    for segment, count in format_counts.items():
        indices = segment_to_indices[segment]
        selected = random.sample(indices, count)
        selected_indices.extend(selected)
    
    print(f"\n选择统计:")
    print(f"  目标消息数: {target_count}")
    print(f"  实际选择数: {len(selected_indices)}")
    print(f"  格式分布:")
    
    # 显示每种格式的选择情况
    for segment, count in sorted(format_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        original_count = len(segment_to_indices[segment])
        print(f"    格式(原{original_count}条) -> 选{count}条")
    
    if len(format_counts) > 10:
        print(f"    ... 还有 {len(format_counts) - 10} 种格式")
    
    return sorted(selected_indices)


def filter_csv_file(input_csv, output_csv, selected_indices):
    """
    根据选中的索引过滤CSV文件
    
    Args:
        input_csv: 输入CSV文件路径
        output_csv: 输出CSV文件路径
        selected_indices: 选中的行索引列表
    """
    print(f"\n正在过滤CSV文件...")
    
    selected_set = set(selected_indices)
    
    with open(input_csv, 'r', encoding='utf-8') as fin:
        reader = csv.DictReader(fin)
        fieldnames = reader.fieldnames
        
        if fieldnames is None:
            print("  错误: CSV文件没有列名")
            return
        
        with open(output_csv, 'w', encoding='utf-8', newline='') as fout:
            writer = csv.DictWriter(fout, fieldnames=fieldnames)
            writer.writeheader()
            
            for idx, row in enumerate(reader):
                if idx in selected_set:
                    writer.writerow(row)
    
    print(f"  已保存到: {output_csv}")


def filter_pcap_file(input_pcap, output_pcap, selected_indices):
    """
    根据选中的索引过滤PCAP文件
    
    Args:
        input_pcap: 输入PCAP文件路径
        output_pcap: 输出PCAP文件路径
        selected_indices: 选中的包索引列表
    """
    print(f"\n正在过滤PCAP文件...")
    
    try:
        # 读取所有包
        packets = rdpcap(str(input_pcap))
        
        print(f"  原始包数量: {len(packets)}")
        
        # 选择指定索引的包
        selected_packets = [packets[idx] for idx in selected_indices if idx < len(packets)]
        
        print(f"  选中包数量: {len(selected_packets)}")
        
        # 写入新的PCAP文件
        wrpcap(str(output_pcap), selected_packets)
        
        print(f"  已保存到: {output_pcap}")
        
    except Exception as e:
        print(f"  错误: 处理PCAP文件时出错: {e}")


def process_protocol(protocol_name, csv_dir, pcap_dir, output_csv_dir, output_pcap_dir, 
                     min_count=5, target_count=1000, max_len=None):
    """
    处理单个协议的消息过滤
    
    Args:
        protocol_name: 协议名称
        csv_dir: CSV输入目录
        pcap_dir: PCAP输入目录
        output_csv_dir: CSV输出目录
        output_pcap_dir: PCAP输出目录
        min_count: 每种格式最少消息数
        target_count: 目标消息总数
        max_len: Segment最大长度
    """
    csv_file = csv_dir / f"{protocol_name}_messages.csv"
    pcap_file = pcap_dir / f"{protocol_name}_messages.pcap"
    
    if not csv_file.exists():
        print(f"跳过 {protocol_name}: CSV文件不存在")
        return
    
    if not pcap_file.exists():
        print(f"警告: {protocol_name} 的PCAP文件不存在")
    
    print(f"\n{'='*60}")
    print(f"处理协议: {protocol_name}")
    print(f"{'='*60}")
    
    # 分析格式分布
    segment_to_indices = analyze_format_distribution(csv_file, max_len)
    
    print(f"\n原始统计:")
    print(f"  总消息数: {sum(len(indices) for indices in segment_to_indices.values())}")
    print(f"  格式总数: {len(segment_to_indices)}")
    
    # 过滤少于min_count的格式
    filtered_segments = filter_by_min_count(segment_to_indices, min_count)
    
    if not filtered_segments:
        print(f"警告: 没有符合条件的格式（至少{min_count}条消息）")
        return
    
    # 按比例选择消息
    selected_indices = select_messages_proportionally(filtered_segments, target_count, min_count)
    
    # 创建输出目录
    output_csv_dir.mkdir(parents=True, exist_ok=True)
    output_pcap_dir.mkdir(parents=True, exist_ok=True)
    
    # 过滤CSV文件
    output_csv = output_csv_dir / f"{protocol_name}_messages.csv"
    filter_csv_file(csv_file, output_csv, selected_indices)
    
    # 过滤PCAP文件
    if pcap_file.exists():
        output_pcap = output_pcap_dir / f"{protocol_name}_messages.pcap"
        filter_pcap_file(pcap_file, output_pcap, selected_indices)


def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(
        description='消息过滤脚本 - 从5000条消息中筛选1000条高质量消息',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 过滤所有协议
  python filter_messages.py
  
  # 只过滤s7comm协议
  python filter_messages.py -p s7comm
  
  # 过滤多个协议
  python filter_messages.py -p s7comm modbus dnp3
  
  # 列出所有可用协议
  python filter_messages.py --list
        """
    )
    parser.add_argument(
        '-p', '--protocols',
        nargs='+',
        help='指定要处理的协议名称（多个协议用空格分隔）。不指定则处理所有协议'
    )
    parser.add_argument(
        '--list',
        action='store_true',
        help='列出所有可用的协议并退出'
    )
    parser.add_argument(
        '--min-count',
        type=int,
        default=5,
        help='每种格式的最小消息数（默认: 5）'
    )
    parser.add_argument(
        '--target-count',
        type=int,
        default=1000,
        help='目标输出消息总数（默认: 1000）'
    )
    
    args = parser.parse_args()
    
    # 设置路径
    generate_dir = Path(__file__).parent
    csv_dir = generate_dir / "csv"
    pcap_dir = generate_dir / "pcap"
    output_csv_dir = generate_dir / "filter" / "csv"
    output_pcap_dir = generate_dir / "filter" / "pcap"
    
    # 从config获取TEST_MAX_LEN
    max_len = TrainingConfig.TEST_MAX_LEN
    
    # 获取所有可用协议（从CSV文件列表）
    available_protocols = []
    if csv_dir.exists():
        for csv_file in csv_dir.glob("*_messages.csv"):
            protocol_name = csv_file.stem.replace("_messages", "")
            available_protocols.append(protocol_name)
    
    if not available_protocols:
        print("错误: 未找到任何CSV文件")
        return
    
    available_protocols.sort()
    
    # 如果只是列出协议
    if args.list:
        print(f"\n找到 {len(available_protocols)} 个可用协议:\n")
        for i, proto in enumerate(available_protocols, 1):
            print(f"  {i:2d}. {proto}")
        print(f"\n使用 -p 参数指定要过滤的协议，例如:")
        print(f"  python filter_messages.py -p s7comm modbus")
        return
    
    # 确定要处理的协议
    if args.protocols:
        # 验证指定的协议是否存在
        protocols = []
        for proto in args.protocols:
            if proto in available_protocols:
                protocols.append(proto)
            else:
                print(f"警告: 协议 '{proto}' 不存在，将被跳过")
                print(f"      可用协议: {', '.join(available_protocols)}")
        
        if not protocols:
            print("\n错误: 没有有效的协议可处理")
            return
        
        protocols.sort()
        print(f"\n消息过滤脚本 - 处理指定协议")
    else:
        protocols = available_protocols
        print(f"\n消息过滤脚本 - 处理所有协议")
    
    print(f"配置参数:")
    print(f"  TEST_MAX_LEN: {max_len}")
    print(f"  最小格式消息数: {args.min_count}")
    print(f"  目标输出消息数: {args.target_count}")
    print(f"  CSV输入目录: {csv_dir}")
    print(f"  PCAP输入目录: {pcap_dir}")
    print(f"  CSV输出目录: {output_csv_dir}")
    print(f"  PCAP输出目录: {output_pcap_dir}")
    
    print(f"\n将处理 {len(protocols)} 个协议: {', '.join(protocols)}")
    
    # 处理每个协议
    success_count = 0
    fail_count = 0
    
    for protocol_name in protocols:
        try:
            process_protocol(
                protocol_name=protocol_name,
                csv_dir=csv_dir,
                pcap_dir=pcap_dir,
                output_csv_dir=output_csv_dir,
                output_pcap_dir=output_pcap_dir,
                min_count=args.min_count,
                target_count=args.target_count,
                max_len=max_len
            )
            success_count += 1
        except Exception as e:
            print(f"\n错误: 处理 {protocol_name} 时出错: {e}")
            import traceback
            traceback.print_exc()
            fail_count += 1
    
    print(f"\n{'='*60}")
    print(f"处理完成！")
    print(f"{'='*60}")
    print(f"  成功: {success_count} 个协议")
    if fail_count > 0:
        print(f"  失败: {fail_count} 个协议")
    print(f"\n输出目录:")
    print(f"  CSV:  {output_csv_dir}")
    print(f"  PCAP: {output_pcap_dir}")


if __name__ == "__main__":
    # 设置随机种子以保证可重复性
    random.seed(42)
    main()
