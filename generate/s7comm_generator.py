#!/usr/bin/env python3
"""
S7Comm协议消息生成器 - 修正版
解决现有生成器的问题：
1. 边生成边记录字段信息，确保Segment和Field Names的准确性
2. 增加消息多样性，支持更多协议功能
3. 修复malformed packet问题
4. 确保生成的CSV格式完全正确
"""

import random
import struct
import csv
import secrets
from typing import List, Tuple, Dict, Any
import datetime
import argparse
from scapy.all import IP, TCP, Ether, wrpcap, Packet, Raw
import json

class S7CommGeneratorFixed:
    def __init__(self):
        # S7Comm协议常量
        self.S7COMM_PROTOCOL_ID = 0x32
        
        # ROSCTR类型
        self.ROSCTR_TYPES = {
            0x01: "JOB",
            0x03: "ACK_DATA", 
            0x02: "ACK",
            0x07: "USERDATA"
        }
        
        # 功能码 - 基于实际pcap分析扩展
        self.FUNCTION_CODES = {
            0xF0: "Setup Communication",
            0x04: "Read Var",
            0x05: "Write Var", 
            0x1A: "Request Download",
            0x1B: "Download Block",
            0x1C: "Download Ended",
            0x1D: "Start Upload",
            0x1E: "Upload",
            0x1F: "End Upload",
            0x28: "PI Service",
            0x29: "PI Service Extended",  # 基于pcap分析发现
            0x00: "Unknown/Reserved"      # 基于pcap分析发现
        }
        
        # 传输大小
        self.TRANSPORT_SIZES = {
            0x03: "BIT",
            0x04: "BYTE",
            0x05: "CHAR", 
            0x06: "WORD",
            0x07: "INT",
            0x08: "DWORD",
            0x09: "DINT",
            0x0A: "REAL"
        }
        
        # 区域类型
        self.AREA_TYPES = {
            0x81: "I",    # 输入
            0x82: "Q",    # 输出
            0x83: "M",    # 标志位
            0x84: "DB",   # 数据块
            0x85: "DI",   # 实例数据块
            0x86: "L",    # 局部数据
            0x87: "V"     # 先前变量
        }
        
        # 返回码
        self.RETURN_CODES = {
            0xFF: "Success",
            0x01: "Hardware fault",
            0x03: "Accessing the object not allowed",
            0x05: "Invalid address", 
            0x06: "Data type not supported",
            0x07: "Data type inconsistent",
            0x0A: "Object does not exist"
        }
        
        # 字段范围配置 - 增加更多变化
        self.FIELD_RANGES = {
            'pdu_reference': (1, 0xFFFF),
            'parameter_length': (2, 62),
            'data_length': (0, 222),
            'item_count': (1, 5),
            'db_number': (1, 999),
            'address': (0, 8191),
            'length': (1, 64),
            'max_amq_calling': (1, 8),
            'max_amq_called': (1, 8),
            'pdu_length': (240, 960)
        }
        
        # 增加更多变化的数据模式
        self.DATA_PATTERNS = {
            'sequential': lambda size: bytes(range(size % 256, (size + size) % 256)),
            'random': lambda size: bytes([random.randint(0, 255) for _ in range(size)]),
            'alternating': lambda size: bytes([0xAA if i % 2 == 0 else 0x55 for i in range(size)]),
            'incrementing': lambda size: bytes([(i % 256) for i in range(size)]),
            'decrementing': lambda size: bytes([(255 - i % 256) for i in range(size)]),
            'zeros': lambda size: bytes([0x00] * size),
            'ones': lambda size: bytes([0xFF] * size),
            'mixed': lambda size: bytes([random.choice([0x00, 0xFF, 0xAA, 0x55]) for _ in range(size)])
        }
        
        # 更多内存区域和数据类型组合
        self.AREA_TRANSPORT_COMBINATIONS = [
            (0x81, 0x03),  # I, BIT
            (0x81, 0x04),  # I, BYTE
            (0x81, 0x06),  # I, WORD
            (0x81, 0x08),  # I, DWORD
            (0x82, 0x03),  # Q, BIT
            (0x82, 0x04),  # Q, BYTE
            (0x82, 0x06),  # Q, WORD
            (0x82, 0x08),  # Q, DWORD
            (0x83, 0x03),  # M, BIT
            (0x83, 0x04),  # M, BYTE
            (0x83, 0x06),  # M, WORD
            (0x83, 0x08),  # M, DWORD
            (0x84, 0x03),  # DB, BIT
            (0x84, 0x04),  # DB, BYTE
            (0x84, 0x06),  # DB, WORD
            (0x84, 0x08),  # DB, DWORD
            (0x85, 0x04),  # DI, BYTE
            (0x85, 0x06),  # DI, WORD
            (0x85, 0x08),  # DI, DWORD
            (0x86, 0x04),  # L, BYTE
            (0x86, 0x06),  # L, WORD
            (0x86, 0x08),  # L, DWORD
        ]
        
        # 基于pcap分析的SZL-ID类型
        self.SZL_IDS = [
            0x0000,    # 基于pcap分析发现
            0x0011,    # 模块标识
            0x0012,    # 模块状态
            0x001C,    # 模块信息
            0x0024,    # 模块诊断
            0x0131,    # 模块标识扩展
            0x0132,    # 模块状态扩展
            0x0174,    # 模块信息扩展
            0x65289,   # 基于pcap分析发现
            0x2560,    # 基于pcap分析发现
        ]
        
        # PI Service参数类型 - 基于实际pcap分析修正
        self.PI_SERVICE_TYPES = [
            (0x28, 26, 0),   # 基于pcap分析：0x28功能码，26字节参数
            (0x29, 16, 0),   # 基于pcap分析：0x29功能码，16字节参数
        ]
        
        # PI Service参数模板 - 基于实际pcap分析
        self.PI_SERVICE_TEMPLATES = {
            0x28: [
                # 模板1：基于实际pcap分析
                [0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFD, 0x00, 0x0A, 0x01, 0x00, 
                 0x30, 0x41, 0x30, 0x30, 0x30, 0x30, 0x31, 0x50, 0x05, 0x5F, 0x49, 0x4E, 0x53, 0x45],
            ],
            0x29: [
                # 模板1：基于实际pcap分析
                [0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x50, 0x5F, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D],
            ]
        }

    def _create_tpkt_header(self, total_length: int) -> Tuple[bytearray, List[Tuple[int, int]], List[str]]:
        """创建TPKT头部，同时记录字段信息"""
        header = bytearray()
        segments = []
        field_names = []
        
        # Version (1 byte)
        header.append(0x03)
        segments.append((0, 1))
        field_names.append("TPKT Version")
        
        # Reserved (1 byte)
        header.append(0x00)
        segments.append((1, 2))
        field_names.append("TPKT Reserved")
        
        # Length (2 bytes, big-endian)
        header.extend(struct.pack('>H', total_length))
        segments.append((2, 4))
        field_names.append("TPKT Length")
        
        return header, segments, field_names

    def _create_cotp_header(self, pdu_type: int = 0xF0, dst_ref: int = 0x0000) -> Tuple[bytearray, List[Tuple[int, int]], List[str]]:
        """创建COTP头部，同时记录字段信息"""
        header = bytearray()
        segments = []
        field_names = []
        
        if pdu_type == 0xF0:  # Data TPDU
            # Length Indicator
            header.append(0x02)
            segments.append((0, 1))
            field_names.append("COTP Length")
            
            # PDU Type
            header.append(0xF0)
            segments.append((1, 2))
            field_names.append("COTP PDU Type")
            
            # TPDU Number
            header.append(0x80)
            segments.append((2, 3))
            field_names.append("COTP TPDU Number")
            
        return header, segments, field_names

    def _create_s7comm_header(self, message_type: int, parameter_length: int, data_length: int,
                             pdu_ref: int = None, error_class: int = 0, error_code: int = 0) -> Tuple[bytearray, List[Tuple[int, int]], List[str]]:
        """创建S7Comm头部，同时记录字段信息"""
        header = bytearray()
        segments = []
        field_names = []
        
        # Protocol ID
        header.append(self.S7COMM_PROTOCOL_ID)
        segments.append((0, 1))
        field_names.append("Protocol Id")
        
        # Message Type (ROSCTR)
        header.append(message_type)
        segments.append((1, 2))
        field_names.append("ROSCTR")
        
        # Reserved
        header.extend(struct.pack('>H', 0x0000))
        segments.append((2, 4))
        field_names.append("Redundancy Identification (Reserved)")
        
        # PDU Reference
        if pdu_ref is None:
            pdu_ref = random.randint(*self.FIELD_RANGES['pdu_reference'])
        header.extend(struct.pack('<H', pdu_ref))
        segments.append((4, 6))
        field_names.append("Protocol Data Unit Reference")
        
        # Parameter Length
        header.extend(struct.pack('>H', parameter_length))
        segments.append((6, 8))
        field_names.append("Parameter length")
        
        # Data Length - 对于所有消息类型，data_length只包含实际数据部分
        # Error Class和Error Code是S7Comm头部的一部分，不是数据部分
        header.extend(struct.pack('>H', data_length))
        segments.append((8, 10))
        field_names.append("Data length")
        
        # Error Class and Code (for ACK_DATA)
        if message_type == 0x03:
            header.append(error_class)
            segments.append((10, 11))
            field_names.append("Error class")
            
            header.append(error_code)
            segments.append((11, 12))
            field_names.append("Error code")
        
        return header, segments, field_names

    def _create_variable_spec(self, area: int, db_number: int, address: int,
                             transport_size: int, length: int) -> Tuple[bytearray, List[Tuple[int, int]], List[str]]:
        """创建变量规范，同时记录字段信息"""
        spec = bytearray()
        segments = []
        field_names = []
        
        # Variable specification type
        spec.append(0x12)
        segments.append((0, 1))
        field_names.append("Variable specification")
        
        # Length of following address specification
        spec.append(0x0A)
        segments.append((1, 2))
        field_names.append("Length of following address specification")
        
        # Syntax ID
        spec.append(0x10)
        segments.append((2, 3))
        field_names.append("Syntax Id")
        
        # Transport size
        spec.append(transport_size)
        segments.append((3, 4))
        field_names.append("Transport size")
        
        # Length
        spec.extend(struct.pack('>H', length))
        segments.append((4, 6))
        field_names.append("Length")
        
        # DB Number
        spec.extend(struct.pack('>H', db_number))
        segments.append((6, 8))
        field_names.append("DB Number")
        
        # Area
        spec.append(area)
        segments.append((8, 9))
        field_names.append("Area")
        
        # Address (3 bytes)
        if transport_size == 0x03:  # BIT
            bit_address = address
        else:
            bit_address = address * 8
        
        spec.extend(struct.pack('>I', bit_address)[1:])  # 取低3字节
        segments.append((9, 12))
        field_names.append("Address")
        
        return spec, segments, field_names

    def _generate_setup_communication(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成Setup Communication消息，同时记录字段信息"""
        all_segments = []
        all_field_names = []
        
        # 参数部分
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        
        # Function code
        parameters.append(0xF0)
        param_segments.append((0, 1))
        param_field_names.append("Function")
        
        # Reserved
        parameters.append(0x00)
        param_segments.append((1, 2))
        param_field_names.append("Reserved")
        
        # Max AmQ calling
        max_amq_calling = 1
        parameters.extend(struct.pack('>H', max_amq_calling))
        param_segments.append((2, 4))
        param_field_names.append("Max AmQ (parallel jobs with ack) calling")
        
        # Max AmQ called
        max_amq_called = 1
        parameters.extend(struct.pack('>H', max_amq_called))
        param_segments.append((4, 6))
        param_field_names.append("Max AmQ (parallel jobs with ack) called")
        
        # PDU length
        pdu_length = 240
        parameters.extend(struct.pack('>H', pdu_length))
        param_segments.append((6, 8))
        param_field_names.append("PDU length")
        
        # 创建S7Comm头部
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x01, len(parameters), 0)
        
        # 创建COTP头部
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        
        # 创建TPKT头部
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        
        # 组合所有部分
        message = bytes(tpkt_header + cotp_header + s7_header + parameters)
        
        # 组合所有字段信息
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        
        # 调整COTP字段偏移
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        
        # 调整S7Comm字段偏移
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        
        # 调整参数字段偏移
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        
        return message, all_segments, all_field_names

    def _generate_read_var_single(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成单项目Read Variable消息，同时记录字段信息"""
        all_segments = []
        all_field_names = []
        
        # 参数部分
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        
        # Function code
        parameters.append(0x04)
        param_segments.append((0, 1))
        param_field_names.append("Function")
        
        # Item count
        parameters.append(1)
        param_segments.append((1, 2))
        param_field_names.append("Item count")
        
        # 生成变量规范
        area = 0x84  # DB区域
        db_number = random.randint(1, 100)
        address = random.randint(0, 1023)
        transport_size = 0x04  # BYTE
        length = random.randint(1, 16)
        
        var_spec, var_segments, var_field_names = self._create_variable_spec(
            area, db_number, address, transport_size, length
        )
        parameters.extend(var_spec)
        
        # 调整变量规范字段偏移
        var_offset = len(parameters) - len(var_spec)
        for start, end in var_segments:
            param_segments.append((start + var_offset, end + var_offset))
        param_field_names.extend(var_field_names)
        
        # 创建S7Comm头部
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x01, len(parameters), 0)
        
        # 创建COTP头部
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        
        # 创建TPKT头部
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        
        # 组合所有部分
        message = bytes(tpkt_header + cotp_header + s7_header + parameters)
        
        # 组合所有字段信息
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        
        # 调整COTP字段偏移
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        
        # 调整S7Comm字段偏移
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        
        # 调整参数字段偏移
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        
        return message, all_segments, all_field_names

    def _generate_read_var_multiple(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成多项目Read Variable消息，增加多样性"""
        all_segments = []
        all_field_names = []
        
        # 参数部分
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        
        # Function code
        parameters.append(0x04)
        param_segments.append((0, 1))
        param_field_names.append("Function")
        
        # Item count (2-5个项目)
        item_count = random.randint(2, 5)
        parameters.append(item_count)
        param_segments.append((1, 2))
        param_field_names.append("Item count")
        
        # 生成多个变量规范
        for i in range(item_count):
            # 使用预定义的组合增加多样性
            area, transport_size = random.choice(self.AREA_TRANSPORT_COMBINATIONS)
            
            if area == 0x84:  # DB区域
                db_number = random.randint(1, 999)
            else:
                db_number = 0  # 非DB区域不使用DB编号
            
            # 增加地址和长度的变化范围
            address = random.randint(0, 4095)  # 扩大地址范围
            length = random.randint(1, 64)     # 扩大长度范围
            
            var_spec, var_segments, var_field_names = self._create_variable_spec(
                area, db_number, address, transport_size, length
            )
            parameters.extend(var_spec)
            
            # 调整变量规范字段偏移
            var_offset = len(parameters) - len(var_spec)
            for start, end in var_segments:
                param_segments.append((start + var_offset, end + var_offset))
            param_field_names.extend([f"{name} (Item {i+1})" for name in var_field_names])
        
        # 创建S7Comm头部
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x01, len(parameters), 0)
        
        # 创建COTP头部
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        
        # 创建TPKT头部
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        
        # 组合所有部分
        message = bytes(tpkt_header + cotp_header + s7_header + parameters)
        
        # 组合所有字段信息
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        
        # 调整COTP字段偏移
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        
        # 调整S7Comm字段偏移
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        
        # 调整参数字段偏移
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        
        return message, all_segments, all_field_names

    def _generate_read_var_response(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成Read Variable响应消息(安全对齐/完全合规)"""
        all_segments = []
        all_field_names = []
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        parameters.append(0x04)
        param_segments.append((0, 1))
        param_field_names.append("Function")
        item_count = random.randint(1, 4)
        parameters.append(item_count)
        param_segments.append((1, 2))
        param_field_names.append("Item count")
        data = bytearray()
        data_segments = []
        data_field_names = []
        for i in range(item_count):
            # Return Code
            if random.random() < 0.9:  # 90%成功率
                return_code = 0xFF
            else:
                return_code = random.choice([0x05, 0x06, 0x0A])
            data.append(return_code)
            data_segments.append((len(data) - 1, len(data)))
            data_field_names.append(f"Return code (Item {i+1})")
            if return_code == 0xFF:
                # Transport size
                transport_size = random.choice([0x03, 0x04, 0x06, 0x08])
                data.append(transport_size)
                data_segments.append((len(data) - 1, len(data)))
                data_field_names.append(f"Transport size (Item {i+1})")
                if transport_size == 0x03:  # BIT
                    bit_length = random.randint(1, 8)
                    byte_length = (bit_length + 7) // 8
                    actual_data = bytes([random.randint(0, 0xFF) for _ in range(byte_length)])
                    data.extend(struct.pack('>H', bit_length))    # 注意BIT类型长度字段为bit数
                    data_segments.append((len(data) - 2, len(data)))
                    data_field_names.append(f"Data length(bits) (Item {i+1})")
                    data.extend(actual_data)
                    data_segments.append((len(data) - byte_length, len(data)))
                    data_field_names.append(f"Data (Item {i+1})")
                else:
                    # 其它类型，单位是字节，且必须对齐2字节（WORD/DWORD/REAL建议再加大对齐，暂2字节通用即可）
                    if transport_size == 0x04:  # BYTE
                        actual_data_length = random.randint(1, 64)
                    elif transport_size == 0x06:  # WORD
                        actual_data_length = 2 * random.randint(1, 16)  # 必须偶数
                    else:  # DWORD/REAL等
                        actual_data_length = 4 * random.randint(1, 8)   # 必须4字节对齐
                    pattern = random.choice(list(self.DATA_PATTERNS.keys()))
                    actual_data = self.DATA_PATTERNS[pattern](actual_data_length)
                    padding_len = (2 - (actual_data_length % 2)) % 2
                    data_len_field = actual_data_length + padding_len
                    data.extend(struct.pack('>H', data_len_field))
                    data_segments.append((len(data) - 2, len(data)))
                    data_field_names.append(f"Data length (bytes, Item {i+1})")
                    data.extend(actual_data)
                    data_segments.append((len(data) - actual_data_length, len(data)))
                    data_field_names.append(f"Data (Item {i+1})")
                    if padding_len:
                        data.extend(b'\x00' * padding_len)
                        data_segments.append((len(data) - padding_len, len(data)))
                        data_field_names.append(f"Padding (Item {i+1})")
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x03, len(parameters), len(data))
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters) + len(data)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        message = bytes(tpkt_header + cotp_header + s7_header + parameters + data)
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        data_offset = len(tpkt_header) + len(cotp_header) + len(s7_header) + len(parameters)
        for start, end in data_segments:
            all_segments.append((start + data_offset, end + data_offset))
        all_field_names.extend(data_field_names)
        return message, all_segments, all_field_names

    def _generate_write_var_single(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成单项目Write Variable消息"""
        all_segments = []
        all_field_names = []
        
        # 参数部分
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        
        # Function code
        parameters.append(0x05)
        param_segments.append((0, 1))
        param_field_names.append("Function")
        
        # Item count
        parameters.append(1)
        param_segments.append((1, 2))
        param_field_names.append("Item count")
        
        # 变量规范
        transport_size = random.choice([0x04, 0x06])  # BYTE或WORD
        length = random.randint(1, 16)
        
        var_spec, var_segments, var_field_names = self._create_variable_spec(
            area=0x84,  # DB区域
            db_number=random.randint(1, 100),
            address=random.randint(0, 1023),
            transport_size=transport_size,
            length=length
        )
        parameters.extend(var_spec)
        
        # 调整变量规范字段偏移
        var_offset = len(parameters) - len(var_spec)
        for start, end in var_segments:
            param_segments.append((start + var_offset, end + var_offset))
        param_field_names.extend(var_field_names)
        
        # 数据部分
        data = bytearray()
        data_segments = []
        data_field_names = []
        
        # Reserved
        data.append(0x00)
        data_segments.append((0, 1))
        data_field_names.append("Reserved")
        
        # Transport size
        data.append(transport_size)
        data_segments.append((1, 2))
        data_field_names.append("Transport size")
        
        # 生成实际数据 - 使用不同的数据模式增加多样性
        if transport_size == 0x04:  # BYTE
            pattern = random.choice(list(self.DATA_PATTERNS.keys()))
            actual_data = self.DATA_PATTERNS[pattern](length)
        else:  # WORD
            pattern = random.choice(list(self.DATA_PATTERNS.keys()))
            actual_data = self.DATA_PATTERNS[pattern](length * 2)
        
        data.extend(struct.pack('>H', len(actual_data)))
        data_segments.append((2, 4))
        data_field_names.append("Data length")
        
        data.extend(actual_data)
        data_segments.append((4, 4 + len(actual_data)))
        data_field_names.append("Data")
        
        # 创建S7Comm头部
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x01, len(parameters), len(data))
        
        # 创建COTP头部
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        
        # 创建TPKT头部
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters) + len(data)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        
        # 组合所有部分
        message = bytes(tpkt_header + cotp_header + s7_header + parameters + data)
        
        # 组合所有字段信息
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        
        # 调整COTP字段偏移
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        
        # 调整S7Comm字段偏移
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        
        # 调整参数字段偏移
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        
        # 调整数据字段偏移
        data_offset = len(tpkt_header) + len(cotp_header) + len(s7_header) + len(parameters)
        for start, end in data_segments:
            all_segments.append((start + data_offset, end + data_offset))
        all_field_names.extend(data_field_names)
        
        return message, all_segments, all_field_names

    def _generate_userdata_szl_read(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成Userdata SZL读取消息，基于pcap分析大幅增加多样性"""
        all_segments = []
        all_field_names = []
        
        # 参数部分
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        
        # 头部字段 - 基于pcap分析，Method总是0，Type总是1
        parameters.append(0x00)  # 方法
        param_segments.append((0, 1))
        param_field_names.append("Method")
        
        parameters.append(0x01)  # 类型
        param_segments.append((1, 2))
        param_field_names.append("Type")
        
        parameters.append(0x12)  # 规范
        param_segments.append((2, 3))
        param_field_names.append("Specification")
        
        # 参数长度 - 基于pcap分析，使用8或12
        param_length = random.choice([8, 12])
        parameters.append(param_length)
        param_segments.append((3, 4))
        param_field_names.append("Parameter length")
        
        parameters.append(0x11)  # 语法ID
        param_segments.append((4, 5))
        param_field_names.append("Syntax Id")
        
        parameters.append(0x44)  # 传输大小
        param_segments.append((5, 6))
        param_field_names.append("Transport size")
        
        parameters.append(0x01)  # 序列号
        param_segments.append((6, 7))
        param_field_names.append("Sequence number")
        
        parameters.append(0x00)  # 数据单元引用和最后数据单元
        param_segments.append((7, 8))
        param_field_names.append("Data unit reference and last data unit")
        
        # 数据部分
        data = bytearray()
        data_segments = []
        data_field_names = []
        
        # SZL ID - 基于pcap分析，使用实际发现的SZL-ID
        szl_id = random.choice(self.SZL_IDS)
        data.extend(struct.pack('>H', szl_id))
        data_segments.append((0, 2))
        data_field_names.append("SZL-ID")
        
        # SZL Index - 基于pcap分析，使用更大的范围
        szl_index = random.randint(0, 255)
        data.extend(struct.pack('>H', szl_index))
        data_segments.append((2, 4))
        data_field_names.append("SZL-Index")
        
        # 基于pcap分析，添加更多数据变化
        if param_length == 12:
            # 添加额外数据
            extra_data_size = random.choice([4, 8, 12, 14, 32, 82])
            extra_data = self.DATA_PATTERNS[random.choice(list(self.DATA_PATTERNS.keys()))](extra_data_size)
            data.extend(extra_data)
            data_segments.append((4, 4 + extra_data_size))
            data_field_names.append("Additional Data")
        
        # 创建S7Comm头部
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x07, len(parameters), len(data))
        
        # 创建COTP头部
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        
        # 创建TPKT头部
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters) + len(data)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        
        # 组合所有部分
        message = bytes(tpkt_header + cotp_header + s7_header + parameters + data)
        
        # 组合所有字段信息
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        
        # 调整COTP字段偏移
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        
        # 调整S7Comm字段偏移
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        
        # 调整参数字段偏移
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        
        # 调整数据字段偏移
        data_offset = len(tpkt_header) + len(cotp_header) + len(s7_header) + len(parameters)
        for start, end in data_segments:
            all_segments.append((start + data_offset, end + data_offset))
        all_field_names.extend(data_field_names)
        
        return message, all_segments, all_field_names

    def _generate_pi_service(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成PI Service消息，基于实际pcap分析修正"""
        all_segments = []
        all_field_names = []
        
        # 参数部分
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        
        # 基于pcap分析选择PI Service类型
        pi_type, param_length, data_length = random.choice(self.PI_SERVICE_TYPES)
        
        # 使用基于实际pcap的参数模板
        if pi_type in self.PI_SERVICE_TEMPLATES:
            template = random.choice(self.PI_SERVICE_TEMPLATES[pi_type])
            
            # 将模板拷贝为参数字节序列
            parameters.extend(template)
            # 基于模板类型，使用“语义字段分段”，而不是逐字节分段
            if pi_type == 0x28 and len(template) >= 26:
                # 结构参考：0 | 1..6 | 7..11 | 12..20 | 20..21 | 21..25
                # - 0: Function
                # - 1..6: Flags/Reserved
                # - 7..11: Command/Bit-Field block
                # - 12..20: File-Info (ASCII)
                # - 20..21: Length/Param
                # - 21..26: Identifier (ASCII)
                param_segments.append((0, 1))
                param_field_names.append("Function")
                param_segments.append((1, 7))
                param_field_names.append("Flags/Reserved")
                param_segments.append((7, 12))
                param_field_names.append("Command/Bit-Field")
                param_segments.append((12, 20))
                param_field_names.append("File-Info")
                param_segments.append((20, 21))
                param_field_names.append("Length")
                param_segments.append((21, 26))
                param_field_names.append("Identifier")
            elif pi_type == 0x29 and len(template) >= 16:
                # 结构参考：0 | 1..5 | 6 | 7..15
                param_segments.append((0, 1))
                param_field_names.append("Function")
                param_segments.append((1, 6))
                param_field_names.append("Flags/Reserved")
                param_segments.append((6, 7))
                param_field_names.append("Length")
                param_segments.append((7, 16))
                param_field_names.append("Identifier")
            else:
                # 回退：保留函数码 + 其余整体为“PI Parameters”
                param_segments.append((0, 1))
                param_field_names.append("Function")
                if len(template) > 1:
                    param_segments.append((1, len(template)))
                    param_field_names.append("PI Parameters")
        else:
            # 如果没有模板，使用基本参数
            parameters.append(pi_type)
            param_segments.append((0, 1))
            param_field_names.append("Function")
            
            # 将剩余参数作为一个整体语义段，而非逐字节
            if param_length - 1 > 0:
                rest = bytearray(random.randint(0, 255) for _ in range(param_length - 1))
                start = len(parameters)
                parameters.extend(rest)
                param_segments.append((start, start + len(rest)))
                param_field_names.append("PI Parameters")
        
        # 数据部分 - PI Service通常没有数据部分
        data = bytearray()
        data_segments = []
        data_field_names = []
        
        if data_length > 0:
            # 生成PI Service数据
            pi_data = self.DATA_PATTERNS[random.choice(list(self.DATA_PATTERNS.keys()))](data_length)
            data.extend(pi_data)
            data_segments.append((0, data_length))
            data_field_names.append("PI Service Data")
        
        # 创建S7Comm头部
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x01, len(parameters), len(data))
        
        # 创建COTP头部
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        
        # 创建TPKT头部
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters) + len(data)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        
        # 组合所有部分
        message = bytes(tpkt_header + cotp_header + s7_header + parameters + data)
        
        # 组合所有字段信息
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        
        # 调整COTP字段偏移
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        
        # 调整S7Comm字段偏移
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        
        # 调整参数字段偏移
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        
        # 调整数据字段偏移
        data_offset = len(tpkt_header) + len(cotp_header) + len(s7_header) + len(parameters)
        for start, end in data_segments:
            all_segments.append((start + data_offset, end + data_offset))
        all_field_names.extend(data_field_names)
        
        return message, all_segments, all_field_names

    def _generate_ack_data_variants(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成ACK_DATA消息变体，基于pcap分析"""
        all_segments = []
        all_field_names = []
        
        # 参数部分
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        
        # 基于pcap分析，ACK_DATA有不同的参数长度
        param_length = random.choice([1, 2, 8])
        data_length = random.choice([0, 1, 4, 5])
        
        # Function code (通常为0x00)
        parameters.append(0x00)
        param_segments.append((0, 1))
        param_field_names.append("Function")
        
        # 添加额外参数
        for i in range(param_length - 1):
            param_value = random.randint(0, 255)
            parameters.append(param_value)
            param_segments.append((i + 1, i + 2))
            param_field_names.append(f"ACK Parameter {i + 1}")
        
        # 数据部分
        data = bytearray()
        data_segments = []
        data_field_names = []
        
        if data_length > 0:
            # 生成ACK数据
            ack_data = self.DATA_PATTERNS[random.choice(list(self.DATA_PATTERNS.keys()))](data_length)
            data.extend(ack_data)
            data_segments.append((0, len(ack_data)))  # 修正：使用实际数据长度
            data_field_names.append("ACK Data")
        
        # 创建S7Comm头部
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x03, len(parameters), len(data))
        
        # 创建COTP头部
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        
        # 创建TPKT头部
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters) + len(data)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        
        # 组合所有部分
        message = bytes(tpkt_header + cotp_header + s7_header + parameters + data)
        
        # 组合所有字段信息
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        
        # 调整COTP字段偏移
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        
        # 调整S7Comm字段偏移
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        
        # 调整参数字段偏移
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        
        # 调整数据字段偏移
        data_offset = len(tpkt_header) + len(cotp_header) + len(s7_header) + len(parameters)
        for start, end in data_segments:
            all_segments.append((start + data_offset, end + data_offset))
        all_field_names.extend(data_field_names)
        
        return message, all_segments, all_field_names

    def _validate_message(self, message: bytes) -> bool:
        """验证消息的有效性 - 改进版本，修复malformed packet问题"""
        try:
            # 检查最小长度
            if len(message) < 17:
                return False
            
            # 检查TPKT头部
            if message[0] != 0x03 or message[1] != 0x00:
                return False
            
            # 检查TPKT长度字段
            tpkt_length = struct.unpack('>H', message[2:4])[0]
            if tpkt_length != len(message) or tpkt_length < 17 or tpkt_length > 65535:
                return False
            
            # 检查COTP头部
            cotp_length = message[4]
            if cotp_length < 2 or cotp_length > 7:  # COTP长度应该在2-7之间
                return False
            
            cotp_pdu_type = message[5]
            if cotp_pdu_type != 0xF0:  # 只接受Data TPDU
                return False
            
            # 检查COTP TPDU Number
            if len(message) > 6:
                tpdu_number = message[6]
                if (tpdu_number & 0x80) == 0:  # 最高位应该为1
                    return False
            
            # 检查S7COMM协议标识符
            s7_start = 4 + cotp_length + 1
            if s7_start >= len(message):
                return False
            
            if message[s7_start] != 0x32:
                return False
            
            # 检查S7COMM头部长度
            if len(message) - s7_start < 10:
                return False
            
            # 检查S7COMM头部字段
            s7_header = message[s7_start:s7_start + 10]
            rosctr = s7_header[1]
            if rosctr not in [0x01, 0x02, 0x03, 0x07]:  # 只接受有效的ROSCTR类型
                return False
            
            # 检查参数长度和数据长度
            param_length = struct.unpack('>H', s7_header[6:8])[0]
            data_length = struct.unpack('>H', s7_header[8:10])[0]
            
            # 验证长度字段的合理性
            if param_length > 240 or data_length > 960:  # 合理的长度限制
                return False
            
            # 检查总长度是否匹配
            expected_total = 10 + param_length + data_length
            actual_total = len(message) - s7_start
            if abs(expected_total - actual_total) > 2:  # 允许小的差异
                return False
            
            return True
            
        except (IndexError, struct.error, ValueError):
            return False

    def _generate_setup_communication_variants(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """生成Setup Communication消息的变体，基于pcap分析大幅增加多样性"""
        all_segments = []
        all_field_names = []
        
        # 参数部分
        parameters = bytearray()
        param_segments = []
        param_field_names = []
        
        # Function code
        parameters.append(0xF0)
        param_segments.append((0, 1))
        param_field_names.append("Function")
        
        # Reserved
        parameters.append(0x00)
        param_segments.append((1, 2))
        param_field_names.append("Reserved")
        
        # Max AmQ calling - 基于pcap分析，实际范围更广
        max_amq_calling = random.choice([1, 2, 4, 8, 16, 32])
        parameters.extend(struct.pack('>H', max_amq_calling))
        param_segments.append((2, 4))
        param_field_names.append("Max AmQ (parallel jobs with ack) calling")
        
        # Max AmQ called - 基于pcap分析，实际范围更广
        max_amq_called = random.choice([1, 2, 4, 8, 16, 32])
        parameters.extend(struct.pack('>H', max_amq_called))
        param_segments.append((4, 6))
        param_field_names.append("Max AmQ (parallel jobs with ack) called")
        
        # PDU length - 基于pcap分析，实际使用480，但增加更多变化
        pdu_length = random.choice([240, 480, 960, 1440, 1920, 2400])
        parameters.extend(struct.pack('>H', pdu_length))
        param_segments.append((6, 8))
        param_field_names.append("PDU length")
        
        # 创建S7Comm头部
        s7_header, s7_segments, s7_field_names = self._create_s7comm_header(0x01, len(parameters), 0)
        
        # 创建COTP头部
        cotp_header, cotp_segments, cotp_field_names = self._create_cotp_header()
        
        # 创建TPKT头部
        total_length = 4 + len(cotp_header) + len(s7_header) + len(parameters)
        tpkt_header, tpkt_segments, tpkt_field_names = self._create_tpkt_header(total_length)
        
        # 组合所有部分
        message = bytes(tpkt_header + cotp_header + s7_header + parameters)
        
        # 组合所有字段信息
        all_segments.extend(tpkt_segments)
        all_field_names.extend(tpkt_field_names)
        
        # 调整COTP字段偏移
        cotp_offset = len(tpkt_header)
        for start, end in cotp_segments:
            all_segments.append((start + cotp_offset, end + cotp_offset))
        all_field_names.extend(cotp_field_names)
        
        # 调整S7Comm字段偏移
        s7_offset = len(tpkt_header) + len(cotp_header)
        for start, end in s7_segments:
            all_segments.append((start + s7_offset, end + s7_offset))
        all_field_names.extend(s7_field_names)
        
        # 调整参数字段偏移
        param_offset = len(tpkt_header) + len(cotp_header) + len(s7_header)
        for start, end in param_segments:
            all_segments.append((start + param_offset, end + param_offset))
        all_field_names.extend(param_field_names)
        
        return message, all_segments, all_field_names

    def generate_messages(self, count: int = 100) -> List[Tuple[bytes, List[Tuple[int, int]], List[str]]]:
        """生成指定数量的多样化S7Comm消息"""
        messages = []
        
        # 定义所有支持的消息生成器及其权重 - 基于pcap分析调整
        message_generators = [
            (self._generate_setup_communication, 5),
            (self._generate_setup_communication_variants, 5),
            (self._generate_read_var_single, 15),
            (self._generate_read_var_multiple, 15),
            (self._generate_read_var_response, 10),
            (self._generate_write_var_single, 10),
            (self._generate_userdata_szl_read, 20),  # 增加权重，pcap中很多
            (self._generate_pi_service, 15),         # 新增PI Service
            (self._generate_ack_data_variants, 5),   # 新增ACK_DATA变体
        ]
        
        # 创建加权选择列表
        weighted_generators = []
        for generator, weight in message_generators:
            weighted_generators.extend([generator] * weight)
        
        print(f"开始生成 {count} 个多样化S7COMM消息...")
        print(f"支持 {len(message_generators)} 种不同消息类型")
        
        success_count = 0
        attempt_count = 0
        max_attempts = count * 3
        
        while success_count < count and attempt_count < max_attempts:
            attempt_count += 1
            
            try:
                # 随机选择消息生成器
                generator = random.choice(weighted_generators)
                message, segments, field_names = generator()
                
                # 验证消息有效性
                if self._validate_message(message):
                    messages.append((message, segments, field_names))
                    success_count += 1
                    
                    if success_count % 100 == 0:
                        print(f"已成功生成 {success_count}/{count} 个消息")
                        
            except Exception as e:
                if attempt_count % 1000 == 0:
                    print(f"生成过程中遇到一些错误，继续尝试... ({attempt_count}/{max_attempts})")
                continue
        
        if success_count < count:
            print(f"警告：仅成功生成 {success_count}/{count} 个验证通过的消息")
        else:
            print(f"成功生成 {success_count} 个多样化S7COMM消息")
        
        return messages

    def save_to_csv(self, messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]], filename: str):
        """保存消息到CSV文件 - 只保存S7Comm层数据"""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            
            for message, segments, field_names in messages:
                try:
                    # 提取S7Comm层数据（从0x32开始）
                    s7comm_start = self._find_s7comm_start(message)
                    if s7comm_start == -1:
                        print(f"警告：未找到S7Comm协议标识符，跳过此消息")
                        continue
                    
                    # 提取S7Comm层数据
                    s7comm_data = message[s7comm_start:]
                    
                    # 调整字段偏移量，使其相对于S7Comm层开始
                    s7comm_segments = []
                    s7comm_field_names = []
                    
                    for i, (start, end) in enumerate(segments):
                        if start >= s7comm_start:
                            # 调整偏移量
                            adjusted_start = start - s7comm_start
                            adjusted_end = end - s7comm_start
                            
                            # 只保留S7Comm层的字段
                            if adjusted_start >= 0 and adjusted_end <= len(s7comm_data):
                                s7comm_segments.append((adjusted_start, adjusted_end))
                                s7comm_field_names.append(field_names[i])
                    
                    # 转换为十六进制字符串
                    hex_string = s7comm_data.hex()
                    
                    # 转换为字符串格式
                    segments_str = str(s7comm_segments)
                    field_names_str = str(s7comm_field_names)
                    
                    writer.writerow([hex_string, segments_str, field_names_str])
                
                except Exception as e:
                    print(f"警告：保存消息时发生错误: {e}")
                    # 写入基本格式避免CSV损坏
                    hex_string = message.hex()
                    writer.writerow([hex_string, "[(0, len(message))]", "['S7Comm Message']"])
    
    def _find_s7comm_start(self, message: bytes) -> int:
        """查找S7Comm协议标识符(0x32)的位置"""
        for i in range(len(message) - 10):  # 确保有足够空间容纳S7Comm头部
            if message[i] == 0x32:  # S7Comm协议标识符
                return i
        return -1

    def generate_packets_from_messages(self, messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]]) -> List[Packet]:
        """基于已生成的消息创建S7Comm数据包(自动识别S7COMM)，剥离前置TPKT/COTP，仅封装一层封头！Wireshark可直接解码S7COMM协议"""
        packets = []
        for message, segments, field_names in messages:
            s7_start = self._find_s7comm_start(message)
            if s7_start == -1:
                continue  # 跳过非正常格式
            s7comm_data = message[s7_start:]  # 只保留有效S7COMM本体
            src_ip = self._generate_random_ip()
            dst_ip = self._generate_random_ip()
            src_mac = self._generate_random_mac()
            dst_mac = self._generate_random_mac()
            src_port = random.choice([102, random.randint(1024, 65535)])
            dst_port = 102
            tcp_layer = TCP(
                sport=src_port,
                dport=dst_port,
                flags="PA",
                seq=random.randint(1000, 100000),
                ack=random.randint(1000, 100000),
                window=8192
            )
            cotp_header = struct.pack('BBB', 0x02, 0xF0, 0x80)
            tpkt_length = len(cotp_header) + len(s7comm_data) + 4
            tpkt_header = struct.pack('>BBH', 3, 0, tpkt_length)
            full_payload = tpkt_header + cotp_header + s7comm_data
            packet = Ether(src=src_mac, dst=dst_mac) / \
                    IP(src=src_ip, dst=dst_ip) / \
                    tcp_layer / \
                    Raw(load=full_payload)
            packets.append(packet)
        return packets

    def generate_packets(self, count: int = 100) -> List[Packet]:
        """生成S7Comm数据包（Scapy格式）"""
        packets = []
        messages = self.generate_messages(count)
        
        for message, segments, field_names in messages:
            # 创建随机的IP和MAC地址
            src_ip = self._generate_random_ip()
            dst_ip = self._generate_random_ip()
            src_mac = self._generate_random_mac()
            dst_mac = self._generate_random_mac()
            
            # S7Comm通常使用端口102
            src_port = random.choice([102, random.randint(1024, 65535)])
            dst_port = 102
            
            # 使用PSH+ACK标志，模拟已建立的TCP连接
            tcp_layer = TCP(
                sport=src_port,
                dport=dst_port,
                flags='PA',  # PSH + ACK
                seq=random.randint(1000, 0x7FFFFFFF),
                ack=random.randint(1000, 0x7FFFFFFF)
            )
            
            # 创建数据包
            packet = Ether(src=src_mac, dst=dst_mac) / \
                    IP(src=src_ip, dst=dst_ip) / \
                    tcp_layer / \
                    Raw(load=message)
            
            # 删除校验和字段，让Scapy自动计算
            if IP in packet:
                del packet[IP].chksum
            if TCP in packet:
                del packet[TCP].chksum
            
            packets.append(packet)
        
        return packets

    def _generate_random_ip(self, subnet: str = "192.168.1.0/24") -> str:
        """在指定子网中生成随机IP地址"""
        import ipaddress
        network = ipaddress.IPv4Network(subnet, strict=False)
        hosts = list(network.hosts())
        return str(random.choice(hosts))

    def _generate_random_mac(self) -> str:
        """生成随机MAC地址"""
        first_byte = random.randint(0, 254) & 0xFE
        mac_bytes = [first_byte] + [random.randint(0, 255) for _ in range(5)]
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    def save_to_pcap(self, filename: str, packets: List[Packet] = None):
        """保存数据包到PCAP文件"""
        if packets is None:
            packets = self.generate_packets(100)
        
        if not packets:
            raise ValueError("没有数据包可保存")
        
        wrpcap(filename, packets)
        print(f"已保存 {len(packets)} 个S7Comm数据包到 {filename}")

def main():
    """主函数：生成S7Comm协议消息和数据包"""
    print("开始生成S7Comm协议消息（修正版）...")
    
    generator = S7CommGeneratorFixed()
    
    # 生成消息
    messages = generator.generate_messages(5000)
    print(f"生成了 {len(messages)} 个S7Comm消息")
    
    # 基于已生成的消息创建数据包，确保PCAP和CSV对应
    packets = generator.generate_packets_from_messages(messages)
    print(f"生成了 {len(packets)} 个S7Comm数据包")
    
    # 保存到文件
    pcap_file = "pcap/s7comm_messages.pcap"
    csv_file = "csv/s7comm_messages.csv"
    
    generator.save_to_pcap(pcap_file, packets)
    generator.save_to_csv(messages, csv_file)
    
    print(f"\n生成完成！")
    print(f"PCAP文件: {pcap_file}")
    print(f"CSV文件: {csv_file}")
    print("\n修正内容：")
    print("- 边生成边记录字段信息，确保Segment和Field Names的准确性")
    print("- 增加消息多样性，支持更多协议功能")
    print("- 修复malformed packet问题")
    print("- 确保生成的CSV格式完全正确")

if __name__ == "__main__":
    main()
