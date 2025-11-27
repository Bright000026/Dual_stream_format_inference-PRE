#!/usr/bin/env python3
"""
HART/IP协议消息生成器
基于HART/IP协议规范实现，生成符合标准的HART/IP消息
支持多种消息类型：Session Initiate, Pass Through, Keep Alive等
"""

import random
import struct
import csv
import secrets
from typing import List, Tuple, Dict, Any
import datetime
import argparse
from scapy.all import IP, UDP, Ether, wrpcap, Packet, Raw
import os

class HartIpGenerator:
    def __init__(self):
        # HART/IP协议常量
        self.HART_IP_VERSION = 1
        self.HART_IP_PORT = 5094
        
        # 消息类型
        self.MESSAGE_TYPES = {
            0x00: "Request",
            0x01: "Response"
        }
        
        # 消息ID类型
        self.MESSAGE_IDS = {
            0x00: "Session Initiate",
            0x01: "Session Close", 
            0x02: "Keep Alive",
            0x03: "Pass Through"
        }
        
        # 状态码
        self.STATUS_CODES = {
            0x00: "Success",
            0x01: "Invalid Message",
            0x02: "Session Not Found",
            0x03: "Session Already Exists",
            0x04: "Invalid Sequence Number",
            0x05: "Session Timeout"
        }
        
        # HART命令码
        self.HART_COMMANDS = {
            0x00: "Read Primary Variable",
            0x01: "Read Loop Current and Percent of Range",
            0x02: "Read Dynamic Variables and Loop Current",
            0x03: "Read Device Variables",
            0x06: "Write Polling Address",
            0x07: "Read Unique Identifier",
            0x08: "Read Message",
            0x09: "Read Tag, Descriptor, Date",
            0x0B: "Read Unique Identifier Associated with Tag",
            0x0C: "Read Message (2)",
            0x0D: "Read Tag, Descriptor, Date (2)",
            0x0E: "Read Primary Variable Information",
            0x0F: "Read Device Information",
            0x11: "Read Unique Identifier",
            0x12: "Read Message (3)",
            0x13: "Read Tag, Descriptor, Date (3)",
            0x14: "Read Primary Variable Information (2)",
            0x15: "Read Device Information (2)",
            0x16: "Read Device Variables with Status",
            0x17: "Read Device Configuration",
            0x18: "Read Device Variables with Status (2)",
            0x19: "Read Device Configuration (2)",
            0x1A: "Read Device Variables with Status (3)",
            0x1B: "Read Device Configuration (3)",
            0x1C: "Read Device Variables with Status (4)",
            0x1D: "Read Device Configuration (4)",
            0x1E: "Read Device Variables with Status (5)",
            0x1F: "Read Device Configuration (5)",
            0x20: "Read Long Tag",
            0x21: "Read Long Tag (2)",
            0x22: "Read Long Tag (3)",
            0x23: "Read Long Tag (4)",
            0x24: "Read Long Tag (5)",
            0x25: "Read Long Tag (6)",
            0x26: "Read Long Tag (7)",
            0x27: "Read Long Tag (8)",
            0x28: "Read Long Tag (9)",
            0x29: "Read Long Tag (10)",
            0x2A: "Read Long Tag (11)",
            0x2B: "Read Long Tag (12)",
            0x2C: "Read Long Tag (13)",
            0x2D: "Read Long Tag (14)",
            0x2E: "Read Long Tag (15)",
            0x2F: "Read Long Tag (16)",
            0x30: "Read Long Tag (17)",
            0x31: "Read Long Tag (18)",
            0x32: "Read Long Tag (19)",
            0x33: "Read Long Tag (20)",
            0x34: "Read Long Tag (21)",
            0x35: "Read Long Tag (22)",
            0x36: "Read Long Tag (23)",
            0x37: "Read Long Tag (24)",
            0x38: "Read Long Tag (25)",
            0x39: "Read Long Tag (26)",
            0x3A: "Read Long Tag (27)",
            0x3B: "Read Long Tag (28)",
            0x3C: "Read Long Tag (29)",
            0x3D: "Read Long Tag (30)",
            0x3E: "Read Long Tag (31)",
            0x3F: "Read Long Tag (32)",
            0x40: "Read Long Tag (33)",
            0x41: "Read Long Tag (34)",
            0x42: "Read Long Tag (35)",
            0x43: "Read Long Tag (36)",
            0x44: "Read Long Tag (37)",
            0x45: "Read Long Tag (38)",
            0x46: "Read Long Tag (39)",
            0x47: "Read Long Tag (40)",
            0x48: "Read Long Tag (41)",
            0x49: "Read Long Tag (42)",
            0x4A: "Read Long Tag (43)",
            0x4B: "Read Long Tag (44)",
            0x4C: "Read Long Tag (45)",
            0x4D: "Read Long Tag (46)",
            0x4E: "Read Long Tag (47)",
            0x4F: "Read Long Tag (48)",
            0x50: "Read Long Tag (49)",
            0x51: "Read Long Tag (50)",
            0x52: "Read Long Tag (51)",
            0x53: "Read Long Tag (52)",
            0x54: "Read Long Tag (53)",
            0x55: "Read Long Tag (54)",
            0x56: "Read Long Tag (55)",
            0x57: "Read Long Tag (56)",
            0x58: "Read Long Tag (57)",
            0x59: "Read Long Tag (58)",
            0x5A: "Read Long Tag (59)",
            0x5B: "Read Long Tag (60)",
            0x5C: "Read Long Tag (61)",
            0x5D: "Read Long Tag (62)",
            0x5E: "Read Long Tag (63)",
            0x5F: "Read Long Tag (64)",
            0x60: "Read Long Tag (65)",
            0x61: "Read Long Tag (66)",
            0x62: "Read Long Tag (67)",
            0x63: "Read Long Tag (68)",
            0x64: "Read Long Tag (69)",
            0x65: "Read Long Tag (70)",
            0x66: "Read Long Tag (71)",
            0x67: "Read Long Tag (72)",
            0x68: "Read Long Tag (73)",
            0x69: "Read Long Tag (74)",
            0x6A: "Read Long Tag (75)",
            0x6B: "Read Long Tag (76)",
            0x6C: "Read Long Tag (77)",
            0x6D: "Read Long Tag (78)",
            0x6E: "Read Long Tag (79)",
            0x6F: "Read Long Tag (80)",
            0x70: "Read Long Tag (81)",
            0x71: "Read Long Tag (82)",
            0x72: "Read Long Tag (83)",
            0x73: "Read Long Tag (84)",
            0x74: "Read Long Tag (85)",
            0x75: "Read Long Tag (86)",
            0x76: "Read Long Tag (87)",
            0x77: "Read Long Tag (88)",
            0x78: "Read Long Tag (89)",
            0x79: "Read Long Tag (90)",
            0x7A: "Read Long Tag (91)",
            0x7B: "Read Long Tag (92)",
            0x7C: "Read Long Tag (93)",
            0x7D: "Read Long Tag (94)",
            0x7E: "Read Long Tag (95)",
            0x7F: "Read Long Tag (96)",
            0x80: "Read Long Tag (97)",
            0x81: "Read Long Tag (98)",
            0x82: "Read Long Tag (99)",
            0x83: "Read Long Tag (100)",
            0x84: "Read Long Tag (101)",
            0x85: "Read Long Tag (102)",
            0x86: "Read Long Tag (103)",
            0x87: "Read Long Tag (104)",
            0x88: "Read Long Tag (105)",
            0x89: "Read Long Tag (106)",
            0x8A: "Read Long Tag (107)",
            0x8B: "Read Long Tag (108)",
            0x8C: "Read Long Tag (109)",
            0x8D: "Read Long Tag (110)",
            0x8E: "Read Long Tag (111)",
            0x8F: "Read Long Tag (112)",
            0x90: "Read Long Tag (113)",
            0x91: "Read Long Tag (114)",
            0x92: "Read Long Tag (115)",
            0x93: "Read Long Tag (116)",
            0x94: "Read Long Tag (117)",
            0x95: "Read Long Tag (118)",
            0x96: "Read Long Tag (119)",
            0x97: "Read Long Tag (120)",
            0x98: "Read Long Tag (121)",
            0x99: "Read Long Tag (122)",
            0x9A: "Read Long Tag (123)",
            0x9B: "Read Long Tag (124)",
            0x9C: "Read Long Tag (125)",
            0x9D: "Read Long Tag (126)",
            0x9E: "Read Long Tag (127)",
            0x9F: "Read Long Tag (128)",
            0xA0: "Read Long Tag (129)",
            0xA1: "Read Long Tag (130)",
            0xA2: "Read Long Tag (131)",
            0xA3: "Read Long Tag (132)",
            0xA4: "Read Long Tag (133)",
            0xA5: "Read Long Tag (134)",
            0xA6: "Read Long Tag (135)",
            0xA7: "Read Long Tag (136)",
            0xA8: "Read Long Tag (137)",
            0xA9: "Read Long Tag (138)",
            0xAA: "Read Long Tag (139)",
            0xAB: "Read Long Tag (140)",
            0xAC: "Read Long Tag (141)",
            0xAD: "Read Long Tag (142)",
            0xAE: "Read Long Tag (143)",
            0xAF: "Read Long Tag (144)",
            0xB0: "Read Long Tag (145)",
            0xB1: "Read Long Tag (146)",
            0xB2: "Read Long Tag (147)",
            0xB3: "Read Long Tag (148)",
            0xB4: "Read Long Tag (149)",
            0xB5: "Read Long Tag (150)",
            0xB6: "Read Long Tag (151)",
            0xB7: "Read Long Tag (152)",
            0xB8: "Read Long Tag (153)",
            0xB9: "Read Long Tag (154)",
            0xBA: "Read Long Tag (155)",
            0xBB: "Read Long Tag (156)",
            0xBC: "Read Long Tag (157)",
            0xBD: "Read Long Tag (158)",
            0xBE: "Read Long Tag (159)",
            0xBF: "Read Long Tag (160)",
            0xC0: "Read Long Tag (161)",
            0xC1: "Read Long Tag (162)",
            0xC2: "Read Long Tag (163)",
            0xC3: "Read Long Tag (164)",
            0xC4: "Read Long Tag (165)",
            0xC5: "Read Long Tag (166)",
            0xC6: "Read Long Tag (167)",
            0xC7: "Read Long Tag (168)",
            0xC8: "Read Long Tag (169)",
            0xC9: "Read Long Tag (170)",
            0xCA: "Read Long Tag (171)",
            0xCB: "Read Long Tag (172)",
            0xCC: "Read Long Tag (173)",
            0xCD: "Read Long Tag (174)",
            0xCE: "Read Long Tag (175)",
            0xCF: "Read Long Tag (176)",
            0xD0: "Read Long Tag (177)",
            0xD1: "Read Long Tag (178)",
            0xD2: "Read Long Tag (179)",
            0xD3: "Read Long Tag (180)",
            0xD4: "Read Long Tag (181)",
            0xD5: "Read Long Tag (182)",
            0xD6: "Read Long Tag (183)",
            0xD7: "Read Long Tag (184)",
            0xD8: "Read Long Tag (185)",
            0xD9: "Read Long Tag (186)",
            0xDA: "Read Long Tag (187)",
            0xDB: "Read Long Tag (188)",
            0xDC: "Read Long Tag (189)",
            0xDD: "Read Long Tag (190)",
            0xDE: "Read Long Tag (191)",
            0xDF: "Read Long Tag (192)",
            0xE0: "Read Long Tag (193)",
            0xE1: "Read Long Tag (194)",
            0xE2: "Read Long Tag (195)",
            0xE3: "Read Long Tag (196)",
            0xE4: "Read Long Tag (197)",
            0xE5: "Read Long Tag (198)",
            0xE6: "Read Long Tag (199)",
            0xE7: "Read Long Tag (200)",
            0xE8: "Read Long Tag (201)",
            0xE9: "Read Long Tag (202)",
            0xEA: "Read Long Tag (203)",
            0xEB: "Read Long Tag (204)",
            0xEC: "Read Long Tag (205)",
            0xED: "Read Long Tag (206)",
            0xEE: "Read Long Tag (207)",
            0xEF: "Read Long Tag (208)",
            0xF0: "Read Long Tag (209)",
            0xF1: "Read Long Tag (210)",
            0xF2: "Read Long Tag (211)",
            0xF3: "Read Long Tag (212)",
            0xF4: "Read Long Tag (213)",
            0xF5: "Read Long Tag (214)",
            0xF6: "Read Long Tag (215)",
            0xF7: "Read Long Tag (216)",
            0xF8: "Read Long Tag (217)",
            0xF9: "Read Long Tag (218)",
            0xFA: "Read Long Tag (219)",
            0xFB: "Read Long Tag (220)",
            0xFC: "Read Long Tag (221)",
            0xFD: "Read Long Tag (222)",
            0xFE: "Read Long Tag (223)",
            0xFF: "Read Long Tag (224)"
        }
        
        # 字段范围配置
        self.FIELD_RANGES = {
            'sequence_number': (1, 0xFFFF),
            'message_length': (8, 1024),
            'host_type': (1, 2),
            'inactivity_timer': (1000, 300000),
            'hart_address': (0, 0xFFFFFFFF),
            'hart_command': (0, 255),
            'hart_length': (0, 255)
        }
        
        # 输出目录
        self.output_dir_csv = "csv"
        self.output_dir_pcap = "pcap"
        os.makedirs(self.output_dir_csv, exist_ok=True)
        os.makedirs(self.output_dir_pcap, exist_ok=True)
        
        # 序列号计数器
        self.sequence_counter = 1
        
    def _rand_mac(self):
        """生成随机MAC地址"""
        return ':'.join(['%02x' % random.randint(0x00, 0xff) for _ in range(6)])
    
    def _rand_ip(self):
        """生成随机IP地址"""
        return '.'.join(str(random.randint(0, 255)) for _ in range(4))
    
    def _calculate_checksum(self, data: bytes) -> int:
        """计算HART帧校验和"""
        checksum = 0
        for byte in data:
            checksum ^= byte
        return checksum & 0xFF
    
    def _build_hart_ip_header(self, message_type: int, message_id: int, 
                             status: int = 0, sequence_number: int = None,
                             message_length: int = 8) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建HART/IP头部"""
        header = bytearray()
        segments = []
        field_names = []
        
        # Version (1 byte)
        header.append(self.HART_IP_VERSION)
        segments.append((0, 1))
        field_names.append("Version")
        
        # Message Type (1 byte)
        header.append(message_type)
        segments.append((1, 2))
        field_names.append("Message_Type")
        
        # Message ID (1 byte)
        header.append(message_id)
        segments.append((2, 3))
        field_names.append("Message_ID")
        
        # Status (1 byte)
        header.append(status)
        segments.append((3, 4))
        field_names.append("Status")
        
        # Sequence Number (2 bytes)
        if sequence_number is None:
            sequence_number = self.sequence_counter
            self.sequence_counter = (self.sequence_counter + 1) % 65536
        header.extend(struct.pack('>H', sequence_number))
        segments.append((4, 6))
        field_names.append("Sequence_Number")
        
        # Message Length (2 bytes)
        header.extend(struct.pack('>H', message_length))
        segments.append((6, 8))
        field_names.append("Message_Length")
        
        return bytes(header), segments, field_names
    
    def _build_session_initiate_request(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建Session Initiate Request消息"""
        # HART/IP头部
        header, header_segments, header_names = self._build_hart_ip_header(
            message_type=0x00,  # Request
            message_id=0x00,    # Session Initiate
            message_length=13
        )
        
        # 消息体
        body = bytearray()
        body_segments = []
        body_names = []
        
        # Host Type (1 byte)
        host_type = random.choice([1, 2])  # Primary Host or Secondary Host
        body.append(host_type)
        body_segments.append((8, 9))
        body_names.append("Host_Type")
        
        # Inactivity Close Timer (4 bytes)
        timer = random.randint(10000, 300000)  # 10-300 seconds
        body.extend(struct.pack('>I', timer))
        body_segments.append((9, 13))
        body_names.append("Inactivity_Timer")
        
        # 合并头部和消息体
        full_message = header + body
        
        # 调整消息体字段的偏移量
        for i, (start, end) in enumerate(body_segments):
            body_segments[i] = (start, end)
        
        # 合并所有字段信息
        all_segments = header_segments + body_segments
        all_names = header_names + body_names
        
        return full_message, all_segments, all_names
    
    def _build_session_initiate_response(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建Session Initiate Response消息"""
        # HART/IP头部
        header, header_segments, header_names = self._build_hart_ip_header(
            message_type=0x01,  # Response
            message_id=0x00,    # Session Initiate
            message_length=13
        )
        
        # 消息体
        body = bytearray()
        body_segments = []
        body_names = []
        
        # Host Type (1 byte)
        host_type = random.choice([1, 2])
        body.append(host_type)
        body_segments.append((8, 9))
        body_names.append("Host_Type")
        
        # Inactivity Close Timer (4 bytes)
        timer = random.randint(10000, 300000)
        body.extend(struct.pack('>I', timer))
        body_segments.append((9, 13))
        body_names.append("Inactivity_Timer")
        
        # 合并头部和消息体
        full_message = header + body
        
        # 调整消息体字段的偏移量
        for i, (start, end) in enumerate(body_segments):
            body_segments[i] = (start, end)
        
        # 合并所有字段信息
        all_segments = header_segments + body_segments
        all_names = header_names + body_names
        
        return full_message, all_segments, all_names
    
    def _build_keep_alive_request(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建Keep Alive Request消息"""
        # Keep Alive Request消息只有8字节头部，没有填充数据
        header, header_segments, header_names = self._build_hart_ip_header(
            message_type=0x00,  # Request
            message_id=0x02,    # Keep Alive
            message_length=8
        )
        
        return header, header_segments, header_names
    
    def _build_keep_alive_response(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建Keep Alive Response消息"""
        # Keep Alive Response消息有12字节的填充数据
        padding = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        
        # HART/IP头部
        header, header_segments, header_names = self._build_hart_ip_header(
            message_type=0x01,  # Response
            message_id=0x02,    # Keep Alive
            message_length=8 #+ len(padding)  # 头部 + 填充数据
        )
        
        # 合并头部和填充数据
        full_message = header + padding
        
        # 添加填充数据字段信息
        padding_segments = [(8, 8 + len(padding))]
        padding_names = ["Padding"]
        
        # 合并所有字段信息
        all_segments = header_segments + padding_segments
        all_names = header_names + padding_names
        
        return full_message, all_segments, all_names
    
    def _build_pass_through_request(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建Pass Through Request消息"""
        # 生成HART帧数据 (Request)
        hart_frame = self._build_hart_frame(is_response=False)
        hart_length = len(hart_frame)
        
        # HART/IP头部
        header, header_segments, header_names = self._build_hart_ip_header(
            message_type=0x00,  # Request
            message_id=0x03,    # Pass Through
            message_length=8 + hart_length
        )
        
        # 合并头部和HART帧
        full_message = header + hart_frame
        
        # 添加HART帧字段信息
        hart_segments = []
        hart_names = []
        
        # HART帧字段
        hart_segments.append((8, 8 + hart_length))
        hart_names.append("HART_Frame")
        
        # 合并所有字段信息
        all_segments = header_segments + hart_segments
        all_names = header_names + hart_names
        
        return full_message, all_segments, all_names
    
    def _build_pass_through_response(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建Pass Through Response消息"""
        # 生成HART帧数据 (Response)
        hart_frame = self._build_hart_frame(is_response=True)
        hart_length = len(hart_frame)
        
        # HART/IP头部
        header, header_segments, header_names = self._build_hart_ip_header(
            message_type=0x01,  # Response
            message_id=0x03,    # Pass Through
            message_length=8 + hart_length
        )
        
        # 合并头部和HART帧
        full_message = header + hart_frame
        
        # 添加HART帧字段信息
        hart_segments = []
        hart_names = []
        
        # HART帧字段
        hart_segments.append((8, 8 + hart_length))
        hart_names.append("HART_Frame")
        
        # 合并所有字段信息
        all_segments = header_segments + hart_segments
        all_names = header_names + hart_names
        
        return full_message, all_segments, all_names
    
    def _build_hart_frame(self, is_response: bool = False) -> bytes:
        """构建HART帧"""
        frame = bytearray()
        
        # Delimiter (1 byte)
        if is_response:
            delimiter = 0x86  # ACK, Field Device to Master, Asynchronous, Unique Address
        else:
            delimiter = 0x82  # STX, Master to Field Device, Asynchronous, Unique Address
        frame.append(delimiter)
        
        # Long Address (5 bytes) - 使用固定的示例地址
        frame.extend(bytes.fromhex('264e0000d2'))
        
        # Command (1 byte)
        command = random.choice([0, 1, 2, 3])  # 使用示例中的命令
        frame.append(command)
        
        # Length (1 byte)
        if is_response:
            # Response消息根据命令类型设置不同的长度
            if command == 0:
                length = 24  # 设备信息响应
            elif command == 1:
                length = 7   # 主变量响应
            elif command == 2:
                length = 10  # 动态变量响应
            elif command == 3:
                length = 26  # 设备变量响应
            else:
                length = random.randint(0, 25)
        else:
            length = 0  # Request消息通常没有数据
        
        frame.append(length)
        
        # Data (variable length)
        if length > 0 and is_response:
            # 构建响应数据
            data = bytearray()
            
            if command == 0:  # 设备信息响应
                data.extend([0x00])  # Response Code
                data.extend([0xd0])  # Device Status
                data.extend([0xfe])  # Expansion Code
                data.extend(struct.pack('>H', 0x264e))  # Expanded Device Type
                data.extend([0x05])  # Minimum Number of Request Preambles
                data.extend([0x07])  # HART Universal Revision
                data.extend([0x04])  # Device Revision
                data.extend([0x01])  # Device Software Revision
                data.extend([0x0e])  # Hardware Rev and Physical Signaling
                data.extend([0x0c])  # Flags
                data.extend(bytes.fromhex('0000d2'))  # Device ID
                data.extend([0x05])  # Minimum Number of Response Preambles
                data.extend([0x02])  # Maximum Number of Device Variables
                data.extend([0x02])  # Configuration Change Counter
                data.extend([0xd0])  # Extended Device Status
                data.extend([0x26])  # Manufacturer ID
                data.extend([0x26])  # Private Label
                data.extend([0x84])  # Device Profile
            elif command == 1:  # 主变量响应
                data.extend([0x00])  # Response Code
                data.extend([0xd0])  # Device Status
                data.extend([0xfb])  # PV Units
                data.extend(struct.pack('>I', 0))  # PV
            elif command == 2:  # 动态变量响应
                data.extend([0x00])  # Response Code
                data.extend([0xd0])  # Device Status
                data.extend(struct.pack('>f', 0.0))  # PV Loop Current (4 bytes)
                data.extend(struct.pack('>f', 0.0))  # PV Percent Range (4 bytes)
            elif command == 3:  # 设备变量响应
                data.extend([0x00])  # Response Code
                data.extend([0xd0])  # Device Status
                data.extend(struct.pack('>f', 0.0))  # PV Loop Current (4 bytes)
                data.extend([0xfb])  # PV Units
                data.extend(struct.pack('>I', 0))  # PV (4 bytes)
                data.extend([0xfb])  # SV Units
                data.extend(struct.pack('>I', 0))  # SV (4 bytes)
                data.extend([0x20])  # TV Units
                data.extend(struct.pack('>f', 32.5))  # TV (4 bytes)
                data.extend([0x20])  # QV Units
                data.extend(struct.pack('>f', 32.0))  # QV (4 bytes)
            
            frame.extend(data)
        
        # Checksum (1 byte)
        checksum = self._calculate_checksum(frame)
        frame.append(checksum)
        
        return bytes(frame)
    
    def _build_session_close_request(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建Session Close Request消息"""
        # HART/IP头部
        header, header_segments, header_names = self._build_hart_ip_header(
            message_type=0x00,  # Request
            message_id=0x01,    # Session Close
            message_length=8
        )
        
        return header, header_segments, header_names
    
    def _build_session_close_response(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建Session Close Response消息"""
        # HART/IP头部
        header, header_segments, header_names = self._build_hart_ip_header(
            message_type=0x01,  # Response
            message_id=0x01,    # Session Close
            message_length=8
        )
        
        return header, header_segments, header_names
    
    def generate_messages(self, count: int = 1000) -> List[Tuple[str, List[Tuple[int, int]], List[str]]]:
        """生成指定数量的HART/IP消息"""
        messages = []
        
        # 消息生成器权重配置
        message_generators = [
            (self._build_session_initiate_request, 10),   # 10%
            (self._build_session_initiate_response, 10),  # 10%
            (self._build_keep_alive_request, 20),         # 20%
            (self._build_keep_alive_response, 20),        # 20%
            (self._build_pass_through_request, 20),       # 20%
            (self._build_pass_through_response, 20),      # 20%
        ]
        
        total_weight = sum(weight for _, weight in message_generators)
        
        for _ in range(count):
            try:
                # 根据权重随机选择消息生成器
                choice = random.choices(message_generators, weights=[w for _, w in message_generators], k=1)[0]
                generator_func = choice[0]
                
                message, segments, names = generator_func()
                messages.append((message.hex().upper(), segments, names))
                
            except Exception as e:
                print(f"生成消息时出错: {e}")
                continue
        
        return messages
    
    def generate_packets_from_messages(self, messages: List[Tuple[str, List[Tuple[int, int]], List[str]]]) -> List[Packet]:
        """基于已生成的消息创建HART/IP数据包，确保PCAP和CSV对应"""
        packets = []
        
        for hex_payload, _, _ in messages:
            payload_bytes = bytes.fromhex(hex_payload)
            
            # 生成随机网络参数
            src_ip = self._rand_ip()
            dst_ip = self._rand_ip()
            src_mac = self._rand_mac()
            dst_mac = self._rand_mac()
            src_port = random.randint(1024, 65535)
            dst_port = 5094  # HART/IP标准端口
            
            # 创建UDP数据包
            udp_packet = Ether(src=src_mac, dst=dst_mac) / \
                        IP(src=src_ip, dst=dst_ip) / \
                        UDP(sport=src_port, dport=dst_port) / \
                        Raw(load=payload_bytes)
            
            packets.append(udp_packet)
        
        return packets

    def generate_packets(self, count: int = 1000) -> List[Packet]:
        """生成HART/IP数据包"""
        packets = []
        messages = self.generate_messages(count)
        
        for hex_payload, _, _ in messages:
            payload_bytes = bytes.fromhex(hex_payload)
            
            # 生成随机网络参数
            src_ip = self._rand_ip()
            dst_ip = self._rand_ip()
            src_port = random.randint(1024, 65535)
            dst_port = self.HART_IP_PORT
            
            # 构建数据包
            ether_layer = Ether(src=self._rand_mac(), dst=self._rand_mac())
            ip_layer = IP(src=src_ip, dst=dst_ip)
            udp_layer = UDP(sport=src_port, dport=dst_port)
            
            pkt = ether_layer / ip_layer / udp_layer / Raw(load=payload_bytes)
            packets.append(pkt)
        
        return packets
    
    def save_to_csv(self, messages: List[Tuple[str, List[Tuple[int, int]], List[str]]], filename: str):
        """保存消息到CSV文件"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            for hex_str, segments, names in messages:
                writer.writerow([hex_str, str(segments), str(names)])
        print(f"CSV文件已保存: {filename}")
    
    def save_to_pcap(self, filename: str, packets: List[Packet]):
        """保存数据包到PCAP文件"""
        wrpcap(filename, packets)
        print(f"PCAP文件已保存: {filename}")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='HART/IP协议消息生成器')
    parser.add_argument('--count', type=int, default=1000, help='生成消息数量')
    parser.add_argument('--output-csv', type=str, default='csv/hart_ip_messages.csv', help='CSV输出文件')
    parser.add_argument('--output-pcap', type=str, default='pcap/hart_ip_messages.pcap', help='PCAP输出文件')
    
    args = parser.parse_args()
    
    print("HART/IP协议消息生成器")
    print("=" * 50)
    
    # 创建生成器
    generator = HartIpGenerator()
    
    # 生成消息
    print(f"生成 {args.count} 条HART/IP消息...")
    messages = generator.generate_messages(args.count)
    print(f"成功生成 {len(messages)} 条消息")
    
    # 基于已生成的消息创建数据包，确保PCAP和CSV对应
    print("生成PCAP数据包...")
    packets = generator.generate_packets_from_messages(messages)
    print(f"成功生成 {len(packets)} 个数据包")
    
    # 保存文件
    csv_path = os.path.join(generator.output_dir_csv, "hart_ip_messages.csv")
    pcap_path = os.path.join(generator.output_dir_pcap, "hart_ip_messages.pcap")
    
    generator.save_to_csv(messages, csv_path)
    generator.save_to_pcap(pcap_path, packets)
    
    print("\n生成完成！")
    print(f"CSV文件: {csv_path}")
    print(f"PCAP文件: {pcap_path}")
    
    # 验证提示
    print("\n验证建议:")
    print("1. 使用Wireshark打开PCAP文件检查HART/IP协议识别")
    print("2. 使用tshark验证协议解析:")
    print(f"   tshark -r {pcap_path} -T fields -e hart_ip.message_id -e hart_ip.message_type")

if __name__ == "__main__":
    main()
