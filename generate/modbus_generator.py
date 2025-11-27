#!/usr/bin/env python3
"""
Modbus协议消息生成器
严格按照Modbus Application Protocol Specification V1.1标准规范实现
支持生成多样化的Modbus TCP和RTU消息
"""

import struct
import socket
import random
import csv
from typing import List, Dict, Any, Optional, Tuple
from scapy.all import IP, TCP, Ether, wrpcap, Packet, Raw
import json


class ModbusGenerator:
    """Modbus协议消息生成器，严格按照标准规范"""
    
    # Modbus功能码
    FUNC_READ_COILS = 0x01                    # 读取线圈
    FUNC_READ_DISCRETE_INPUTS = 0x02          # 读取离散输入
    FUNC_READ_HOLDING_REGISTERS = 0x03        # 读取保持寄存器
    FUNC_READ_INPUT_REGISTERS = 0x04          # 读取输入寄存器
    FUNC_WRITE_SINGLE_COIL = 0x05             # 写单个线圈
    FUNC_WRITE_SINGLE_REGISTER = 0x06         # 写单个寄存器
    FUNC_READ_EXCEPTION_STATUS = 0x07         # 读取异常状态
    FUNC_DIAGNOSTICS = 0x08                   # 诊断
    FUNC_WRITE_MULTIPLE_COILS = 0x0F          # 写多个线圈
    FUNC_WRITE_MULTIPLE_REGISTERS = 0x10      # 写多个寄存器
    FUNC_READ_DEVICE_IDENTIFICATION = 0x2B    # 读取设备标识
    
    # Modbus异常码
    EXCEPTION_ILLEGAL_FUNCTION = 0x01          # 非法功能
    EXCEPTION_ILLEGAL_DATA_ADDRESS = 0x02      # 非法数据地址
    EXCEPTION_ILLEGAL_DATA_VALUE = 0x03        # 非法数据值
    EXCEPTION_SLAVE_DEVICE_FAILURE = 0x04      # 从设备故障
    EXCEPTION_ACKNOWLEDGE = 0x05               # 确认
    EXCEPTION_SLAVE_DEVICE_BUSY = 0x06         # 从设备忙
    EXCEPTION_MEMORY_PARITY_ERROR = 0x08       # 内存奇偶校验错误
    EXCEPTION_GATEWAY_PATH_UNAVAILABLE = 0x0A  # 网关路径不可用
    EXCEPTION_GATEWAY_TARGET_FAILED = 0x0B     # 网关目标设备响应失败
    
    def __init__(self):
        """初始化Modbus生成器"""
        self.generated_packets = []
        self.packet_info = []
        self.transaction_id_counter = 1
        
    def generate_random_ip(self, subnet: str = "192.168.1.0/24") -> str:
        """在指定子网中生成随机IP地址"""
        import ipaddress
        network = ipaddress.IPv4Network(subnet, strict=False)
        hosts = list(network.hosts())
        return str(random.choice(hosts))
    
    def generate_random_mac(self) -> str:
        """生成随机MAC地址"""
        first_byte = random.randint(0, 254) & 0xFE
        mac_bytes = [first_byte] + [random.randint(0, 255) for _ in range(5)]
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    
    def calculate_crc16(self, data: bytes) -> int:
        """计算Modbus RTU CRC16校验码"""
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc >>= 1
                    crc ^= 0xA001
                else:
                    crc >>= 1
        return crc
    
    def create_modbus_tcp_header(self, transaction_id: int, protocol_id: int = 0, 
                                length: int = 0, unit_id: int = 1) -> bytes:
        """
        创建Modbus TCP MBAP头部 (7字节)
        
        Modbus TCP MBAP头部格式:
        - Transaction ID (2字节): 事务标识符
        - Protocol ID (2字节): 协议标识符 (固定为0)
        - Length (2字节): 后续字节数
        - Unit ID (1字节): 单元标识符
        """
        return struct.pack('>HHHB', transaction_id, protocol_id, length, unit_id)
    
    def create_modbus_read_coils_request(self, starting_address: int, 
                                       quantity: int) -> bytes:
        """创建读取线圈请求PDU"""
        return struct.pack('>BHH', self.FUNC_READ_COILS, starting_address, quantity)
    
    def create_modbus_read_coils_response(self, byte_count: int, 
                                        coil_values: List[bool]) -> bytes:
        """创建读取线圈响应PDU"""
        # 将布尔值转换为字节
        data_bytes = []
        for i in range(0, len(coil_values), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(coil_values) and coil_values[i + j]:
                    byte_val |= (1 << j)
            data_bytes.append(byte_val)
        
        pdu = struct.pack('>BB', self.FUNC_READ_COILS, byte_count)
        return pdu + bytes(data_bytes)
    
    def create_modbus_read_holding_registers_request(self, starting_address: int, 
                                                   quantity: int) -> bytes:
        """创建读取保持寄存器请求PDU"""
        return struct.pack('>BHH', self.FUNC_READ_HOLDING_REGISTERS, 
                          starting_address, quantity)
    
    def create_modbus_read_holding_registers_response(self, byte_count: int, 
                                                    register_values: List[int]) -> bytes:
        """创建读取保持寄存器响应PDU"""
        pdu = struct.pack('>BB', self.FUNC_READ_HOLDING_REGISTERS, byte_count)
        for value in register_values:
            pdu += struct.pack('>H', value)
        return pdu
    
    def create_modbus_write_single_coil_request(self, address: int, 
                                              value: bool) -> bytes:
        """创建写单个线圈请求PDU"""
        coil_value = 0xFF00 if value else 0x0000
        return struct.pack('>BHH', self.FUNC_WRITE_SINGLE_COIL, address, coil_value)
    
    def create_modbus_write_single_register_request(self, address: int, 
                                                  value: int) -> bytes:
        """创建写单个寄存器请求PDU"""
        return struct.pack('>BHH', self.FUNC_WRITE_SINGLE_REGISTER, address, value)
    
    def create_modbus_exception_response(self, function_code: int, 
                                       exception_code: int) -> bytes:
        """创建Modbus异常响应PDU"""
        return struct.pack('>BB', function_code | 0x80, exception_code)
    
    def create_modbus_read_discrete_inputs_request(self, starting_address: int, 
                                                  quantity: int) -> bytes:
        """创建读取离散输入请求PDU"""
        return struct.pack('>BHH', self.FUNC_READ_DISCRETE_INPUTS, 
                          starting_address, quantity)
    
    def create_modbus_read_discrete_inputs_response(self, byte_count: int, 
                                                   input_values: List[bool]) -> bytes:
        """创建读取离散输入响应PDU"""
        # 将布尔值转换为字节
        data_bytes = []
        for i in range(0, len(input_values), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(input_values) and input_values[i + j]:
                    byte_val |= (1 << j)
            data_bytes.append(byte_val)
        
        pdu = struct.pack('>BB', self.FUNC_READ_DISCRETE_INPUTS, byte_count)
        return pdu + bytes(data_bytes)
    
    def create_modbus_read_input_registers_response(self, byte_count: int, 
                                                   register_values: List[int]) -> bytes:
        """创建读取输入寄存器响应PDU"""
        pdu = struct.pack('>BB', self.FUNC_READ_INPUT_REGISTERS, byte_count)
        for value in register_values:
            pdu += struct.pack('>H', value)
        return pdu
    
    def create_modbus_write_single_coil_response(self, address: int, value: bool) -> bytes:
        """创建写单个线圈响应PDU"""
        coil_value = 0xFF00 if value else 0x0000
        return struct.pack('>BHH', self.FUNC_WRITE_SINGLE_COIL, address, coil_value)
    
    def create_modbus_write_single_register_response(self, address: int, value: int) -> bytes:
        """创建写单个寄存器响应PDU"""
        return struct.pack('>BHH', self.FUNC_WRITE_SINGLE_REGISTER, address, value)
    
    def create_modbus_write_multiple_coils_response(self, starting_address: int, quantity: int) -> bytes:
        """创建写多个线圈响应PDU"""
        return struct.pack('>BHH', self.FUNC_WRITE_MULTIPLE_COILS, starting_address, quantity)
    
    def create_modbus_write_multiple_registers_response(self, starting_address: int, quantity: int) -> bytes:
        """创建写多个寄存器响应PDU"""
        return struct.pack('>BHH', self.FUNC_WRITE_MULTIPLE_REGISTERS, starting_address, quantity)
    
    def create_modbus_write_multiple_coils_request(self, starting_address: int, 
                                                  coil_values: List[bool]) -> bytes:
        """创建写多个线圈请求PDU"""
        quantity = len(coil_values)
        byte_count = (quantity + 7) // 8
        
        # 将布尔值转换为字节
        data_bytes = []
        for i in range(0, len(coil_values), 8):
            byte_val = 0
            for j in range(8):
                if i + j < len(coil_values) and coil_values[i + j]:
                    byte_val |= (1 << j)
            data_bytes.append(byte_val)
        
        pdu = struct.pack('>BHHB', self.FUNC_WRITE_MULTIPLE_COILS, 
                          starting_address, quantity, byte_count)
        return pdu + bytes(data_bytes)
    
    def create_modbus_write_multiple_registers_request(self, starting_address: int, 
                                                      values: List[int]) -> bytes:
        """创建写多个寄存器请求PDU"""
        quantity = len(values)
        byte_count = quantity * 2
        
        pdu = struct.pack('>BHHB', self.FUNC_WRITE_MULTIPLE_REGISTERS, 
                          starting_address, quantity, byte_count)
        for value in values:
            pdu += struct.pack('>H', value)
        return pdu
    
    def create_modbus_tcp_packet(self, src_ip: str, dst_ip: str, 
                                src_port: Optional[int] = None, dst_port: int = 502,
                                transaction_id: Optional[int] = None, unit_id: int = 1,
                                pdu_data: bytes = b'',
                                is_response: bool = False,
                                client_port: Optional[int] = None) -> Packet:
        """创建Modbus TCP数据包"""
        if src_port is None:
            src_port = random.randint(1024, 65535)
        if transaction_id is None:
            transaction_id = self.transaction_id_counter
            self.transaction_id_counter += 1
        
        # 创建以太网层
        eth_src = self.generate_random_mac()
        eth_dst = self.generate_random_mac()
        eth_packet = Ether(src=eth_src, dst=eth_dst)
        
        # 创建IP层
        ip_packet = IP(src=src_ip, dst=dst_ip)
        
        # 创建TCP层
        if is_response:
            # 服务器响应：来源端口应为502，目标端口为客户端临时端口
            server_sport = 502
            client_dport = client_port if client_port is not None else src_port
            tcp_packet = TCP(sport=server_sport, dport=client_dport, flags="PA")
        else:
            # 客户端请求：目标端口为502，来源端口为临时端口
            tcp_packet = TCP(sport=src_port, dport=dst_port, flags="PA")
        
        # 创建Modbus TCP MBAP头部
        length = len(pdu_data) + 1  # PDU长度 + Unit ID
        mbap_header = self.create_modbus_tcp_header(transaction_id, 0, length, unit_id)
        
        # 组合Modbus数据
        modbus_data = mbap_header + pdu_data
        
        # 创建原始数据层
        raw_data = Raw(load=modbus_data)
        
        # 组合完整数据包
        packet = eth_packet / ip_packet / tcp_packet / raw_data
        
        # 记录数据包信息
        packet_info = {
            "type": "MODBUS_TCP",
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "ip_src": src_ip,
            "ip_dst": dst_ip,
            "tcp_sport": int(tcp_packet.sport),
            "tcp_dport": int(tcp_packet.dport),
            "modbus_transaction_id": transaction_id,
            "modbus_protocol_id": 0,
            "modbus_length": length,
            "modbus_unit_id": unit_id,
            "modbus_function_code": pdu_data[0] if pdu_data else 0,
            "packet_size": len(packet),
            "is_response": is_response
        }
        
        self.packet_info.append(packet_info)
        return packet
    
    def generate_diverse_modbus_packets(self, count: int = 50) -> List[Packet]:
        """生成多样化的Modbus数据包，确保请求和响应各占50%"""
        packets = []
        
        for i in range(count):
            src_ip = self.generate_random_ip("192.168.1.0/24")
            dst_ip = self.generate_random_ip("10.0.1.0/24")
            
            # 确保请求和响应各占50%比例
            is_response = random.random() < 0.5
            
            if is_response:
                # 生成响应类型
                function_type = random.choice([
                    'read_coils_resp',
                    'read_discrete_inputs_resp',
                    'read_holding_registers_resp',
                    'read_input_registers_resp',
                    'write_single_coil_resp',
                    'write_single_register_resp',
                    'write_multiple_coils_resp',
                    'write_multiple_registers_resp',
                    'exception_response'
                ])
                
                client_port = random.randint(1024, 65535)
                transaction_id = self.transaction_id_counter
                self.transaction_id_counter += 1
                
                if function_type.startswith('read_coils'):
                    num_coils = random.randint(1, 100)
                    coil_values = [random.choice([True, False]) for _ in range(num_coils)]
                    byte_count = (len(coil_values) + 7) // 8
                    pdu = self.create_modbus_read_coils_response(byte_count, coil_values)
                    
                elif function_type.startswith('read_discrete_inputs'):
                    num_inputs = random.randint(1, 50)
                    input_values = [random.choice([True, False]) for _ in range(num_inputs)]
                    byte_count = (len(input_values) + 7) // 8
                    pdu = self.create_modbus_read_discrete_inputs_response(byte_count, input_values)
                    
                elif function_type.startswith('read_holding_registers'):
                    num_registers = random.randint(1, 125)
                    register_values = [random.randint(0, 65535) for _ in range(num_registers)]
                    byte_count = len(register_values) * 2
                    pdu = self.create_modbus_read_holding_registers_response(byte_count, register_values)
                    
                elif function_type.startswith('read_input_registers'):
                    num_registers = random.randint(1, 125)
                    register_values = [random.randint(0, 65535) for _ in range(num_registers)]
                    byte_count = len(register_values) * 2
                    pdu = self.create_modbus_read_input_registers_response(byte_count, register_values)
                    
                elif function_type.startswith('write_single_coil'):
                    address = random.randint(0, 65535)
                    value = random.choice([True, False])
                    pdu = self.create_modbus_write_single_coil_response(address, value)
                    
                elif function_type.startswith('write_single_register'):
                    address = random.randint(0, 65535)
                    value = random.randint(0, 65535)
                    pdu = self.create_modbus_write_single_register_response(address, value)
                    
                elif function_type.startswith('write_multiple_coils'):
                    starting_addr = random.randint(0, 9999)
                    quantity = random.randint(1, 50)
                    pdu = self.create_modbus_write_multiple_coils_response(starting_addr, quantity)
                    
                elif function_type.startswith('write_multiple_registers'):
                    starting_addr = random.randint(0, 9999)
                    quantity = random.randint(1, 25)
                    pdu = self.create_modbus_write_multiple_registers_response(starting_addr, quantity)
                    
                elif function_type == 'exception_response':
                    func_code = random.choice([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10])
                    exception_code = random.choice([
                        self.EXCEPTION_ILLEGAL_FUNCTION,
                        self.EXCEPTION_ILLEGAL_DATA_ADDRESS,
                        self.EXCEPTION_ILLEGAL_DATA_VALUE,
                        self.EXCEPTION_SLAVE_DEVICE_FAILURE
                    ])
                    pdu = self.create_modbus_exception_response(func_code, exception_code)
                else:
                    # 默认生成读取保持寄存器响应
                    num_registers = random.randint(1, 125)
                    register_values = [random.randint(0, 65535) for _ in range(num_registers)]
                    byte_count = len(register_values) * 2
                    pdu = self.create_modbus_read_holding_registers_response(byte_count, register_values)
                
                # 创建响应方向的数据包（服务端->客户端）
                packet = self.create_modbus_tcp_packet(dst_ip, src_ip, transaction_id=transaction_id, pdu_data=pdu, is_response=True, client_port=client_port)
                packets.append(packet)
                self.generated_packets.append(packet)
            else:
                # 生成请求类型
                function_type = random.choice([
                    'read_coils_req',
                    'read_discrete_inputs_req',
                    'read_holding_registers_req',
                    'read_input_registers_req',
                    'write_single_coil_req',
                    'write_single_register_req',
                    'write_multiple_coils_req',
                    'write_multiple_registers_req'
                ])
                
                client_port = random.randint(1024, 65535)
                transaction_id = self.transaction_id_counter
                self.transaction_id_counter += 1
                
                if function_type.startswith('read_coils'):
                    starting_addr = random.randint(0, 65535)
                    quantity = random.randint(1, 2000)
                    pdu = self.create_modbus_read_coils_request(starting_addr, quantity)
                    
                elif function_type.startswith('read_discrete_inputs'):
                    starting_addr = random.randint(0, 65535)
                    quantity = random.randint(1, 2000)
                    pdu = self.create_modbus_read_discrete_inputs_request(starting_addr, quantity)
                    
                elif function_type.startswith('read_holding_registers'):
                    starting_addr = random.randint(0, 65535)
                    quantity = random.randint(1, 125)
                    pdu = self.create_modbus_read_holding_registers_request(starting_addr, quantity)
                    
                elif function_type.startswith('read_input_registers'):
                    starting_addr = random.randint(0, 65535)
                    quantity = random.randint(1, 125)
                    pdu = self.create_modbus_read_input_registers_request(starting_addr, quantity)
                    
                elif function_type.startswith('write_single_coil'):
                    address = random.randint(0, 65535)
                    value = random.choice([True, False])
                    pdu = self.create_modbus_write_single_coil_request(address, value)
                    
                elif function_type.startswith('write_single_register'):
                    address = random.randint(0, 65535)
                    value = random.randint(0, 65535)
                    pdu = self.create_modbus_write_single_register_request(address, value)
                    
                elif function_type.startswith('write_multiple_coils'):
                    starting_addr = random.randint(0, 65535)
                    quantity = random.randint(1, 1968)
                    coil_values = [random.choice([True, False]) for _ in range(quantity)]
                    pdu = self.create_modbus_write_multiple_coils_request(starting_addr, coil_values)
                    
                elif function_type.startswith('write_multiple_registers'):
                    starting_addr = random.randint(0, 65535)
                    values = [random.randint(0, 65535) for _ in range(random.randint(1, 123))]
                    pdu = self.create_modbus_write_multiple_registers_request(starting_addr, values)
                else:
                    # 默认读取保持寄存器请求
                    starting_addr = random.randint(0, 65535)
                    quantity = random.randint(1, 125)
                    pdu = self.create_modbus_read_holding_registers_request(starting_addr, quantity)
                
                # 创建请求方向的数据包（客户端->服务端，目的端口502）
                packet = self.create_modbus_tcp_packet(src_ip, dst_ip, src_port=client_port, transaction_id=transaction_id, pdu_data=pdu, is_response=False)
                packets.append(packet)
                self.generated_packets.append(packet)
        
        return packets
    
    def generate_specific_scenarios(self) -> List[Packet]:
        """生成特定场景的Modbus数据包 - 已移除，避免额外生成消息"""
        # 此函数已被禁用，所有消息都通过generate_diverse_modbus_packets生成
        # 以确保精确控制消息数量
        return []
    def generate_specific_scenarios(self) -> List[Packet]:
        """生成特定场景的Modbus数据包 - 已移除，避免额外生成消息"""
        # 此函数已被禁用，所有消息都通过generate_diverse_modbus_packets生成
        # 以确保精确控制消息数量
        return []
    
    def create_modbus_read_input_registers_request(self, starting_address: int, 
                                                 quantity: int) -> bytes:
        """创建读取输入寄存器请求PDU"""
        return struct.pack('>BHH', self.FUNC_READ_INPUT_REGISTERS, 
                          starting_address, quantity)
    
    def save_to_pcap(self, filename: str, packets: Optional[List[Packet]] = None):
        """保存数据包到PCAP文件"""
        if packets is None:
            packets = self.generated_packets
        
        if not packets:
            raise ValueError("没有数据包可保存")
        
        wrpcap(filename, packets)
        print(f"已保存 {len(packets)} 个Modbus数据包到 {filename}")
    
    def save_to_csv(self, filename: str):
        """保存生成的消息到CSV文件 - 只包含Modbus协议数据"""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            
            for i, packet in enumerate(self.generated_packets):
                # 提取Modbus数据（只要Raw层的数据）
                if packet.haslayer(Raw):
                    modbus_data = bytes(packet[Raw])
                    hex_data = modbus_data.hex()
                    
                    segments = []
                    field_names = []
                    offset = 0
                    
                    # 解析Modbus TCP MBAP头部（7字节）- 使用字节偏移
                    if len(modbus_data) >= 7:
                        segments.append((0, 2))  # Transaction ID (2字节)
                        field_names.append('Transaction ID')
                        
                        segments.append((2, 4))  # Protocol ID (2字节)  
                        field_names.append('Protocol ID')
                        
                        segments.append((4, 6))  # Length (2字节)
                        field_names.append('Length')
                        
                        segments.append((6, 7))  # Unit ID (1字节)
                        field_names.append('Unit ID')
                        
                        # 解析Modbus PDU
                        if len(modbus_data) > 7:
                            function_code = modbus_data[7]
                            segments.append((7, 8))  # Function Code (1字节)
                            field_names.append('Function Code')
                            
                            # 根据功能码解析不同的PDU数据
                            self._parse_modbus_pdu(modbus_data[8:], function_code, segments, field_names, 8)
                    
                    writer.writerow([hex_data, str(segments), str(field_names)])
    
    def _parse_modbus_pdu(self, pdu_data: bytes, function_code: int, segments: List[Tuple[int, int]], field_names: List[str], start_offset: int):
        """解析Modbus PDU数据部分"""
        offset = start_offset
        
        if function_code == self.FUNC_READ_COILS:  # 读取线圈
            if len(pdu_data) == 4:  # 请求格式严格4字节
                segments.append((offset, offset + 2))  # Starting Address (2字节)
                field_names.append('Starting Address')
                offset += 2
                
                segments.append((offset, offset + 2))  # Quantity (2字节)
                field_names.append('Quantity')
                offset += 2
            elif len(pdu_data) >= 1:  # 响应格式
                segments.append((offset, offset + 1))  # Byte Count (1字节)
                field_names.append('Byte Count')
                offset += 1
                
                if len(pdu_data) > 1:
                    segments.append((offset, offset + (len(pdu_data) - 1)))  # Coil Status
                    field_names.append('Coil Status')
        
        elif function_code == self.FUNC_READ_HOLDING_REGISTERS:  # 读取保持寄存器
            if len(pdu_data) == 4:  # 请求格式严格4字节
                segments.append((offset, offset + 2))  # Starting Address (2字节)
                field_names.append('Starting Address')
                offset += 2
                
                segments.append((offset, offset + 2))  # Quantity (2字节)
                field_names.append('Quantity')
                offset += 2
            elif len(pdu_data) >= 1:  # 响应格式
                segments.append((offset, offset + 1))  # Byte Count (1字节)
                field_names.append('Byte Count')
                offset += 1
                
                if len(pdu_data) > 1:
                    segments.append((offset, offset + (len(pdu_data) - 1)))  # Register Values
                    field_names.append('Register Values')

        elif function_code == self.FUNC_READ_DISCRETE_INPUTS:  # 读取离散输入
            if len(pdu_data) == 4:  # 请求
                segments.append((offset, offset + 2))
                field_names.append('Starting Address')
                offset += 2
                segments.append((offset, offset + 2))
                field_names.append('Quantity')
                offset += 2
            elif len(pdu_data) >= 1:  # 响应
                segments.append((offset, offset + 1))
                field_names.append('Byte Count')
                offset += 1
                if len(pdu_data) > 1:
                    segments.append((offset, offset + (len(pdu_data) - 1)))
                    field_names.append('Input Status')

        elif function_code == self.FUNC_READ_INPUT_REGISTERS:  # 读取输入寄存器
            if len(pdu_data) == 4:  # 请求
                segments.append((offset, offset + 2))
                field_names.append('Starting Address')
                offset += 2
                segments.append((offset, offset + 2))
                field_names.append('Quantity')
                offset += 2
            elif len(pdu_data) >= 1:  # 响应
                segments.append((offset, offset + 1))
                field_names.append('Byte Count')
                offset += 1
                if len(pdu_data) > 1:
                    segments.append((offset, offset + (len(pdu_data) - 1)))
                    field_names.append('Register Values')
        
        elif function_code == self.FUNC_WRITE_SINGLE_COIL:  # 写单个线圈
            if len(pdu_data) >= 4:
                segments.append((offset, offset + 2))  # Output Address (2字节)
                field_names.append('Output Address')
                offset += 2
                
                segments.append((offset, offset + 2))  # Output Value (2字节)
                field_names.append('Output Value')
                offset += 2
        
        elif function_code == self.FUNC_WRITE_SINGLE_REGISTER:  # 写单个寄存器
            if len(pdu_data) >= 4:
                segments.append((offset, offset + 2))  # Register Address (2字节)
                field_names.append('Register Address')
                offset += 2
                
                segments.append((offset, offset + 2))  # Register Value (2字节)
                field_names.append('Register Value')
                offset += 2
        
        elif function_code & 0x80:  # 异常响应
            if len(pdu_data) >= 1:
                segments.append((offset, offset + 1))  # Exception Code (1字节)
                field_names.append('Exception Code')
                offset += 1
        
        else:  # 其他功能码，剩余数据作为一个整体
            if len(pdu_data) > 0:
                segments.append((offset, offset + len(pdu_data)))  # Data
                field_names.append('Data')
                offset += len(pdu_data)
    
    def get_diversity_stats(self) -> Dict[str, Any]:
        """获取多样性统计信息"""
        if not self.packet_info:
            return {}
        
        # 统计不同的值
        function_codes = set()
        transaction_ids = set()
        unit_ids = set()
        src_ips = set()
        dst_ips = set()
        src_ports = set()
        dst_ports = set()
        
        for info in self.packet_info:
            function_codes.add(info.get('modbus_function_code', 0))
            transaction_ids.add(info.get('modbus_transaction_id', 0))
            unit_ids.add(info.get('modbus_unit_id', 0))
            src_ips.add(info.get('ip_src', ''))
            dst_ips.add(info.get('ip_dst', ''))
            src_ports.add(info.get('tcp_sport', 0))
            dst_ports.add(info.get('tcp_dport', 0))
        
        return {
            "total_packets": len(self.packet_info),
            "unique_function_codes": len(function_codes),
            "function_codes": list(function_codes),
            "unique_transaction_ids": len(transaction_ids),
            "unique_unit_ids": len(unit_ids),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "unique_src_ports": len(src_ports),
            "unique_dst_ports": len(dst_ports),
            "diversity_score": {
                "function_diversity": len(function_codes) / 11,  # 11个主要功能码
                "transaction_diversity": len(transaction_ids) / len(self.packet_info),
                "ip_diversity": len(src_ips | dst_ips) / len(self.packet_info),
                "port_diversity": len(src_ports | dst_ports) / len(self.packet_info)
            }
        }


def main():
    """主函数：演示Modbus生成器的使用"""
    generator = ModbusGenerator()
    
    print("开始生成Modbus协议消息...")
    
    # 生成多样化的Modbus数据包
    diverse_packets = generator.generate_diverse_modbus_packets(5000)
    print(f"生成了 {len(diverse_packets)} 个Modbus数据包")
    
    # 设置生成的数据包，确保CSV和PCAP对应
    generator.generated_packets = diverse_packets
    
    # 保存到文件
    all_packets = diverse_packets
    
    # 修改输出路径为新的目录结构
    pcap_file = "pcap/modbus_messages.pcap"
    csv_file = "csv/modbus_messages.csv"
    
    generator.save_to_pcap(pcap_file, all_packets)
    generator.save_to_csv(csv_file)
    
    # 显示多样性统计
    stats = generator.get_diversity_stats()
    print("\n多样性统计:")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    
    print(f"\n生成完成！总共生成 {len(all_packets)} 个Modbus数据包")
    print(f"PCAP文件: {pcap_file}")
    print(f"CSV文件: {csv_file}")


if __name__ == "__main__":
    main()