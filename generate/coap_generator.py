#!/usr/bin/env python3
"""
CoAP协议消息生成器
严格按照RFC 7252标准规范实现
支持生成多样化的约束应用协议消息
"""

import struct
import random
import csv
import os
from typing import List, Dict, Any, Optional, Tuple
from scapy.all import IP, UDP, Ether, wrpcap, Packet, Raw # type: ignore[error]
import json

class CoAPGenerator:
    """CoAP协议消息生成器，严格按照RFC 7252标准规范"""
    
    # CoAP消息类型
    TYPE_CONFIRMABLE = 0
    TYPE_NON_CONFIRMABLE = 1
    TYPE_ACKNOWLEDGEMENT = 2
    TYPE_RESET = 3
    
    # CoAP方法码
    METHOD_EMPTY = 0
    METHOD_GET = 1
    METHOD_POST = 2
    METHOD_PUT = 3
    METHOD_DELETE = 4
    
    # CoAP响应码
    RESPONSE_CREATED = 65      # 2.01
    RESPONSE_DELETED = 66      # 2.02
    RESPONSE_VALID = 67        # 2.03
    RESPONSE_CHANGED = 68      # 2.04
    RESPONSE_CONTENT = 69      # 2.05
    RESPONSE_CONTINUE = 95     # 2.31
    RESPONSE_BAD_REQUEST = 128 # 4.00
    RESPONSE_UNAUTHORIZED = 129 # 4.01
    RESPONSE_BAD_OPTION = 130  # 4.02
    RESPONSE_FORBIDDEN = 131   # 4.03
    RESPONSE_NOT_FOUND = 132   # 4.04
    RESPONSE_METHOD_NOT_ALLOWED = 133 # 4.05
    RESPONSE_NOT_ACCEPTABLE = 134 # 4.06
    RESPONSE_PRECONDITION_FAILED = 140 # 4.12
    RESPONSE_REQUEST_ENTITY_TOO_LARGE = 141 # 4.13
    RESPONSE_UNSUPPORTED_CONTENT_FORMAT = 143 # 4.15
    RESPONSE_INTERNAL_SERVER_ERROR = 160 # 5.00
    RESPONSE_NOT_IMPLEMENTED = 161 # 5.01
    RESPONSE_BAD_GATEWAY = 162 # 5.02
    RESPONSE_SERVICE_UNAVAILABLE = 163 # 5.03
    RESPONSE_GATEWAY_TIMEOUT = 164 # 5.04
    RESPONSE_PROXYING_NOT_SUPPORTED = 165 # 5.05
    
    # CoAP选项编号
    OPTION_IF_MATCH = 1
    OPTION_URI_HOST = 3
    OPTION_ETAG = 4
    OPTION_IF_NONE_MATCH = 5
    OPTION_URI_PORT = 7
    OPTION_LOCATION_PATH = 8
    OPTION_URI_PATH = 11
    OPTION_CONTENT_FORMAT = 12
    OPTION_MAX_AGE = 14
    OPTION_URI_QUERY = 15
    OPTION_ACCEPT = 17
    OPTION_LOCATION_QUERY = 20
    OPTION_PROXY_URI = 35
    OPTION_PROXY_SCHEME = 39
    OPTION_SIZE1 = 60
    
    # 内容格式
    CONTENT_FORMAT_TEXT_PLAIN = 0
    CONTENT_FORMAT_APPLICATION_LINK_FORMAT = 40
    CONTENT_FORMAT_APPLICATION_XML = 41
    CONTENT_FORMAT_APPLICATION_OCTET_STREAM = 42
    CONTENT_FORMAT_APPLICATION_EXI = 47
    CONTENT_FORMAT_APPLICATION_JSON = 50
    
    def __init__(self):
        """初始化CoAP生成器"""
        self.generated_packets = []
        self.packet_info = []
        self.stored_messages = []  # 存储生成的消息
        self.message_id = 1
        
    def _generate_random_ip(self) -> str:
        """生成随机IP地址"""
        return f"{random.randint(192, 223)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    def _generate_random_mac(self) -> str:
        """生成随机MAC地址"""
        first_byte = random.randint(0, 254) & 0xFE
        mac_bytes = [first_byte] + [random.randint(0, 255) for _ in range(5)]
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    
    def encode_option(self, option_number: int, option_value: bytes) -> bytes:
        """
        编码CoAP选项
        
        选项格式:
        - Option Delta (4位)
        - Option Length (4位)
        - Option Delta Extended (可选)
        - Option Length Extended (可选)
        - Option Value (可变长度)
        """
        option_length = len(option_value)
        
        # 计算选项增量和长度编码
        if option_number < 13:
            delta = option_number
            delta_extended = b''
        elif option_number < 269:
            delta = 13
            delta_extended = struct.pack('B', option_number - 13)
        else:
            delta = 14
            delta_extended = struct.pack('>H', option_number - 269)
        
        if option_length < 13:
            length = option_length
            length_extended = b''
        elif option_length < 269:
            length = 13
            length_extended = struct.pack('B', option_length - 13)
        else:
            length = 14
            length_extended = struct.pack('>H', option_length - 269)
        
        # 组合选项头部
        header = struct.pack('B', (delta << 4) | length)
        
        return header + delta_extended + length_extended + option_value
    
    def create_coap_header(self, version: int = 1, msg_type: int = TYPE_CONFIRMABLE,
                          token_length: int = 0, code: int = METHOD_GET,
                          message_id: Optional[int] = None) -> bytes:
        """
        创建CoAP消息头部（4字节）
        
        格式:
        - Version (2位): 版本号（固定为1）
        - Type (2位): 消息类型
        - Token Length (4位): 令牌长度
        - Code (8位): 方法或响应码
        - Message ID (16位): 消息ID
        """
        if message_id is None:
            message_id = self.message_id
            self.message_id += 1
        
        # 第一个字节：版本(2) + 类型(2) + 令牌长度(4)
        first_byte = (version << 6) | (msg_type << 4) | (token_length & 0x0F)
        
        return struct.pack('>BBH', first_byte, code, message_id)
    
    def create_token(self, length: Optional[int] = None) -> bytes:
        """创建CoAP令牌"""
        if length is None:
            length = random.randint(0, 8)
        
        if length > 8:
            length = 8
        
        return os.urandom(length) if length > 0 else b''
    
    def create_get_request(self, uri_path: str = "temperature", uri_host: Optional[str] = None) -> bytes:
        """创建CoAP GET请求"""
        # 创建令牌
        token = self.create_token(random.randint(1, 4))
        
        # 创建头部
        header = self.create_coap_header(
            msg_type=random.choice([self.TYPE_CONFIRMABLE, self.TYPE_NON_CONFIRMABLE]),
            token_length=len(token),
            code=self.METHOD_GET
        )
        
        # 创建选项
        options = b''
        current_option_number = 0
        
        # Uri-Host选项
        if uri_host:
            host_option = self.encode_option(self.OPTION_URI_HOST - current_option_number, uri_host.encode('utf-8'))
            options += host_option
            current_option_number = self.OPTION_URI_HOST
        
        # Uri-Path选项
        path_parts = uri_path.split('/')
        for part in path_parts:
            if part:
                path_option = self.encode_option(self.OPTION_URI_PATH - current_option_number, part.encode('utf-8'))
                options += path_option
                current_option_number = self.OPTION_URI_PATH
        
        # Accept选项（随机添加）
        if random.random() < 0.3:
            accept_format = random.choice([
                self.CONTENT_FORMAT_TEXT_PLAIN,
                self.CONTENT_FORMAT_APPLICATION_JSON,
                self.CONTENT_FORMAT_APPLICATION_XML
            ])
            accept_option = self.encode_option(self.OPTION_ACCEPT - current_option_number, struct.pack('>H', accept_format))
            options += accept_option
        
        return header + token + options
    
    def create_post_request(self, uri_path: str = "sensors", payload: Optional[str] = None) -> bytes:
        """创建CoAP POST请求"""
        if payload is None:
            payloads = [
                '{"temperature": 23.5, "humidity": 60}',
                '{"sensor_id": "temp001", "value": 25.3}',
                '{"device": "sensor01", "status": "active"}',
                'temperature=24.1&humidity=58',
                'Hello, CoAP!'
            ]
            payload = random.choice(payloads)
        
        # 创建令牌
        token = self.create_token(random.randint(2, 6))
        
        # 创建头部
        header = self.create_coap_header(
            msg_type=self.TYPE_CONFIRMABLE,
            token_length=len(token),
            code=self.METHOD_POST
        )
        
        # 创建选项
        options = b''
        current_option_number = 0
        
        # Uri-Path选项
        path_parts = uri_path.split('/')
        for part in path_parts:
            if part:
                path_option = self.encode_option(self.OPTION_URI_PATH - current_option_number, part.encode('utf-8'))
                options += path_option
                current_option_number = self.OPTION_URI_PATH
        
        # Content-Format选项
        if payload.startswith('{'):
            content_format = self.CONTENT_FORMAT_APPLICATION_JSON
        elif 'temperature=' in payload:
            content_format = self.CONTENT_FORMAT_TEXT_PLAIN
        else:
            content_format = self.CONTENT_FORMAT_TEXT_PLAIN
        
        content_format_option = self.encode_option(self.OPTION_CONTENT_FORMAT - current_option_number, struct.pack('B', content_format))
        options += content_format_option
        
        # 载荷标记（0xFF）和载荷
        payload_marker = b'\xFF' if payload else b''
        payload_bytes = payload.encode('utf-8') if payload else b''
        
        return header + token + options + payload_marker + payload_bytes
    
    def create_put_request(self, uri_path: str = "actuators/led", payload: Optional[str] = None) -> bytes:
        """创建CoAP PUT请求"""
        if payload is None:
            payloads = [
                '{"state": "on"}',
                '{"brightness": 75}',
                '{"color": "red"}',
                'ON',
                'OFF'
            ]
            payload = random.choice(payloads)
        
        # 创建令牌
        token = self.create_token(random.randint(2, 6))
        
        # 创建头部
        header = self.create_coap_header(
            msg_type=self.TYPE_CONFIRMABLE,
            token_length=len(token),
            code=self.METHOD_PUT
        )
        
        # 创建选项
        options = b''
        current_option_number = 0
        
        # Uri-Path选项
        path_parts = uri_path.split('/')
        for part in path_parts:
            if part:
                path_option = self.encode_option(self.OPTION_URI_PATH - current_option_number, part.encode('utf-8'))
                options += path_option
                current_option_number = self.OPTION_URI_PATH
        
        # Content-Format选项
        content_format = self.CONTENT_FORMAT_APPLICATION_JSON if payload.startswith('{') else self.CONTENT_FORMAT_TEXT_PLAIN
        content_format_option = self.encode_option(self.OPTION_CONTENT_FORMAT - current_option_number, struct.pack('B', content_format))
        options += content_format_option
        
        # 载荷标记和载荷
        payload_marker = b'\xFF' if payload else b''
        payload_bytes = payload.encode('utf-8') if payload else b''
        
        return header + token + options + payload_marker + payload_bytes
    
    def create_delete_request(self, uri_path: str = "temp-sensors/001") -> bytes:
        """创建CoAP DELETE请求"""
        # 创建令牌
        token = self.create_token(random.randint(1, 4))
        
        # 创建头部
        header = self.create_coap_header(
            msg_type=self.TYPE_CONFIRMABLE,
            token_length=len(token),
            code=self.METHOD_DELETE
        )
        
        # 创建选项
        options = b''
        current_option_number = 0
        
        # Uri-Path选项
        path_parts = uri_path.split('/')
        for part in path_parts:
            if part:
                path_option = self.encode_option(self.OPTION_URI_PATH - current_option_number, part.encode('utf-8'))
                options += path_option
                current_option_number = self.OPTION_URI_PATH
        
        return header + token + options
    
    def create_response(self, response_code: int, token: Optional[bytes] = None, payload: Optional[str] = None) -> bytes:
        """创建CoAP响应"""
        if token is None:
            token = self.create_token(random.randint(0, 4))
        
        # 创建头部
        header = self.create_coap_header(
            msg_type=random.choice([self.TYPE_ACKNOWLEDGEMENT, self.TYPE_NON_CONFIRMABLE]),
            token_length=len(token),
            code=response_code
        )
        
        # 创建选项
        options = b''
        current_option_number = 0
        
        # 如果有载荷，添加Content-Format选项
        if payload:
            content_format = self.CONTENT_FORMAT_APPLICATION_JSON if payload.startswith('{') else self.CONTENT_FORMAT_TEXT_PLAIN
            content_format_option = self.encode_option(self.OPTION_CONTENT_FORMAT, struct.pack('B', content_format))
            options += content_format_option
            
            # Max-Age选项（随机添加）
            if random.random() < 0.4:
                max_age = random.randint(60, 3600)
                max_age_option = self.encode_option(self.OPTION_MAX_AGE - self.OPTION_CONTENT_FORMAT, struct.pack('>L', max_age))
                options += max_age_option
        
        # 载荷标记和载荷
        payload_marker = b'\xFF' if payload else b''
        payload_bytes = payload.encode('utf-8') if payload else b''
        
        return header + token + options + payload_marker + payload_bytes
    
    def create_ack_response(self, token: Optional[bytes] = None) -> bytes:
        """创建ACK响应"""
        response_payloads = [
            '{"status": "ok"}',
            '{"temperature": 22.5, "timestamp": 1635789123}',
            '{"result": "success"}',
            'Data received',
            None  # 空载荷
        ]
        payload = random.choice(response_payloads)
        
        response_codes = [
            self.RESPONSE_CONTENT,
            self.RESPONSE_CREATED,
            self.RESPONSE_CHANGED,
            self.RESPONSE_DELETED
        ]
        response_code = random.choice(response_codes)
        
        return self.create_response(response_code, token, payload)
    
    def create_error_response(self, token: Optional[bytes] = None) -> bytes:
        """创建错误响应"""
        error_codes = [
            self.RESPONSE_BAD_REQUEST,
            self.RESPONSE_UNAUTHORIZED,
            self.RESPONSE_FORBIDDEN,
            self.RESPONSE_NOT_FOUND,
            self.RESPONSE_METHOD_NOT_ALLOWED,
            self.RESPONSE_INTERNAL_SERVER_ERROR,
            self.RESPONSE_NOT_IMPLEMENTED,
            self.RESPONSE_SERVICE_UNAVAILABLE
        ]
        error_code = random.choice(error_codes)
        
        error_payloads = [
            '{"error": "Bad Request"}',
            '{"error": "Not Found"}',
            '{"error": "Internal Server Error"}',
            'Unauthorized access',
            None
        ]
        payload = random.choice(error_payloads)
        
        return self.create_response(error_code, token, payload)
    
    def generate_messages(self, count: int = 100) -> List[bytes]:
        """
        生成多样化的CoAP消息（并存储以保证CSV和PCAP一致性）
        恢复为完全原始高多样性逻辑
        """
        messages = []
        self.stored_messages = []
        for i in range(count):
            # 随机选择消息类型
            msg_type = random.choice([
                'get_request',
                'post_request',
                'put_request',
                'delete_request',
                'ack_response',
                'error_response'
            ])
            if msg_type == 'get_request':
                uri_paths = [ "temperature","humidity","sensors/001","status", "well-known/core","actuators/led","data/latest" ]
                uri_path = random.choice(uri_paths)
                uri_host = random.choice([None, "coap.example.com", "192.168.1.100"])
                message = self.create_get_request(uri_path, uri_host)
            elif msg_type == 'post_request':
                uri_paths = [ "sensors", "data", "measurements","events","notifications" ]
                uri_path = random.choice(uri_paths)
                message = self.create_post_request(uri_path)
            elif msg_type == 'put_request':
                uri_paths = [ "actuators/led", "settings/threshold", "config/interval", "control/pump", "devices/001/state" ]
                uri_path = random.choice(uri_paths)
                message = self.create_put_request(uri_path)
            elif msg_type == 'delete_request':
                uri_paths = [ "temp-sensors/001", "measurements/old", "cache/expired", "sessions/abc123", "logs/debug" ]
                uri_path = random.choice(uri_paths)
                message = self.create_delete_request(uri_path)
            elif msg_type == 'ack_response':
                message = self.create_ack_response()
            elif msg_type == 'error_response':
                message = self.create_error_response()
            else:
                message = self.create_get_request()
            messages.append(message)
            self.stored_messages.append(message)
        return messages
    
    def generate_packets(self, count: int = 100) -> List[Packet]:
        """生成CoAP数据包"""
        packets = []
        messages = self.generate_messages(count)
        
        for message in messages:
            src_ip = self._generate_random_ip()
            dst_ip = self._generate_random_ip()
            src_mac = self._generate_random_mac()
            dst_mac = self._generate_random_mac()
            src_port = random.randint(1024, 65535)
            dst_port = 5683  # CoAP端口
            
            # 创建数据包
            packet = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=message)
            packets.append(packet)
        
        return packets
    
    def save_to_pcap(self, filename: str, packets: Optional[List[Packet]] = None):
        """保存数据包到PCAP文件"""
        if packets is None:
            packets = self.generated_packets
        
        if not packets:
            raise ValueError("没有数据包可保存")
        
        wrpcap(filename, packets)
        print(f"已保存 {len(packets)} 个CoAP数据包到 {filename}")
    
    def save_to_csv(self, filename: str):
        """保存生成的消息到CSV文件（使用已生成的消息保证一致性）"""
        if not hasattr(self, 'stored_messages') or not self.stored_messages:
            raise ValueError("没有已生成的消息可保存，请先调用generate_messages()")
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Hex', 'Segment', 'Field Names'])  # 修正：Segments -> Segment
            
            for message in self.stored_messages:
                hex_data = message.hex()
                segments, field_names = self._parse_coap_message(message)
                writer.writerow([hex_data, str(segments), str(field_names)])
    
    def _parse_coap_message(self, data: bytes) -> Tuple[List[Tuple[int, int]], List[str]]:
        """正确解析CoAP消息结构"""
        segments = []
        field_names = []
        
        if len(data) < 4:
            return segments, field_names
        
        # === CoAP Header (4 bytes) ===
        segments.extend([
            (0, 1),   # Version + Type + Token Length
            (1, 2),   # Code
            (2, 4),   # Message ID
        ])
        field_names.extend(['Ver+Type+TKL', 'Code', 'Message ID'])
        
        # === Token ===
        first_byte = data[0]
        token_length = first_byte & 0x0F
        offset = 4
        
        if token_length > 0:
            if offset + token_length > len(data):
                # Token 超出范围，按实际截断或报错（这里保守处理）
                token_end = len(data)
            else:
                token_end = offset + token_length
            segments.append((offset, token_end))
            field_names.append('Token')
            offset = token_end
        
        # === Options ===
        current_option_number = 0
        
        while offset < len(data):
            if data[offset] == 0xFF:
                # Payload marker
                segments.append((offset, offset + 1))
                field_names.append('Payload Marker')
                offset += 1
                break
            
            option_start = offset
            option_header = data[offset]
            delta = (option_header >> 4) & 0x0F
            length = option_header & 0x0F
            offset += 1
            
            # --- Parse Delta ---
            if delta == 13:
                if offset >= len(data):
                    break
                delta_ext = data[offset]
                current_option_number += 13 + delta_ext
                offset += 1
            elif delta == 14:
                if offset + 1 >= len(data):
                    break
                delta_ext = struct.unpack('>H', data[offset:offset+2])[0]
                current_option_number += 269 + delta_ext
                offset += 2
            elif delta < 13:
                current_option_number += delta
            else:  # delta == 15，RFC 7252 规定为保留，应终止选项解析
                break
            
            # --- Parse Length ---
            option_value_length = 0
            if length == 13:
                if offset >= len(data):
                    break
                option_value_length = 13 + data[offset]
                offset += 1
            elif length == 14:
                if offset + 1 >= len(data):
                    break
                option_value_length = 269 + struct.unpack('>H', data[offset:offset+2])[0]
                offset += 2
            elif length < 13:
                option_value_length = length
            else:  # length == 15，非法
                break
            
            # --- Option Value ---
            option_value_end = offset + option_value_length
            if option_value_end > len(data):
                # Value 超出范围，按实际截断
                option_value_end = len(data)
            
            segments.append((option_start, option_value_end))
            field_names.append(f'Option({current_option_number})')
            offset = option_value_end
        
        # === Payload ===
        if offset < len(data):
            segments.append((offset, len(data)))
            field_names.append('Payload')
        
        return segments, field_names


def main():
    generator = CoAPGenerator()
    print("开始生成CoAP协议消息...")

    # 生成原始 CoAP 消息（bytes）
    messages = generator.generate_messages(5000)
    
    # 用这些消息生成 packets 用于 pcap
    packets = []
    for message in messages:
        src_ip = generator._generate_random_ip()
        dst_ip = generator._generate_random_ip()
        src_mac = generator._generate_random_mac()
        dst_mac = generator._generate_random_mac()
        src_port = random.randint(1024, 65535)
        dst_port = 5683

        packet = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=message)
        packets.append(packet)

    # 保存
    os.makedirs("pcap", exist_ok=True)
    os.makedirs("csv", exist_ok=True)

    wrpcap("pcap/coap_messages.pcap", packets)
    generator.save_to_csv("csv/coap_messages.csv")

    print(f"生成完成！PCAP: pcap/coap_messages.pcap, CSV: csv/coap_messages.csv")
    print(f"消息数量: PCAP={len(packets)}, CSV={len(generator.stored_messages)}")


if __name__ == "__main__":
    main()