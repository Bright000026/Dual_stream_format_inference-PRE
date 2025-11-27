#!/usr/bin/env python3
"""
MQTT Protocol Message Generator
基于OASIS MQTT v3.1.1和v5.0标准规范

MQTT控制报文类型：
1 - CONNECT：客户端请求连接到服务器
2 - CONNACK：连接确认
3 - PUBLISH：发布消息
4 - PUBACK：发布确认(QoS 1)
5 - PUBREC：发布收到(QoS 2)
6 - PUBREL：发布释放(QoS 2)
7 - PUBCOMP：发布完成(QoS 2)
8 - SUBSCRIBE：客户端订阅请求
9 - SUBACK：订阅确认
10 - UNSUBSCRIBE：客户端取消订阅请求
11 - UNSUBACK：取消订阅确认
12 - PINGREQ：心跳请求
13 - PINGRESP：心跳响应
14 - DISCONNECT：断开连接
"""

import struct
import random
import csv
import logging
from typing import List, Tuple, Dict, Optional, Any
from datetime import datetime
from scapy.all import Ether, IP, TCP, Raw, wrpcap, Packet

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# MQTT控制报文类型常量
MQTT_CONNECT = 1
MQTT_CONNACK = 2
MQTT_PUBLISH = 3
MQTT_PUBACK = 4
MQTT_PUBREC = 5
MQTT_PUBREL = 6
MQTT_PUBCOMP = 7
MQTT_SUBSCRIBE = 8
MQTT_SUBACK = 9
MQTT_UNSUBSCRIBE = 10
MQTT_UNSUBACK = 11
MQTT_PINGREQ = 12
MQTT_PINGRESP = 13
MQTT_DISCONNECT = 14

# QoS级别
QOS_0 = 0  # 最多一次
QOS_1 = 1  # 至少一次
QOS_2 = 2  # 只有一次

# 连接返回码
CONN_ACCEPTED = 0x00
CONN_REFUSED_PROTOCOL_VERSION = 0x01
CONN_REFUSED_IDENTIFIER_REJECTED = 0x02
CONN_REFUSED_SERVER_UNAVAILABLE = 0x03
CONN_REFUSED_BAD_USERNAME_PASSWORD = 0x04
CONN_REFUSED_NOT_AUTHORIZED = 0x05

class MQTTGenerator:
    def __init__(self):
        self.generated_messages = []
        self.packet_id_counter = 1
        
    def encode_string(self, s: str) -> bytes:
        """编码UTF-8字符串，前缀长度字段"""
        encoded = s.encode('utf-8')
        return struct.pack('>H', len(encoded)) + encoded
    
    def encode_remaining_length(self, length: int) -> bytes:
        """编码剩余长度字段（可变长度编码）"""
        encoded = bytearray()
        while True:
            byte = length % 128
            length = length // 128
            if length > 0:
                byte |= 0x80
            encoded.append(byte)
            if length == 0:
                break
        return bytes(encoded)
    
    def create_fixed_header(self, msg_type: int, flags: int = 0, remaining_length: int = 0) -> bytes:
        """创建MQTT固定头部"""
        # 第一个字节：消息类型(4位) + 标志位(4位)
        first_byte = (msg_type << 4) | (flags & 0x0F)
        header = bytes([first_byte])
        
        # 剩余长度字段
        header += self.encode_remaining_length(remaining_length)
        
        return header
    
    def create_connect_message(self, client_id: Optional[str] = None, username: Optional[str] = None, 
                             password: Optional[str] = None, will_topic: Optional[str] = None, 
                             will_message: Optional[str] = None, clean_session: bool = True,
                             keep_alive: int = 60, protocol_version: int = 4) -> bytes:
        """创建CONNECT消息"""
        if client_id is None:
            client_id = f"mqtt_client_{random.randint(1000, 9999)}"
        
        # 可变头部
        variable_header = bytearray()
        
        # 协议名称
        if protocol_version == 4:
            protocol_name = "MQTT"
        else:
            protocol_name = "MQIsdp"
        variable_header.extend(self.encode_string(protocol_name))
        
        # 协议级别
        variable_header.append(protocol_version)
        
        # 连接标志
        connect_flags = 0
        if clean_session:
            connect_flags |= 0x02
        if will_topic and will_message:
            connect_flags |= 0x04  # Will Flag
            connect_flags |= (QOS_0 << 3)  # Will QoS
        if password:
            connect_flags |= 0x40
        if username:
            connect_flags |= 0x80
        variable_header.append(connect_flags)
        
        # 保持连接时间
        variable_header.extend(struct.pack('>H', keep_alive))
        
        # 有效载荷
        payload = bytearray()
        payload.extend(self.encode_string(client_id))
        
        if will_topic and will_message:
            payload.extend(self.encode_string(will_topic))
            payload.extend(self.encode_string(will_message))
        
        if username:
            payload.extend(self.encode_string(username))
        
        if password:
            payload.extend(self.encode_string(password))
        
        # 计算剩余长度
        remaining_length = len(variable_header) + len(payload)
        
        # 创建固定头部
        fixed_header = self.create_fixed_header(MQTT_CONNECT, 0, remaining_length)
        
        return fixed_header + variable_header + payload
    
    def create_connack_message(self, session_present: bool = False, 
                              return_code: int = CONN_ACCEPTED) -> bytes:
        """创建CONNACK消息"""
        # 可变头部
        variable_header = bytearray()
        
        # 连接确认标志
        ack_flags = 0x01 if session_present else 0x00
        variable_header.append(ack_flags)
        
        # 连接返回码
        variable_header.append(return_code)
        
        # 创建固定头部
        fixed_header = self.create_fixed_header(MQTT_CONNACK, 0, len(variable_header))
        
        return fixed_header + variable_header
    
    def create_publish_message(self, topic: str, payload: Optional[str] = None, 
                             qos: int = QOS_0, retain: bool = False, 
                             dup: bool = False, packet_id: Optional[int] = None) -> bytes:
        """创建PUBLISH消息"""
        if payload is None:
            payload = f"test_message_{random.randint(1, 1000)}"
        
        # 标志位
        flags = 0
        if retain:
            flags |= 0x01
        flags |= (qos << 1)
        if dup:
            flags |= 0x08
        
        # 可变头部
        variable_header = bytearray()
        variable_header.extend(self.encode_string(topic))
        
        # QoS > 0需要包标识符
        if qos > 0:
            if packet_id is None:
                packet_id = self.packet_id_counter
                self.packet_id_counter += 1
            variable_header.extend(struct.pack('>H', packet_id))
        
        # 有效载荷
        payload_bytes = payload.encode('utf-8')
        
        # 计算剩余长度
        remaining_length = len(variable_header) + len(payload_bytes)
        
        # 创建固定头部
        fixed_header = self.create_fixed_header(MQTT_PUBLISH, flags, remaining_length)
        
        return fixed_header + variable_header + payload_bytes
    
    def create_puback_message(self, packet_id: int) -> bytes:
        """创建PUBACK消息（QoS 1确认）"""
        variable_header = struct.pack('>H', packet_id)
        fixed_header = self.create_fixed_header(MQTT_PUBACK, 0, len(variable_header))
        return fixed_header + variable_header
    
    def create_subscribe_message(self, topics: List[Tuple[str, int]], 
                               packet_id: Optional[int] = None) -> bytes:
        """创建SUBSCRIBE消息"""
        if packet_id is None:
            packet_id = self.packet_id_counter
            self.packet_id_counter += 1
        
        # 可变头部
        variable_header = struct.pack('>H', packet_id)
        
        # 有效载荷
        payload = bytearray()
        for topic, qos in topics:
            payload.extend(self.encode_string(topic))
            payload.append(qos)
        
        # 计算剩余长度
        remaining_length = len(variable_header) + len(payload)
        
        # 创建固定头部（标志位必须是0010）
        fixed_header = self.create_fixed_header(MQTT_SUBSCRIBE, 0x02, remaining_length)
        
        return fixed_header + variable_header + payload
    
    def create_suback_message(self, packet_id: int, return_codes: List[int]) -> bytes:
        """创建SUBACK消息"""
        # 可变头部
        variable_header = struct.pack('>H', packet_id)
        
        # 有效载荷
        payload = bytes(return_codes)
        
        # 计算剩余长度
        remaining_length = len(variable_header) + len(payload)
        
        # 创建固定头部
        fixed_header = self.create_fixed_header(MQTT_SUBACK, 0, remaining_length)
        
        return fixed_header + variable_header + payload
    
    def create_unsubscribe_message(self, topics: List[str], 
                                 packet_id: Optional[int] = None) -> bytes:
        """创建UNSUBSCRIBE消息"""
        if packet_id is None:
            packet_id = self.packet_id_counter
            self.packet_id_counter += 1
        
        # 可变头部
        variable_header = struct.pack('>H', packet_id)
        
        # 有效载荷
        payload = bytearray()
        for topic in topics:
            payload.extend(self.encode_string(topic))
        
        # 计算剩余长度
        remaining_length = len(variable_header) + len(payload)
        
        # 创建固定头部（标志位必须是0010）
        fixed_header = self.create_fixed_header(MQTT_UNSUBSCRIBE, 0x02, remaining_length)
        
        return fixed_header + variable_header + payload
    
    def create_unsuback_message(self, packet_id: int) -> bytes:
        """创建UNSUBACK消息"""
        variable_header = struct.pack('>H', packet_id)
        fixed_header = self.create_fixed_header(MQTT_UNSUBACK, 0, len(variable_header))
        return fixed_header + variable_header
    
    def create_pingreq_message(self) -> bytes:
        """创建PINGREQ消息"""
        return self.create_fixed_header(MQTT_PINGREQ, 0, 0)
    
    def create_pingresp_message(self) -> bytes:
        """创建PINGRESP消息"""
        return self.create_fixed_header(MQTT_PINGRESP, 0, 0)
    
    def create_disconnect_message(self) -> bytes:
        """创建DISCONNECT消息"""
        return self.create_fixed_header(MQTT_DISCONNECT, 0, 0)
    
    def create_mqtt_tcp_packet(self, src_ip: str, dst_ip: str, src_port: int, 
                              dst_port: int, mqtt_data: bytes, 
                              seq_num: Optional[int] = None, ack_num: Optional[int] = None) -> Packet:
        """创建完整的MQTT TCP数据包"""
        if seq_num is None:
            seq_num = random.randint(1000000, 9999999)
        if ack_num is None:
            ack_num = random.randint(1000000, 9999999)
        
        # 创建以太网帧
        eth = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
        
        # 创建IP包
        ip = IP(src=src_ip, dst=dst_ip)
        
        # 创建TCP段
        tcp = TCP(sport=src_port, dport=dst_port, seq=seq_num, ack=ack_num, flags="PA")
        
        # 创建原始数据
        raw_data = Raw(load=mqtt_data)
        
        # 组装完整数据包
        packet = eth / ip / tcp / raw_data
        
        return packet
    
    def bytes_to_hex_with_segments(self, data: bytes, segments: List[Tuple[int, int, str]]) -> Tuple[str, str, str]:
        """将字节数据转换为十六进制，并生成段划分和字段名称 - 符合smb_messages.csv格式"""
        hex_str = data.hex()
        
        # 生成段划分和字段名称 - 直接使用字节偏移
        segments_list = []
        field_names_list = []
        
        for start_byte, length_bytes, name in segments:
            # 直接使用字节偏移，不需要转换为十六进制字符偏移
            end_byte = start_byte + length_bytes
            segments_list.append((start_byte, end_byte))
            field_names_list.append(name)
        
        return hex_str, str(segments_list), str(field_names_list)
    
    def get_mqtt_message_segments(self, msg_type: int, data: bytes) -> List[Tuple[int, int, str]]:
        """获取MQTT消息的字段段划分信息"""
        segments = []
        
        if len(data) == 0:
            return segments
        
        # 固定头部
        segments.append((0, 1, "Message Type & Flags"))
        
        # 剩余长度字段（可变长度）
        remaining_len_bytes = 1
        pos = 1
        while pos < len(data) and (data[pos] & 0x80):
            remaining_len_bytes += 1
            pos += 1
        
        segments.append((1, remaining_len_bytes, "Remaining Length"))
        current_pos = 1 + remaining_len_bytes
        
        # 根据消息类型添加具体字段
        if msg_type == MQTT_CONNECT:
            if current_pos + 10 <= len(data):
                segments.extend([
                    (current_pos, 2, "Protocol Name Length"),
                    (current_pos + 2, 4, "Protocol Name"),
                    (current_pos + 6, 1, "Protocol Level"),
                    (current_pos + 7, 1, "Connect Flags"),
                    (current_pos + 8, 2, "Keep Alive")
                ])
                current_pos += 10
                
                # 客户端ID长度和内容
                if current_pos + 2 <= len(data):
                    client_id_len = struct.unpack('>H', data[current_pos:current_pos + 2])[0]
                    if current_pos + 2 + client_id_len <= len(data):
                        segments.extend([
                            (current_pos, 2, "Client ID Length"),
                            (current_pos + 2, client_id_len, "Client ID")
                        ])
                        current_pos += 2 + client_id_len
                
                # 处理可选的Will Topic、Will Message、Username、Password
                if current_pos < len(data):
                    segments.append((current_pos, len(data) - current_pos, "Optional Fields"))
        
        elif msg_type == MQTT_CONNACK:
            if current_pos + 2 <= len(data):
                segments.extend([
                    (current_pos, 1, "Connect Ack Flags"),
                    (current_pos + 1, 1, "Connect Return Code")
                ])
        
        elif msg_type == MQTT_PUBLISH:
            if current_pos + 2 <= len(data):
                topic_len = struct.unpack('>H', data[current_pos:current_pos + 2])[0]
                if current_pos + 2 + topic_len <= len(data):
                    segments.extend([
                        (current_pos, 2, "Topic Length"),
                        (current_pos + 2, topic_len, "Topic Name")
                    ])
                    current_pos += 2 + topic_len
                    
                    # 检查QoS标志位判断是否有Packet ID
                    flags = data[0] & 0x0F
                    qos = (flags >> 1) & 0x03
                    if qos > 0 and current_pos + 2 <= len(data):
                        segments.append((current_pos, 2, "Packet ID"))
                        current_pos += 2
                    
                    # 剩余部分为有效载荷
                    if current_pos < len(data):
                        segments.append((current_pos, len(data) - current_pos, "Payload"))
        
        elif msg_type in [MQTT_PUBACK, MQTT_PUBREC, MQTT_PUBREL, MQTT_PUBCOMP, MQTT_UNSUBACK]:
            if current_pos + 2 <= len(data):
                segments.append((current_pos, 2, "Packet ID"))
        
        elif msg_type == MQTT_SUBSCRIBE:
            if current_pos + 2 <= len(data):
                segments.append((current_pos, 2, "Packet ID"))
                current_pos += 2
                
                # 主题过滤器
                while current_pos + 3 <= len(data):
                    topic_len = struct.unpack('>H', data[current_pos:current_pos + 2])[0] 
                    if current_pos + 2 + topic_len + 1 <= len(data):
                        segments.extend([
                            (current_pos, 2, "Topic Filter Length"),
                            (current_pos + 2, topic_len, "Topic Filter"),
                            (current_pos + 2 + topic_len, 1, "Requested QoS")
                        ])
                        current_pos += 3 + topic_len
                    else:
                        break
        
        elif msg_type == MQTT_SUBACK:
            if current_pos + 2 <= len(data):
                segments.append((current_pos, 2, "Packet ID"))
                current_pos += 2
                
                # 返回码列表
                if current_pos < len(data):
                    segments.append((current_pos, len(data) - current_pos, "Return Codes"))
        
        elif msg_type == MQTT_UNSUBSCRIBE:
            if current_pos + 2 <= len(data):
                segments.append((current_pos, 2, "Packet ID"))
                current_pos += 2
                
                # 主题过滤器列表
                while current_pos + 2 < len(data):
                    topic_len = struct.unpack('>H', data[current_pos:current_pos + 2])[0]
                    if current_pos + 2 + topic_len <= len(data):
                        segments.extend([
                            (current_pos, 2, "Topic Filter Length"),
                            (current_pos + 2, topic_len, "Topic Filter")
                        ])
                        current_pos += 2 + topic_len
                    else:
                        break
        
        elif msg_type in [MQTT_PINGREQ, MQTT_PINGRESP, MQTT_DISCONNECT]:
            # 这些消息只有固定头部，没有可变头部和有效载荷
            pass
        
        return segments
    
    def generate_diverse_payloads(self) -> List[str]:
        """生成多样化的MQTT载荷，包括更多长消息"""
        short_payloads = [
            "ON", "OFF", "true", "false", "1", "0", "OK", "ERROR"
        ]
        
        medium_payloads = [
            f"{{\"temperature\": {random.randint(15, 35)}, \"humidity\": {random.randint(40, 80)}}}",
            f"{{\"device_id\": \"DEV{random.randint(100, 999)}\", \"status\": \"active\"}}",
            f"{{\"sensor\": \"S{random.randint(1, 99)}\", \"value\": {random.randint(0, 100)}}}",
            f"{{\"user_id\": {random.randint(1000, 9999)}, \"action\": \"login\"}}",
            f"ALERT: System temperature exceeded threshold at {random.randint(1600000000, 1700000000)}",
            f"Device DEV{random.randint(1, 99)} status update: battery level {random.randint(10, 100)}%",
            f"Sensor reading from location {random.randint(1, 50)}: value {random.randint(0, 1000)}"
        ]
        
        # 增加更多长消息（超过8字节）
        long_payloads = [
            f"{{\"timestamp\": {random.randint(1600000000, 1700000000)}, \"device_info\": {{\"id\": \"DEVICE_{random.randint(1000, 9999)}\", \"type\": \"sensor\", \"location\": \"room_{random.randint(1, 20)}\", \"battery\": {random.randint(10, 100)}, \"signal_strength\": {random.randint(-90, -30)}}}, \"data\": {{\"temperature\": {random.randint(15, 35)}, \"humidity\": {random.randint(30, 80)}, \"pressure\": {random.randint(980, 1030)}}}}}",
            
            f"{{\"event_id\": \"{random.randint(100000, 999999)}\", \"event_type\": \"security_alert\", \"severity\": \"high\", \"description\": \"Unauthorized access attempt detected from IP {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}\", \"timestamp\": {random.randint(1600000000, 1700000000)}, \"metadata\": {{\"attempts\": {random.randint(1, 10)}, \"source_country\": \"Unknown\", \"blocked\": true}}}}",
            
            f"{{\"sensor_array\": [{{\"id\": \"S001\", \"value\": {random.randint(0, 100)}}}, {{\"id\": \"S002\", \"value\": {random.randint(0, 100)}}}, {{\"id\": \"S003\", \"value\": {random.randint(0, 100)}}}], \"location\": \"Building_A_Floor_{random.randint(1, 10)}\", \"coordinator\": \"COORD_{random.randint(100, 999)}\", \"timestamp\": {random.randint(1600000000, 1700000000)}, \"status\": \"operational\"}}",
            
            f"SYSTEM_REPORT: Multi-device status update for network segment {random.randint(1, 10)}. Device count: {random.randint(5, 50)}. Active devices: {random.randint(1, 45)}. Inactive devices: {random.randint(0, 5)}. Network utilization: {random.randint(10, 95)}%. Last maintenance: {random.randint(1, 30)} days ago. Next scheduled maintenance: {random.randint(1, 14)} days. Critical alerts: {random.randint(0, 3)}.",
            
            f"DATA_BATCH: {{\"batch_id\": \"{random.randint(10000, 99999)}\", \"samples\": [{{\"time\": {random.randint(1600000000, 1700000000)}, \"temp\": {random.randint(15, 35)}, \"hum\": {random.randint(30, 80)}}}, {{\"time\": {random.randint(1600000000, 1700000000)}, \"temp\": {random.randint(15, 35)}, \"hum\": {random.randint(30, 80)}}}, {{\"time\": {random.randint(1600000000, 1700000000)}, \"temp\": {random.randint(15, 35)}, \"hum\": {random.randint(30, 80)}}}], \"device\": \"SENSOR_{random.randint(100, 999)}\", \"quality\": \"high\"}}",
            
            f"MAINTENANCE_LOG: Device ID {random.randint(1000, 9999)} underwent scheduled maintenance. Operations performed: sensor calibration, firmware update to version {random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}, battery replacement, connectivity test. All systems operational. Next maintenance due in {random.randint(30, 90)} days. Technician: TECH_{random.randint(100, 999)}. Duration: {random.randint(30, 180)} minutes.",
            
            f"{{\"notification\": {{\"type\": \"weather_alert\", \"priority\": \"medium\", \"message\": \"Weather conditions may affect outdoor sensors in zones {random.randint(1, 10)}-{random.randint(11, 20)}\", \"valid_until\": {random.randint(1600000000, 1700000000)}}}, \"affected_devices\": [\"DEV_{random.randint(100, 199)}\", \"DEV_{random.randint(200, 299)}\", \"DEV_{random.randint(300, 399)}\"], \"recommended_action\": \"Monitor closely and adjust thresholds if necessary\"}}"
        ]
        
        # 控制长消息的比例：10%短消息，40%中等消息，50%长消息
        payload_choice = random.random()
        if payload_choice < 0.1:
            return short_payloads
        elif payload_choice < 0.5:
            return medium_payloads
        else:
            return long_payloads
    
    def generate_diverse_mqtt_messages(self, count: int = 100) -> List[Dict[str, Any]]:
        """生成多样化的MQTT消息"""
        messages = []
        
        # 定义主题
        topics = [
            "home/living_room/temperature",
            "home/kitchen/humidity", 
            "office/sensor/motion",
            "factory/machine/status",
            "vehicle/gps/location",
            "smart_city/traffic/flow",
            "agriculture/soil/moisture",
            "healthcare/device/heartrate",
            "security/camera/alert",
            "weather/station/data",
            "energy/meter/consumption",
            "building/hvac/control"
        ]
        
        # MQTT端口 - 只使用标凇端口避免SSL识别问题
        mqtt_ports = [1883]
        
        for i in range(count):
            src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(mqtt_ports)
            
            # 随机选择消息类型
            msg_type = random.choice([
                MQTT_CONNECT, MQTT_CONNACK, MQTT_PUBLISH, MQTT_PUBACK,
                MQTT_SUBSCRIBE, MQTT_SUBACK, MQTT_UNSUBSCRIBE, MQTT_UNSUBACK,
                MQTT_PINGREQ, MQTT_PINGRESP, MQTT_DISCONNECT
            ])
            
            mqtt_data = None
            description = ""
            
            if msg_type == MQTT_CONNECT:
                client_id = f"client_{random.randint(1000, 9999)}"
                mqtt_data = self.create_connect_message(client_id=client_id)
                description = f"CONNECT from {client_id}"
            
            elif msg_type == MQTT_CONNACK:
                return_code = random.choice([0, 1, 2, 3, 4, 5])
                mqtt_data = self.create_connack_message(return_code=return_code)
                description = f"CONNACK code {return_code}"
            
            elif msg_type == MQTT_PUBLISH:
                topic = random.choice(topics)
                # 使用新的多样化载荷生成器
                payload_list = self.generate_diverse_payloads()
                payload = random.choice(payload_list)
                qos = random.choice([0, 1, 2])
                mqtt_data = self.create_publish_message(topic=topic, payload=payload, qos=qos)
                description = f"PUBLISH to {topic} (QoS {qos})"
            
            elif msg_type == MQTT_PUBACK:
                packet_id = random.randint(1, 65535)
                mqtt_data = self.create_puback_message(packet_id)
                description = f"PUBACK for packet {packet_id}"
            
            elif msg_type == MQTT_SUBSCRIBE:
                topic = random.choice(topics)
                qos = random.choice([0, 1, 2])
                mqtt_data = self.create_subscribe_message([(topic, qos)])
                description = f"SUBSCRIBE to {topic} (QoS {qos})"
            
            elif msg_type == MQTT_SUBACK:
                packet_id = random.randint(1, 65535)
                return_codes = [random.choice([0, 1, 2, 0x80])]
                mqtt_data = self.create_suback_message(packet_id, return_codes)
                description = f"SUBACK for packet {packet_id}"
            
            elif msg_type == MQTT_UNSUBSCRIBE:
                topic = random.choice(topics)
                mqtt_data = self.create_unsubscribe_message([topic])
                description = f"UNSUBSCRIBE from {topic}"
            
            elif msg_type == MQTT_UNSUBACK:
                packet_id = random.randint(1, 65535)
                mqtt_data = self.create_unsuback_message(packet_id)
                description = f"UNSUBACK for packet {packet_id}"
            
            elif msg_type == MQTT_PINGREQ:
                mqtt_data = self.create_pingreq_message()
                description = "PINGREQ"
            
            elif msg_type == MQTT_PINGRESP:
                mqtt_data = self.create_pingresp_message()
                description = "PINGRESP"
            
            elif msg_type == MQTT_DISCONNECT:
                mqtt_data = self.create_disconnect_message()
                description = "DISCONNECT"
            
            if mqtt_data:
                # 创建TCP数据包
                packet = self.create_mqtt_tcp_packet(src_ip, dst_ip, src_port, dst_port, mqtt_data)
                
                # 获取段划分信息
                segments = self.get_mqtt_message_segments(msg_type, mqtt_data)
                hex_str, segments_str, field_names = self.bytes_to_hex_with_segments(
                    mqtt_data, segments
                )
                
                message = {
                    'packet': packet,
                    'mqtt_data': mqtt_data,
                    'hex': hex_str,
                    'segments': segments_str,
                    'field_names': field_names,
                    'msg_type': msg_type,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'description': description
                }
                
                messages.append(message)
                self.generated_messages.append(message)
        
        return messages
    
    def save_to_csv(self, filename: str):
        """保存消息到CSV文件（与smb_messages.csv格式一致）"""
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Hex', 'Segment', 'Field Names']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for msg in self.generated_messages:
                writer.writerow({
                    'Hex': msg['hex'],
                    'Segment': msg['segments'],
                    'Field Names': msg['field_names']
                })
        
        logger.info(f"已保存 {len(self.generated_messages)} 条MQTT消息到 {filename}")
    
    def save_to_pcap(self, filename: str):
        """保存数据包到PCAP文件"""
        packets = [msg['packet'] for msg in self.generated_messages]
        wrpcap(filename, packets)
        logger.info(f"已保存 {len(packets)} 个数据包到 {filename}")
    
    def get_diversity_stats(self) -> Dict[str, Any]:
        """获取生成消息的多样性统计"""
        if not self.generated_messages:
            return {}
        
        stats = {
            'total_messages': len(self.generated_messages),
            'message_types': {},
            'unique_src_ips': set(),
            'unique_dst_ips': set(),
            'unique_ports': set(),
            'message_sizes': []
        }
        
        for msg in self.generated_messages:
            # 先检查字段是否存在
            if 'message_type' not in msg:
                continue
                
            msg_type = msg['message_type']
            if msg_type not in stats['message_types']:
                stats['message_types'][msg_type] = 0
            stats['message_types'][msg_type] += 1
            
            stats['unique_src_ips'].add(msg['src_ip'])
            stats['unique_dst_ips'].add(msg['dst_ip'])
            stats['unique_ports'].add(msg['src_port'])
            stats['unique_ports'].add(msg['dst_port'])
            stats['message_sizes'].append(len(msg['mqtt_data']))
        
        # 转换集合为列表以便JSON序列化
        stats['unique_src_ips'] = list(stats['unique_src_ips'])
        stats['unique_dst_ips'] = list(stats['unique_dst_ips'])
        stats['unique_ports'] = list(stats['unique_ports'])
        
        return stats

def main():
    """主函数"""
    logger.info("开始生成MQTT协议消息...")
    
    generator = MQTTGenerator()
    
    # 生成多样化的MQTT消息
    messages = generator.generate_diverse_mqtt_messages(count=7000)
    
    logger.info(f"成功生成 {len(messages)} 条MQTT消息")
    
    # 保存到CSV文件 - 修改输出路径
    generator.save_to_csv('csv/mqtt_messages.csv')
    
    # 保存到PCAP文件 - 修改输出路径
    generator.save_to_pcap('pcap/mqtt_messages.pcap')
    
    # 打印多样性统计
    stats = generator.get_diversity_stats()
    logger.info(f"多样性统计: {stats}")
    
    logger.info("MQTT协议消息生成完成！")

if __name__ == '__main__':
    main()