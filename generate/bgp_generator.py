#!/usr/bin/env python3
"""
BGP Protocol Message Generator
基于RFC 4271标准规范

BGP消息类型：
1 - OPEN：打开连接
2 - UPDATE：路由更新
3 - NOTIFICATION：错误通知
4 - KEEPALIVE：保持连接
"""

import struct
import random
import csv
import logging
import ipaddress
from typing import List, Tuple, Dict, Optional, Any
from datetime import datetime
from scapy.all import Ether, IP, TCP, Raw, wrpcap, Packet

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# BGP消息类型常量
BGP_OPEN = 1
BGP_UPDATE = 2
BGP_NOTIFICATION = 3
BGP_KEEPALIVE = 4

# BGP错误代码
BGP_ERROR_MESSAGE_HEADER = 1
BGP_ERROR_OPEN_MESSAGE = 2
BGP_ERROR_UPDATE_MESSAGE = 3
BGP_ERROR_HOLD_TIMER_EXPIRED = 4
BGP_ERROR_FINITE_STATE_MACHINE = 5
BGP_ERROR_CEASE = 6

# BGP路径属性类型
BGP_ATTR_ORIGIN = 1
BGP_ATTR_AS_PATH = 2
BGP_ATTR_NEXT_HOP = 3
BGP_ATTR_MULTI_EXIT_DISC = 4
BGP_ATTR_LOCAL_PREF = 5
BGP_ATTR_ATOMIC_AGGREGATE = 6
BGP_ATTR_AGGREGATOR = 7

# BGP原点类型
BGP_ORIGIN_IGP = 0
BGP_ORIGIN_EGP = 1
BGP_ORIGIN_INCOMPLETE = 2

class BGPGenerator:
    def __init__(self):
        self.generated_messages = []
        
    def create_bgp_header(self, length: int, msg_type: int) -> bytes:
        """创建BGP消息头部（19字节）"""
        # BGP标记（16字节全1）
        marker = b'\xff' * 16
        
        # 长度（2字节）+ 类型（1字节）
        header = marker + struct.pack('>HB', length, msg_type)
        
        return header
    
    def create_open_message(self, version: int = 4, my_as: int = 65001, 
                          hold_time: int = 180, bgp_id: str = "192.168.1.1",
                          capabilities: Optional[List[Tuple[int, bytes]]] = None) -> bytes:
        """创建BGP OPEN消息"""
        
        # BGP版本（1字节）
        open_data = struct.pack('B', version)
        
        # 自治系统号（2字节）
        open_data += struct.pack('>H', my_as)
        
        # 保持时间（2字节）
        open_data += struct.pack('>H', hold_time)
        
        # BGP标识符（4字节）
        bgp_id_bytes = struct.pack('>I', int(ipaddress.IPv4Address(bgp_id)))
        open_data += bgp_id_bytes
        
        # 可选参数
        optional_params = b''
        if capabilities:
            for cap_code, cap_data in capabilities:
                # 能力类型（1字节）+ 能力长度（1字节）+ 能力数据
                cap_param = struct.pack('BB', 2, len(cap_data) + 2)  # 参数类型2=能力
                cap_param += struct.pack('BB', cap_code, len(cap_data))
                cap_param += cap_data
                optional_params += cap_param
        
        # 可选参数长度（1字节）
        open_data += struct.pack('B', len(optional_params))
        open_data += optional_params
        
        # 创建完整消息（头部+数据）
        total_length = 19 + len(open_data)
        header = self.create_bgp_header(total_length, BGP_OPEN)
        
        return header + open_data
    
    def create_path_attribute(self, attr_type: int, attr_value: bytes, 
                            optional: bool = False, transitive: bool = True,
                            partial: bool = False, extended_length: bool = False) -> bytes:
        """创建BGP路径属性"""
        
        # 属性标志
        flags = 0
        if optional:
            flags |= 0x80
        if transitive:
            flags |= 0x40
        if partial:
            flags |= 0x20
        if extended_length or len(attr_value) > 255:
            flags |= 0x10
            extended_length = True
        
        # 属性头部
        attr_header = struct.pack('BB', flags, attr_type)
        
        # 属性长度
        if extended_length:
            attr_header += struct.pack('>H', len(attr_value))
        else:
            attr_header += struct.pack('B', len(attr_value))
        
        return attr_header + attr_value
    
    def create_origin_attribute(self, origin: int = BGP_ORIGIN_IGP) -> bytes:
        """创建ORIGIN属性"""
        return self.create_path_attribute(BGP_ATTR_ORIGIN, struct.pack('B', origin))
    
    def create_as_path_attribute(self, as_path: List[int]) -> bytes:
        """创建AS_PATH属性"""
        # AS_PATH段类型：2=AS_SEQUENCE
        path_segment = struct.pack('BB', 2, len(as_path))
        
        # AS号列表（每个AS号2字节）
        for as_num in as_path:
            path_segment += struct.pack('>H', as_num)
        
        return self.create_path_attribute(BGP_ATTR_AS_PATH, path_segment)
    
    def create_next_hop_attribute(self, next_hop: str) -> bytes:
        """创建NEXT_HOP属性"""
        next_hop_bytes = struct.pack('>I', int(ipaddress.IPv4Address(next_hop)))
        return self.create_path_attribute(BGP_ATTR_NEXT_HOP, next_hop_bytes)
    
    def create_update_message(self, withdrawn_routes: Optional[List[Tuple[str, int]]] = None,
                            path_attributes: Optional[List[bytes]] = None,
                            nlri: Optional[List[Tuple[str, int]]] = None) -> bytes:
        """创建BGP UPDATE消息"""
        
        update_data = b''
        
        # 撤回路由长度和撤回路由
        withdrawn_data = b''
        if withdrawn_routes:
            for prefix, prefix_len in withdrawn_routes:
                # 前缀长度（1字节）
                withdrawn_data += struct.pack('B', prefix_len)
                # 前缀（变长）
                prefix_bytes = int(ipaddress.IPv4Address(prefix)).to_bytes(4, 'big')
                # 只包含有效字节
                bytes_needed = (prefix_len + 7) // 8
                withdrawn_data += prefix_bytes[:bytes_needed]
        
        update_data += struct.pack('>H', len(withdrawn_data))
        update_data += withdrawn_data
        
        # 路径属性长度和路径属性
        path_attr_data = b''
        if path_attributes:
            for attr in path_attributes:
                path_attr_data += attr
        
        update_data += struct.pack('>H', len(path_attr_data))
        update_data += path_attr_data
        
        # NLRI（网络层可达性信息）
        nlri_data = b''
        if nlri:
            for prefix, prefix_len in nlri:
                # 前缀长度（1字节）
                nlri_data += struct.pack('B', prefix_len)
                # 前缀（变长）
                prefix_bytes = int(ipaddress.IPv4Address(prefix)).to_bytes(4, 'big')
                # 只包含有效字节
                bytes_needed = (prefix_len + 7) // 8
                nlri_data += prefix_bytes[:bytes_needed]
        
        update_data += nlri_data
        
        # 创建完整消息
        total_length = 19 + len(update_data)
        header = self.create_bgp_header(total_length, BGP_UPDATE)
        
        return header + update_data
    
    def create_notification_message(self, error_code: int, error_subcode: int = 0,
                                  error_data: bytes = b'') -> bytes:
        """创建BGP NOTIFICATION消息"""
        
        notification_data = struct.pack('BB', error_code, error_subcode)
        notification_data += error_data
        
        # 创建完整消息
        total_length = 19 + len(notification_data)
        header = self.create_bgp_header(total_length, BGP_NOTIFICATION)
        
        return header + notification_data
    
    def create_keepalive_message(self) -> bytes:
        """创建BGP KEEPALIVE消息"""
        # KEEPALIVE消息只有头部，没有数据
        return self.create_bgp_header(19, BGP_KEEPALIVE)
    
    def create_bgp_tcp_packet(self, src_ip: str, dst_ip: str, bgp_data: bytes,
                            src_port: int = 179, dst_port: int = 179,
                            seq_num: Optional[int] = None, ack_num: Optional[int] = None) -> Packet:
        """创建完整的BGP TCP数据包"""
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
        raw_data = Raw(load=bgp_data)
        
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
    
    def get_bgp_message_segments(self, msg_type: int, data: bytes) -> List[Tuple[int, int, str]]:
        """获取BGP消息的字段段划分信息"""
        segments = []
        
        # BGP头部（19字节）
        segments.extend([
            (0, 16, "BGP Marker"),
            (16, 2, "Length"),
            (18, 1, "Type")
        ])
        
        current_pos = 19
        
        # 根据消息类型添加具体字段
        if msg_type == BGP_OPEN and current_pos < len(data):
            segments.extend([
                (current_pos, 1, "Version"),
                (current_pos + 1, 2, "My AS"),
                (current_pos + 3, 2, "Hold Time"),
                (current_pos + 5, 4, "BGP Identifier"),
                (current_pos + 9, 1, "Opt Param Length")
            ])
            
            # 可选参数
            if current_pos + 10 < len(data):
                opt_param_len = data[current_pos + 9]
                if opt_param_len > 0:
                    segments.append((current_pos + 10, opt_param_len, "Optional Parameters"))
        
        elif msg_type == BGP_UPDATE and current_pos < len(data):
            # 撤回路由长度
            if current_pos + 2 <= len(data):
                withdrawn_len = struct.unpack('>H', data[current_pos:current_pos + 2])[0]
                segments.append((current_pos, 2, "Withdrawn Routes Length"))
                current_pos += 2
                
                # 撤回路由
                if withdrawn_len > 0 and current_pos + withdrawn_len <= len(data):
                    segments.append((current_pos, withdrawn_len, "Withdrawn Routes"))
                    current_pos += withdrawn_len
                
                # 路径属性长度
                if current_pos + 2 <= len(data):
                    path_attr_len = struct.unpack('>H', data[current_pos:current_pos + 2])[0]
                    segments.append((current_pos, 2, "Path Attr Length"))
                    current_pos += 2
                    
                    # 路径属性
                    if path_attr_len > 0 and current_pos + path_attr_len <= len(data):
                        segments.append((current_pos, path_attr_len, "Path Attributes"))
                        current_pos += path_attr_len
                    
                    # NLRI
                    if current_pos < len(data):
                        segments.append((current_pos, len(data) - current_pos, "NLRI"))
        
        elif msg_type == BGP_NOTIFICATION and current_pos < len(data):
            segments.extend([
                (current_pos, 1, "Error Code"),
                (current_pos + 1, 1, "Error Subcode")
            ])
            
            # 错误数据
            if current_pos + 2 < len(data):
                segments.append((current_pos + 2, len(data) - current_pos - 2, "Error Data"))
        
        # KEEPALIVE消息没有额外数据
        
        return segments
    
    def generate_diverse_bgp_messages(self, count: int = 100) -> List[Dict[str, Any]]:
        """生成多样化的BGP消息"""
        messages = []
        
        # AS号范围
        as_numbers = [65001, 65002, 65003, 65004, 65005, 65010, 65020, 65100]
        
        # BGP路由器ID
        router_ids = [
            "192.168.1.1", "192.168.1.2", "10.0.0.1", "10.0.0.2",
            "172.16.1.1", "172.16.1.2", "203.0.113.1", "198.51.100.1"
        ]
        
        # 网络前缀
        network_prefixes = [
            ("192.168.0.0", 16), ("10.0.0.0", 8), ("172.16.0.0", 12),
            ("203.0.113.0", 24), ("198.51.100.0", 24), ("192.0.2.0", 24),
            ("10.1.0.0", 16), ("172.20.0.0", 16), ("192.168.100.0", 24)
        ]
        
        for i in range(count):
            src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            # 随机选择消息类型
            msg_type = random.choice([BGP_OPEN, BGP_UPDATE, BGP_NOTIFICATION, BGP_KEEPALIVE])
            
            bgp_data = None
            description = ""
            
            if msg_type == BGP_OPEN:
                my_as = random.choice(as_numbers)
                hold_time = random.choice([60, 90, 120, 180, 240])
                bgp_id = random.choice(router_ids)
                
                # 添加一些能力
                capabilities = []
                if random.random() > 0.5:
                    # 四字节AS号能力
                    capabilities.append((65, struct.pack('>I', my_as)))
                
                bgp_data = self.create_open_message(
                    my_as=my_as, hold_time=hold_time, bgp_id=bgp_id,
                    capabilities=capabilities if capabilities else None
                )
                description = f"OPEN from AS{my_as}"
            
            elif msg_type == BGP_UPDATE:
                # 随机决定是否包含各种组件
                withdrawn_routes = None
                path_attributes = []
                nlri = None
                
                if random.random() > 0.7:
                    # 添加撤回路由
                    withdrawn_routes = [random.choice(network_prefixes)]
                
                if random.random() > 0.3:
                    # 添加路径属性
                    path_attributes.append(self.create_origin_attribute())
                    
                    # AS路径
                    as_path = random.sample(as_numbers, random.randint(1, 3))
                    path_attributes.append(self.create_as_path_attribute(as_path))
                    
                    # 下一跳
                    next_hop = random.choice(router_ids)
                    path_attributes.append(self.create_next_hop_attribute(next_hop))
                
                if random.random() > 0.5:
                    # 添加NLRI
                    nlri = [random.choice(network_prefixes)]
                
                bgp_data = self.create_update_message(
                    withdrawn_routes=withdrawn_routes,
                    path_attributes=path_attributes if path_attributes else None,
                    nlri=nlri
                )
                description = "UPDATE message"
            
            elif msg_type == BGP_NOTIFICATION:
                error_code = random.choice([
                    BGP_ERROR_MESSAGE_HEADER, BGP_ERROR_OPEN_MESSAGE,
                    BGP_ERROR_UPDATE_MESSAGE, BGP_ERROR_HOLD_TIMER_EXPIRED,
                    BGP_ERROR_FINITE_STATE_MACHINE, BGP_ERROR_CEASE
                ])
                error_subcode = random.randint(0, 5)
                
                bgp_data = self.create_notification_message(error_code, error_subcode)
                description = f"NOTIFICATION error {error_code}.{error_subcode}"
            
            elif msg_type == BGP_KEEPALIVE:
                bgp_data = self.create_keepalive_message()
                description = "KEEPALIVE"
            
            if bgp_data:
                # 创建TCP数据包
                packet = self.create_bgp_tcp_packet(src_ip, dst_ip, bgp_data=bgp_data)
                
                # 获取段划分信息
                segments = self.get_bgp_message_segments(msg_type, bgp_data)
                hex_str, segments_str, field_names = self.bytes_to_hex_with_segments(
                    bgp_data, segments
                )
                
                message = {
                    'packet': packet,
                    'bgp_data': bgp_data,
                    'hex': hex_str,
                    'segments': segments_str,
                    'field_names': field_names,
                    'message_type': msg_type,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
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
        
        logger.info(f"已保存 {len(self.generated_messages)} 条BGP消息到 {filename}")
    
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
            'message_sizes': []
        }
        
        for msg in self.generated_messages:
            msg_type = msg['message_type']
            if msg_type not in stats['message_types']:
                stats['message_types'][msg_type] = 0
            stats['message_types'][msg_type] += 1
            
            stats['unique_src_ips'].add(msg['src_ip'])
            stats['unique_dst_ips'].add(msg['dst_ip'])
            stats['message_sizes'].append(len(msg['bgp_data']))
        
        # 转换集合为列表以便JSON序列化
        stats['unique_src_ips'] = list(stats['unique_src_ips'])
        stats['unique_dst_ips'] = list(stats['unique_dst_ips'])
        
        return stats

def main():
    """主函数"""
    logger.info("开始生成BGP协议消息...")
    
    generator = BGPGenerator()
    
    # 生成多样化的BGP消息
    messages = generator.generate_diverse_bgp_messages(count=5000)
    
    logger.info(f"成功生成 {len(messages)} 条BGP消息")
    
    # 保存到CSV文件 - 修改输出路径
    generator.save_to_csv('csv/bgp_messages.csv')
    
    # 保存到PCAP文件 - 修改输出路径
    generator.save_to_pcap('pcap/bgp_messages.pcap')
    
    # 打印多样性统计
    stats = generator.get_diversity_stats()
    logger.info(f"多样性统计: {stats}")
    
    logger.info("BGP协议消息生成完成！")

if __name__ == '__main__':
    main()