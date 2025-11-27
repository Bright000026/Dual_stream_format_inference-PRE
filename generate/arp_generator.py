#!/usr/bin/env python3
"""
ARP协议消息生成器
严格按照RFC 826标准规范实现
支持生成多样化的ARP请求和响应消息
"""

import struct
import socket
import random
import ipaddress
from typing import List, Dict, Any, Optional
from scapy.all import Ether, ARP, wrpcap, Packet
import json


class ARPGenerator:
    """ARP协议消息生成器，严格按照RFC 826标准"""
    
    # ARP操作码（RFC 826）
    ARP_REQUEST = 1
    ARP_REPLY = 2
    
    # 硬件类型（RFC 826）
    HTYPE_ETHERNET = 1
    
    # 协议类型（RFC 826）
    PTYPE_IPV4 = 0x0800
    
    # 硬件地址长度（以太网）
    HLEN_ETHERNET = 6
    
    # 协议地址长度（IPv4）
    PLEN_IPV4 = 4
    
    def __init__(self):
        """初始化ARP生成器"""
        self.generated_packets = []
        self.packet_info = []
        
    def generate_random_mac(self) -> str:
        """生成随机MAC地址"""
        # 确保第一个字节的最低位为0（单播地址）
        first_byte = random.randint(0, 254) & 0xFE
        mac_bytes = [first_byte] + [random.randint(0, 255) for _ in range(5)]
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    
    def generate_random_ip(self, subnet: str = "192.168.1.0/24") -> str:
        """在指定子网中生成随机IP地址"""
        network = ipaddress.IPv4Network(subnet, strict=False)
        # 避免网络地址和广播地址
        hosts = list(network.hosts())
        return str(random.choice(hosts))
    
    def mac_to_bytes(self, mac: str) -> bytes:
        """将MAC地址字符串转换为字节"""
        return bytes.fromhex(mac.replace(':', ''))
    
    def ip_to_bytes(self, ip: str) -> bytes:
        """将IP地址字符串转换为字节"""
        return socket.inet_aton(ip)
    
    def create_arp_packet(self, 
                         operation: int,
                         sender_mac: Optional[str] = None,
                         sender_ip: Optional[str] = None,
                         target_mac: Optional[str] = None,
                         target_ip: Optional[str] = None,
                         eth_src: Optional[str] = None,
                         eth_dst: Optional[str] = None) -> Packet:
        """
        创建ARP数据包，严格按照RFC 826规范
        
        Args:
            operation: ARP操作码（1=请求，2=响应）
            sender_mac: 发送方MAC地址
            sender_ip: 发送方IP地址
            target_mac: 目标MAC地址
            target_ip: 目标IP地址
            eth_src: 以太网源MAC地址
            eth_dst: 以太网目标MAC地址
        """
        # 生成默认值以增加多样性
        if sender_mac is None:
            sender_mac = self.generate_random_mac()
        if sender_ip is None:
            sender_ip = self.generate_random_ip()
        if target_ip is None:
            target_ip = self.generate_random_ip()
        
        # 对于ARP请求，目标MAC通常为00:00:00:00:00:00
        if operation == self.ARP_REQUEST and target_mac is None:
            target_mac = "00:00:00:00:00:00"
        elif operation == self.ARP_REPLY and target_mac is None:
            target_mac = self.generate_random_mac()
        
        # 以太网层默认值
        if eth_src is None:
            eth_src = sender_mac
        if eth_dst is None:
            if operation == self.ARP_REQUEST:
                eth_dst = "ff:ff:ff:ff:ff:ff"  # 广播
            else:
                eth_dst = target_mac
        
        # 创建以太网头部
        eth_packet = Ether(src=eth_src, dst=eth_dst)
        
        # 创建ARP头部
        arp_packet = ARP(
            hwtype=self.HTYPE_ETHERNET,    # 硬件类型：以太网
            ptype=self.PTYPE_IPV4,         # 协议类型：IPv4
            hwlen=self.HLEN_ETHERNET,      # 硬件地址长度：6字节
            plen=self.PLEN_IPV4,           # 协议地址长度：4字节
            op=operation,                   # 操作码
            hwsrc=sender_mac,              # 发送方硬件地址
            psrc=sender_ip,                # 发送方协议地址
            hwdst=target_mac,              # 目标硬件地址
            pdst=target_ip                 # 目标协议地址
        )
        
        # 组合完整数据包
        packet = eth_packet / arp_packet
        
        # 记录数据包信息
        packet_info = {
            "type": "ARP_REQUEST" if operation == self.ARP_REQUEST else "ARP_REPLY",
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "arp_hwtype": self.HTYPE_ETHERNET,
            "arp_ptype": self.PTYPE_IPV4,
            "arp_hwlen": self.HLEN_ETHERNET,
            "arp_plen": self.PLEN_IPV4,
            "arp_op": operation,
            "arp_hwsrc": sender_mac,
            "arp_psrc": sender_ip,
            "arp_hwdst": target_mac,
            "arp_pdst": target_ip,
            "packet_size": len(packet)
        }
        
        self.packet_info.append(packet_info)
        return packet
    
    def generate_diverse_arp_packets(self, count: int = 100) -> List[Packet]:
        """生成多样化的ARP数据包"""
        packets = []
        
        # 定义不同的子网以增加多样性
        subnets = [
            "192.168.1.0/24",
            "10.0.0.0/24",
            "172.16.1.0/24",
            "192.168.100.0/24"
        ]
        
        for i in range(count):
            # 随机选择操作类型
            operation = random.choice([self.ARP_REQUEST, self.ARP_REPLY])
            
            # 随机选择子网
            subnet = random.choice(subnets)
            
            # 生成数据包
            packet = self.create_arp_packet(
                operation=operation,
                sender_ip=self.generate_random_ip(subnet),
                target_ip=self.generate_random_ip(subnet)
            )
            
            packets.append(packet)
        
        self.generated_packets.extend(packets)
        return packets
    
    def generate_specific_scenarios(self) -> List[Packet]:
        """生成特定场景的ARP数据包"""
        packets = []
        
        # 场景1：典型的ARP请求-响应对
        request = self.create_arp_packet(
            operation=self.ARP_REQUEST,
            sender_mac="aa:bb:cc:dd:ee:01",
            sender_ip="192.168.1.100",
            target_ip="192.168.1.1"
        )
        
        response = self.create_arp_packet(
            operation=self.ARP_REPLY,
            sender_mac="aa:bb:cc:dd:ee:02",
            sender_ip="192.168.1.1",
            target_mac="aa:bb:cc:dd:ee:01",
            target_ip="192.168.1.100"
        )
        
        packets.extend([request, response])
        
        # 场景2：网关ARP请求
        gateway_request = self.create_arp_packet(
            operation=self.ARP_REQUEST,
            sender_mac="aa:bb:cc:dd:ee:03",
            sender_ip="192.168.1.50",
            target_ip="192.168.1.1"  # 网关IP
        )
        
        packets.append(gateway_request)
        
        # 场景3：ARP公告（Gratuitous ARP）
        gratuitous_arp = self.create_arp_packet(
            operation=self.ARP_REQUEST,
            sender_mac="aa:bb:cc:dd:ee:04",
            sender_ip="192.168.1.200",
            target_ip="192.168.1.200"  # 源和目标IP相同
        )
        
        packets.append(gratuitous_arp)
        
        self.generated_packets.extend(packets)
        return packets
    
    def save_to_pcap(self, filename: str, packets: Optional[List[Packet]] = None):
        """保存数据包到PCAP文件"""
        if packets is None:
            packets = self.generated_packets
        
        if not packets:
            raise ValueError("没有数据包可保存")
        
        wrpcap(filename, packets)
        print(f"已保存 {len(packets)} 个ARP数据包到 {filename}")
    
    def save_to_csv(self, filename: str):
        """保存生成的消息到CSV文件 - 只包含ARP协议数据"""
        if not self.generated_packets:
            raise ValueError("没有数据包可保存")
        
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            
            for i, packet in enumerate(self.generated_packets):
                # 提取ARP层数据
                if packet.haslayer(ARP):
                    arp_layer = packet[ARP]
                    arp_data = bytes(arp_layer)
                    
                    hex_data = arp_data.hex()
                    
                    # 解析ARP头部字段（按RFC 826顺序）
                    segments_list = []
                    field_names_list = []
                    
                    # ARP头部字段（28字节）
                    segments_list.append((0, 2))     # Hardware Type (2字节)
                    field_names_list.append('Hardware Type')
                    
                    segments_list.append((2, 4))     # Protocol Type (2字节)
                    field_names_list.append('Protocol Type')
                    
                    segments_list.append((4, 5))     # Hardware Address Length (1字节)
                    field_names_list.append('Hardware Address Length')
                    
                    segments_list.append((5, 6))     # Protocol Address Length (1字节)
                    field_names_list.append('Protocol Address Length')
                    
                    segments_list.append((6, 8))     # ARP Opcode (2字节)
                    field_names_list.append('ARP Opcode')
                    
                    segments_list.append((8, 14))    # Sender Hardware Address (6字节)
                    field_names_list.append('Sender Hardware Address')
                    
                    segments_list.append((14, 18))   # Sender Protocol Address (4字节)
                    field_names_list.append('Sender Protocol Address')
                    
                    segments_list.append((18, 24))   # Target Hardware Address (6字节)
                    field_names_list.append('Target Hardware Address')
                    
                    segments_list.append((24, 28))   # Target Protocol Address (4字节)
                    field_names_list.append('Target Protocol Address')
                    
                    writer.writerow([hex_data, str(segments_list), str(field_names_list)])
        
        print(f"ARP协议CSV文件已保存到 {filename}")
    
    def get_diversity_stats(self) -> Dict[str, Any]:
        """获取多样性统计信息"""
        if not self.packet_info:
            return {}
        
        # 统计不同的值
        operations = set(info['arp_op'] for info in self.packet_info)
        src_ips = set(info['arp_psrc'] for info in self.packet_info)
        dst_ips = set(info['arp_pdst'] for info in self.packet_info)
        src_macs = set(info['arp_hwsrc'] for info in self.packet_info)
        dst_macs = set(info['arp_hwdst'] for info in self.packet_info)
        
        return {
            "total_packets": len(self.packet_info),
            "unique_operations": len(operations),
            "operations": list(operations),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "unique_src_macs": len(src_macs),
            "unique_dst_macs": len(dst_macs),
            "diversity_score": {
                "operation_diversity": len(operations) / 2,  # 最多2种操作
                "ip_diversity": len(src_ips | dst_ips) / (len(src_ips) + len(dst_ips)),
                "mac_diversity": len(src_macs | dst_macs) / (len(src_macs) + len(dst_macs))
            }
        }


def main():
    """主函数：演示ARP生成器的使用"""
    generator = ARPGenerator()
    
    print("开始生成ARP协议消息...")
    
    # 生成多样化的ARP数据包
    diverse_packets = generator.generate_diverse_arp_packets(5000)
    print(f"生成了 {len(diverse_packets)} 个多样化ARP数据包")
    
    # 生成特定场景的数据包
    scenario_packets = generator.generate_specific_scenarios()
    print(f"生成了 {len(scenario_packets)} 个场景化ARP数据包")
    
    # 保存到文件
    all_packets = diverse_packets + scenario_packets
    
    # 生成输出文件名 - 修改为新的目录结构
    pcap_file = "pcap/arp_messages.pcap"
    csv_file = "csv/arp_messages.csv"
    
    generator.save_to_pcap(pcap_file, all_packets)
    generator.save_to_csv(csv_file)
    
    # 显示多样性统计
    stats = generator.get_diversity_stats()
    print("\n多样性统计:")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    
    print(f"\n生成完成！总共生成 {len(all_packets)} 个ARP数据包")
    print(f"PCAP文件: {pcap_file}")
    print(f"CSV文件: {csv_file}")


if __name__ == "__main__":
    main()