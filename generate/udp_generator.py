#!/usr/bin/env python3
"""
UDP协议消息生成器
严格按照RFC 768标准规范实现
支持生成多样化的UDP数据包
"""

import struct
import socket
import random
import ipaddress
from typing import List, Dict, Any, Optional
from scapy.all import IP, UDP, Ether, wrpcap, Packet, Raw
import json


class UDPGenerator:
    """UDP协议消息生成器，严格按照RFC 768标准"""
    
    def __init__(self):
        """初始化UDP生成器"""
        self.generated_packets = []
        self.packet_info = []
        
    def generate_random_ip(self, subnet: str = "192.168.1.0/24") -> str:
        """在指定子网中生成随机IP地址"""
        network = ipaddress.IPv4Network(subnet, strict=False)
        hosts = list(network.hosts())
        return str(random.choice(hosts))
    
    def generate_random_mac(self) -> str:
        """生成随机MAC地址"""
        first_byte = random.randint(0, 254) & 0xFE
        mac_bytes = [first_byte] + [random.randint(0, 255) for _ in range(5)]
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    
    def create_udp_packet(self,
                         src_ip: Optional[str] = None,
                         dst_ip: Optional[str] = None,
                         src_port: Optional[int] = None,
                         dst_port: Optional[int] = None,
                         payload: Optional[bytes] = None,
                         eth_src: Optional[str] = None,
                         eth_dst: Optional[str] = None) -> Packet:
        """
        创建UDP数据包，严格按照RFC 768规范
        
        UDP头部格式（8字节）：
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Source Port          |       Destination Port       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |            Length             |           Checksum            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        # 生成默认值
        if src_ip is None:
            src_ip = self.generate_random_ip()
        if dst_ip is None:
            dst_ip = self.generate_random_ip()
        if src_port is None:
            src_port = random.randint(1024, 65535)
        if dst_port is None:
            dst_port = random.choice([53, 67, 68, 69, 123, 161, 162, 514, 1812, 5353])
        if payload is None:
            # 生成随机载荷，限制不超过128字节
            payload_len = random.randint(0, 128)
            payload = bytes(random.getrandbits(8) for _ in range(payload_len))
        if eth_src is None:
            eth_src = self.generate_random_mac()
        if eth_dst is None:
            eth_dst = self.generate_random_mac()
        
        # 创建以太网层
        eth_packet = Ether(src=eth_src, dst=eth_dst)
        
        # 创建IP层
        ip_packet = IP(src=src_ip, dst=dst_ip)
        
        # 创建UDP层
        # UDP长度 = UDP头部(8字节) + 数据长度
        udp_length = 8 + len(payload)
        udp_packet = UDP(
            sport=src_port,
            dport=dst_port,
            len=udp_length
            # checksum会由scapy自动计算
        )
        
        # 组合数据包
        packet = eth_packet / ip_packet / udp_packet
        
        # 添加载荷数据
        if payload:
            packet = packet / Raw(load=payload)
        
        # 记录数据包信息
        packet_info = {
            "type": f"UDP_{dst_port}",
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "ip_src": src_ip,
            "ip_dst": dst_ip,
            "udp_sport": src_port,
            "udp_dport": dst_port,
            "udp_length": udp_length,
            "payload_len": len(payload),
            "packet_size": len(packet)
        }
        
        self.packet_info.append(packet_info)
        return packet
    
    def generate_diverse_udp_payloads(self, size: int) -> bytes:
        """生成多样化的UDP载荷，避免包含DNS、DHCP等协议数据"""
        payload_types = [
            # 网络服务类载荷
            lambda s: f"PING {random.randint(1000, 9999)} data".encode()[:s],
            lambda s: f"ECHO response {random.randint(100, 999)}".encode()[:s],
            lambda s: f"STATUS OK - Service running on port {random.randint(1000, 9999)}".encode()[:s],
            
            # 应用数据类载荷
            lambda s: f"{{\"user_id\": {random.randint(1, 999)}, \"action\": \"login\", \"timestamp\": {random.randint(1600000000, 1700000000)}}}".encode()[:s],
            lambda s: f"{{\"sensor_id\": \"S{random.randint(100, 999)}\", \"temperature\": {random.randint(15, 35)}, \"humidity\": {random.randint(30, 70)}}}".encode()[:s],
            lambda s: f"{{\"device\": \"DEV{random.randint(1, 99)}\", \"status\": \"active\", \"battery\": {random.randint(10, 100)}}}".encode()[:s],
            
            # 游戏协议类载荷
            lambda s: f"GAME_UPDATE player:{random.randint(1, 999)} x:{random.randint(0, 1000)} y:{random.randint(0, 1000)}".encode()[:s],
            lambda s: f"CHAT_MSG user{random.randint(1, 99)}: Hello world! {random.randint(1, 999)}".encode()[:s],
            lambda s: f"SCORE_UPDATE team:{random.randint(1, 4)} score:{random.randint(0, 100)}".encode()[:s],
            
            # 监控数据类载荷
            lambda s: f"HEALTH_CHECK server{random.randint(1, 10)} OK mem:{random.randint(1, 100)}% cpu:{random.randint(1, 100)}%".encode()[:s],
            lambda s: f"LOG_EVENT [{random.randint(1600000000, 1700000000)}] User login successful".encode()[:s],
            lambda s: f"ALERT system_overload threshold_exceeded cpu:{random.randint(80, 100)}%".encode()[:s],
            
            # 测试数据类载荷
            lambda s: f"TEST_PACKET_{random.randint(1000, 9999)} len:{s} checksum:{random.randint(1000, 9999)}".encode()[:s],
            lambda s: f"BENCHMARK run:{random.randint(1, 100)} latency:{random.randint(1, 50)}ms".encode()[:s],
            lambda s: f"DEBUG session:{random.randint(1000, 9999)} state:connected".encode()[:s],
            
            # 二进制数据载荷
            lambda s: bytes([random.randint(1, 255) for _ in range(min(s, random.randint(4, 32)))]),
            lambda s: bytes([i % 256 for i in range(min(s, random.randint(8, 64)))]),
            lambda s: bytes([0xAA, 0xBB, 0xCC, 0xDD] * (s // 4 + 1))[:s],
            lambda s: bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF] * (s // 8 + 1))[:s],
            
            # 文本数据载荷
            lambda s: f"Message {random.randint(1, 999)}: This is a test UDP payload with length {s}".encode()[:s],
            lambda s: f"Stream data chunk {random.randint(1, 999)} of transmission".encode()[:s],
            lambda s: f"Notification: Event {random.randint(1000, 9999)} triggered".encode()[:s],
        ]
        
        payload_func = random.choice(payload_types)
        payload = payload_func(size)
        
        # 确保载荷长度不超过请求大小
        if len(payload) > size:
            payload = payload[:size]
        elif len(payload) < size:
            # 用随机字节填充不足的部分
            padding = bytes(random.randint(1, 255) for _ in range(size - len(payload)))
            payload += padding
            
        return payload
        """生成DNS查询载荷"""
        # DNS头部（12字节）
        dns_id = random.randint(0, 65535)
        flags = 0x0100  # 标准查询
        qdcount = 1     # 1个查询
        ancount = 0     # 0个答案
        nscount = 0     # 0个权威记录
        arcount = 0     # 0个附加记录
        
        header = struct.pack('!HHHHHH', dns_id, flags, qdcount, ancount, nscount, arcount)
        
        # 查询部分
        question = b''
        for label in domain.split('.'):
            question += bytes([len(label)]) + label.encode()
        question += b'\x00'  # 结束标志
        question += struct.pack('!HH', 1, 1)  # A记录，IN类
        
        return header + question
    
    def generate_dhcp_payload(self, msg_type: int = 1) -> bytes:
        """生成DHCP载荷"""
        # DHCP消息格式
        op = msg_type  # 1=请求，2=响应
        htype = 1      # 以太网
        hlen = 6       # MAC地址长度
        hops = 0
        xid = random.randint(0, 0xFFFFFFFF)
        secs = 0
        flags = 0
        ciaddr = 0     # 客户端IP地址
        yiaddr = 0     # 你的IP地址
        siaddr = 0     # 服务器IP地址
        giaddr = 0     # 网关IP地址
        
        # 客户端MAC地址 + 填充
        chaddr = bytes([random.randint(0, 255) for _ in range(6)]) + b'\x00' * 10
        
        # 服务器名称和启动文件名（空填充）
        sname = b'\x00' * 64
        file = b'\x00' * 128
        
        # DHCP魔术cookie
        magic_cookie = b'\x63\x82\x53\x63'
        
        payload = struct.pack('!BBBBIHHHIII', op, htype, hlen, hops, xid, secs, flags,
                             ciaddr, yiaddr, siaddr, giaddr)
        payload += chaddr + sname + file + magic_cookie
        
        return payload
    
    def generate_snmp_payload(self) -> bytes:
        """生成简单的SNMP载荷"""
        # 简化的SNMP GET请求
        community = b"public"
        oid = b"\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        
        # ASN.1编码的SNMP消息
        payload = b"\x30" + bytes([len(community) + len(oid) + 10])
        payload += b"\x02\x01\x00"  # 版本1
        payload += b"\x04" + bytes([len(community)]) + community
        payload += b"\xa0" + bytes([len(oid) + 6])
        payload += b"\x02\x01\x00"  # 请求ID
        payload += b"\x02\x01\x00"  # 错误状态
        payload += b"\x02\x01\x00"  # 错误索引
        payload += oid
        
        return payload
    
    def generate_diverse_udp_packets(self, count: int = 100) -> List[Packet]:
        """生成多样化的UDP数据包"""
        packets = []
        
        # 定义不同的子网
        subnets = [
            "192.168.1.0/24",
            "10.0.0.0/24",
            "172.16.1.0/24",
            "192.168.100.0/24"
        ]
        
        # 常用UDP端口和对应的协议（移除DNS和DHCP）
        udp_services = {
            69: "TFTP",
            123: "NTP",
            161: "SNMP",
            162: "SNMP_Trap",
            514: "Syslog",
            1812: "RADIUS_Auth",
            5353: "mDNS"
        }
        
        for i in range(count):
            subnet = random.choice(subnets)
            src_ip = self.generate_random_ip(subnet)
            dst_ip = self.generate_random_ip(subnet)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(list(udp_services.keys()))
            
            # 使用新的多样化载荷生成器
            payload_len = random.randint(8, 128)
            payload = self.generate_diverse_udp_payloads(payload_len)
            
            packet = self.create_udp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                payload=payload
            )
            packets.append(packet)
        
        self.generated_packets.extend(packets)
        return packets
    
    def generate_specific_scenarios(self) -> List[Packet]:
        """生成特定场景的UDP数据包"""
        packets = []
        
        # 场景1：网络连通性测试
        for i in range(4):
            test_packet = self.create_udp_packet(
                src_ip="192.168.1.100", dst_ip="192.168.1.1",
                src_port=random.randint(1024, 65535), dst_port=69,
                payload=f"TEST_CONNECTIVITY_{i+1} ping data".encode()
            )
            packets.append(test_packet)
        
        # 场景2：服务状态检查
        status_packet = self.create_udp_packet(
            src_ip="192.168.1.10", dst_ip="192.168.1.200",
            src_port=random.randint(1024, 65535), dst_port=161,
            payload=b"SERVICE_STATUS_CHECK server_health OK"
        )
        packets.append(status_packet)
        
        # 场景3：NTP时间同步
        ntp_payload = b'\x1b' + b'\x00' * 47  # 简化的NTP请求
        ntp_packet = self.create_udp_packet(
            src_ip="192.168.1.50", dst_ip="pool.ntp.org",
            src_port=123, dst_port=123,
            payload=ntp_payload
        )
        packets.append(ntp_packet)
        
        # 场景4：网络监控数据
        monitor_packet = self.create_udp_packet(
            src_ip="192.168.1.10", dst_ip="192.168.1.200",
            src_port=random.randint(1024, 65535), dst_port=161,
            payload=b"MONITOR_DATA device_001 status:OK cpu:25% mem:60%"
        )
        packets.append(monitor_packet)
        
        # 场景5：Syslog消息
        syslog_msg = b"<134>Oct 11 22:14:15 server01 nginx: 192.168.1.100 - - [11/Oct/2023:22:14:15 +0000] \"GET / HTTP/1.1\" 200 612"
        syslog_packet = self.create_udp_packet(
            src_ip="192.168.1.100", dst_ip="192.168.1.10",
            src_port=random.randint(1024, 65535), dst_port=514,
            payload=syslog_msg
        )
        packets.append(syslog_packet)
        
        self.generated_packets.extend(packets)
        return packets
    
    def save_to_pcap(self, filename: str, packets: Optional[List[Packet]] = None):
        """保存数据包到PCAP文件"""
        if packets is None:
            packets = self.generated_packets
        
        if not packets:
            raise ValueError("没有数据包可保存")
        
        wrpcap(filename, packets)
        print(f"已保存 {len(packets)} 个UDP数据包到 {filename}")
    
    def save_to_csv(self, filename: str):
        """保存生成的消息到CSV文件 - 只包含UDP协议数据"""
        if not self.generated_packets:
            raise ValueError("没有数据包可保存")
        
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            
            for i, packet in enumerate(self.generated_packets):
                # 提取UDP层数据
                if packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    udp_data = bytes(udp_layer)
                    
                    hex_data = udp_data.hex()
                    
                    # 解析UDP头部字段（按RFC 768顺序）
                    segments_list = []
                    field_names_list = []
                    
                    # UDP头部字段（8字节）- 修复为字节偏移
                    segments_list.append((0, 2))     # Source Port (2字节)
                    field_names_list.append('Source Port')
                    
                    segments_list.append((2, 4))     # Destination Port (2字节)
                    field_names_list.append('Destination Port')
                    
                    segments_list.append((4, 6))     # Length (2字节)
                    field_names_list.append('UDP Length')
                    
                    segments_list.append((6, 8))     # Checksum (2字节)
                    field_names_list.append('UDP Checksum')
                    
                    # 如果有数据载荷
                    if len(udp_data) > 8:
                        segments_list.append((8, len(udp_data)))  # 数据部分使用字节偏移
                        field_names_list.append('UDP Data')
                    
                    writer.writerow([hex_data, str(segments_list), str(field_names_list)])
        
        print(f"UDP协议CSV文件已保存到 {filename}")
    
    def get_diversity_stats(self) -> Dict[str, Any]:
        """获取多样性统计信息"""
        if not self.packet_info:
            return {}
        
        # 统计不同的值
        packet_types = set(info['type'] for info in self.packet_info)
        src_ips = set(info['ip_src'] for info in self.packet_info)
        dst_ips = set(info['ip_dst'] for info in self.packet_info)
        src_ports = set(info['udp_sport'] for info in self.packet_info)
        dst_ports = set(info['udp_dport'] for info in self.packet_info)
        payload_sizes = set(info['payload_len'] for info in self.packet_info)
        
        return {
            "total_packets": len(self.packet_info),
            "unique_packet_types": len(packet_types),
            "packet_types": list(packet_types),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "unique_src_ports": len(src_ports),
            "unique_dst_ports": len(dst_ports),
            "unique_payload_sizes": len(payload_sizes),
            "diversity_score": {
                "service_diversity": len(dst_ports) / max(len(dst_ports), 10),
                "ip_diversity": len(src_ips | dst_ips) / len(self.packet_info),
                "port_diversity": len(src_ports | dst_ports) / len(self.packet_info),
                "size_diversity": len(payload_sizes) / len(self.packet_info)
            }
        }


def main():
    """主函数：演示UDP生成器的使用"""
    generator = UDPGenerator()
    
    print("开始生成UDP协议消息...")
    
    # 生成多样化的UDP数据包
    diverse_packets = generator.generate_diverse_udp_packets(5000)
    print(f"生成了 {len(diverse_packets)} 个多样化UDP数据包")
    
    # 生成特定场景的数据包
    scenario_packets = generator.generate_specific_scenarios()
    print(f"生成了 {len(scenario_packets)} 个场景化UDP数据包")
    
    # 保存到文件
    all_packets = diverse_packets + scenario_packets
    
    # 修改输出路径为新的目录结构
    pcap_file = "pcap/udp_messages.pcap"
    csv_file = "csv/udp_messages.csv"
    
    generator.save_to_pcap(pcap_file, all_packets)
    generator.save_to_csv(csv_file)
    
    # 显示多样性统计
    stats = generator.get_diversity_stats()
    print("\n多样性统计:")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    
    print(f"\n生成完成！总共生成 {len(all_packets)} 个UDP数据包")
    print(f"PCAP文件: {pcap_file}")
    print(f"CSV文件: {csv_file}")


if __name__ == "__main__":
    main()