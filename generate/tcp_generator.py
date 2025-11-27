#!/usr/bin/env python3
"""
TCP协议消息生成器
严格按照RFC 793 (更新为RFC 9293)标准规范实现
支持生成多样化的TCP数据包，包括SYN、SYN-ACK、ACK、FIN、RST等
"""

import struct
import socket
import random
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from scapy.all import IP, TCP, Ether, wrpcap, Packet, Raw # type: ignore[error]
import json


class TCPGenerator:
    """TCP协议消息生成器，严格按照RFC 793/9293标准"""
    
    # TCP标志位（RFC 793）
    TCP_FIN = 0x01    # 结束标志
    TCP_SYN = 0x02    # 同步标志
    TCP_RST = 0x04    # 重置标志
    TCP_PSH = 0x08    # 推送标志
    TCP_ACK = 0x10    # 确认标志
    TCP_URG = 0x20    # 紧急标志
    TCP_ECE = 0x40    # ECN-Echo（RFC 3168）
    TCP_CWR = 0x80    # Congestion Window Reduced（RFC 3168）
    
    # 常用TCP选项（RFC 793, RFC 1323, RFC 2018等）
    TCP_OPT_EOL = 0         # End of Option List
    TCP_OPT_NOP = 1         # No-Operation
    TCP_OPT_MSS = 2         # Maximum Segment Size
    TCP_OPT_WINDOW_SCALE = 3 # Window Scale Factor (RFC 1323)
    TCP_OPT_SACK_PERMIT = 4  # SACK Permitted (RFC 2018)
    TCP_OPT_SACK = 5        # SACK (RFC 2018)
    TCP_OPT_TIMESTAMP = 8   # Timestamps (RFC 1323)
    
    def __init__(self):
        """初始化TCP生成器"""
        self.generated_packets = []
        self.packet_info = []
        self.connections = {}  # 跟踪连接状态
        
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
    
    def generate_tcp_options(self, option_types: Optional[List[int]] = None) -> bytes:
        """生成TCP选项字段"""
        if option_types is None:
            # 随机选择一些常见选项
            available_opts = [
                self.TCP_OPT_MSS,
                self.TCP_OPT_WINDOW_SCALE,
                self.TCP_OPT_SACK_PERMIT,
                self.TCP_OPT_TIMESTAMP
            ]
            option_types = random.sample(available_opts, random.randint(0, 3))
        
        options = b''
        
        for opt_type in option_types:
            if opt_type == self.TCP_OPT_MSS:
                # MSS选项：类型(1) + 长度(1) + MSS值(2)
                mss = random.randint(536, 1460)  # 常见MSS范围
                options += struct.pack('!BBH', self.TCP_OPT_MSS, 4, mss)
            elif opt_type == self.TCP_OPT_WINDOW_SCALE:
                # 窗口缩放选项：类型(1) + 长度(1) + 缩放因子(1) + 填充(1)
                scale_factor = random.randint(0, 14)
                options += struct.pack('!BBB', self.TCP_OPT_WINDOW_SCALE, 3, scale_factor)
            elif opt_type == self.TCP_OPT_SACK_PERMIT:
                # SACK许可选项：类型(1) + 长度(1)
                options += struct.pack('!BB', self.TCP_OPT_SACK_PERMIT, 2)
            elif opt_type == self.TCP_OPT_TIMESTAMP:
                # 时间戳选项：类型(1) + 长度(1) + TSval(4) + TSecr(4)
                ts_val = random.randint(0, 0xFFFFFFFF)
                ts_ecr = random.randint(0, 0xFFFFFFFF)
                options += struct.pack('!BBII', self.TCP_OPT_TIMESTAMP, 10, ts_val, ts_ecr)
        
        # 添加填充以确保选项长度是4的倍数
        while len(options) % 4 != 0:
            options += struct.pack('!B', self.TCP_OPT_NOP)
        
        return options
    
    def create_tcp_packet(self,
                         src_ip: Optional[str] = None,
                         dst_ip: Optional[str] = None,
                         src_port: Optional[int] = None,
                         dst_port: Optional[int] = None,
                         seq: Optional[int] = None,
                         ack: Optional[int] = None,
                         flags: int = 0,
                         window: Optional[int] = None,
                         urgent: int = 0,
                         options: Optional[bytes] = None,
                         payload: Optional[bytes] = None,
                         eth_src: Optional[str] = None,
                         eth_dst: Optional[str] = None) -> Packet:
        """
        创建TCP数据包，严格按照RFC 793/9293规范
        
        Args:
            src_ip: 源IP地址
            dst_ip: 目标IP地址
            src_port: 源端口
            dst_port: 目标端口
            seq: 序列号
            ack: 确认号
            flags: TCP标志位
            window: 窗口大小
            urgent: 紧急指针
            options: TCP选项
            payload: 数据载荷
            eth_src: 以太网源MAC地址
            eth_dst: 以太网目标MAC地址
        """
        # 生成默认值
        if src_ip is None:
            src_ip = self.generate_random_ip()
        if dst_ip is None:
            dst_ip = self.generate_random_ip()
        if src_port is None:
            src_port = random.randint(1024, 65535)
        if dst_port is None:
            dst_port = random.choice([80, 443, 22, 25, 53, 993, 995, 8080, 3389])
        if seq is None:
            seq = random.randint(0, 0xFFFFFFFF)
        if ack is None and (flags & self.TCP_ACK):
            ack = random.randint(0, 0xFFFFFFFF)
        if window is None:
            window = random.randint(1024, 65535)
        if eth_src is None:
            eth_src = self.generate_random_mac()
        if eth_dst is None:
            eth_dst = self.generate_random_mac()
        
        # 创建以太网层
        eth_packet = Ether(src=eth_src, dst=eth_dst)
        
        # 创建IP层
        ip_packet = IP(src=src_ip, dst=dst_ip)
        
        # 创建TCP层
        tcp_packet = TCP(
            sport=src_port,
            dport=dst_port,
            seq=seq,
            ack=ack if ack is not None else 0,
            flags=flags,
            window=window,
            urgptr=urgent
        )
        
        # 添加TCP选项
        if options:
            tcp_packet.options = self._parse_tcp_options(options)
        elif flags & self.TCP_SYN:  # SYN包通常包含选项
            tcp_packet.options = self._parse_tcp_options(self.generate_tcp_options())
        
        # 组合数据包
        packet = eth_packet / ip_packet / tcp_packet
        
        # 添加载荷数据
        if payload:
            packet = packet / Raw(load=payload)
        
        # 记录数据包信息
        packet_info = {
            "type": self._get_tcp_type_name(flags),
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "ip_src": src_ip,
            "ip_dst": dst_ip,
            "tcp_sport": src_port,
            "tcp_dport": dst_port,
            "tcp_seq": seq,
            "tcp_ack": ack if ack is not None else 0,
            "tcp_flags": flags,
            "tcp_flags_str": self._flags_to_string(flags),
            "tcp_window": window,
            "tcp_urgptr": urgent,
            "tcp_options_len": len(options) if options else 0,
            "payload_len": len(payload) if payload else 0,
            "packet_size": len(packet)
        }
        
        self.packet_info.append(packet_info)
        return packet
    
    def _parse_tcp_options(self, options: bytes) -> List[Tuple]:
        """解析TCP选项字节为scapy格式"""
        scapy_options = []
        i = 0
        while i < len(options):
            if options[i] == self.TCP_OPT_MSS and i + 3 < len(options):
                mss = struct.unpack('!H', options[i+2:i+4])[0]
                scapy_options.append(('MSS', mss))
                i += 4
            elif options[i] == self.TCP_OPT_WINDOW_SCALE and i + 2 < len(options):
                scale = options[i+2]
                scapy_options.append(('WScale', scale))
                i += 3
            elif options[i] == self.TCP_OPT_SACK_PERMIT:
                scapy_options.append(('SAckOK', ''))
                i += 2
            elif options[i] == self.TCP_OPT_TIMESTAMP and i + 9 < len(options):
                ts_val, ts_ecr = struct.unpack('!II', options[i+2:i+10])
                scapy_options.append(('Timestamp', (ts_val, ts_ecr)))
                i += 10
            elif options[i] == self.TCP_OPT_NOP:
                scapy_options.append(('NOP', None))
                i += 1
            else:
                i += 1
        return scapy_options
    
    def _get_tcp_type_name(self, flags: int) -> str:
        """根据标志位获取TCP包类型名称"""
        if flags & self.TCP_SYN and flags & self.TCP_ACK:
            return "SYN-ACK"
        elif flags & self.TCP_SYN:
            return "SYN"
        elif flags & self.TCP_FIN and flags & self.TCP_ACK:
            return "FIN-ACK"
        elif flags & self.TCP_FIN:
            return "FIN"
        elif flags & self.TCP_RST:
            return "RST"
        elif flags & self.TCP_ACK:
            return "ACK"
        elif flags & self.TCP_PSH and flags & self.TCP_ACK:
            return "PSH-ACK"
        else:
            return f"FLAGS_{flags:02x}"
    
    def _flags_to_string(self, flags: int) -> str:
        """将标志位转换为字符串表示"""
        flag_names = []
        if flags & self.TCP_FIN:
            flag_names.append("FIN")
        if flags & self.TCP_SYN:
            flag_names.append("SYN")
        if flags & self.TCP_RST:
            flag_names.append("RST")
        if flags & self.TCP_PSH:
            flag_names.append("PSH")
        if flags & self.TCP_ACK:
            flag_names.append("ACK")
        if flags & self.TCP_URG:
            flag_names.append("URG")
        if flags & self.TCP_ECE:
            flag_names.append("ECE")
        if flags & self.TCP_CWR:
            flag_names.append("CWR")
        return ','.join(flag_names) if flag_names else "None"
    
    def generate_tcp_handshake(self, src_ip: str, dst_ip: str, 
                              src_port: int, dst_port: int) -> List[Packet]:
        """生成TCP三次握手序列"""
        packets = []
        
        # 生成MAC地址
        client_mac = self.generate_random_mac()
        server_mac = self.generate_random_mac()
        
        # 1. SYN包
        initial_seq = random.randint(0, 0xFFFFFFFF)
        syn_packet = self.create_tcp_packet(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            seq=initial_seq, flags=self.TCP_SYN,
            eth_src=client_mac, eth_dst=server_mac
        )
        packets.append(syn_packet)
        
        # 2. SYN-ACK包
        server_seq = random.randint(0, 0xFFFFFFFF)
        syn_ack_packet = self.create_tcp_packet(
            src_ip=dst_ip, dst_ip=src_ip,
            src_port=dst_port, dst_port=src_port,
            seq=server_seq, ack=initial_seq + 1,
            flags=self.TCP_SYN | self.TCP_ACK,
            eth_src=server_mac, eth_dst=client_mac
        )
        packets.append(syn_ack_packet)
        
        # 3. ACK包
        ack_packet = self.create_tcp_packet(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            seq=initial_seq + 1, ack=server_seq + 1,
            flags=self.TCP_ACK,
            eth_src=client_mac, eth_dst=server_mac
        )
        packets.append(ack_packet)
        
        self.generated_packets.extend(packets)
        return packets
    
    def generate_tcp_termination(self, src_ip: str, dst_ip: str,
                               src_port: int, dst_port: int,
                               client_seq: int, server_seq: int) -> List[Packet]:
        """生成TCP四次挥手序列"""
        packets = []
        
        client_mac = self.generate_random_mac()
        server_mac = self.generate_random_mac()
        
        # 1. FIN包（客户端发起关闭）
        fin_packet = self.create_tcp_packet(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            seq=client_seq, ack=server_seq,
            flags=self.TCP_FIN | self.TCP_ACK,
            eth_src=client_mac, eth_dst=server_mac
        )
        packets.append(fin_packet)
        
        # 2. ACK包（服务器确认）
        ack_packet = self.create_tcp_packet(
            src_ip=dst_ip, dst_ip=src_ip,
            src_port=dst_port, dst_port=src_port,
            seq=server_seq, ack=client_seq + 1,
            flags=self.TCP_ACK,
            eth_src=server_mac, eth_dst=client_mac
        )
        packets.append(ack_packet)
        
        # 3. FIN包（服务器发起关闭）
        fin_packet2 = self.create_tcp_packet(
            src_ip=dst_ip, dst_ip=src_ip,
            src_port=dst_port, dst_port=src_port,
            seq=server_seq, ack=client_seq + 1,
            flags=self.TCP_FIN | self.TCP_ACK,
            eth_src=server_mac, eth_dst=client_mac
        )
        packets.append(fin_packet2)
        
        # 4. 最终ACK包（客户端确认）
        final_ack_packet = self.create_tcp_packet(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port,
            seq=client_seq + 1, ack=server_seq + 1,
            flags=self.TCP_ACK,
            eth_src=client_mac, eth_dst=server_mac
        )
        packets.append(final_ack_packet)
        
        self.generated_packets.extend(packets)
        return packets
    
    def generate_diverse_tcp_payloads(self, size: int) -> bytes:
        """生成多样化的TCP载荷，避免包含其他协议数据"""
        payload_types = [
            # HTTP类载荷
            lambda s: f"GET /api/data?id={random.randint(1000, 9999)} HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: CustomApp/1.0\r\n\r\n".encode()[:s],
            lambda s: f"POST /submit HTTP/1.1\r\nHost: api.service.com\r\nContent-Length: {random.randint(10, 50)}\r\n\r\n{{\"key\": \"value\"}}".encode()[:s],
            lambda s: f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {random.randint(20, 80)}\r\n\r\n{{\"status\": \"success\"}}".encode()[:s],
            
            # FTP类载荷
            lambda s: f"USER ftpuser{random.randint(1, 99)}\r\n".encode()[:s],
            lambda s: f"PASS password{random.randint(100, 999)}\r\n".encode()[:s],
            lambda s: f"LIST /home/user/files\r\n".encode()[:s],
            lambda s: f"RETR file_{random.randint(1, 999)}.txt\r\n".encode()[:s],
            
            # SSH/Telnet类载荷
            lambda s: f"SSH-2.0-OpenSSH_8.{random.randint(0, 9)}\r\n".encode()[:s],
            lambda s: f"login: user{random.randint(1, 99)}\r\n".encode()[:s],
            lambda s: f"password: \r\n".encode()[:s],
            
            # SMTP类载荷
            lambda s: f"HELO mail.example.com\r\n".encode()[:s],
            lambda s: f"MAIL FROM:<sender{random.randint(1, 99)}@example.com>\r\n".encode()[:s],
            lambda s: f"RCPT TO:<recipient@domain.com>\r\n".encode()[:s],
            lambda s: f"DATA\r\nSubject: Test Message {random.randint(1, 999)}\r\n\r\nHello World!\r\n.\r\n".encode()[:s],
            
            # 二进制数据载荷
            lambda s: bytes([random.randint(1, 255) for _ in range(min(s, random.randint(5, 64)))]),
            lambda s: bytes([0x00, 0x01, 0x02, 0x03] * (s // 4 + 1))[:s],
            lambda s: bytes([0xFF, 0xFE, 0xFD, 0xFC] * (s // 4 + 1))[:s],
            
            # 文本数据载荷
            lambda s: f"Data packet {random.randint(1000, 9999)} with content length {s}".encode()[:s],
            lambda s: f"Session {random.randint(100, 999)}: Connection established".encode()[:s],
            lambda s: f"Response code: {random.randint(200, 599)}, Message: Operation completed".encode()[:s],
            
            # 应用特定载荷
            lambda s: f"{{\"command\": \"status\", \"id\": {random.randint(1, 999)}, \"timestamp\": {random.randint(1600000000, 1700000000)}}}".encode()[:s],
            lambda s: f"<xml><request><action>query</action><id>{random.randint(1, 999)}</id></request></xml>".encode()[:s],
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

    def generate_diverse_tcp_packets(self, count: int = 100) -> List[Packet]:
        """生成多样化的TCP数据包"""
        packets = []
        
        # 定义不同的子网
        subnets = [
            "192.168.1.0/24",
            "10.0.0.0/24", 
            "172.16.1.0/24",
            "192.168.100.0/24"
        ]
        
        # 常用端口
        common_ports = [80, 443, 22, 25, 53, 993, 995, 8080, 3389, 21, 23, 143]
        
        # 各种TCP标志组合
        flag_combinations = [
            self.TCP_SYN,
            self.TCP_SYN | self.TCP_ACK,
            self.TCP_ACK,
            self.TCP_FIN | self.TCP_ACK,
            self.TCP_RST,
            self.TCP_PSH | self.TCP_ACK,
            self.TCP_FIN,
            self.TCP_URG | self.TCP_ACK
        ]
        
        for i in range(count):
            subnet = random.choice(subnets)
            src_ip = self.generate_random_ip(subnet)
            dst_ip = self.generate_random_ip(subnet)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(common_ports)
            flags = random.choice(flag_combinations)
            
            # 生成有效载荷（概率性）
            payload = None
            if random.random() < 0.3:  # 30%概率有载荷
                # 限制载荷长度不超过128字节
                payload_size = random.randint(1, 128)
                payload = self.generate_diverse_tcp_payloads(payload_size)
            
            packet = self.create_tcp_packet(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                flags=flags, payload=payload
            )
            packets.append(packet)
        
        self.generated_packets.extend(packets)
        return packets
    
    def generate_specific_scenarios(self) -> List[Packet]:
        """生成特定场景的TCP数据包"""
        packets = []
        
        # 场景1：HTTP连接（三次握手 + 数据传输）
        http_handshake = self.generate_tcp_handshake(
            "192.168.1.100", "192.168.1.1", 12345, 80
        )
        packets.extend(http_handshake)
        
        # HTTP GET请求
        http_get = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        get_packet = self.create_tcp_packet(
            src_ip="192.168.1.100", dst_ip="192.168.1.1",
            src_port=12345, dst_port=80,
            flags=self.TCP_PSH | self.TCP_ACK,
            payload=http_get
        )
        packets.append(get_packet)
        
        # 场景2：SSH连接
        ssh_handshake = self.generate_tcp_handshake(
            "10.0.0.100", "10.0.0.1", 54321, 22
        )
        packets.extend(ssh_handshake)
        
        # 场景3：连接重置
        rst_packet = self.create_tcp_packet(
            src_ip="172.16.1.100", dst_ip="172.16.1.200",
            src_port=8080, dst_port=443,
            flags=self.TCP_RST
        )
        packets.append(rst_packet)
        
        # 场景4：端口扫描（SYN扫描）
        for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
            scan_packet = self.create_tcp_packet(
                src_ip="192.168.1.200", dst_ip="192.168.1.1",
                src_port=random.randint(1024, 65535), dst_port=port,
                flags=self.TCP_SYN
            )
            packets.append(scan_packet)
        
        self.generated_packets.extend(packets)
        return packets
    
    def save_to_pcap(self, filename: str, packets: Optional[List[Packet]] = None):
        """保存数据包到PCAP文件"""
        if packets is None:
            packets = self.generated_packets
        
        if not packets:
            raise ValueError("没有数据包可保存")
        
        wrpcap(filename, packets)
        print(f"已保存 {len(packets)} 个TCP数据包到 {filename}")
    
    def save_to_csv(self, filename: str):
        """保存生成的消息到CSV文件 - 只包含TCP协议数据"""
        if not self.packet_info:
            raise ValueError("没有数据包信息可保存")
        
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            
            for i, packet in enumerate(self.generated_packets):
                # 提取TCP层数据
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    tcp_data = bytes(tcp_layer)
                    
                    hex_data = tcp_data.hex()
                    
                    # 解析TCP头部字段
                    segments_list = []
                    field_names_list = []
                    
                    # TCP头部字段（按RFC 793顺序）- 使用字节偏移
                    segments_list.append((0, 2))     # Source Port (2字节)
                    field_names_list.append('Source Port')
                    
                    segments_list.append((2, 4))     # Destination Port (2字节)
                    field_names_list.append('Destination Port')
                    
                    segments_list.append((4, 8))     # Sequence Number (4字节)
                    field_names_list.append('Sequence Number')
                    
                    segments_list.append((8, 12))    # Acknowledgment Number (4字节)
                    field_names_list.append('Acknowledgment Number')
                    
                    segments_list.append((12, 13))   # Data Offset + Reserved (1字节)
                    field_names_list.append('Data Offset and Reserved')
                    
                    segments_list.append((13, 14))   # TCP Flags (1字节)
                    field_names_list.append('TCP Flags')
                    
                    segments_list.append((14, 16))   # Window Size (2字节)
                    field_names_list.append('Window Size')
                    
                    segments_list.append((16, 18))   # Checksum (2字节)
                    field_names_list.append('TCP Checksum')
                    
                    segments_list.append((18, 20))   # Urgent Pointer (2字节)
                    field_names_list.append('Urgent Pointer')
                    
                    # TCP选项（如果有）
                    if len(tcp_data) > 20:
                        # 计算头部长度
                        data_offset = (tcp_data[12] >> 4) * 4
                        if data_offset > 20:
                            segments_list.append((20, data_offset))  # TCP Options
                            field_names_list.append('TCP Options')
                            
                            # 数据载荷（如果有）
                            if len(tcp_data) > data_offset:
                                segments_list.append((data_offset, len(tcp_data)))  # TCP Data
                                field_names_list.append('TCP Data')
                        else:
                            # 没有选项，直接是数据
                            if len(tcp_data) > 20:
                                segments_list.append((20, len(tcp_data)))  # TCP Data
                                field_names_list.append('TCP Data')
                    
                    writer.writerow([
                        hex_data,
                        str(segments_list),
                        str(field_names_list)
                    ])
        
        print(f"已保存 {len(self.generated_packets)} 条TCP消息到 {filename}")
    
    def get_diversity_stats(self) -> Dict[str, Any]:
        """获取多样性统计信息"""
        if not self.packet_info:
            return {}
        
        # 统计不同的值
        packet_types = set(info['type'] for info in self.packet_info)
        src_ips = set(info['ip_src'] for info in self.packet_info)
        dst_ips = set(info['ip_dst'] for info in self.packet_info)
        src_ports = set(info['tcp_sport'] for info in self.packet_info)
        dst_ports = set(info['tcp_dport'] for info in self.packet_info)
        flag_combinations = set(info['tcp_flags'] for info in self.packet_info)
        
        return {
            "total_packets": len(self.packet_info),
            "unique_packet_types": len(packet_types),
            "packet_types": list(packet_types),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "unique_src_ports": len(src_ports),
            "unique_dst_ports": len(dst_ports),
            "unique_flag_combinations": len(flag_combinations),
            "diversity_score": {
                "type_diversity": len(packet_types) / max(len(packet_types), 8),  # 最多8种常见类型
                "ip_diversity": len(src_ips | dst_ips) / len(self.packet_info),
                "port_diversity": len(src_ports | dst_ports) / len(self.packet_info),
                "flag_diversity": len(flag_combinations) / max(len(flag_combinations), 16)  # 最多16种标志组合
            }
        }


def main():
    """主函数：演示TCP生成器的使用"""
    generator = TCPGenerator()
    
    print("开始生成TCP协议消息...")
    
    # 生成多样化的TCP数据包
    diverse_packets = generator.generate_diverse_tcp_packets(5000)
    print(f"生成了 {len(diverse_packets)} 个多样化TCP数据包")
    
    # 生成特定场景的数据包
    scenario_packets = generator.generate_specific_scenarios()
    print(f"生成了 {len(scenario_packets)} 个场景化TCP数据包")
    
    # 保存到文件
    all_packets = diverse_packets + scenario_packets
    
    # 修改输出路径为新的目录结构
    pcap_file = "pcap/tcp_messages.pcap"
    csv_file = "csv/tcp_messages.csv"
    
    generator.save_to_pcap(pcap_file, all_packets)
    generator.save_to_csv(csv_file)
    
    # 显示多样性统计
    stats = generator.get_diversity_stats()
    print("\n多样性统计:")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    
    print(f"\n生成完成！总共生成 {len(all_packets)} 个TCP数据包")
    print(f"PCAP文件: {pcap_file}")
    print(f"CSV文件: {csv_file}")


if __name__ == "__main__":
    main()