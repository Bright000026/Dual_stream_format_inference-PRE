#!/usr/bin/env python3
"""
DNS协议消息生成器
严格按照RFC 1035标准规范实现
支持生成多样化的DNS查询和响应消息
"""

import struct
import socket
import random
import ipaddress
from typing import List, Dict, Any, Optional, Tuple
from scapy.all import IP, UDP, Ether, wrpcap, Packet, Raw, DNS, DNSQR, DNSRR
import json


class DNSGenerator:
    """DNS协议消息生成器，严格按照RFC 1035标准"""
    
    # DNS消息类型（OPCODE）
    DNS_QUERY = 0        # 标准查询
    DNS_IQUERY = 1       # 反向查询
    DNS_STATUS = 2       # 服务器状态请求
    
    # DNS响应代码（RCODE）
    DNS_NOERROR = 0      # 无错误
    DNS_FORMERR = 1      # 格式错误
    DNS_SERVFAIL = 2     # 服务器故障
    DNS_NXDOMAIN = 3     # 域名不存在
    DNS_NOTIMP = 4       # 未实现
    DNS_REFUSED = 5      # 拒绝
    
    # DNS记录类型
    DNS_A = 1           # IPv4地址
    DNS_NS = 2          # 权威名称服务器
    DNS_CNAME = 5       # 规范名称
    DNS_SOA = 6         # 授权开始
    DNS_PTR = 12        # 指针记录
    DNS_MX = 15         # 邮件交换
    DNS_TXT = 16        # 文本记录
    DNS_AAAA = 28       # IPv6地址
    
    # DNS类
    DNS_IN = 1          # Internet类
    
    def __init__(self):
        """初始化DNS生成器"""
        self.generated_packets = []
        self.packet_info = []
        self.messages = []
        
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
    
    def generate_random_domain(self) -> str:
        """生成随机域名"""
        tlds = ['.com', '.org', '.net', '.edu', '.gov', '.mil', '.local']
        prefixes = ['www', 'mail', 'ftp', 'ns1', 'ns2', 'api', 'blog', 'shop']
        domains = ['example', 'test', 'sample', 'demo', 'company', 'website']
        
        if random.random() < 0.3:  # 30%概率生成简单域名
            return random.choice(domains) + random.choice(tlds)
        else:  # 70%概率生成带前缀的域名
            return random.choice(prefixes) + '.' + random.choice(domains) + random.choice(tlds)
    
    def create_dns_query(self,
                        domain: str,
                        qtype: int = DNS_A,
                        qclass: int = DNS_IN,
                        src_ip: Optional[str] = None,
                        dst_ip: Optional[str] = None,
                        src_port: Optional[int] = None,
                        dst_port: int = 53,
                        dns_id: Optional[int] = None,
                        rd: bool = True) -> Packet:
        """
        创建DNS查询数据包
        
        DNS头部格式（12字节）：
                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        """
        # 生成默认值
        if src_ip is None:
            src_ip = self.generate_random_ip()
        if dst_ip is None:
            dst_ip = self.generate_random_ip()
        if src_port is None:
            src_port = random.randint(1024, 65535)
        if dns_id is None:
            dns_id = random.randint(0, 65535)
        
        # 创建以太网层
        eth_src = self.generate_random_mac()
        eth_dst = self.generate_random_mac()
        eth_packet = Ether(src=eth_src, dst=eth_dst)
        
        # 创建IP层
        ip_packet = IP(src=src_ip, dst=dst_ip)
        
        # 创建UDP层
        udp_packet = UDP(sport=src_port, dport=dst_port)
        
        # 创建DNS查询
        dns_query = DNS(
            id=dns_id,
            qr=0,           # 查询
            opcode=0,       # 标准查询
            aa=0,           # 非权威应答
            tc=0,           # 未截断
            rd=1 if rd else 0,  # 期望递归
            ra=0,           # 递归可用（仅在响应中设置）
            z=0,            # 保留位
            rcode=0,        # 无错误
            qdcount=1,      # 1个查询
            ancount=0,      # 0个答案
            nscount=0,      # 0个权威记录
            arcount=0,      # 0个附加记录
            qd=DNSQR(qname=domain, qtype=qtype, qclass=qclass)
        )
        
        # 组合数据包
        packet = eth_packet / ip_packet / udp_packet / dns_query
        
        # 记录数据包信息
        packet_info = {
            "type": "DNS_QUERY",
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "ip_src": src_ip,
            "ip_dst": dst_ip,
            "udp_sport": src_port,
            "udp_dport": dst_port,
            "dns_id": dns_id,
            "dns_qr": 0,
            "dns_opcode": 0,
            "dns_rcode": 0,
            "dns_domain": domain,
            "dns_qtype": qtype,
            "dns_qclass": qclass,
            "packet_size": len(packet)
        }
        
        self.packet_info.append(packet_info)
        return packet
    
    def create_dns_response(self,
                           domain: str,
                           answer_ip: str,
                           qtype: int = DNS_A,
                           qclass: int = DNS_IN,
                           src_ip: Optional[str] = None,
                           dst_ip: Optional[str] = None,
                           src_port: int = 53,
                           dst_port: Optional[int] = None,
                           dns_id: Optional[int] = None,
                           rcode: int = DNS_NOERROR,
                           authoritative: bool = False,
                           ttl: int = 300) -> Packet:
        """创建DNS响应数据包"""
        # 生成默认值
        if src_ip is None:
            src_ip = self.generate_random_ip()
        if dst_ip is None:
            dst_ip = self.generate_random_ip()
        if dst_port is None:
            dst_port = random.randint(1024, 65535)
        if dns_id is None:
            dns_id = random.randint(0, 65535)
        
        # 创建以太网层
        eth_src = self.generate_random_mac()
        eth_dst = self.generate_random_mac()
        eth_packet = Ether(src=eth_src, dst=eth_dst)
        
        # 创建IP层
        ip_packet = IP(src=src_ip, dst=dst_ip)
        
        # 创建UDP层
        udp_packet = UDP(sport=src_port, dport=dst_port)
        
        # 创建DNS响应
        dns_response = DNS(
            id=dns_id,
            qr=1,           # 响应
            opcode=0,       # 标准查询
            aa=1 if authoritative else 0,  # 权威应答
            tc=0,           # 未截断
            rd=1,           # 期望递归
            ra=1,           # 递归可用
            z=0,            # 保留位
            rcode=rcode,    # 响应代码
            qdcount=1,      # 1个查询
            ancount=1 if rcode == self.DNS_NOERROR else 0,  # 1个答案（如果成功）
            nscount=0,      # 0个权威记录
            arcount=0,      # 0个附加记录
            qd=DNSQR(qname=domain, qtype=qtype, qclass=qclass)
        )
        
        # 添加答案记录（如果成功）
        if rcode == self.DNS_NOERROR:
            if qtype == self.DNS_A:
                dns_response.an = DNSRR(rrname=domain, type=qtype, rclass=qclass, 
                                      ttl=ttl, rdata=answer_ip)
            elif qtype == self.DNS_CNAME:
                dns_response.an = DNSRR(rrname=domain, type=qtype, rclass=qclass,
                                      ttl=ttl, rdata=answer_ip)
        
        # 组合数据包
        packet = eth_packet / ip_packet / udp_packet / dns_response
        
        # 记录数据包信息
        packet_info = {
            "type": "DNS_RESPONSE",
            "eth_src": eth_src,
            "eth_dst": eth_dst,
            "ip_src": src_ip,
            "ip_dst": dst_ip,
            "udp_sport": src_port,
            "udp_dport": dst_port,
            "dns_id": dns_id,
            "dns_qr": 1,
            "dns_opcode": 0,
            "dns_rcode": rcode,
            "dns_domain": domain,
            "dns_qtype": qtype,
            "dns_qclass": qclass,
            "dns_answer": answer_ip if rcode == self.DNS_NOERROR else None,
            "packet_size": len(packet)
        }
        
        self.packet_info.append(packet_info)
        return packet
    
    def generate_dns_transaction(self, domain: str) -> List[Packet]:
        """生成DNS查询-响应事务"""
        packets = []
        
        # 生成IP地址对
        client_ip = self.generate_random_ip("192.168.1.0/24")
        server_ip = "8.8.8.8"  # Google DNS
        client_port = random.randint(1024, 65535)
        dns_id = random.randint(0, 65535)
        
        # 1. DNS查询
        query = self.create_dns_query(
            domain=domain,
            src_ip=client_ip,
            dst_ip=server_ip,
            src_port=client_port,
            dns_id=dns_id
        )
        packets.append(query)
        
        # 2. DNS响应
        if random.random() < 0.9:  # 90%成功率
            # 生成随机IP作为答案
            answer_ip = self.generate_random_ip("203.0.113.0/24")  # RFC 5737测试地址
            response = self.create_dns_response(
                domain=domain,
                answer_ip=answer_ip,
                src_ip=server_ip,
                dst_ip=client_ip,
                dst_port=client_port,
                dns_id=dns_id
            )
        else:  # 10%失败率
            response = self.create_dns_response(
                domain=domain,
                answer_ip="",  # 无答案
                src_ip=server_ip,
                dst_ip=client_ip,
                dst_port=client_port,
                dns_id=dns_id,
                rcode=random.choice([self.DNS_NXDOMAIN, self.DNS_SERVFAIL])
            )
        packets.append(response)
        
        self.generated_packets.extend(packets)
        return packets
    
    def generate_diverse_dns_packets(self, count: int = 50) -> List[Packet]:
        """生成多样化的DNS数据包"""
        packets = []
        
        # DNS查询类型
        query_types = [
            self.DNS_A,      # IPv4地址
            self.DNS_AAAA,   # IPv6地址
            self.DNS_MX,     # 邮件交换
            self.DNS_NS,     # 名称服务器
            self.DNS_CNAME,  # 规范名称
            self.DNS_TXT,    # 文本记录
            self.DNS_PTR     # 指针记录
        ]
        
        for i in range(count):
            domain = self.generate_random_domain()
            qtype = random.choice(query_types)
            
            if random.random() < 0.7:  # 70%生成查询-响应对
                transaction_packets = self.generate_dns_transaction(domain)
                packets.extend(transaction_packets)
            else:  # 30%只生成查询
                query = self.create_dns_query(domain=domain, qtype=qtype)
                packets.append(query)
                self.generated_packets.append(query)
        
        return packets
    
    def generate_specific_scenarios(self) -> List[Packet]:
        """生成特定场景的DNS数据包"""
        packets = []
        
        # 场景1：常见网站查询
        popular_domains = [
            "www.google.com",
            "www.facebook.com",
            "www.youtube.com",
            "www.amazon.com",
            "www.microsoft.com"
        ]
        
        for domain in popular_domains:
            transaction = self.generate_dns_transaction(domain)
            packets.extend(transaction)
        
        # 场景2：邮件服务器查询
        email_domains = ["gmail.com", "outlook.com", "yahoo.com"]
        for domain in email_domains:
            mx_query = self.create_dns_query(domain=domain, qtype=self.DNS_MX)
            packets.append(mx_query)
            self.generated_packets.append(mx_query)
        
        # 场景3：反向DNS查询
        test_ips = ["192.168.1.1", "10.0.0.1", "172.16.1.1"]
        for ip in test_ips:
            # 构造反向查询域名
            parts = ip.split('.')
            reverse_domain = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
            ptr_query = self.create_dns_query(domain=reverse_domain, qtype=self.DNS_PTR)
            packets.append(ptr_query)
            self.generated_packets.append(ptr_query)
        
        # 场景4：DNS错误响应
        error_cases = [
            ("nonexistent.invalid", self.DNS_NXDOMAIN),
            ("timeout.test", self.DNS_SERVFAIL),
            ("refused.example", self.DNS_REFUSED)
        ]
        
        for domain, rcode in error_cases:
            error_response = self.create_dns_response(
                domain=domain,
                answer_ip="",
                rcode=rcode
            )
            packets.append(error_response)
            self.generated_packets.append(error_response)
        
        return packets
    
    def save_to_pcap(self, filename: str, packets: Optional[List[Packet]] = None):
        """保存数据包到PCAP文件"""
        if packets is None:
            packets = self.generated_packets
        
        if not packets:
            raise ValueError("没有数据包可保存")
        
        wrpcap(filename, packets)
        print(f"已保存 {len(packets)} 个DNS数据包到 {filename}")
    
    def save_to_csv(self, filename: str):
        """保存生成的消息到CSV文件 - 只包含DNS协议数据"""
        if not self.generated_packets:
            raise ValueError("没有数据包可保存")
        
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            
            for i, packet in enumerate(self.generated_packets):
                # 提取DNS层数据
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    dns_data = bytes(dns_layer)
                    
                    hex_data = dns_data.hex()
                    
                    # 解析DNS头部字段（按RFC 1035顺序）
                    segments_list = []
                    field_names_list = []
                    
                    # DNS头部字段（12字节固定部分）- 使用字节偏移
                    segments_list.append((0, 2))     # Transaction ID (2字节)
                    field_names_list.append('DNS Transaction ID')
                    
                    segments_list.append((2, 4))     # Flags (2字节)
                    field_names_list.append('DNS Flags')
                    
                    segments_list.append((4, 6))     # Questions Count (2字节)
                    field_names_list.append('DNS Questions Count')
                    
                    segments_list.append((6, 8))     # Answer RRs (2字节)
                    field_names_list.append('DNS Answer RRs')
                    
                    segments_list.append((8, 10))    # Authority RRs (2字节)
                    field_names_list.append('DNS Authority RRs')
                    
                    segments_list.append((10, 12))   # Additional RRs (2字节)
                    field_names_list.append('DNS Additional RRs')
                    
                    # DNS查询部分（可变长度）
                    offset = 12  # 12字节头部
                    
                    if dns_layer.qdcount > 0:
                        # 域名部分（可变长度）
                        # 通过包信息获取域名
                        domain = self.packet_info[i]['dns_domain'] if i < len(self.packet_info) else 'example.com'
                        
                        # 计算域名编码长度（实际域名编码格式：长度字节+内容+...+0）
                        domain_parts = domain.split('.')
                        domain_encoded_len = sum(len(part) + 1 for part in domain_parts) + 1  # 每部分长度+内容+结尾0
                        
                        segments_list.append((offset, offset + domain_encoded_len))  # Query Name
                        field_names_list.append('DNS Query Name')
                        offset += domain_encoded_len
                        
                        segments_list.append((offset, offset + 2))    # Query Type (2字节)
                        field_names_list.append('DNS Query Type')
                        offset += 2
                        
                        segments_list.append((offset, offset + 2))    # Query Class (2字节)
                        field_names_list.append('DNS Query Class')
                        offset += 2
                    
                    # 如果有答案部分
                    if dns_layer.ancount > 0 and offset < len(dns_data):
                        segments_list.append((offset, len(dns_data)))  # Answer Section
                        field_names_list.append('DNS Answer Section')
                    
                    # 写入CSV行
                    writer.writerow([
                        hex_data,
                        str(segments_list),
                        str(field_names_list)
                    ])
        
        print(f"已保存 {len(self.generated_packets)} 条DNS协议记录到 {filename}")
    
    def get_diversity_stats(self) -> Dict[str, Any]:
        """获取多样性统计信息"""
        if not self.packet_info:
            return {}
        
        # 统计不同的值
        packet_types = set(info['type'] for info in self.packet_info)
        domains = set(info['dns_domain'] for info in self.packet_info)
        query_types = set(info['dns_qtype'] for info in self.packet_info)
        response_codes = set(info['dns_rcode'] for info in self.packet_info)
        src_ips = set(info['ip_src'] for info in self.packet_info)
        dst_ips = set(info['ip_dst'] for info in self.packet_info)
        
        return {
            "total_packets": len(self.packet_info),
            "unique_packet_types": len(packet_types),
            "packet_types": list(packet_types),
            "unique_domains": len(domains),
            "unique_query_types": len(query_types),
            "query_types": list(query_types),
            "unique_response_codes": len(response_codes),
            "response_codes": list(response_codes),
            "unique_src_ips": len(src_ips),
            "unique_dst_ips": len(dst_ips),
            "diversity_score": {
                "type_diversity": len(packet_types) / 2,  # 查询和响应
                "domain_diversity": len(domains) / len(self.packet_info),
                "query_type_diversity": len(query_types) / 7,  # 7种常见类型
                "ip_diversity": len(src_ips | dst_ips) / len(self.packet_info)
            }
        }


def main():
    """主函数：演示DNS生成器的使用"""
    generator = DNSGenerator()
    
    print("开始生成DNS协议消息...")
    
    # 生成多样化的DNS数据包
    diverse_packets = generator.generate_diverse_dns_packets(4000)
    print(f"生成了 {len(diverse_packets)} 个多样化DNS数据包")
    
    # 生成特定场景的数据包
    scenario_packets = generator.generate_specific_scenarios()
    print(f"生成了 {len(scenario_packets)} 个场景化DNS数据包")
    
    # 保存到文件
    all_packets = diverse_packets + scenario_packets
    
    # 修改输出路径为新的目录结构
    pcap_file = "pcap/dns_messages.pcap"
    csv_file = "csv/dns_messages.csv"
    
    generator.save_to_pcap(pcap_file, all_packets)
    generator.save_to_csv(csv_file)
    
    # 显示多样性统计
    stats = generator.get_diversity_stats()
    print("\n多样性统计:")
    print(json.dumps(stats, indent=2, ensure_ascii=False))
    
    print(f"\n生成完成！总共生成 {len(all_packets)} 个DNS数据包")
    print(f"PCAP文件: {pcap_file}")
    print(f"CSV文件: {csv_file}")


if __name__ == "__main__":
    main()