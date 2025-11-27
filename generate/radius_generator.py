import os
import csv
import random
import socket
import struct
from typing import List, Tuple

from scapy.all import Ether, IP, UDP, Raw, wrpcap


class RadiusGenerator:
    """
    RADIUS 协议报文生成器（兼容CSV/PCAP输出，与项目内其它生成器一致）

    - CSV仅保存协议层负载（RADIUS PDU）的十六进制、字段分段与字段名
    - PCAP保存完整以太网/IP/UDP封装，负载为RADIUS PDU
    - 确保Length字段与实际长度一致；属性TLV长度正确；不生成畸形报文

    参考：RFC 2865（RADIUS Authentication），RFC 2866（Accounting）
    基本格式：
      Code(1) | Identifier(1) | Length(2) | Authenticator(16) | Attributes(...)
    属性：
      Type(1) | Length(1, 含T与L) | Value(Length-2)
    """

    # 常用端口（认证/计费）
    AUTH_PORTS = [1812, 1645]
    ACCT_PORTS = [1813, 1646]

    # RADIUS Code
    CODE_ACCESS_REQUEST = 1
    CODE_ACCESS_ACCEPT = 2
    CODE_ACCESS_REJECT = 3
    CODE_ACCOUNTING_REQUEST = 4
    CODE_ACCOUNTING_RESPONSE = 5

    # 常见属性Type
    ATTR_USER_NAME = 1
    ATTR_USER_PASSWORD = 2  # 本生成器不做加密，仅用于长度/格式演示，避免复杂性
    ATTR_NAS_IP_ADDRESS = 4
    ATTR_NAS_PORT = 5
    ATTR_SERVICE_TYPE = 6
    ATTR_CALLING_STATION_ID = 31
    ATTR_CALLED_STATION_ID = 30
    ATTR_VENDOR_SPECIFIC = 26

    def __init__(self) -> None:
        self.output_dir_pcap = os.path.join(os.path.dirname(__file__), 'pcap')
        self.output_dir_csv = os.path.join(os.path.dirname(__file__), 'csv')
        os.makedirs(self.output_dir_pcap, exist_ok=True)
        os.makedirs(self.output_dir_csv, exist_ok=True)

    # ------------------------- 公共工具 -------------------------
    def _rand_ip(self) -> str:
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _rand_mac(self) -> str:
        first = random.randint(0, 254) & 0xFE
        rest = [random.randint(0, 255) for _ in range(5)]
        return ':'.join(f'{b:02x}' for b in [first] + rest)

    def _rand_bytes(self, length: int) -> bytes:
        return bytes(random.getrandbits(8) for _ in range(length))

    # ----------------------- RADIUS 构建 ------------------------
    def _build_attribute(self, attr_type: int, value: bytes) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """
        构建单个RADIUS属性TLV，返回：bytes, 段范围(offset相对当前属性起点), 字段名
        注意：属性Length包含Type和Length本身，因此最小为2。
        """
        length = 2 + len(value)
        if length < 2 or length > 255:
            # 强制合法长度范围，避免畸形
            value = value[:253]
            length = 2 + len(value)
        tlv = struct.pack('!BB', attr_type, length) + value
        # 段标注按属性内部三段
        segments = [(0, 1), (1, 2), (2, length)]
        names = [f"Attr[{attr_type}].Type", f"Attr[{attr_type}].Length", f"Attr[{attr_type}].Value"]
        return tlv, segments, names

    def _build_vendor_specific(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建合法的Vendor-Specific属性：Value = Vendor-Id(4) + Vendor-Data(子TLV)"""
        vendor_id = random.choice([9, 311, 14823])  # Cisco/Microsoft/Aruba 示例
        # 子TLV：Vendor-Type(1), Vendor-Length(1), Vendor-Value(N)
        v_type = random.randint(1, 5)
        v_val = self._rand_bytes(random.randint(1, 6))
        v_len = 2 + len(v_val)
        vendor_data = struct.pack('!BB', v_type, v_len) + v_val
        value = struct.pack('!I', vendor_id) + vendor_data

        tlv, segs, names = self._build_attribute(self.ATTR_VENDOR_SPECIFIC, value)
        # 细分Value内部（将Value区再细分为Vendor-Id与Vendor-Data）
        # 原Value段是segs[2] = (2, total_len)，在属性内偏移
        val_start, val_end = segs[2]
        # Vendor-Id占前4字节
        vendor_id_seg = (val_start, val_start + 4)
        vendor_data_seg = (val_start + 4, val_end)
        # 替换原Value名称为更细分的两段
        names[2] = f"Attr[{self.ATTR_VENDOR_SPECIFIC}].Value.Vendor-Id"
        segs[2] = vendor_id_seg
        segs.append(vendor_data_seg)
        names.append(f"Attr[{self.ATTR_VENDOR_SPECIFIC}].Value.Vendor-Data")
        return tlv, segs, names

    def _build_common_attributes(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """构建一组常见属性，返回属性区bytes、属性相对段、名称。"""
        attributes = bytearray()
        segments: List[Tuple[int, int]] = []
        names: List[str] = []

        def add_attr(t: int, v: bytes, *, prebuilt: bool = False):
            nonlocal attributes, segments, names
            start = len(attributes)
            if prebuilt and t == self.ATTR_VENDOR_SPECIFIC:
                tlv, inner_segs, inner_names = self._build_vendor_specific()
            else:
                tlv, inner_segs, inner_names = self._build_attribute(t, v)
            attributes += tlv
            # 把属性内的相对段映射到属性区绝对段
            for off_s, off_e in inner_segs:
                segments.append((start + off_s, start + off_e))
            names.extend(inner_names)

        # User-Name（ASCII）
        uname = random.choice([b'alice', b'bob', b'operator', b'admin', b'user01'])
        add_attr(self.ATTR_USER_NAME, uname)

        # NAS-IP-Address（4字节）
        nas_ip = socket.inet_aton(self._rand_ip())
        add_attr(self.ATTR_NAS_IP_ADDRESS, nas_ip)

        # NAS-Port（4字节整数，值域任意）
        nas_port = struct.pack('!I', random.randint(1, 65535))
        add_attr(self.ATTR_NAS_PORT, nas_port)

        # Service-Type（4字节，1=Login, 2=Framed等）
        service_type = struct.pack('!I', random.choice([1, 2, 8]))
        add_attr(self.ATTR_SERVICE_TYPE, service_type)

        # Calling-Station-Id / Called-Station-Id（ASCII）
        calling = f"{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}".encode()
        called = f"AP-{random.randint(1,9999):04d}".encode()
        add_attr(self.ATTR_CALLING_STATION_ID, calling)
        add_attr(self.ATTR_CALLED_STATION_ID, called)

        # Vendor-Specific（合规结构：Vendor-Id + Vendor-Data子TLV）
        add_attr(self.ATTR_VENDOR_SPECIFIC, b"", prebuilt=True)

        return bytes(attributes), segments, names

    def _build_radius_pdu(self, code: int, identifier: int,
                           include_password: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        """
        构建一个RADIUS PDU（不含UDP/IP封装），返回：
          - bytes: RADIUS报文
          - segments: 字段边界列表（相对RADIUS起点）
          - names: 字段名列表

        说明：
          - Authenticator：对于Request使用随机16字节；Response使用随机16字节（Wireshark不校验Secret，不会标Malformed）
          - Length：严格匹配总长度
          - Attribute：TLV合法
        """
        segments: List[Tuple[int, int]] = []
        names: List[str] = []

        header = bytearray()
        # 先占位：Code, Identifier, Length(2), Authenticator(16)
        header += struct.pack('!B', code)
        segments.append((0, 1)); names.append('Code')
        header += struct.pack('!B', identifier)
        segments.append((1, 2)); names.append('Identifier')
        header += struct.pack('!H', 0)  # Length占位
        segments.append((2, 4)); names.append('Length')
        # 按规范：Request使用随机16字节，Response此处仍用随机值（Wireshark不校验Secret，不会标Malformed）
        auth = self._rand_bytes(16)
        header += auth
        segments.append((4, 20)); names.append('Authenticator')

        # Attributes
        attrs, attr_segments, attr_names = self._build_common_attributes()
        attributes = bytearray(attrs)

        # 可选添加User-Password属性（仅为长度/合法性，不做MD5加密处理）
        if include_password:
            # 为避免Wireshark误判，将User-Password值模拟为16字节块（看起来像已加密的块）
            pwd_val = self._rand_bytes(16)
            tlv, inner_segs, inner_names = self._build_attribute(self.ATTR_USER_PASSWORD, pwd_val)
            start = len(attributes)
            attributes += tlv
            for off_s, off_e in inner_segs:
                attr_segments.append((start + off_s, start + off_e))
            attr_names.extend(inner_names)

        # 组装完整PDU并回填Length
        pdu = bytes(header) + bytes(attributes)
        total_len = len(pdu)
        pdu = pdu[:2] + struct.pack('!H', total_len) + pdu[4:]

        # 修正segments中Length字段仍为(2,4)保持一致；属性段偏移+20（头部长度）
        # 将属性段映射到RADIUS整体偏移
        for s, e in attr_segments:
            segments.append((20 + s, 20 + e))
        names.extend(attr_names)
        
        # 限制RADIUS总长度不超过传统最大值（避免极端组合导致异常）
        if total_len > 4096:
            pdu = pdu[:4096]
            # 更新Length
            pdu = pdu[:2] + struct.pack('!H', len(pdu)) + pdu[4:]

        return pdu, segments, names

    # ---------------------- 消息与数据包 -----------------------
    def generate_messages(self, count: int = 1000) -> List[Tuple[bytes, List[Tuple[int, int]], List[str]]]:
        messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]] = []
        for i in range(count):
            code = random.choices(
                [self.CODE_ACCESS_REQUEST, self.CODE_ACCESS_ACCEPT, self.CODE_ACCESS_REJECT,
                 self.CODE_ACCOUNTING_REQUEST, self.CODE_ACCOUNTING_RESPONSE],
                weights=[40, 15, 10, 25, 10], k=1
            )[0]
            identifier = random.randint(0, 255)
            include_pwd = (code == self.CODE_ACCESS_REQUEST) and (random.random() < 0.4)
            pdu, segs, names = self._build_radius_pdu(code, identifier, include_password=include_pwd)
            messages.append((pdu, segs, names))
        return messages

    def generate_packets_from_messages(self, messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]]):
        packets = []
        for pdu, _segs, _names in messages:
            src_mac = self._rand_mac()
            dst_mac = self._rand_mac()
            src_ip = self._rand_ip()
            dst_ip = self._rand_ip()

            # 选择认证或计费端口
            if pdu[0] in (self.CODE_ACCOUNTING_REQUEST, self.CODE_ACCOUNTING_RESPONSE):
                dport = random.choice(self.ACCT_PORTS)
            else:
                dport = random.choice(self.AUTH_PORTS)
            sport = random.randint(1024, 65535)

            pkt = Ether(src=src_mac, dst=dst_mac) / \
                  IP(src=src_ip, dst=dst_ip) / \
                  UDP(sport=sport, dport=dport) / \
                  Raw(load=pdu)
            packets.append(pkt)
        return packets

    # -------------------------- 输出 ---------------------------
    def save_to_csv(self, messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]], filename: str) -> None:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            for pdu, segs, names in messages:
                hex_str = pdu.hex()
                writer.writerow([
                    hex_str,
                    str(segs),
                    str(names)
                ])

    def save_to_pcap(self, filename: str, packets: List) -> None:
        if not packets:
            raise ValueError('没有可保存的数据包')
        wrpcap(filename, packets)


def main():
    print('RADIUS 协议消息生成器')
    print('=' * 50)

    gen = RadiusGenerator()
    messages = gen.generate_messages(1000)
    packets = gen.generate_packets_from_messages(messages)

    csv_path = os.path.join(gen.output_dir_csv, 'radius_messages.csv')
    pcap_path = os.path.join(gen.output_dir_pcap, 'radius_messages.pcap')

    gen.save_to_csv(messages, csv_path)
    gen.save_to_pcap(pcap_path, packets)

    print('生成完成:')
    print(f'CSV: {csv_path}')
    print(f'PCAP: {pcap_path}')


if __name__ == '__main__':
    main()


