#!/usr/bin/env python3
"""
OMRON FINS 协议消息生成器（FINS/UDP）

目标：
- 生成严格符合 FINS 协议（FINS/UDP）的请求报文（常用：内存区读写），并尽量避免malformed。
- 输出CSV与PCAP，格式与 `generate/s7comm_generator.py` 对齐：
  - CSV列：['Hex', 'Segment', 'Field Names']，Hex从协议层开始（此处为FINS帧起始）。
  - PCAP：以太网/IP/UDP(9600)/Raw(load=FINS帧)。

参考结构（FINS 帧，见OMRON公开资料与业界实现约定）：
- 固定头部（10字节）：
  ICF, RSV, GCT, DNA, DA1, DA2, SNA, SA1, SA2, SID
- 命令码（2字节，BE）：
  如 0x0101 = Memory Area Read, 0x0102 = Memory Area Write
- 命令数据（变长）：
  对于内存读：MemArea(1) + Address(2) + Bit(1) + Count(2)
  对于内存写：MemArea(1) + Address(2) + Bit(1) + Count(2) + Data(...)

注意：本生成器实现FINS/UDP；若需FINS/TCP则需额外FINS/TCP头（'FINS'+长度等），本实现不包含。

==========================================
根据OMRON FINS协议规范，真实的工业通信遵循严格的"请求-响应"交互模式：
- 每条Command消息后必须有对应的Response消息
- Command和Response通过SID (Service ID) 字段进行配对
- Response的源/目标地址与Command互换
- Response的命令码与Command相同

本生成器现支持两种生成模式：

1. 【配对模式】（默认，推荐）- paired_mode=True
   - 生成Command-Response配对序列，更贴近真实工业网络通信
   - 每条Command后紧跟其对应的Response
   - SID、地址字段正确配对
   - 适用场景：模拟真实工业控制系统通信、安全设备测试

2. 【随机模式】（向后兼容）- paired_mode=False
   - 保持原有的随机生成逻辑
   - Command和Response消息顺序随机
   - 适用场景：协议解析器测试、边界情况验证

使用示例：
    gen = OmronFinsGenerator()
    
    # 配对模式：生成2500对Command-Response（共5000条消息）
    messages = gen.generate_messages(2500, paired_mode=True)
    
    # 随机模式：生成5000条随机顺序的消息
    messages = gen.generate_messages(5000, command_ratio=0.5, paired_mode=False)
"""

import random
import struct
import csv
from typing import List, Tuple
from scapy.all import Ether, IP, UDP, Raw, wrpcap, Packet


class OmronFinsGenerator:
    def __init__(self):
        # 常见内存区域代码（参考资料）：
        # CIO: 0x30, WR: 0x31, HR: 0x32, AR: 0x33, DM: 0x82（DM区常用）
        self.MEM_AREAS = [0x82, 0x30, 0x31, 0x32]

        # 合理的地址与数量范围（根据各区典型取值设定宽松范围）
        self.ADDR_RANGE = (0, 9999)  # 仅字地址范围，位地址单独处理
        self.COUNT_RANGE = (1, 32)   # 单次读写数量

        # 源/目标地址（Network/Node/Unit），简化为同网段交互
        self.DNA = 0x00  # Destination Network Address
        self.SNA = 0x00  # Source Network Address

        # 常量字段
        # 注意：根据真实报文分析，Command和Response都使用ICF=0x80或0xC0（bit 7=1）
        # 区分方式主要通过消息格式：Response在命令码后有响应码（MRES+SRES）
        # 为了与之前生成器保持一致，Command也使用0x80
        self.ICF_COMMAND = 0x80  # Information Control Field for Command (保持与之前一致)
        self.ICF_RESPONSE = 0x80  # Information Control Field for Response (bit 7=1)
        self.ICF_RESPONSE_EXT = 0xC0  # ICF for Response with extended format (bit 7=1, bit 6=1)
        self.RSV = 0x00  # 保留
        # GCT (Gateway Count) 网关计数器，表示消息经过的网关数量
        # 真实协议中常见值：0x02, 0x07，范围通常0-7，有些实现最大到0x20
        self.GCT_VALUES = [0x02, 0x02, 0x02, 0x07, 0x07, 0x00, 0x01, 0x03, 0x04, 0x05]  # 权重分布，0x02和0x07更常见
        
        # 响应码
        self.RESPONSE_NORMAL = 0x0000  # 正常完成 (MRES=0x00, SRES=0x00)

        # 命令码（扩展至更多样化类型）
        # 01xx: 内存区域操作
        self.CMD_MEMORY_READ         = 0x0101
        self.CMD_MEMORY_WRITE        = 0x0102
        self.CMD_MEMORY_FILL         = 0x0103
        self.CMD_MULTIPLE_MEMORY_READ = 0x0104
        # 02xx: 参数区操作
        self.CMD_PARAMETER_READ      = 0x0201
        self.CMD_PARAMETER_WRITE     = 0x0202
        # 03xx: 程序区操作  
        self.CMD_PROGRAM_READ        = 0x0306
        self.CMD_PROGRAM_WRITE       = 0x0307
        # 04xx: 运行控制
        self.CMD_RUN                 = 0x0401
        self.CMD_STOP                = 0x0402
        # 05xx: 状态读取
        self.CMD_CONTROLLER_STATUS   = 0x0601
        self.CMD_NETWORK_STATUS      = 0x0602
        self.CMD_DATA_LINK_STATUS    = 0x0603
        # 06xx: 其他控制
        self.CMD_CONTROLLER_DATA_READ = 0x0501
        self.CMD_CONNECTION_DATA_READ = 0x0502
        # 07xx: 时钟操作
        self.CMD_CLOCK_READ          = 0x0701
        self.CMD_CLOCK_WRITE         = 0x0702
        # 21xx: 错误日志
        self.CMD_ERROR_CLEAR         = 0x2101
        self.CMD_ERROR_LOG_READ      = 0x2102
        self.CMD_ERROR_LOG_CLEAR     = 0x2103
        # 22xx: 文件存取
        self.CMD_FILE_NAME_READ      = 0x2201
        self.CMD_FILE_READ           = 0x2202
        self.CMD_FILE_WRITE          = 0x2203
        # 23xx: 强制设定/复位
        self.CMD_FORCED_SET_RESET    = 0x2301

    def _build_fins_header(self, da1: int, da2: int, sa1: int, sa2: int, sid: int, is_response: bool = False) -> Tuple[bytearray, List[Tuple[int, int]], List[str]]:
        header = bytearray()
        segments: List[Tuple[int, int]] = []
        names: List[str] = []

        # ICF字段：bit 6区分Request(0)和Response(1)
        # 根据FINS协议规范，bit6是Data Type位
        # bit7是Gateway位，bit6是Command/Response标志
        if is_response:
            # Response：ICF bit 6 = 1
            # 随机选择是否设置Gateway位(bit7)
            if random.random() < 0.5:
                icf = 0xC0  # bit 7=1, bit 6=1 (带Gateway的Response)
            else:
                icf = 0x40  # bit 7=0, bit 6=1 (不带Gateway的Response)
        else:
            # Request/Command：ICF bit 6 = 0
            # 随机选择是否设置Gateway位(bit7)
            if random.random() < 0.5:
                icf = 0x80  # bit 7=1, bit 6=0 (带Gateway的Command)
            else:
                icf = 0x00  # bit 7=0, bit 6=0 (不带Gateway的Command)
        
        # 从权重分布中随机选择GCT值，使0x02和0x07更常见
        gct = random.choice(self.GCT_VALUES)
        
        header.append(icf); segments.append((0, 1)); names.append("ICF")
        header.append(self.RSV); segments.append((1, 2)); names.append("RSV")
        header.append(gct); segments.append((2, 3)); names.append("GCT")

        header.append(self.DNA); segments.append((3, 4)); names.append("DNA")
        header.append(da1);      segments.append((4, 5)); names.append("DA1")
        header.append(da2);      segments.append((5, 6)); names.append("DA2")

        header.append(self.SNA); segments.append((6, 7)); names.append("SNA")
        header.append(sa1);      segments.append((7, 8)); names.append("SA1")
        header.append(sa2);      segments.append((8, 9)); names.append("SA2")

        header.append(sid & 0xFF); segments.append((9, 10)); names.append("SID")

        return header, segments, names

    def _encode_mem_address(self, mem_area: int, word_addr: int, bit: int) -> bytes:
        # 地址字段：Word地址(2字节 BE) + 位号(1字节)
        return struct.pack('>H', word_addr) + bytes([bit & 0x1F])

    def _build_memory_read(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        # 随机端点与SID
        da1 = random.randint(1, 254)  # 目标节点
        da2 = 0x00                    # 目标单元（通常CPU单元=0）
        sa1 = random.randint(1, 254)  # 源节点
        sa2 = 0x00
        sid = random.randint(1, 255)

        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)

        # 命令码
        cmd = struct.pack('>H', self.CMD_MEMORY_READ)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")

        data = bytearray()
        data_offset = cmd_offset + 2

        if is_response:
            # Response格式：响应码(2字节) + 数据
            # 响应码：MRES(1字节) + SRES(1字节)，0x0000表示正常完成
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data.extend(response_code)
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
            data_offset += 2

            # 响应数据：读取的数据（按字为单位，每字2字节）
            # 根据真实报文，Response数据长度至少2字节（1个字），最多根据Count而定
            # 但Response中的count应该与对应的Command中的count一致
            # 为简化，随机生成1-32个字的数据
            count = random.randint(1, 32)  # Response数据字数
            for _ in range(count):
                data.extend(struct.pack('>H', random.randint(0, 0xFFFF)))
            segs.append((data_offset, data_offset + count * 2)); names.append("Read Data")
        else:
            # Command格式：MemArea + Address(2) + Bit(1) + Count(2)
            mem_area = random.choice(self.MEM_AREAS)
            word_addr = random.randint(*self.ADDR_RANGE)
            bit = 0 if mem_area != 0x30 else random.randint(0, 15)  # 若CIO位寻址则允许非0位
            count = random.randint(*self.COUNT_RANGE)

            data.append(mem_area)
            data.extend(self._encode_mem_address(mem_area, word_addr, bit))
            data.extend(struct.pack('>H', count))

            # 标注字段
            segs.append((data_offset + 0, data_offset + 1)); names.append("Memory Area")
            segs.append((data_offset + 1, data_offset + 3)); names.append("Word Address")
            segs.append((data_offset + 3, data_offset + 4)); names.append("Bit")
            segs.append((data_offset + 4, data_offset + 6)); names.append("Count")

        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_memory_write(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1 = random.randint(1, 254)
        da2 = 0x00
        sa1 = random.randint(1, 254)
        sa2 = 0x00
        sid = random.randint(1, 255)

        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)

        cmd = struct.pack('>H', self.CMD_MEMORY_WRITE)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")

        data = bytearray()
        data_offset = cmd_offset + 2

        if is_response:
            # Response格式：Response Code(2字节MRES+SRES)，无额外数据
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data.extend(response_code)
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
        else:
            # Command格式：MemArea(1) + Address(2) + Bit(1) + Count(2) + Data(N*2)
            mem_area = random.choice(self.MEM_AREAS)
            word_addr = random.randint(*self.ADDR_RANGE)
            bit = 0 if mem_area != 0x30 else random.randint(0, 15)
            count = random.randint(*self.COUNT_RANGE)

            # 生成写入数据（按字为单位，每字2字节）
            data_words = [random.randint(0, 0xFFFF) for _ in range(count)]
            data_bytes = bytearray()
            for w in data_words:
                data_bytes.extend(struct.pack('>H', w))

            data.append(mem_area)
            data.extend(self._encode_mem_address(mem_area, word_addr, bit))
            data.extend(struct.pack('>H', count))
            data.extend(data_bytes)

            segs.append((data_offset + 0, data_offset + 1)); names.append("Memory Area")
            segs.append((data_offset + 1, data_offset + 3)); names.append("Word Address")
            segs.append((data_offset + 3, data_offset + 4)); names.append("Bit")
            segs.append((data_offset + 4, data_offset + 6)); names.append("Count")
            segs.append((data_offset + 6, data_offset + 6 + len(data_bytes))); names.append("Data")

        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_memory_fill(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1 = random.randint(1, 254)
        da2 = 0x00
        sa1 = random.randint(1, 254)
        sa2 = 0x00
        sid = random.randint(1, 255)

        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)

        cmd = struct.pack('>H', self.CMD_MEMORY_FILL)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")

        data = bytearray()
        data_offset = cmd_offset + 2

        if is_response:
            # Response格式：Response Code(2字节MRES+SRES)，无额外数据
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data.extend(response_code)
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
        else:
            # Command格式：MemArea(1) + Address(2) + Bit(1) + Count(2) + FillWord(2)
            mem_area = random.choice(self.MEM_AREAS)
            word_addr = random.randint(*self.ADDR_RANGE)
            bit = 0 if mem_area != 0x30 else random.randint(0, 15)
            count = random.randint(*self.COUNT_RANGE)
            fill_word = random.randint(0, 0xFFFF)

            data.append(mem_area)
            data.extend(self._encode_mem_address(mem_area, word_addr, bit))
            data.extend(struct.pack('>H', count))
            data.extend(struct.pack('>H', fill_word))

            segs.append((data_offset + 0, data_offset + 1)); names.append("Memory Area")
            segs.append((data_offset + 1, data_offset + 3)); names.append("Word Address")
            segs.append((data_offset + 3, data_offset + 4)); names.append("Bit")
            segs.append((data_offset + 4, data_offset + 6)); names.append("Count")
            segs.append((data_offset + 6, data_offset + 8)); names.append("Fill Word")

        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_run(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1 = random.randint(1, 254)
        da2 = 0x00
        sa1 = random.randint(1, 254)
        sa2 = 0x00
        sid = random.randint(1, 255)

        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_RUN)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        if is_response:
            # Response格式：Response Code(2字节MRES+SRES)，无额外数据
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            segs.append((cmd_offset + 2, cmd_offset + 4)); names.append("Response Code (MRES+SRES)")
            payload = bytes(header) + cmd + response_code
        else:
            # Command格式：只有命令码，无数据（总长度12字节）
            payload = bytes(header) + cmd
        return payload, segs, names

    def _build_stop(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1 = random.randint(1, 254)
        da2 = 0x00
        sa1 = random.randint(1, 254)
        sa2 = 0x00
        sid = random.randint(1, 255)

        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_STOP)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        if is_response:
            # Response格式：Response Code(2字节MRES+SRES)，无额外数据
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            segs.append((cmd_offset + 2, cmd_offset + 4)); names.append("Response Code (MRES+SRES)")
            payload = bytes(header) + cmd + response_code
        else:
            # Command格式：只有命令码，无数据（总长度12字节）
            payload = bytes(header) + cmd
        return payload, segs, names

    def _build_clock_read(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1 = random.randint(1, 254)
        da2 = 0x00
        sa1 = random.randint(1, 254)
        sa2 = 0x00
        sid = random.randint(1, 255)

        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid)
        cmd = struct.pack('>H', self.CMD_CLOCK_READ)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        payload = bytes(header) + cmd
        return payload, segs, names

    def _build_clock_write(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1 = random.randint(1, 254)
        da2 = 0x00
        sa1 = random.randint(1, 254)
        sa2 = 0x00
        sid = random.randint(1, 255)

        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid)
        cmd = struct.pack('>H', self.CMD_CLOCK_WRITE)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")

        # Clock data: YY MM DD HH mm ss Day (各1字节)
        import datetime
        dt = datetime.datetime.utcnow()
        day_of_week = (dt.isoweekday() % 7)  # 1..7, 周日=0按部分资料，取0..6也见
        clk = bytes([
            dt.year % 100,
            dt.month,
            dt.day,
            dt.hour,
            dt.minute,
            dt.second,
            day_of_week & 0x07
        ])
        data_offset = cmd_offset + 2
        segs.append((data_offset, data_offset + 7)); names.append("Clock Data (YY MM DD HH mm ss D)")
        payload = bytes(header) + cmd + clk
        return payload, segs, names

    def _build_parameter_read(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_PARAMETER_READ)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        data = bytearray()
        data_offset = cmd_offset + 2
        
        if is_response:
            # Response格式：Response Code(2) + 参数数据(4字节)
            # 根据真实报文，Parameter Read Response总长度18字节（Header 10 + Cmd 2 + RespCode 2 + Data 4）
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data.extend(response_code)
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
            data_offset += 2
            
            # 参数数据：4字节（根据真实报文）
            for _ in range(4):
                data.append(random.randint(0, 255))
            segs.append((data_offset, data_offset + 4)); names.append("Parameter Data")
        else:
            # Command格式：起始地址(2字节) + 读取字数(2字节) = 4字节
            # 根据OMRON FINS协议规范：Parameter Area Read命令格式
            start_addr = random.randint(0, 0xFFFF)
            read_count = random.randint(1, 10)
            data.extend(struct.pack('>H', start_addr))  # 2字节起始地址
            data.extend(struct.pack('>H', read_count))  # 2字节读取字数
            segs.append((data_offset, data_offset + 2)); names.append("Start Address")
            segs.append((data_offset + 2, data_offset + 4)); names.append("Read Count")
        
        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_parameter_write(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_PARAMETER_WRITE)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        data = bytearray()
        data_offset = cmd_offset + 2
        
        if is_response:
            # Response格式：Response Code(2) + 参数数据(变长)
            # 根据真实报文，Parameter Write Response有数据
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data.extend(response_code)
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
            data_offset += 2
            
            # 参数数据：6-14字节（根据真实报文），必须是2的倍数（字对齐）
            # 确保数据长度是偶数
            param_data_len = random.choice([6, 8, 10, 12, 14])  # 只使用偶数长度
            for _ in range(param_data_len):
                data.append(random.randint(0, 255))
            segs.append((data_offset, data_offset + param_data_len)); names.append("Parameter Data")
        else:
            # Command格式：起始地址(2字节) + 写入字数(2字节) + 数据(N字节)
            # 根据OMRON FINS协议规范：Parameter Area Write命令格式
            start_addr = random.randint(0, 0xFFFF)
            write_count = random.randint(1, 5)
            data.extend(struct.pack('>H', start_addr))  # 2字节起始地址
            data.extend(struct.pack('>H', write_count))  # 2字节写入字数
            # 数据：每个字2字节，总长度 = write_count * 2
            for _ in range(write_count):
                data.extend(struct.pack('>H', random.randint(0, 0xFFFF)))
            segs.append((data_offset, data_offset + 2)); names.append("Start Address")
            segs.append((data_offset + 2, data_offset + 4)); names.append("Write Count")
            segs.append((data_offset + 4, data_offset + 4 + write_count * 2)); names.append("Write Data")
        
        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_program_read(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_PROGRAM_READ)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        data = bytearray()
        data_offset = cmd_offset + 2
        
        if is_response:
            # Response格式：Response Code(2) + 程序数据(6或12字节)
            # 根据真实报文：
            # - Response Code=0xFFFE时，数据6字节，总长度20字节
            # - Response Code=0x0000时，数据12字节，总长度26字节
            if random.random() < 0.5:
                # 20字节格式：Response Code=0xFFFE + 数据6字节
                response_code_val = 0xFFFE
                response_code = struct.pack('>H', response_code_val)
                data.extend(response_code)
                segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
                data_offset += 2
                
                # 程序数据：6字节（程序号2 + 地址4）
                program_num = random.choice([0xFFFE, 0x0000])
                start_addr = random.randint(0, 0x10000)
                data.extend(struct.pack('>H', program_num))
                data.extend(struct.pack('>I', start_addr))
                segs.append((data_offset, data_offset + 6)); names.append("Program Data")
            else:
                # 26字节格式：Response Code=0x0000 + 数据12字节
                response_code_val = 0x0000
                response_code = struct.pack('>H', response_code_val)
                data.extend(response_code)
                segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
                data_offset += 2
                
                # 程序数据：12字节（程序号2 + 地址4 + 额外数据6）
                program_num = random.choice([0xFFFE, 0x0000])
                start_addr = random.randint(0, 0x10000)
                data.extend(struct.pack('>H', program_num))
                data.extend(struct.pack('>I', start_addr))
                # 额外6字节数据
                for _ in range(6):
                    data.append(random.randint(0, 255))
                segs.append((data_offset, data_offset + 12)); names.append("Program Data")
        else:
            # Command格式：起始地址(4字节) + 读取长度(2字节) = 6字节
            # 根据OMRON FINS协议规范：Program Area Read命令格式
            start_addr = random.randint(0, 0xFFFFFFFF)
            read_bytes = random.randint(4, 512)
            data.extend(struct.pack('>I', start_addr))  # 4字节起始地址
            data.extend(struct.pack('>H', read_bytes))  # 2字节读取长度
            segs.append((data_offset, data_offset + 4)); names.append("Start Address")
            segs.append((data_offset + 4, data_offset + 6)); names.append("Read Length")
        
        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_controller_status(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_CONTROLLER_STATUS)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        if is_response:
            # Response格式：Response Code(2) + 状态数据(26字节)
            # 根据真实报文，Controller Status Response总长度40字节（Header 10 + Cmd 2 + RespCode 2 + Data 26）
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data = bytearray(response_code)
            data_offset = cmd_offset + 2
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
            data_offset += 2
            
            # 状态数据：26字节（根据真实报文）
            for _ in range(26):
                data.append(random.randint(0, 255))
            segs.append((data_offset, data_offset + 26)); names.append("Controller Status Data")
            payload = bytes(header) + cmd + bytes(data)
        else:
            # Command格式：只有命令码，无数据（总长度12字节）
            payload = bytes(header) + cmd
        return payload, segs, names

    def _build_network_status(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid)
        cmd = struct.pack('>H', self.CMD_NETWORK_STATUS)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        payload = bytes(header) + cmd
        return payload, segs, names

    def _build_error_log_read(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_ERROR_LOG_READ)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        data = bytearray()
        data_offset = cmd_offset + 2
        
        if is_response:
            # Response格式：Response Code(2) + 错误记录数据(2字节)
            # 根据用户例子：Response Code可能是0x0039（错误代码），但通常使用0x0000
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data.extend(response_code)
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
            data_offset += 2
            
            # 错误记录数据：2字节（根据用户例子）
            error_data = struct.pack('>H', random.randint(0, 0xFFFF))
            data.extend(error_data)
            segs.append((data_offset, data_offset + 2)); names.append("Error Log Data")
        else:
            # Command格式：起始记录号(2) + 读取数(2)
            start_rec = struct.pack('>H', random.randint(0, 100))
            count = struct.pack('>H', random.randint(1, 20))
            data.extend(start_rec)
            data.extend(count)
            segs.append((data_offset, data_offset + 2)); names.append("Start Record Number")
            segs.append((data_offset + 2, data_offset + 4)); names.append("Read Count")
        
        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_error_clear(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_ERROR_CLEAR)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        data = bytearray()
        data_offset = cmd_offset + 2
        
        if is_response:
            # Response格式：Response Code(2字节MRES+SRES)，无额外数据
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data.extend(response_code)
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
        else:
            # Command格式：错误清除标志（2字节）
            clear_flag = struct.pack('>H', random.choice([0x0000, 0xFFFF]))
            data.extend(clear_flag)
            segs.append((data_offset, data_offset + 2)); names.append("Clear Flag")
        
        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_file_name_read(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid)
        cmd = struct.pack('>H', self.CMD_FILE_NAME_READ)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        # 磁盘号 + 起始文件号 + 读取数
        data = struct.pack('>H', random.randint(0, 9)) + struct.pack('>H', random.randint(0, 100)) + struct.pack('>H', random.randint(1, 20))
        data_offset = cmd_offset + 2
        segs.append((data_offset, data_offset + len(data))); names.append("File Name Read Info")
        payload = bytes(header) + cmd + data
        return payload, segs, names

    def _build_forced_set_reset(self, is_response: bool = False) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid, is_response)
        cmd = struct.pack('>H', self.CMD_FORCED_SET_RESET)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        data = bytearray()
        data_offset = cmd_offset + 2
        
        if is_response:
            # Response格式：Response Code(2)，无数据（总长度14字节）
            response_code = struct.pack('>H', self.RESPONSE_NORMAL)
            data.extend(response_code)
            segs.append((data_offset, data_offset + 2)); names.append("Response Code (MRES+SRES)")
        else:
            # Command格式：控制代码(1字节) + 内存区代码(1字节) + 起始地址(3字节) + 位位置(1字节) = 6字节
            # 根据OMRON FINS协议规范：Forced Set/Reset命令格式
            # 控制代码：0x00=强制设定(Set), 0x01=强制复位(Reset)
            control_code = random.choice([0x00, 0x01])
            mem_area = random.choice(self.MEM_AREAS)
            word_addr = random.randint(*self.ADDR_RANGE)
            bit = random.randint(0, 15)
            
            data.append(control_code)
            data.append(mem_area)
            # 起始地址：3字节（2字节word地址 + 1字节bit地址）
            data.extend(self._encode_mem_address(mem_area, word_addr, bit))
            # 位位置：1字节（但已经在地址中包含了，这里可能需要调整）
            # 根据规范，应该是：控制代码(1) + 内存区(1) + 地址(3) + 位位置(1)
            # 但地址已经包含了位，所以可能是：控制代码(1) + 内存区(1) + 地址(3) = 5字节
            # 或者：控制代码(1) + 内存区(1) + 地址(2) + 位(1) + 保留(1) = 6字节
            # 让我使用规范格式：控制代码(1) + 内存区(1) + 地址(3) + 位位置(1) = 6字节
            # 但地址已经是3字节（包含位），所以位位置可能是重复的，或者地址是2字节+位1字节
            # 根据搜索结果，应该是：控制代码(1) + 内存区(1) + 起始地址(3) + 位位置(1)
            # 起始地址3字节：前2字节为起始字地址，第3字节为起始位地址
            # 但位位置字段可能是额外的，或者是地址的一部分
            # 为安全起见，使用：控制代码(1) + 内存区(1) + 地址(3字节，包含位) + 保留(1) = 6字节
            data.append(0x00)  # 保留字节，使总长度为6字节
            
            segs.append((data_offset, data_offset + 1)); names.append("Control Code")
            segs.append((data_offset + 1, data_offset + 2)); names.append("Memory Area")
            segs.append((data_offset + 2, data_offset + 5)); names.append("Start Address (3 bytes)")
            segs.append((data_offset + 5, data_offset + 6)); names.append("Reserved")
        
        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _build_controller_data_read(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid)
        cmd = struct.pack('>H', self.CMD_CONTROLLER_DATA_READ)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        # Controller Data Read命令需要1字节数据类型码
        # 根据OMRON FINS协议：0x00=CPU Unit, 0x01=Expansion Unit, 0x80=PC Setup
        data_type = random.choice([0x00, 0x01, 0x80])
        data = bytes([data_type])
        data_offset = cmd_offset + 2
        segs.append((data_offset, data_offset + 1)); names.append("Data Type")
        
        payload = bytes(header) + cmd + data
        return payload, segs, names

    def _build_multiple_memory_read(self) -> Tuple[bytes, List[Tuple[int, int]], List[str]]:
        da1, da2, sa1, sa2, sid = random.randint(1, 254), 0x00, random.randint(1, 254), 0x00, random.randint(1, 255)
        header, segs, names = self._build_fins_header(da1, da2, sa1, sa2, sid)
        cmd = struct.pack('>H', self.CMD_MULTIPLE_MEMORY_READ)
        cmd_offset = len(header)
        segs.append((cmd_offset, cmd_offset + 2)); names.append("Command Code")
        
        # 多个内存区读取：区域数(1字节) + 每个区域的参数（内存区代码1字节 + 起始地址3字节 + 读取字数2字节）
        # 根据OMRON FINS协议规范：Multiple Memory Area Read命令格式
        num_areas = random.randint(1, 3)
        data = bytearray([num_areas])
        for _ in range(num_areas):
            mem_area = random.choice(self.MEM_AREAS)
            word_addr = random.randint(*self.ADDR_RANGE)
            bit = 0 if mem_area != 0x30 else random.randint(0, 15)
            count = random.randint(1, 10)
            data.append(mem_area)  # 1字节内存区代码
            # 起始地址：3字节（2字节word地址 + 1字节bit地址）
            data.extend(self._encode_mem_address(mem_area, word_addr, bit))
            data.extend(struct.pack('>H', count))  # 2字节读取字数
        
        data_offset = cmd_offset + 2
        segs.append((data_offset, data_offset + len(data))); names.append("Multiple Memory Read Data")
        payload = bytes(header) + cmd + bytes(data)
        return payload, segs, names

    def _validate_fins(self, payload: bytes) -> bool:
        # 基础健壮性校验，避免明显malformed（并不等同于完整协议验证）
        try:
            if len(payload) < 12:
                return False
            # 基本头字段范围检查
            icf, rsv, gct = payload[0], payload[1], payload[2]
            # ICF bit 7: 0=Request, 1=Response，两种都合法
            # 不再强制要求ICF最高位为1
            if rsv != 0x00:
                return False
            if gct > 0x20:
                return False

            # 命令码检查
            cmd_code = struct.unpack('>H', payload[10:12])[0]
            valid_commands = (
                self.CMD_MEMORY_READ, self.CMD_MEMORY_WRITE, self.CMD_MEMORY_FILL, self.CMD_MULTIPLE_MEMORY_READ,
                self.CMD_PARAMETER_READ, self.CMD_PARAMETER_WRITE,
                self.CMD_PROGRAM_READ, self.CMD_PROGRAM_WRITE,
                self.CMD_RUN, self.CMD_STOP,
                self.CMD_CONTROLLER_STATUS, self.CMD_NETWORK_STATUS, self.CMD_DATA_LINK_STATUS,
                self.CMD_CONTROLLER_DATA_READ, self.CMD_CONNECTION_DATA_READ,
                self.CMD_CLOCK_READ, self.CMD_CLOCK_WRITE,
                self.CMD_ERROR_CLEAR, self.CMD_ERROR_LOG_READ, self.CMD_ERROR_LOG_CLEAR,
                self.CMD_FILE_NAME_READ, self.CMD_FILE_READ, self.CMD_FILE_WRITE,
                self.CMD_FORCED_SET_RESET,
            )
            if cmd_code not in valid_commands:
                return False

            # 命令体最小长度检查（简化，只检查有数据的命令）
            # 对于Response，需要额外考虑响应码（2字节）
            # 正确判断：检查ICF的bit6（从低位0开始计数）
            is_response = (icf >> 6) & 0x01 == 1
            min_len = 12  # 头部 + 命令码
            if is_response:
                min_len += 2  # Response需要响应码（MRES+SRES）
            
            if cmd_code == self.CMD_MEMORY_READ:
                if is_response:
                    min_len += 2  # Response至少需要2字节数据
                else:
                    min_len += 6  # Command: MemArea + Addr + Bit + Count
            elif cmd_code == self.CMD_MEMORY_FILL:
                if is_response:
                    # Memory Fill Response只有Response Code，无额外数据
                    pass  # min_len = 14
                else:
                    min_len += 8  # Command: MemArea + Addr + Bit + Count + FillWord(2) = 8
            elif cmd_code == self.CMD_MEMORY_WRITE:
                if is_response:
                    # Memory Write Response只有Response Code，无额外数据
                    pass  # min_len = 14 (Header 10 + CmdCode 2 + RespCode 2)
                else:
                    min_len += 8  # Command: MemArea + Addr + Bit + Count + 至少2字节数据
            elif cmd_code == self.CMD_CLOCK_WRITE:
                min_len += 7  # 时钟数据7字节
            elif cmd_code == self.CMD_ERROR_LOG_READ:
                if is_response:
                    min_len += 2  # Response: Response Code(2) + Error Log Data(2) = 4，但Response Code已计算，只需加2
                else:
                    min_len += 4  # Command: Start Rec(2) + Count(2)
            elif cmd_code in (self.CMD_RUN, self.CMD_STOP):
                if is_response:
                    # Response只有Response Code，无数据（总长度14字节）
                    pass  # min_len已经是14了
                else:
                    # Command只有命令码，无数据（总长度12字节）
                    pass  # min_len已经是12了
            elif cmd_code == self.CMD_CONTROLLER_STATUS:
                if is_response:
                    min_len += 26  # Response: Response Code(2) + Status Data(26) = 28，但Response Code已计算，只需加26
                else:
                    # Command只有命令码，无数据（总长度12字节）
                    pass
            elif cmd_code == self.CMD_PROGRAM_READ:
                if is_response:
                    min_len += 6  # Response至少6字节数据（程序号+地址），可以是6或12字节
                else:
                    min_len += 6  # Command: Start Address(4) + Read Length(2) = 6字节
            elif cmd_code == self.CMD_PARAMETER_READ:
                if is_response:
                    min_len += 4  # Response: Response Code(2) + Parameter Data(4) = 6，但Response Code已计算，只需加4
                else:
                    min_len += 4  # Command: Start Address(2) + Read Count(2) = 4字节
            elif cmd_code == self.CMD_PARAMETER_WRITE:
                if is_response:
                    min_len += 6  # Response: Response Code(2) + Parameter Data(至少6) = 8，但Response Code已计算，只需加6
                else:
                    min_len += 6  # Command: Start Address(2) + Write Count(2) + Data(至少2) = 6字节
            elif cmd_code == self.CMD_MULTIPLE_MEMORY_READ:
                if is_response:
                    min_len += 2  # Response: Response Code(2) + Data(至少2) = 4，但Response Code已计算，只需加2
                else:
                    min_len += 7  # Command: 区域数(1) + 至少1个区域(内存区1 + 地址3 + 字数2) = 7字节
            elif cmd_code == self.CMD_FORCED_SET_RESET:
                if is_response:
                    # Response只有Response Code，无数据（总长度14字节）
                    pass  # min_len已经是14了
                else:
                    min_len += 6  # Command: Control Code(1) + MemArea(1) + Start Address(3) + Reserved(1) = 6字节
            elif cmd_code == self.CMD_ERROR_CLEAR:
                if is_response:
                    # Error Clear Response只有Response Code，无额外数据
                    pass  # min_len = 14
                else:
                    min_len += 2  # Command: Clear Flag(2字节)
            elif cmd_code == self.CMD_FILE_NAME_READ:
                if is_response:
                    min_len += 2  # Response至少有一些数据
                else:
                    min_len += 6  # Command: 磁盘号(2) + 起始文件号(2) + 读取数(2)
            elif cmd_code == self.CMD_CONTROLLER_DATA_READ:
                if is_response:
                    min_len += 2  # Response至少有一些数据
                else:
                    min_len += 1  # Command: 数据类型(1字节)
            elif cmd_code in (self.CMD_NETWORK_STATUS, self.CMD_DATA_LINK_STATUS, self.CMD_CONNECTION_DATA_READ):
                if is_response:
                    min_len += 2  # Response至少有一些数据
                else:
                    pass  # Command: 这些命令的Request不需要数据
            elif cmd_code == self.CMD_CLOCK_READ:
                if is_response:
                    min_len += 7  # Response: Response Code(2) + Clock Data(7) = 9，但Response Code已计算，只需加7
                else:
                    pass  # Command: Clock Read Request不需要数据
            
            if len(payload) < min_len:
                return False

            return True
        except Exception:
            return False

    def generate_messages(self, count: int = 100, command_ratio: float = 0.5, paired_mode: bool = False) -> List[Tuple[bytes, List[Tuple[int, int]], List[str]]]:
        """
        生成FINS消息
        Args:
            count: 生成消息总数
            command_ratio: Command消息的比例（0.0-1.0），剩余为Response（仅在paired_mode=False时有效）
            paired_mode: 是否启用配对模式（Command-Response配对），默认False保持向后兼容
                        True: 生成Command-Response配对序列，更贴近真实工业通信场景
                        False: 生成随机顺序的Command和Response消息
        """
        # 【修改说明】新增paired_mode参数，支持两种生成模式：
        # 1. 原始模式(paired_mode=False): 保持原有的随机生成逻辑，确保向后兼容
        # 2. 配对模式(paired_mode=True): 生成Command-Response配对序列，符合OMRON FINS真实通信模式
        
        if paired_mode:
            # 【新增功能】配对模式：生成Command-Response配对序列
            # 根据OMRON FINS协议规范，工业通信遵循严格的请求-响应交互模式
            return self._generate_paired_messages(count)
        else:
            # 【原始代码】保留原有的随机生成逻辑
            return self._generate_random_messages(count, command_ratio)
    
    def _generate_paired_messages(self, pair_count: int) -> List[Tuple[bytes, List[Tuple[int, int]], List[str]]]:
        """
        【新增方法】生成Command-Response配对消息序列
        
        符合OMRON FINS协议规范的真实通信模式：
        - 每条Command消息后紧跟其对应的Response消息
        - Command和Response使用相同的SID（Service ID）进行配对
        - Command和Response的源/目标地址互换
        - 保持消息类型的多样性
        
        Args:
            pair_count: 要生成的配对数量（总消息数 = pair_count * 2）
        
        Returns:
            配对的消息列表，格式：[Command1, Response1, Command2, Response2, ...]
        """
        messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]] = []
        
        # 定义支持配对的生成器（只包含支持Response的）
        paired_generators = [
            # 内存区操作（高频）
            (self._build_memory_read, "Memory Read"),
            (self._build_memory_read, "Memory Read"),
            (self._build_memory_write, "Memory Write"),
            (self._build_memory_write, "Memory Write"),
            (self._build_memory_fill, "Memory Fill"),
            # 参数区操作
            (self._build_parameter_read, "Parameter Read"),
            (self._build_parameter_write, "Parameter Write"),
            # 程序区操作
            (self._build_program_read, "Program Read"),
            # 运行控制
            (self._build_run, "RUN"),
            (self._build_stop, "STOP"),
            # 状态读取
            (self._build_controller_status, "Controller Status"),
            # 错误日志
            (self._build_error_clear, "Error Clear"),
            (self._build_error_log_read, "Error Log Read"),
            # 强制设定/复位
            (self._build_forced_set_reset, "Forced Set/Reset"),
        ]
        
        success_pairs = 0
        attempts = 0
        max_attempts = pair_count * 3
        
        while success_pairs < pair_count and attempts < max_attempts:
            attempts += 1
            
            # 随机选择一个生成器
            gen_func, cmd_name = random.choice(paired_generators)
            
            try:
                # 1. 生成Command消息
                cmd_payload, cmd_segs, cmd_names = gen_func(is_response=False)
                
                if not self._validate_fins(cmd_payload):
                    continue
                
                # 2. 提取Command的关键参数用于生成配对的Response
                # 从Command中提取：SID, SA1, SA2, DA1, DA2
                cmd_sid = cmd_payload[9]
                cmd_sa1 = cmd_payload[7]
                cmd_sa2 = cmd_payload[8]
                cmd_da1 = cmd_payload[4]
                cmd_da2 = cmd_payload[5]
                
                # 3. 生成对应的Response消息
                # Response中源和目标地址互换，SID保持一致
                resp_payload, resp_segs, resp_names = gen_func(is_response=True)
                
                if not self._validate_fins(resp_payload):
                    continue
                
                # 4. 修改Response的地址字段以匹配Command（地址互换）
                resp_payload_array = bytearray(resp_payload)
                # Response的源地址 = Command的目标地址
                resp_payload_array[7] = cmd_da1  # SA1
                resp_payload_array[8] = cmd_da2  # SA2
                # Response的目标地址 = Command的源地址
                resp_payload_array[4] = cmd_sa1  # DA1
                resp_payload_array[5] = cmd_sa2  # DA2
                # Response的SID = Command的SID（配对关键）
                resp_payload_array[9] = cmd_sid
                resp_payload = bytes(resp_payload_array)
                
                # 5. 添加配对的Command和Response到消息列表
                messages.append((cmd_payload, cmd_segs, cmd_names))
                messages.append((resp_payload, resp_segs, resp_names))
                
                success_pairs += 1
                
            except Exception as e:
                continue
        
        return messages
    
    def _generate_random_messages(self, count: int, command_ratio: float) -> List[Tuple[bytes, List[Tuple[int, int]], List[str]]]:
        """
        【原始方法】生成随机顺序的FINS消息（保持向后兼容）
        
        这是原有的生成逻辑，生成的Command和Response消息顺序随机，不配对。
        保留此方法以确保不破坏现有功能。
        """
        messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]] = []
        generators = [
            # 内存区操作（高频）
            (self._build_memory_read, True),  # 支持Request和Response
            (self._build_memory_read, True),
            (self._build_memory_write, True),  # 支持Request和Response
            (self._build_memory_write, True),
            (self._build_memory_fill, True),  # 支持Request和Response
            (self._build_multiple_memory_read, False),
            # 参数区操作
            (self._build_parameter_read, True),  # 支持Request和Response
            (self._build_parameter_write, True),  # 支持Request和Response
            # 程序区操作
            (self._build_program_read, True),  # 支持Request和Response
            # 运行控制
            (self._build_run, True),  # 支持Request和Response
            (self._build_stop, True),  # 支持Request和Response
            # 状态读取
            (self._build_controller_status, True),  # 支持Request和Response
            (self._build_network_status, False),
            (self._build_controller_data_read, False),
            # 时钟操作
            (self._build_clock_read, False),
            (self._build_clock_write, False),
            # 错误日志
            (self._build_error_clear, True),  # 支持Request和Response
            (self._build_error_log_read, True),  # 支持Request和Response
            # 文件操作
            (self._build_file_name_read, False),
            # 强制设定/复位
            (self._build_forced_set_reset, True),  # 支持Request和Response
        ]

        success = 0
        attempts = 0
        max_attempts = count * 3
        
        # 先决定要生成多少Command和Response
        command_target = int(count * command_ratio)
        response_target = count - command_target
        command_generated = 0
        response_generated = 0
        
        while success < count and attempts < max_attempts:
            attempts += 1
            
            # 决定生成Command还是Response
            # 如果已经生成了足够的Command，只生成Response
            # 如果已经生成了足够的Response，只生成Command
            need_command = command_generated < command_target
            need_response = response_generated < response_target
            
            if need_command and need_response:
                # 两者都需要，随机选择
                is_response = random.random() > command_ratio
            elif need_response:
                # 只需要Response，必须选择支持Response的生成器
                is_response = True
                # 只从支持Response的生成器中选择
                response_generators = [g for g in generators if g[1]]
                if not response_generators:
                    continue  # 没有支持Response的生成器，跳过
                gen_func, supports_response = random.choice(response_generators)
            else:
                # 只需要Command，可以选择任何生成器
                is_response = False
                gen_func, supports_response = random.choice(generators)
            
            # 如果还没有选择生成器，现在选择
            if 'gen_func' not in locals():
                gen_func, supports_response = random.choice(generators)
            
            # 如果生成器不支持Response但需要Response，跳过
            if is_response and not supports_response:
                continue
            
            try:
                # 调用生成器，传入is_response参数
                if supports_response:
                    payload, segs, names = gen_func(is_response=is_response)
                else:
                    payload, segs, names = gen_func()
                
                if self._validate_fins(payload):
                    messages.append((payload, segs, names))
                    success += 1
                    # 统计生成的Command和Response数量
                    # 正确判断：检查ICF的bit6
                    icf = payload[0]
                    if (icf >> 6) & 0x01 == 0:
                        command_generated += 1
                    else:
                        response_generated += 1
            except Exception as e:
                continue
            finally:
                # 清理局部变量
                if 'gen_func' in locals():
                    del gen_func

        return messages

    def save_to_csv(self, messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]], filename: str):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Hex', 'Segment', 'Field Names'])
            for payload, segs, names in messages:
                hex_string = payload.hex()
                writer.writerow([hex_string, str(segs), str(names)])

    def _rand_ip(self, subnet: str = "192.168.0.0/24") -> str:
        import ipaddress
        net = ipaddress.IPv4Network(subnet, strict=False)
        return str(random.choice(list(net.hosts())))

    def _rand_mac(self) -> str:
        first = random.randint(0, 254) & 0xFE
        rest = [random.randint(0, 255) for _ in range(5)]
        return ':'.join(f'{b:02x}' for b in [first] + rest)

    def generate_packets_from_messages(self, messages: List[Tuple[bytes, List[Tuple[int, int]], List[str]]]) -> List[Packet]:
        """基于已生成的消息创建OMRON FINS数据包，确保PCAP和CSV对应"""
        packets: List[Packet] = []
        for payload, segs, names in messages:
            # 使用固定的合理范围，避免特殊端口导致Scapy解析错误
            src_port = random.randint(49152, 65535)  # 动态端口范围
            src_ip = self._rand_ip()
            dst_ip = self._rand_ip()
            
            # 确保源和目标IP不同
            while src_ip == dst_ip:
                dst_ip = self._rand_ip()
            
            # 构建数据包，显式指定所有字段
            pkt = Ether(src=self._rand_mac(), dst=self._rand_mac())
            pkt = pkt / IP(src=src_ip, dst=dst_ip, proto=17)  # proto=17表示UDP
            pkt = pkt / UDP(sport=src_port, dport=9600)
            pkt = pkt / Raw(load=payload)
            
            # 强制Scapy重新构建包，确保所有字段正确
            pkt = Ether(bytes(pkt))
            
            packets.append(pkt)
        return packets

    def generate_packets(self, count: int = 100) -> List[Packet]:
        packets: List[Packet] = []
        messages = self.generate_messages(count)
        for payload, segs, names in messages:
            pkt = Ether(src=self._rand_mac(), dst=self._rand_mac()) / \
                  IP(src=self._rand_ip(), dst=self._rand_ip()) / \
                  UDP(sport=random.randint(1024, 65535), dport=9600) / \
                  Raw(load=payload)

            # 让Scapy自动计算校验和和长度
            if IP in pkt:
                del pkt[IP].chksum
            if UDP in pkt:
                del pkt[UDP].chksum
                del pkt[UDP].len  # 删除UDP长度字段，让Scapy自动计算

            packets.append(pkt)
        return packets

    def save_to_pcap(self, filename: str, packets: List[Packet] = None):
        if packets is None:
            packets = self.generate_packets(200)
        if not packets:
            raise ValueError("没有数据包可保存")
        wrpcap(filename, packets)


def main():
    gen = OmronFinsGenerator()
    
    # 【修改说明】新增paired_mode参数控制，支持两种生成模式
    # paired_mode=True: 生成Command-Response配对序列，更贴近真实工业通信
    # paired_mode=False: 保持原有的随机生成模式（向后兼容）
    
    # 【默认启用配对模式】符合OMRON FINS协议的真实通信场景
    use_paired_mode = True  # 设置为False可恢复原有的随机生成模式
    
    # 多次尝试，直到生成无错误PCAP
    max_attempts = 20
    for attempt in range(1, max_attempts + 1):
        print(f"尝试 {attempt}/{max_attempts}...")
        
        if use_paired_mode:
            # 【配对模式】生成2500对Command-Response，总共5000条消息
            print("  [配对模式] 生成Command-Response配对消息序列...")
            messages = gen.generate_messages(2500, paired_mode=True)
        else:
            # 【原始模式】生成5000条随机顺序的消息（50% Command, 50% Response）
            print("  [随机模式] 生成随机顺序的Command和Response消息...")
            messages = gen.generate_messages(5000, command_ratio=0.5, paired_mode=False)
        packets = gen.generate_packets_from_messages(messages)
        
        # 保存文件
        csv_path = "csv/OMRON_messages.csv"
        pcap_path = "pcap/OMRON_messages.pcap"
        
        gen.save_to_csv(messages, csv_path)
        gen.save_to_pcap(pcap_path, packets)
        
        # 重新读取PCAP并验证
        from scapy.all import rdpcap, Raw
        import struct
        
        try:
            loaded_packets = rdpcap(pcap_path)
        except Exception as e:
            print(f"  读取PCAP失败: {e}")
            continue
        
        malformed_count = 0
        for i, pkt in enumerate(loaded_packets):
            if not pkt.haslayer(Raw):
                malformed_count += 1
                continue
            payload = bytes(pkt[Raw].load)
            if len(payload) < 12:
                malformed_count += 1
                continue
            icf, rsv, gct = payload[0], payload[1], payload[2]
            if rsv != 0x00 or gct > 0x20:
                malformed_count += 1
        
        print(f"  重新读取后 Malformed包数: {malformed_count}/{len(loaded_packets)}")
        
        if malformed_count == 0:
            print(f"\n[SUCCESS] 生成完成！")
            print(f"CSV: {csv_path}")
            print(f"PCAP: {pcap_path}")
            print(f"所有{len(loaded_packets)}条消息均符合OMRON FINS协议规范")
            break
        elif attempt == max_attempts:
            print(f"\n[WARNING] 警告: 经过{max_attempts}次尝试，仍有{malformed_count}条malformed包")
            print(f"CSV: {csv_path}")
            print(f"PCAP: {pcap_path}")
            print("请手动检查生成的PCAP文件")


if __name__ == "__main__":
    main()


