#!/usr/bin/env python3
"""
PCAP -> CSV converter for generated datasets.
Replicates the FSIBP/data_preprocess_code/text2csv.py parsing logic (tshark JSON),
but operates on generate/pcap/*.pcap and writes CSVs to generate/csv/.

Default protocol: s7comm
Output CSV format: Hex, Segment, Field Names
"""

import os
import json
import csv
import argparse
import subprocess
from typing import List, Tuple, Any, Dict, Union


def obj_pairs_hook(lst):
    """
    Handle duplicate keys in tshark JSON.
    """
    result = {}
    count = {}
    for key, val in lst:
        if key in count:
            count[key] = 1 + count[key]
        else:
            count[key] = 1
        if key in result:
            if count[key] > 2:
                result[key].append(val)
            else:
                result[key] = [result[key], val]
        else:
            result[key] = val
    return result


def protocol_name_check(protocol_name: Union[str, List[str]]):
    if protocol_name == 'modbus':
        protocol_name = ['mbtcp', 'modbus']
    if protocol_name == 'dnp3':
        protocol_name = ['dnp3', 'dnp']

    if isinstance(protocol_name, list):
        protocol_name_o = protocol_name[0]
    else:
        protocol_name_o = protocol_name
    return protocol_name, protocol_name_o


def pcap_to_json(pcap_filepath: str, json_filepath: str, protocol_name: str):
    """
    Use tshark to export protocol layer to JSON with raw hex.
    """
    if protocol_name == 'modbus':
        command = f'tshark -r "{pcap_filepath}" -T json -O "mbtcp modbus" -x > "{json_filepath}"'
    else:
        command = f'tshark -r "{pcap_filepath}" -T json -O "{protocol_name}" -x > "{json_filepath}"'
    subprocess.run(command, shell=True)


def read_field(
    pcap_data: Dict[str, Any],
    field_name_list: List[str],
    packet_field_value_list: List[str],
    packet_field_offset_list: List[int],
    field_offset_end_list: List[int],
    packet_byte_shift: int,
    protocol_name: Union[str, List[str]],
    last_field_len: int
):
    def should_skip_entry(entry, key):
        return (
            (entry[1] == packet_byte_shift and entry[2] == last_field_len) or
            (len(entry[0]) < 2 and key != 'modbus.func_code_raw')
        )

    def key_matches_protocol(key):
        return any(key.startswith(f"{p}.") for p in protocols)

    def process_entry(entry, key):
        nonlocal packet_byte_shift, last_field_len

        if should_skip_entry(entry, key):
            last_field_len = entry[2]
            return

        if key_matches_protocol(key):
            # Replace previous field if this is a finer split at same offset
            if entry[1] == packet_byte_shift and entry[2] <= last_field_len:
                if field_name_list and packet_field_value_list:
                    field_name_list.pop()
                    packet_field_value_list.pop()
                    packet_field_offset_list.pop()
                    field_offset_end_list.pop()

            # Add new entry
            if isinstance(entry[1], int):
                field_name_list.append(key)
                packet_field_value_list.append(entry[0])
                packet_field_offset_list.append(entry[1])
                field_offset_end_list.append(entry[1] + entry[2])
                packet_byte_shift = entry[1]
                last_field_len = entry[2]

    protocols = [protocol_name] if isinstance(protocol_name, str) else protocol_name

    for key, value in pcap_data.items():
        if isinstance(value, dict):
            packet_byte_shift, last_field_len = read_field(
                value, field_name_list, packet_field_value_list,
                packet_field_offset_list, field_offset_end_list,
                packet_byte_shift, protocol_name, last_field_len
            )
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    packet_byte_shift, last_field_len = read_field(
                        item, field_name_list, packet_field_value_list,
                        packet_field_offset_list, field_offset_end_list,
                        packet_byte_shift, protocol_name, last_field_len
                    )
                elif isinstance(item, list) and len(item) == 5 and isinstance(item[0], str):
                    process_entry(item, key)
            if len(value) == 5 and isinstance(value[0], str):
                process_entry(value, key)

    return packet_byte_shift, last_field_len


def clean_res(protocol_name, field_offset_list, field_offset_end_list, field_name_list, original_hex_list):
    # DNP3 special-case alignment fix
    if protocol_name == ['dnp3', 'dnp']:
        if 0 in field_offset_list:
            dnp3_al_start = field_offset_list.index(0)
            max_crc_offset = field_offset_list[dnp3_al_start - 1]
            if any(isinstance(x, str) for x in field_offset_list):
                field_offset_list = field_offset_list[:dnp3_al_start]
                field_offset_end_list = field_offset_end_list[:dnp3_al_start]
                field_name_list = field_name_list[:dnp3_al_start]
            elif max(field_offset_list) > max_crc_offset:
                field_offset_list = field_offset_list[:dnp3_al_start]
                field_offset_end_list = field_offset_end_list[:dnp3_al_start]
                field_name_list = field_name_list[:dnp3_al_start]
            else:
                field_offset_list[dnp3_al_start:] = [x+65 for x in field_offset_list[dnp3_al_start:]]
                field_offset_end_list[dnp3_al_start:] = [x+65 for x in field_offset_end_list[dnp3_al_start:]]

    # Filter fields that cover the entire hex payload
    filtered = []
    max_data_length = len(original_hex_list[-1]) // 2 if original_hex_list else 0
    for offset, end_offset, name in zip(field_offset_list, field_offset_end_list, field_name_list):
        if not (end_offset - offset == max_data_length):
            filtered.append((offset, end_offset, name))
    if not filtered:
        filtered = list(zip(field_offset_list, field_offset_end_list, field_name_list))

    temp_list = sorted(filtered, key=lambda x: x[0])
    if temp_list:
        field_offset_list, field_offset_end_list, field_name_list = zip(*temp_list)
    else:
        field_offset_list, field_offset_end_list, field_name_list = [], [], []

    if not field_offset_list:
        return [], [], original_hex_list

    minus_offset = min(field_offset_list)
    field_offset_list = [x - minus_offset for x in field_offset_list]
    field_offset_end_list = [x - minus_offset for x in field_offset_end_list]

    fmt = list(zip(field_offset_list, field_offset_end_list))
    field_name_list = list(field_name_list)

    max_end_offset = max(pair[1] for pair in fmt) if fmt else 0
    if original_hex_list:
        original_hex_list[-1] = original_hex_list[-1][:2 * max_end_offset]

    return fmt, field_name_list, original_hex_list


def write_new_csv(csv_filepath, packet_results, original_hex_list, protocol_name):
    os.makedirs(os.path.dirname(csv_filepath), exist_ok=True)
    with open(csv_filepath, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Hex', 'Segment', 'Field Names'])
        for i, result in enumerate(packet_results):
            hex_str = original_hex_list[i] if (original_hex_list and i < len(original_hex_list)) else "N/A"
            segment_list = result['format']
            field_names_list = result['field_names']
            writer.writerow([hex_str, segment_list, field_names_list])


def convert_pcap_to_csv(pcap_path: str, out_csv_dir: str, protocol: str = 's7comm'):
    os.makedirs(out_csv_dir, exist_ok=True)
    json_tmp = os.path.join(out_csv_dir, 'temp_json.json')

    pcap_to_json(pcap_path, json_tmp, protocol)

    with open(json_tmp, 'r', encoding='UTF-8') as f:
        json_data = json.load(f, object_pairs_hook=obj_pairs_hook)

    protocol_name, protocol_name_o = protocol_name_check(protocol)

    packet_results = []
    original_hex_list = []

    for packet in json_data:
        field_name_list = []
        field_value_list = []
        field_offset_list = []
        field_offset_end_list = []

        packet_byte_shift = 0
        last_field_len = 0
        try:
            raw = packet['_source']['layers'][protocol_name_o + '_raw'][0]
            if isinstance(raw, str):
                original_hex_list.append(raw)
            elif isinstance(raw, list):
                original_hex_list.append(''.join([msg[0] for msg in packet['_source']['layers'][protocol_name_o + '_raw']]))
        except KeyError:
            # Skip packets without target protocol
            continue

        read_field(packet, field_name_list, field_value_list, field_offset_list, field_offset_end_list, packet_byte_shift, protocol_name, last_field_len)

        fmt, field_name_list, original_hex_list = clean_res(protocol_name, field_offset_list, field_offset_end_list, field_name_list, original_hex_list)
        packet_results.append({'format': fmt, 'field_names': field_name_list})

    # Normalize protocol name for filename
    out_protocol = protocol
    if protocol_name == ['mbtcp', 'modbus']:
        out_protocol = 'modbus'
    if protocol_name == ['dnp3', 'dnp']:
        out_protocol = 'dnp3'

    base = os.path.splitext(os.path.basename(pcap_path))[0]
    out_csv = os.path.join(out_csv_dir, f'{out_protocol}_{base}.csv')
    write_new_csv(out_csv, packet_results, original_hex_list, out_protocol)
    return out_csv


def main():
    parser = argparse.ArgumentParser(
        description="Convert PCAP file(s) to CSV (Hex, Segment, Field Names) using tshark JSON parsing."
    )
    parser.add_argument(
        'pcap_files',
        nargs='+',
        help='One or more PCAP file paths to convert.'
    )
    parser.add_argument(
        '--protocol',
        default='s7comm',
        help='Protocol name passed to tshark -O (e.g., s7comm, modbus, dnp3, smb, smb2, dns, ftp, tls).'
    )
    parser.add_argument(
        '--out_dir',
        default=os.path.join('.', 'csv'),
        help='Output CSV directory (default: generate/csv)'
    )
    args = parser.parse_args()

    out_dir = args.out_dir
    protocol = args.protocol
    pcap_files = args.pcap_files

    print(f'Converting {len(pcap_files)} PCAP(s) using protocol={protocol} ...')
    for pcap_path in pcap_files:
        if not os.path.isfile(pcap_path):
            print(f'SKIP: {pcap_path} (not a file)')
            continue
        try:
            out_csv = convert_pcap_to_csv(pcap_path, out_dir, protocol)
            print(f'OK: {os.path.basename(pcap_path)} -> {os.path.basename(out_csv)}')
        except Exception as e:
            print(f'ERROR converting {pcap_path}: {e}')


if __name__ == '__main__':
    main()


