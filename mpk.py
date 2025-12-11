#!/usr/bin/env python3
# mpk_extract.py
# Usage: python mpk_extract.py <patch.mpkdb | x.mpkinfo> <output_dir>
# Extracts MPK files into <output_dir>/LocalData/Patch/...

import os
import sqlite3
import struct
import lz4.block
import pylzma
import re
import sys
import pyzstd
from Crypto.Cipher import AES

# --------------------
# Helper functions
# --------------------
def connect_db(db_file):
    return sqlite3.connect(db_file)

def fetch_table_data(conn, table_name):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM {table_name}")
    return cur.fetchall()

def scan_mpk_files(directory):
    mpk_files = [f for f in os.listdir(directory) if f.endswith('.mpk')]
    mpk_indices = {}
    for mpk in mpk_files:
        prefix = os.path.splitext(mpk)[0]
        match = re.search(r'(\D+)(\d*)', prefix, re.IGNORECASE)
        if match:
            base_prefix = match.group(1)
            file_position = int(match.group(2)) if match.group(2) else 0
            if base_prefix not in mpk_indices:
                mpk_indices[base_prefix] = {}
            mpk_indices[base_prefix][file_position] = os.path.join(directory, mpk)
    return mpk_indices

def process_output_txt(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile, open(output_file, 'w', encoding='utf-8', errors='ignore') as outfile:
        for line in infile:
            outfile.write(line.replace('-', '').replace('|', ','))

# --------------------
# Decompression helpers
# --------------------
def decompress_lz4_zzz4(data):
    magic = data[:4]
    if magic != b'ZZZ4':
        raise ValueError('Invalid magic number for LZ4 ZZZ4 compression.')
    uncompressed_size = struct.unpack('<I', data[4:8])[0]
    compressed_data = data[8:]
    decompressed_data = lz4.block.decompress(compressed_data, uncompressed_size=uncompressed_size)
    return decompressed_data

def decompress_lzma(data):
    try:
        magic_name = data[:4]
        if magic_name != b'LZMA':
            raise ValueError("File does not have the 'LZMA' magic name")
        uncompressed_size = struct.unpack('<I', data[4:8])[0]
        compressed_data = data[8:]
        decompressed_data = pylzma.decompress(compressed_data, maxlength=uncompressed_size)
        return decompressed_data
    except Exception as e:
        print(f"LZMA Decompression failed: {e}")
        return None

def decompress_zzzx(data):
    EZST_AES_KEY = bytes.fromhex("753572326E586A556728153F912F78385667536250613B2D397636733370596B")
    if data[:4] != b'ZZZX':
        raise ValueError("Invalid ZZZX header!")
    decompressed_size = struct.unpack('<I', data[4:8])[0]
    compressed_data = data[8:]
    block_size = min(0x100, len(compressed_data))
    block_size = (block_size // 16) * 16
    if block_size > 0:
        cipher = AES.new(EZST_AES_KEY, AES.MODE_ECB)
        encrypted_block = compressed_data[:block_size]
        decrypted_block = cipher.decrypt(encrypted_block)
        compressed_data = decrypted_block + compressed_data[block_size:]
    decompressed_data = lz4.block.decompress(compressed_data, uncompressed_size=decompressed_size)
    if len(decompressed_data) != decompressed_size:
        print(f"Warning: Decompressed size mismatch (expected: {decompressed_size}, got: {len(decompressed_data)})")
    return decompressed_data

def decompress_ezst(data):
    EZST_AES_KEY = bytes.fromhex("753572326E586A556728153F912F78385667536250613B2D397636733370596B")
    if data[:4] != b'EZST':
        raise ValueError("Invalid EZST header!")
    decompressed_size = struct.unpack('<I', data[4:8])[0]
    compressed_data = data[8:]
    block_size = min(0x100, len(compressed_data))
    block_size = (block_size // 16) * 16
    if block_size > 0:
        cipher = AES.new(EZST_AES_KEY, AES.MODE_ECB)
        encrypted_block = compressed_data[:block_size]
        decrypted_block = cipher.decrypt(encrypted_block)
        compressed_data = decrypted_block + compressed_data[block_size:]
    decompressed_data = pyzstd.decompress(compressed_data)
    if len(decompressed_data) != decompressed_size:
        print(f"Warning: Decompressed size mismatch (expected: {decompressed_size}, got: {len(decompressed_data)})")
    return decompressed_data

def decompress_lz4hc(data):
    if len(data) < 10:
        raise ValueError('Data too short for LZ4HC compression header')
    if data[6:10] != b'\x1BLua':
        raise ValueError('Invalid magic number for LZ4HC compression.')
    uncompressed_size = struct.unpack('<I', data[0:4])[0]
    compressed_data = data[4:]
    try:
        decompressed_data = lz4.block.decompress(compressed_data, uncompressed_size=uncompressed_size)
        return decompressed_data
    except Exception:
        try:
            return lz4.block.decompress(compressed_data)
        except Exception as e:
            raise ValueError(f'LZ4HC decompression failed: {e}')

# Detect multiple compression headers
def has_multiple_compression_headers(data):
    zzz4_count = data.count(b'ZZZ4')
    lzma_count = data.count(b'LZMA')
    zzzx_count = data.count(b'ZZZX')
    ezst_count = data.count(b'EZST')
    lz4hc_count = data.count(b'\x1BLua', 6)
    return (zzz4_count + lzma_count + zzzx_count + ezst_count + lz4hc_count) > 1

# Write decompressed data to file (detect single header types)
def decompress_if_single_header(data, temp_filename):
    try:
        if data.startswith(b'ZZZ4'):
            decompressed_data = decompress_lz4_zzz4(data)
            with open(temp_filename, 'wb') as write_file:
                write_file.write(decompressed_data)
            print(f"Decompressed LZ4 ZZZ4: {temp_filename}")
        elif data.startswith(b'LZMA'):
            decompressed_data = decompress_lzma(data)
            if decompressed_data is None:
                raise Exception("LZMA returned None")
            with open(temp_filename, 'wb') as write_file:
                write_file.write(decompressed_data)
            print(f"Decompressed LZMA: {temp_filename}")
        elif data.startswith(b'ZZZX'):
            decompressed_data = decompress_zzzx(data)
            with open(temp_filename, 'wb') as write_file:
                write_file.write(decompressed_data)
            print(f"Decompressed ZZZX: {temp_filename}")
        elif data.startswith(b'EZST'):
            decompressed_data = decompress_ezst(data)
            with open(temp_filename, 'wb') as write_file:
                write_file.write(decompressed_data)
            print(f"Decompressed EZST: {temp_filename}")
        elif len(data) > 10 and data[6:10] == b'\x1BLua':
            decompressed_data = decompress_lz4hc(data)
            with open(temp_filename, 'wb') as write_file:
                write_file.write(decompressed_data)
            print(f"Decompressed LZ4HC: {temp_filename}")
        else:
            # No known header, just write raw data
            with open(temp_filename, 'wb') as write_file:
                write_file.write(data)
            print(f"No valid compression headers for {temp_filename}; wrote raw data.")
    except Exception as e:
        # On any failure, save raw data so nothing is lost
        print(f"Decompression failed for {temp_filename}: {e}")
        with open(temp_filename, 'wb') as write_file:
            write_file.write(data)
        print(f"Saved raw data due to failure: {temp_filename}")

# --------------------
# MPK handling
# --------------------
def find_mpk_file(mpk_indices, base_prefix, file_position):
    if base_prefix in mpk_indices and file_position in mpk_indices[base_prefix]:
        return mpk_indices[base_prefix][file_position]
    for prefix, positions in mpk_indices.items():
        if file_position in positions:
            return positions[file_position]
    return None

def handle_mpk_files(info_lines, base_path, mpk_indices, output_dir):
    out_root = os.path.join(output_dir, "LocalData", "Patch")
    for info_line in info_lines:
        parts = info_line.split(',')
        if len(parts) < 7:
            continue
        filename, size, file_position, _, _, mapping, offset = parts
        base_prefix = filename.split('.')[0][:2]
        mpk_filename = find_mpk_file(mpk_indices, base_prefix, int(file_position))
        if not mpk_filename or not os.path.exists(mpk_filename):
            print(f"Skipping {mpk_filename} as it does not exist.")
            continue
        with open(mpk_filename, 'rb') as mpk_file:
            mpk_file.seek(int(offset))
            data = mpk_file.read(int(size))
            # Create appropriate directory inside output_dir
            if int(mapping) == 0:
                path = os.path.join(out_root, filename[:2])
                os.makedirs(path, exist_ok=True)
                target_path = os.path.join(path, filename)
            else:
                target_path = os.path.join(out_root, filename)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
            if has_multiple_compression_headers(data):
                with open(target_path, 'wb') as temp_file:
                    temp_file.write(data)
                print(f"Multiple compression headers detected, saved raw: {target_path}")
            else:
                decompress_if_single_header(data, target_path)

def parse_mpkinfobin(mpkinfobin_file, base_path, output_dir):
    out_root = os.path.join(output_dir, "LocalData", "Patch")
    with open(mpkinfobin_file, 'rb') as f:
        f.seek(8)
        while True:
            data = f.read(20)
            if len(data) < 20:
                break
            file_name_bytes = data[:8]
            file_name = ''.join([f'{b:02x}'.lower() for b in file_name_bytes])
            folder_name = f"{file_name[:2]}"
            file_name = f"{folder_name}/{file_name}"
            offset = struct.unpack('<I', data[8:12])[0]
            size = struct.unpack('<I', data[12:16])[0]
            file_position_raw = struct.unpack('<I', data[16:20])[0]
            if file_position_raw == 1:
                continue
            file_position = file_position_raw // 2
            base_prefix = os.path.splitext(os.path.basename(mpkinfobin_file))[0]
            mpk_indices = scan_mpk_files(base_path)
            mpk_filename = find_mpk_file(mpk_indices, base_prefix, file_position)
            if not mpk_filename or not os.path.exists(mpk_filename):
                continue
            with open(mpk_filename, 'rb') as mpk_file:
                mpk_file.seek(offset)
                data = mpk_file.read(size)
                target_path = os.path.join(out_root, file_name)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                if has_multiple_compression_headers(data):
                    with open(target_path, 'wb') as temp_file:
                        temp_file.write(data)
                else:
                    decompress_if_single_header(data, target_path)

# --------------------
# Main
# --------------------
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print("  python mpk_extract.py <patch.mpkdb | x.mpkinfo> <output_dir>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2]
    base_path = './'  # script expects mpk files in current working directory

    os.makedirs(output_dir, exist_ok=True)

    if input_file.endswith('.mpkdb'):
        conn = connect_db(input_file)
        rows = fetch_table_data(conn, 'info0')
        with open('output.txt', 'w', encoding='utf-8', errors='ignore') as f:
            for row in rows:
                f.write('|'.join([str(item).strip('-') for item in row]) + '\n')
        process_output_txt('output.txt', 'output.mpkinfo')
        mpk_indices = scan_mpk_files(base_path)
        with open('output.mpkinfo', 'r', encoding='utf-8', errors='ignore') as infile:
            info_lines = [line.strip() for line in infile if line.strip()]
        handle_mpk_files(info_lines, base_path, mpk_indices, output_dir)

    elif input_file.endswith('.mpkinfo'):
        parse_mpkinfobin(input_file, base_path, output_dir)
    else:
        print("Input file must be .mpkdb or .mpkinfo")
        sys.exit(1)

