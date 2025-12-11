#!/usr/bin/env python3
"""
mpk_gui_extract.py
All-in-one MPK extractor with GUI, auto-detect, progress and CLI fallback.

Usage (GUI):
    double-click the script (python on PATH), or run:
    python mpk_gui_extract.py --gui

Usage (CLI):
    python mpk_gui_extract.py Patch.mpkdb /path/to/mpk_folder /path/to/output_dir

Dependencies:
    pip install lz4 pylzma pyzstd pycryptodome tqdm

To build EXE (Windows):
    pip install pyinstaller
    pyinstaller --noconsole --onefile mpk_gui_extract.py
"""

import os
import sys
import sqlite3
import struct
import lz4.block
import pylzma
import re
import threading
import pyzstd
from Crypto.Cipher import AES
import argparse
from tqdm import tqdm

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext, messagebox
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

# ------------------------------
# Core extraction / decompress code
# (based on your original functions)
# ------------------------------

EZST_AES_KEY = bytes.fromhex("753572326E586A556728153F912F78385667536250613B2D397636733370596B")

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

# -- decompression helpers --

def decompress_lz4_zzz4(data):
    if data[:4] != b'ZZZ4':
        raise ValueError('Invalid ZZZ4 header')
    uncompressed_size = struct.unpack('<I', data[4:8])[0]
    compressed_data = data[8:]
    return lz4.block.decompress(compressed_data, uncompressed_size=uncompressed_size)

def decompress_lzma(data):
    if data[:4] != b'LZMA':
        raise ValueError('Invalid LZMA header')
    uncompressed_size = struct.unpack('<I', data[4:8])[0]
    compressed_data = data[8:]
    return pylzma.decompress(compressed_data, maxlength=uncompressed_size)

def decrypt_aes_ecb(masked_block):
    cipher = AES.new(EZST_AES_KEY, AES.MODE_ECB)
    return cipher.decrypt(masked_block)

def decompress_zzzx(data):
    if data[:4] != b'ZZZX':
        raise ValueError('Invalid ZZZX header')
    decompressed_size = struct.unpack('<I', data[4:8])[0]
    compressed_data = data[8:]
    block_size = min(0x100, len(compressed_data))
    block_size = (block_size // 16) * 16
    if block_size > 0:
        decrypted = decrypt_aes_ecb(compressed_data[:block_size])
        compressed_data = decrypted + compressed_data[block_size:]
    return lz4.block.decompress(compressed_data, uncompressed_size=decompressed_size)

def decompress_ezst(data):
    if data[:4] != b'EZST':
        raise ValueError('Invalid EZST header')
    decompressed_size = struct.unpack('<I', data[4:8])[0]
    compressed_data = data[8:]
    block_size = min(0x100, len(compressed_data))
    block_size = (block_size // 16) * 16
    if block_size > 0:
        decrypted = decrypt_aes_ecb(compressed_data[:block_size])
        compressed_data = decrypted + compressed_data[block_size:]
    return pyzstd.decompress(compressed_data)

def decompress_lz4hc(data):
    if len(data) < 10 or data[6:10] != b'\x1BLua':
        raise ValueError('Invalid LZ4HC header')
    uncompressed_size = struct.unpack('<I', data[0:4])[0]
    compressed_data = data[4:]
    try:
        return lz4.block.decompress(compressed_data, uncompressed_size=uncompressed_size)
    except Exception:
        return lz4.block.decompress(compressed_data)

def has_multiple_compression_headers(data):
    zzz4_count = data.count(b'ZZZ4')
    lzma_count = data.count(b'LZMA')
    zzzx_count = data.count(b'ZZZX')
    ezst_count = data.count(b'EZST')
    lz4hc_count = data.count(b'\x1BLua', 6)
    return (zzz4_count + lzma_count + zzzx_count + ezst_count + lz4hc_count) > 1

def decompress_if_single_header(data, temp_filename, log):
    try:
        if data.startswith(b'ZZZ4'):
            out = decompress_lz4_zzz4(data)
            with open(temp_filename, 'wb') as wf: wf.write(out)
            log(f"Decompressed ZZZ4 -> {temp_filename}")
        elif data.startswith(b'LZMA'):
            out = decompress_lzma(data)
            with open(temp_filename, 'wb') as wf: wf.write(out)
            log(f"Decompressed LZMA -> {temp_filename}")
        elif data.startswith(b'ZZZX'):
            out = decompress_zzzx(data)
            with open(temp_filename, 'wb') as wf: wf.write(out)
            log(f"Decompressed ZZZX -> {temp_filename}")
        elif data.startswith(b'EZST'):
            out = decompress_ezst(data)
            with open(temp_filename, 'wb') as wf: wf.write(out)
            log(f"Decompressed EZST -> {temp_filename}")
        elif len(data) > 10 and data[6:10] == b'\x1BLua':
            out = decompress_lz4hc(data)
            with open(temp_filename, 'wb') as wf: wf.write(out)
            log(f"Decompressed LZ4HC -> {temp_filename}")
        else:
            with open(temp_filename, 'wb') as wf: wf.write(data)
            log(f"No header: wrote raw -> {temp_filename}")
    except Exception as e:
        # Save raw block on failure
        with open(temp_filename, 'wb') as wf: wf.write(data)
        log(f"Decompression error for {temp_filename}: {e} (saved raw)")

def find_mpk_file(mpk_indices, base_prefix, file_position):
    if base_prefix in mpk_indices and file_position in mpk_indices[base_prefix]:
        return mpk_indices[base_prefix][file_position]
    for prefix, positions in mpk_indices.items():
        if file_position in positions:
            return positions[file_position]
    return None

# ------------------------------
# High-level extraction flow
# ------------------------------
def extract_from_mpkdb(mpkdb_path, mpk_folder, out_dir, gui_log=None, progress_callback=None):
    def log(msg):
        if gui_log: gui_log(msg)
        else: print(msg)

    if not os.path.exists(mpkdb_path):
        raise FileNotFoundError("MPKDB not found: " + mpkdb_path)
    if not os.path.isdir(mpk_folder):
        raise FileNotFoundError("MPK folder not found: " + mpk_folder)
    os.makedirs(out_dir, exist_ok=True)

    conn = connect_db(mpkdb_path)
    rows = fetch_table_data(conn, 'info0')
    tmp_out = os.path.join(os.path.dirname(mpkdb_path), 'output.mpkinfo')
    with open('output.txt', 'w', encoding='utf-8', errors='ignore') as f:
        for row in rows:
            f.write('|'.join([str(item).strip('-') for item in row]) + '\n')
    process_output_txt('output.txt', tmp_out)

    mpk_indices = scan_mpk_files(mpk_folder)
    with open(tmp_out, 'r', encoding='utf-8', errors='ignore') as infile:
        info_lines = [line.strip() for line in infile if line.strip()]

    total = len(info_lines)
    log(f"Found {total} entries to extract.")
    for idx, info_line in enumerate(info_lines, start=1):
        parts = info_line.split(',')
        if len(parts) < 7:
            if progress_callback: progress_callback(idx, total)
            continue
        filename, size, file_position, _, _, mapping, offset = parts
        base_prefix = filename.split('.')[0][:2]
        mpk_filename = find_mpk_file(mpk_indices, base_prefix, int(file_position))
        if not mpk_filename or not os.path.exists(mpk_filename):
            log(f"Missing mpk for {filename} -> {mpk_filename}")
            if progress_callback: progress_callback(idx, total)
            continue
        with open(mpk_filename, 'rb') as mpkf:
            mpkf.seek(int(offset))
            data = mpkf.read(int(size))

        # build target path inside out_dir
        out_root = os.path.join(out_dir, "LocalData", "Patch")
        if int(mapping) == 0:
            path = os.path.join(out_root, filename[:2])
            os.makedirs(path, exist_ok=True)
            target_path = os.path.join(path, filename)
        else:
            target_path = os.path.join(out_root, filename)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

        if has_multiple_compression_headers(data):
            with open(target_path, 'wb') as wf:
                wf.write(data)
            log(f"Saved raw (multi-header) -> {target_path}")
        else:
            decompress_if_single_header(data, target_path, log)

        if progress_callback:
            progress_callback(idx, total)
    log("Extraction complete.")

def extract_from_mpkinfo(mpkinfo_path, mpk_folder, out_dir, gui_log=None, progress_callback=None):
    def log(msg):
        if gui_log: gui_log(msg)
        else: print(msg)
    if not os.path.exists(mpkinfo_path):
        raise FileNotFoundError("mpkinfo not found: " + mpkinfo_path)
    if not os.path.isdir(mpk_folder):
        raise FileNotFoundError("MPK folder not found: " + mpk_folder)
    os.makedirs(out_dir, exist_ok=True)
    mpk_indices = scan_mpk_files(mpk_folder)
    with open(mpkinfo_path, 'rb') as f:
        f.seek(8)
        entries = []
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
            entries.append((file_name, offset, size, file_position))
    total = len(entries)
    log(f"{total} entries found in mpkinfo.")
    for idx, (file_name, offset, size, file_position) in enumerate(entries, start=1):
        base_prefix = os.path.splitext(os.path.basename(mpkinfo_path))[0]
        mpk_filename = find_mpk_file(mpk_indices, base_prefix, file_position)
        if not mpk_filename or not os.path.exists(mpk_filename):
            log(f"Missing mpk for {file_name} -> {mpk_filename}")
            if progress_callback: progress_callback(idx, total)
            continue
        with open(mpk_filename, 'rb') as mpkf:
            mpkf.seek(offset)
            data = mpkf.read(size)
        out_root = os.path.join(out_dir, "LocalData", "Patch")
        target_path = os.path.join(out_root, file_name)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        if has_multiple_compression_headers(data):
            with open(target_path, 'wb') as wf:
                wf.write(data)
            log(f"Saved raw (multi-header) -> {target_path}")
        else:
            decompress_if_single_header(data, target_path, log)
        if progress_callback: progress_callback(idx, total)
    log("Extraction complete (mpkinfo).")

# ------------------------------
# GUI
# ------------------------------
class ExtractorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MPK Extractor")
        self.geometry("760x520")
        self.resizable(True, True)

        frm = ttk.Frame(self, padding=8)
        frm.pack(fill='both', expand=True)

        # Input selection
        row = 0
        ttk.Label(frm, text="MPKDB / MPKINFO file:").grid(column=0, row=row, sticky='w')
        self.input_entry = ttk.Entry(frm, width=70)
        self.input_entry.grid(column=1, row=row, sticky='we', padx=6)
        ttk.Button(frm, text="Browse", command=self.browse_input).grid(column=2, row=row)

        row += 1
        ttk.Label(frm, text="MPK folder (contains .mpk files):").grid(column=0, row=row, sticky='w')
        self.mpk_entry = ttk.Entry(frm, width=70)
        self.mpk_entry.grid(column=1, row=row, sticky='we', padx=6)
        ttk.Button(frm, text="Browse", command=self.browse_mpk_folder).grid(column=2, row=row)

        row += 1
        ttk.Label(frm, text="Output folder:").grid(column=0, row=row, sticky='w')
        self.out_entry = ttk.Entry(frm, width=70)
        self.out_entry.grid(column=1, row=row, sticky='we', padx=6)
        ttk.Button(frm, text="Browse", command=self.browse_out_folder).grid(column=2, row=row)

        row += 1
        ttk.Button(frm, text="Auto-detect (mpk folder)", command=self.auto_detect_mpk).grid(column=0, row=row, pady=6)
        ttk.Button(frm, text="Start Extraction", command=self.start_extraction).grid(column=1, row=row, pady=6, sticky='w')

        # Progress bar and status
        row += 1
        self.progress = ttk.Progressbar(frm, orient='horizontal', mode='determinate')
        self.progress.grid(column=0, row=row, columnspan=3, sticky='we', pady=(6,0))

        row += 1
        ttk.Label(frm, text="Log:").grid(column=0, row=row, sticky='w')
        row += 1
        self.logbox = scrolledtext.ScrolledText(frm, height=18)
        self.logbox.grid(column=0, row=row, columnspan=3, sticky='nsew')

        # configure grid weights
        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(row, weight=1)

    def browse_input(self):
        f = filedialog.askopenfilename(title="Select Patch.mpkdb or .mpkinfo", filetypes=[("mpkdb", "*.mpkdb"), ("mpkinfo", "*.mpkinfo"), ("All files", "*.*")])
        if f:
            self.input_entry.delete(0, 'end')
            self.input_entry.insert(0, f)
            # auto fill mpk folder to parent by default
            parent = os.path.dirname(f)
            self.mpk_entry.delete(0, 'end')
            self.mpk_entry.insert(0, parent)

    def browse_mpk_folder(self):
        d = filedialog.askdirectory(title="Select folder containing .mpk files")
        if d:
            self.mpk_entry.delete(0, 'end')
            self.mpk_entry.insert(0, d)

    def browse_out_folder(self):
        d = filedialog.askdirectory(title="Select output folder (will be created if missing)")
        if d:
            self.out_entry.delete(0, 'end')
            self.out_entry.insert(0, d)

    def auto_detect_mpk(self):
        # find .mpkdb or .mpkinfo in current dir
        cwd = os.getcwd()
        candidates = [f for f in os.listdir(cwd) if f.lower().endswith(('.mpkdb', '.mpkinfo'))]
        if candidates:
            self.input_entry.delete(0, 'end')
            self.input_entry.insert(0, os.path.join(cwd, candidates[0]))
        mpks = [f for f in os.listdir(cwd) if f.endswith('.mpk')]
        if mpks:
            self.mpk_entry.delete(0, 'end')
            self.mpk_entry.insert(0, cwd)
        self.out_entry.delete(0, 'end')
        default_out = os.path.join(cwd, "ExtractedOutput")
        self.out_entry.insert(0, default_out)
        self.log("Auto-detect set folder values. Adjust if needed.")

    def log(self, s):
        self.logbox.insert('end', s + '\n')
        self.logbox.see('end')

    def start_extraction(self):
        input_file = self.input_entry.get().strip()
        mpk_folder = self.mpk_entry.get().strip() or os.path.dirname(input_file) or os.getcwd()
        out_dir = self.out_entry.get().strip() or os.path.join(os.getcwd(), "ExtractedOutput")
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid .mpkdb or .mpkinfo file.")
            return
        if not os.path.isdir(mpk_folder):
            messagebox.showerror("Error", "Please select a valid folder containing .mpk files.")
            return
        # prepare progressbar
        self.progress['value'] = 0
        self.progress['maximum'] = 100
        self.log(f"Starting extraction. This may take a while. Output -> {out_dir}")
        # run in background
        worker = threading.Thread(target=self._worker_extract, args=(input_file, mpk_folder, out_dir), daemon=True)
        worker.start()

    def _worker_extract(self, input_file, mpk_folder, out_dir):
        def gui_log(m): self.log(m)
        def gui_prog(idx, total):
            pct = int((idx / total) * 100) if total else 0
            self.progress['value'] = pct
        try:
            if input_file.lower().endswith('.mpkdb'):
                extract_from_mpkdb(input_file, mpk_folder, out_dir, gui_log, gui_prog)
            else:
                extract_from_mpkinfo(input_file, mpk_folder, out_dir, gui_log, gui_prog)
            self.progress['value'] = 100
            self.log("All done.")
            messagebox.showinfo("Done", "Extraction complete.")
        except Exception as e:
            self.log(f"ERROR: {e}")
            messagebox.showerror("Error", str(e))

# ------------------------------
# CLI wrapper
# ------------------------------
def cli_main(args):
    input_file = args.input
    mpk_folder = args.mpk_folder or os.path.dirname(input_file) or os.getcwd()
    out_dir = args.output
    def print_log(m): print(m)
    if input_file.lower().endswith('.mpkdb'):
        extract_from_mpkdb(input_file, mpk_folder, out_dir, None, lambda i, t: print(f"{i}/{t}"))
    else:
        extract_from_mpkinfo(input_file, mpk_folder, out_dir, None, lambda i, t: print(f"{i}/{t}"))

# ------------------------------
# Entrypoint
# ------------------------------
def main():
    parser = argparse.ArgumentParser(description="MPK Extractor (GUI + CLI)")
    parser.add_argument('input', nargs='?', help=".mpkdb or .mpkinfo file")
    parser.add_argument('mpk_folder', nargs='?', help="Folder containing .mpk files (optional)")
    parser.add_argument('output', nargs='?', help="Output folder (required for CLI)")
    parser.add_argument('--gui', action='store_true', help="Start GUI")
    args = parser.parse_args()

    # If gui requested and GUI libs available, start GUI
    if args.gui or (not args.input and GUI_AVAILABLE):
        if not GUI_AVAILABLE:
            print("GUI libraries not available. Run with CLI mode.")
            sys.exit(1)
        app = ExtractorGUI()
        app.mainloop()
        return

    # CLI mode: require input and output
    if not args.input or not args.output:
        print("CLI usage:")
        print("  python mpk_gui_extract.py Patch.mpkdb /path/to/mpk_folder /path/to/output_dir")
        print("Or run with --gui to use graphical interface.")
        sys.exit(1)

    cli_main(args)

if __name__ == "__main__":
    main()

