#!/usr/bin/env python3
import argparse
import sys

from analyzer.strings import extract_strings
from analyzer.multidecode import multi_decode
from analyzer.xor_bruteforce import xor_bruteforce
from analyzer.entropy import calculate_entropy
from analyzer.flag_detector import detect_flags
from analyzer.hash_id import identify_hashes # Import the new feature

# ANSI Colors
RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA, RESET, BOLD = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[95m", "\033[0m", "\033[1m"

def banner():
    print(CYAN + BOLD + r"""
 ███████╗██╗      █████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██╔════╝██║     ██╔══██╗██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 █████╗  ██║     ███████║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══╝  ██║     ██╔══██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║     ███████╗██║  ██║╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
""" + RESET)
    print(f"{GREEN}{BOLD}[+] FlagHunter v1.2.0{RESET} | {BLUE}Author: Rashid{RESET}\n")

def analyze_string(s, xor_mode=False, auto_mode=False):
    found_anything = False
    ent = calculate_entropy(s)
    
    # Identify Hashes
    if identify_hashes(s):
        found_anything = True

    # Entropy-based Type Hinting
    if ent < 3.0:
        print(f"{GREEN}[TYPE] Plain text{RESET}")
    elif ent < 4.5:
        print(f"{YELLOW}[TYPE] Encoded/Compressed suspected{RESET}")
    else:
        print(f"{RED}[TYPE] High entropy (Encrypted suspected){RESET}")

    # 1. Direct Flag Check
    if detect_flags(s): found_anything = True

    # 2. Multi-Layer Decoding
    if ent >= 3.0:
        for d in multi_decode(s):
            print(f"  {GREEN}[DECODED]{RESET} {d}")
            if detect_flags(d): found_anything = True

    # 3. XOR Brute-force
    if xor_mode or (auto_mode and ent >= 4.5):
        for key, out in xor_bruteforce(s):
            print(f"  {BLUE}[XOR key={key}]{RESET} {out}")
            if detect_flags(out): found_anything = True

    return found_anything

def analyze_file(filepath, xor_mode=False, auto_mode=False):
    banner()
    print(f"{CYAN}[+] Analyzing file: {filepath}{RESET}\n")
    
    try:
        strings = extract_strings(filepath)
    except Exception as e:
        print(f"{RED}[!] Error reading file: {e}{RESET}")
        return

    flags_found = False
    for s in strings:
        print(f"{BOLD}[STRING]{RESET} {s}")
        if analyze_string(s, xor_mode, auto_mode):
            flags_found = True
        print(f"{CYAN}" + "-"*40 + f"{RESET}")

    print(f"\n{MAGENTA}{BOLD}[DETECTION SUMMARY]{RESET}")
    status_color = GREEN if flags_found else RED
    print(f"- Flags/Hashes Detected: {status_color}{'YES' if flags_found else 'NO'}{RESET}")

def main():
    parser = argparse.ArgumentParser(description="CTF Reverse Engineering Helper")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-x", "--xor", action="store_true", help="Forced XOR brute-force")
    parser.add_argument("-a", "--auto", action="store_true", help="Automatic analysis mode")
    args = parser.parse_args()
    analyze_file(args.file, args.xor, args.auto)

if __name__ == "__main__":
    main()
    
