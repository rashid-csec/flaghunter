#!/usr/bin/env python3
import argparse
import sys

from analyzer.strings import extract_strings
from analyzer.multidecode import multi_decode
from analyzer.xor_bruteforce import xor_bruteforce
from analyzer.entropy import calculate_entropy
from analyzer.flag_detector import detect_flags

# Formatting
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
    found_in_this_string = False
    entropy = calculate_entropy(s)
    
    if entropy < 3:
        print(f"{GREEN}[TYPE] Plain text{RESET}")
    elif entropy < 4.5:
        print(f"{YELLOW}[TYPE] Encoded text suspected{RESET}")
    else:
        print(f"{RED}[TYPE] High entropy (XOR suspected){RESET}")

    # 1. Direct detection
    if detect_flags(s): found_in_this_string = True

    # 2. Multi-Decoder
    if entropy >= 3:
        for d in multi_decode(s):
            print(f"  {GREEN}[DECODED]{RESET} {d}")
            if detect_flags(d): found_in_this_string = True

    # 3. XOR Brute Force
    if xor_mode or (auto_mode and entropy >= 4.5):
        for key, out in xor_bruteforce(s):
            print(f"  {BLUE}[XOR key={key}]{RESET} {out}")
            if detect_flags(out): found_in_this_string = True

    return found_in_this_string

def analyze_file(filepath, xor_mode=False, auto_mode=False):
    banner()
    print(f"{CYAN}[+] Analyzing file: {filepath}{RESET}\n")
    
    try:
        strings = extract_strings(filepath)
    except FileNotFoundError:
        print(f"{RED}[!] Error: File '{filepath}' not found.{RESET}")
        return

    summary = {"flags_found": False, "xor_found": False}

    for s in strings:
        print(f"{BOLD}[STRING]{RESET} {s.strip()}")
        if analyze_string(s, xor_mode, auto_mode):
            summary["flags_found"] = True
        print("-" * 30)

    print(f"\n{MAGENTA}{BOLD}[DETECTION SUMMARY]{RESET}")
    print(f"- Flags detected: {GREEN if summary['flags_found'] else RED}{'YES' if summary['flags_found'] else 'NO'}{RESET}")

def main():
    parser = argparse.ArgumentParser(description="CTF Reverse Engineering Helper")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-x", "--xor", action="store_true", help="Enable XOR brute-force")
    parser.add_argument("-a", "--auto", action="store_true", help="Automatic mode")
    args = parser.parse_args()
    analyze_file(args.file, args.xor, args.auto)

if __name__ == "__main__":
    main()
    
