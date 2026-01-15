#!/usr/bin/env python3
import argparse
import sys
import re

from analyzer.strings import extract_strings
from analyzer.multidecode import multi_decode
from analyzer.xor_bruteforce import xor_bruteforce
from analyzer.entropy import calculate_entropy
from analyzer.flag_detector import detect_flags

# ──────────────────────────────────────────────
# Tool Info
# ──────────────────────────────────────────────
TOOL_NAME = "FlagHunter"
VERSION = "v1.2.0"
AUTHOR = "Rashid"

# ──────────────────────────────────────────────
# ANSI Colors
# ──────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ──────────────────────────────────────────────
def banner():
    print(CYAN + BOLD + r"""
 ███████╗██╗      █████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██╔════╝██║     ██╔══██╗██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 █████╗  ██║     ███████║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══╝  ██║     ██╔══██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║     ███████╗██║  ██║╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
""" + RESET)
    print(f"{GREEN}{BOLD}[+] {TOOL_NAME} {VERSION}{RESET}")
    print(f"{BLUE}[+] Author : {AUTHOR}{RESET}")
    print(f"{BLUE}[+] Purpose: CTF / Reverse Engineering Helper{RESET}\n")

# ──────────────────────────────────────────────
def analyze_string(s, xor_mode=False, auto_mode=False):
    """Analyze one extracted string"""
    entropy = calculate_entropy(s)
    file_type = "Unknown"

    # Entropy check → low/high
    if entropy < 3:
        file_type = "Plain text"
        print(f"{GREEN}[TYPE] {file_type}{RESET}")
    elif entropy < 4.5:
        file_type = "Encoded text suspected"
        print(f"{YELLOW}[TYPE] {file_type}{RESET}")
    else:
        file_type = "High entropy (XOR/Encryption suspected)"
        print(f"{RED}[TYPE] {file_type}{RESET}")
        if not xor_mode and not auto_mode:
            print(f"{MAGENTA}[WARNING] Possible XOR/encrypted content detected. Use -x to brute-force XOR{RESET}")

    # Flag detection
    detect_flags(s)

    # Base decoders
    if entropy >= 3:
        decoded_list = multi_decode(s)
        for d in decoded_list:
            print(f"  {GREEN}[DECODED]{RESET} {d}")
            detect_flags(d)

    # XOR brute-force
    if xor_mode:
        print(f"{BLUE}[XOR] Forced XOR brute-force (-x enabled){RESET}")
        for key, out in xor_bruteforce(s):
            print(f"  {BLUE}[XOR key={key}]{RESET} {out}")
            detect_flags(out)
    elif auto_mode and entropy >= 4.5:
        print(f"{BLUE}[XOR] Auto XOR brute-force (high entropy){RESET}")
        for key, out in xor_bruteforce(s):
            print(f"  {BLUE}[XOR key={key}]{RESET} {out}")
            detect_flags(out)

    return file_type, entropy

# ──────────────────────────────────────────────
def analyze_file(filepath, xor_mode=False, auto_mode=False):
    print(f"{CYAN}[+] Analyzing file: {filepath}{RESET}\n")
    strings = extract_strings(filepath)
    summary = {
        "plain_text": False,
        "encoded": False,
        "xor_suspected": False,
        "flags_found": False
    }

    for s in strings:
        print(f"{BOLD}[STRING]{RESET} {s}")
        ftype, entropy = analyze_string(s, xor_mode, auto_mode)

        if ftype == "Plain text":
            summary["plain_text"] = True
        elif "Encoded" in ftype:
            summary["encoded"] = True
        elif "XOR" in ftype:
            summary["xor_suspected"] = True

    # Detection summary
    print(f"\n{MAGENTA}{BOLD}[DETECTION SUMMARY]{RESET}")
    print(f"- Plain text: {'YES' if summary['plain_text'] else 'NO'}")
    print(f"- Base64/ROT13 suspected: {'YES' if summary['encoded'] else 'NO'}")
    print(f"- XOR suspected: {'YES' if summary['xor_suspected'] else 'NO'}")
    print(f"- Flags detected: {'YES' if summary['flags_found'] else 'NO'}")

# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CTF Reverse Engineering Helper")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-x", "--xor", action="store_true", help="Enable XOR brute-force")
    parser.add_argument("-a", "--auto", action="store_true", help="Automatic analysis mode")
    parser.add_argument("-v", "--version", action="version", version=f"{TOOL_NAME} {VERSION}")
    args = parser.parse_args()

    banner()
    analyze_file(args.file, xor_mode=args.xor, auto_mode=args.auto)

# ──────────────────────────────────────────────
if __name__ == "__main__":
    main()
