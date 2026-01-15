#!/usr/bin/env python3
import argparse
import sys

from analyzer.strings import extract_strings
from analyzer.multidecode import multi_decode
from analyzer.xor_bruteforce import xor_bruteforce
from analyzer.entropy import calculate_entropy
from analyzer.flag_detector import detect_flags

# ──────────────────────────────────────────────
# Tool Info
# ──────────────────────────────────────────────
TOOL_NAME = "FlagHunter"
VERSION = "v1.1.0"
AUTHOR = "Rashid"

# ──────────────────────────────────────────────
# ANSI Colors
# ──────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
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
def analyze_file(filepath, xor_mode=False, auto_mode=False):
    print(f"{CYAN}[+] Analyzing file: {filepath}{RESET}\n")

    strings = extract_strings(filepath)

    for s in strings:
        print(f"{BOLD}[STRING]{RESET} {s}")

        entropy = calculate_entropy(s)

        if entropy < 3:
            print(f"{GREEN}[TYPE] Plain text{RESET}")
        elif entropy < 4.5:
            print(f"{YELLOW}[TYPE] Encoded text suspected{RESET}")
        else:
            print(f"{RED}[TYPE] High entropy (XOR/Encryption suspected){RESET}")

        # Flag check
        detect_flags(s)

        # Decode only if likely encoded
        if entropy >= 3:
            decoded = multi_decode(s)
            for d in decoded:
                print(f"  {GREEN}[DECODED]{RESET} {d}")
                detect_flags(d)

        # XOR handling
        if entropy >= 4.5:
            if xor_mode or auto_mode:
                print(f"{BLUE}[XOR] Brute-forcing...{RESET}")
                for key, out in xor_bruteforce(s):
                    print(f"  {BLUE}[XOR key={key}]{RESET} {out}")
                    detect_flags(out)
            else:
                print(f"{YELLOW}[DETECTION] Possible XOR encoding detected{RESET}")
                print(f"{YELLOW}➜ Use -x to brute-force XOR{RESET}")

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
