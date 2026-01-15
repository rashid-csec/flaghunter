#!/usr/bin/env python3
import argparse
import sys

from analyzer.strings import extract_strings
from analyzer.multidecode import multi_decode
from analyzer.xor_bruteforce import xor_bruteforce
from analyzer.hash_id import identify_hash
from analyzer.entropy import calculate_entropy
from analyzer.flag_detector import detect_flags

# ──────────────────────────────────────────────
# Tool Information
# ──────────────────────────────────────────────
TOOL_NAME = "FlagHunter"
VERSION = "v1.0.0"
AUTHOR = "Rashid"

# ──────────────────────────────────────────────
# ANSI Colors (Cross‑platform)
# ──────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ──────────────────────────────────────────────
# Banner
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

    print(YELLOW + BOLD + "⚠️  LEGAL DISCLAIMER" + RESET)
    print(YELLOW + "-" * 60 + RESET)
    print(
        YELLOW +
        "This tool is intended for EDUCATIONAL and CTF purposes only.\n"
        "Do NOT use against systems without explicit authorization.\n"
        "The author (Rashid) is not responsible for misuse."
        + RESET
    )
    print(YELLOW + "-" * 60 + RESET + "\n")

# ──────────────────────────────────────────────
# Core Analysis Logic
# ──────────────────────────────────────────────
def analyze_file(filepath):
    print(f"{CYAN}[+] Analyzing file: {filepath}{RESET}\n")

    try:
        strings = extract_strings(filepath)
    except Exception as e:
        print(f"{RED}[-] Error reading file: {e}{RESET}")
        sys.exit(1)

    for s in strings:
        print(f"{BOLD}[STRING]{RESET} {s}")

        # Entropy check
        entropy = calculate_entropy(s)
        if entropy > 4.5:
            print(f"  {YELLOW}⚠ High entropy detected (possible encoding/encryption){RESET}")

        # Hash identification
        identify_hash(s)

        # Multi‑layer decoding
        decoded_results = multi_decode(s)
        for decoded in decoded_results:
            print(f"  {GREEN}[DECODED]{RESET} {decoded}")
            detect_flags(decoded)

        # XOR brute‑force
        xor_results = xor_bruteforce(s)
        for key, result in xor_results:
            print(f"  {BLUE}[XOR key={key}]{RESET} {result}")
            detect_flags(result)

        # Direct flag detection
        detect_flags(s)

# ──────────────────────────────────────────────
# Main Entry
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog="flaghunter.py",
        description="CTF Reverse Engineering Helper Tool"
    )

    parser.add_argument(
        "file",
        help="Binary file to analyze (e.g. challenge.bin)"
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"{TOOL_NAME} {VERSION}"
    )

    args = parser.parse_args()

    banner()
    analyze_file(args.file)

# ──────────────────────────────────────────────
if __name__ == "__main__":
    main()
