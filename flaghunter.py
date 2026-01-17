#!/usr/bin/env python3
import argparse
import sys
import re

# Internal imports
from analyzer.strings import extract_strings
from analyzer.multidecode import multi_decode
from analyzer.xor_bruteforce import xor_bruteforce
from analyzer.entropy import calculate_entropy
from analyzer.flag_detector import detect_flags
from analyzer.hash_id import identify_hashes 

# ──────────────────────────────────────────────
# ANSI Colors & Formatting
# ──────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

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
    print(f"{GREEN}{BOLD}[+] FlagHunter v1.2.0{RESET} | {BLUE}Author: Rashid{RESET}\n")

# ──────────────────────────────────────────────
def analyze_string(s, xor_mode=False, auto_mode=False):
    """Core analysis logic for a single string"""
    found_anything = False
    ent = calculate_entropy(s)
    
    # 1. Identify Hashes (MD5, SHA, etc.)
    if identify_hashes(s):
        found_anything = True

    # 2. Entropy-based Type Hinting
    if ent < 3.0:
        print(f"{GREEN}[TYPE] Plain text{RESET}")
    elif ent < 4.5:
        print(f"{YELLOW}[TYPE] Encoded/Compressed suspected{RESET}")
    else:
        print(f"{RED}[TYPE] High entropy (Encrypted suspected){RESET}")

    # 3. Direct Flag Check (e.g., flag{...})
    if detect_flags(s): 
        found_anything = True

    # 4. Multi-Layer Decoding (Base64, Hex, URL, ROT13)
    if ent >= 3.0:
        decoded_list = multi_decode(s)
        for d in decoded_list:
            print(f"  {GREEN}[DECODED]{RESET} {d}")
            if detect_flags(d): 
                found_anything = True

    # 5. XOR Brute-force (With High-Sensitivity Highlight for fragments)
    if xor_mode or (auto_mode and ent >= 4.5):
        # We search for common CTF keywords to catch fragments like 'akf' -> 'flag'
        keywords = r"flag|ctf|htb|pico|pass|key"
        
        for key, out in xor_bruteforce(s):
            # A: Check for official flag format in XOR output
            if detect_flags(out):
                print(f"  {MAGENTA}{BOLD}[XOR SUCCESS! Key={key}]{RESET} {YELLOW}{out}{RESET}")
                found_anything = True
            
            # B: Check for fragment keywords (to catch 'flag' without braces)
            elif re.search(keywords, out, re.IGNORECASE):
                print(f"  {MAGENTA}{BOLD}[XOR POTENTIAL! Key={key}]{RESET} {YELLOW}{out}{RESET}")
                found_anything = True
            
            # C: Standard printable XOR output
            else:
                # Only print if not totally empty
                if out.strip():
                    print(f"  {BLUE}[XOR key={key}]{RESET} {out}")

    return found_anything

# ──────────────────────────────────────────────
def analyze_file(filepath, xor_mode=False, auto_mode=False):
    banner()
    print(f"{CYAN}[+] Analyzing file: {filepath}{RESET}\n")
    
    try:
        strings = extract_strings(filepath)
    except Exception as e:
        print(f"{RED}[!] Error reading file: {e}{RESET}")
        return

    final_flag_status = False
    
    for s in strings:
        print(f"{BOLD}[STRING]{RESET} {s}")
        # Run analysis and update the global flag status
        if analyze_string(s, xor_mode, auto_mode):
            final_flag_status = True
            
        print(f"{CYAN}" + "-"*40 + f"{RESET}")

    # ──────────────────────────────────────────────
    # Final Summary
    # ──────────────────────────────────────────────
    print(f"\n{MAGENTA}{BOLD}[DETECTION SUMMARY]{RESET}")
    status_color = GREEN if final_flag_status else RED
    print(f"- Flags/Hashes/Fragments Detected: {status_color}{'YES' if final_flag_status else 'NO'}{RESET}")

# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="FlagHunter: CTF Reverse Engineering & Static Analysis Tool")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-x", "--xor", action="store_true", help="Force XOR brute-force on all strings")
    parser.add_argument("-a", "--auto", action="store_true", help="Auto-mode: XOR brute-force on high-entropy strings")
    args = parser.parse_args()

    analyze_file(args.file, xor_mode=args.xor, auto_mode=args.auto)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Analysis interrupted by user.{RESET}")
        sys.exit(0)
