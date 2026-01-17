#!/usr/bin/env python3
import argparse
import sys
import re

# Absolute imports for package compatibility
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
    print(f"{GREEN}{BOLD}[+] FlagHunter v1.5.0{RESET} | {BLUE}Author: Rashid{RESET}\n")

# ──────────────────────────────────────────────
def analyze_string(s, xor_mode=False, auto_mode=False):
    """Core analysis logic for a single string"""
    found_anything = False
    ent = calculate_entropy(s)
    
    # 1. Identify Hashes
    if identify_hashes(s):
        found_anything = True

    # 2. Entropy-based Type Hinting
    if ent < 3.0:
        print(f"{GREEN}[TYPE] Plain text{RESET}")
    elif ent < 4.5:
        print(f"{YELLOW}[TYPE] Encoded/Compressed suspected{RESET}")
    else:
        print(f"{RED}[TYPE] High entropy (Encrypted suspected){RESET}")

    # 3. Direct Flag Check
    if detect_flags(s): 
        found_anything = True

    # 4. Multi-Layer Decoding (BFS approach)
    if ent >= 3.0:
        decoded_list = multi_decode(s)
        for d in decoded_list:
            print(f"  {GREEN}[DECODED]{RESET} {d}")
            if detect_flags(d): 
                found_anything = True

    # 5. XOR Brute-force (Enhanced to find flags inside junk strings)
    # Trigger if forced (-x) OR if high entropy AND auto mode (-a)
    if xor_mode or (auto_mode and ent >= 4.0):
        keywords = ["flag", "ctf", "htb", "pico"]
        
        # Pull potential XOR results
        results = xor_bruteforce(s)
        
        for key, out in results:
            lower_out = out.lower()
            # Catch fragments even if the full flag structure isn't there yet
            if any(k in lower_out for k in keywords):
                print(f"  {MAGENTA}{BOLD}✨ [XOR MATCH! Key={key}] {YELLOW}{out}{RESET}")
                found_anything = True
                
                # Check if a strict flag format (flag{...}) exists inside the result
                if detect_flags(out):
                    pass # detect_flags already prints the success message
            
            # Show other printable results ONLY if XOR mode is manually forced (-x)
            elif xor_mode:
                if out.strip() and len(out) > 3:
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
        # Filter out very small fragments that cause noise
        if len(s.strip()) < 3: continue
            
        print(f"{BOLD}[STRING]{RESET} {s}")
        if analyze_string(s, xor_mode, auto_mode):
            final_flag_status = True
            
        print(f"{CYAN}" + "-"*40 + f"{RESET}")

    # Final Summary
    print(f"\n{MAGENTA}{BOLD}[DETECTION SUMMARY]{RESET}")
    status_color = GREEN if final_flag_status else RED
    print(f"- Flags/Hashes/Fragments Detected: {status_color}{'YES' if final_flag_status else 'NO'}{RESET}")

# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="FlagHunter: Static Analysis Tool")
    parser.add_argument("file", help="File to analyze")
    parser.add_argument("-x", "--xor", action="store_true", help="Forced XOR brute-force on all strings")
    parser.add_argument("-a", "--auto", action="store_true", help="Automatic high-entropy XOR mode")
    args = parser.parse_args()

    analyze_file(args.file, xor_mode=args.xor, auto_mode=args.auto)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Analysis stopped by user.{RESET}")
        sys.exit(0)


