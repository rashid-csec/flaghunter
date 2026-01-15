import argparse
from analyzer.strings import extract_strings
from analyzer.multidecode import multi_decode
from analyzer.xor_bruteforce import xor_bruteforce
from analyzer.hash_id import identify_hash
from analyzer.entropy import calculate_entropy
from analyzer.flag_detector import detect_flags

TOOL_NAME = "FlagHunter"
VERSION = "v1.0"
AUTHOR = "Rashid"

def banner():
    print("=" * 55)
    print(f"🔎 {TOOL_NAME} {VERSION}")
    print("🧠 CTF Reverse Engineering Helper Tool")
    print(f"👤 Author: {AUTHOR}")
    print("=" * 55 + "\n")

def analyze_file(filepath):
    print(f"[+] Analyzing file: {filepath}\n")

    strings = extract_strings(filepath)

    for s in strings:
        print(f"\n[STRING] {s}")

        entropy = calculate_entropy(s)
        if entropy > 4.5:
            print("  ⚠ High entropy (encoded/encrypted)")

        identify_hash(s)

        decoded = multi_decode(s)
        for d in decoded:
            print(f"  [DECODED] {d}")
            detect_flags(d)

        xor_results = xor_bruteforce(s)
        for key, res in xor_results:
            print(f"  [XOR key={key}] {res}")
            detect_flags(res)

        detect_flags(s)

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

if __name__ == "__main__":
    main()
