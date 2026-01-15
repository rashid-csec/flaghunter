import re

HASHES = {
    "MD5": r"^[a-fA-F0-9]{32}$",
    "SHA1": r"^[a-fA-F0-9]{40}$",
    "SHA256": r"^[a-fA-F0-9]{64}$",
}

def identify_hash(s):
    for name, regex in HASHES.items():
        if re.match(regex, s):
            print(f"  🔐 Possible {name} hash detected")
            print("  ⚠ Use CrackStation or Hashcat for cracking")
