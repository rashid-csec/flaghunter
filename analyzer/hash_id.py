import re

def identify_hashes(s):
    # Regex for common hash types
    patterns = {
        "MD5": r"\b[a-fA-F0-9]{32}\b",
        "SHA1": r"\b[a-fA-F0-9]{40}\b",
        "SHA256": r"\b[a-fA-F0-9]{64}\b"
    }
    
    found = False
    for name, pattern in patterns.items():
        if re.search(pattern, s):
            # Identifying the hash type and providing guidance
            print(f"  \033[95m\033[1m[#] HASH DETECTED: {name}\033[0m")
            mode = "0" if name == "MD5" else "100" if name == "SHA1" else "1400"
            print(f"  \033[94m[TIP] Cracking: hashcat -m {mode} -a 0 {s} wordlist.txt\033[0m")
            print(f"  \033[94m[URL] Quick Check: https://crackstation.net/\033[0m")
            found = True
    return found
    
