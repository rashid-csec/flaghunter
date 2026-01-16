import re

FLAGS = [
    r"flag\{.*?\}",
    r"CTF\{.*?\}",
    r"HTB\{.*?\}",
    r"THM\{.*?\}",
    r"picoCTF\{.*?\}",
    r"rootme\{.*?\}",
    r"[a-zA-Z0-9_-]{3,15}\{[a-zA-Z0-9_\-\.!@#$%^&*]+\}" # Universal Pattern
]

def detect_flags(s):
    found = False
    for f in FLAGS:
        matches = re.finditer(f, s, re.IGNORECASE)
        for match in matches:
            print(f"  \033[92m\033[1m🚩 FLAG FOUND:\033[0m \033[93m{match.group()}\033[0m")
            found = True
    
    # Partial flag heuristic
    if not found and re.search(r"(flag|ctf|htb|pico)", s, re.IGNORECASE):
        print("  \033[93m⚠ Possible partial flag fragment detected\033[0m")
        
    return found
    
