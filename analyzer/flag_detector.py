import re

FLAGS = [
    r"flag\{.*?\}",
    r"CTF\{.*?\}",
    r"HTB\{.*?\}",
    r"THM\{.*?\}",
    r"picoCTF\{.*?\}",
    r"rootme\{.*?\}",
]

def detect_flags(s):
    found = False
    for f in FLAGS:
        match = re.search(f, s, re.IGNORECASE)
        if match:
            print(f"  {GREEN}🚩 FLAG FOUND: {match.group()}{RESET}")
            found = True
    return found # <--- Add this
