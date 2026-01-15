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
    for f in FLAGS:
        match = re.search(f, s, re.IGNORECASE)
        if match:
            print(f"  🚩 FLAG FOUND: {match.group()}")
