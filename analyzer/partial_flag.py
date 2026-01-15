import re

def detect_partial_flag(s):
    if re.search(r"(flag|ctf|htb)", s, re.IGNORECASE):
        print("  ⚠ Possible partial flag fragment detected")
