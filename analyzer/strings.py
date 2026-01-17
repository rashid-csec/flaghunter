import re

def extract_strings(filepath, min_len=4):
    result = []
    with open(filepath, "rb") as f:
        data = f.read()

    # Find printable sequences
    pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
    raw_strings = re.findall(pattern, data)

    for s in raw_strings:
        decoded = s.decode('ascii', errors='ignore')
        # SPLIT on : | , and spaces to isolate encrypted data
        parts = re.split(r'[:|,\s]+', decoded)
        for p in parts:
            if len(p.strip()) >= min_len:
                result.append(p.strip())
    return result
