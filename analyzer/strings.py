import re
import string

def extract_strings(filepath, min_len=4):
    result = []
    # We use a set of printable bytes for much faster lookup
    printable_bytes = set(string.printable.encode('ascii'))
    
    with open(filepath, "rb") as f:
        data = f.read()

    current = bytearray()
    for b in data:
        if b in printable_bytes:
            current.append(b)
        else:
            if len(current) >= min_len:
                try:
                    # Decode and split by whitespace/newlines to prevent giant blobs
                    decoded = current.decode('ascii', errors='ignore')
                    # Split into sub-strings if multiple are bunched together
                    parts = re.split(r'[\s\x00-\x1f]+', decoded)
                    for p in parts:
                        if len(p) >= min_len:
                            result.append(p.strip())
                except:
                    pass
                current = bytearray()
    
    if len(current) >= min_len:
        result.append(current.decode('ascii', errors='ignore').strip())

    return result
    
