import re

def extract_strings(filepath, min_len=4):
    result = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        
        # Find all printable sequences
        pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
        raw_strings = re.findall(pattern, data)

        for s in raw_strings:
            decoded = s.decode('ascii', errors='ignore')
            
            # SPLIT on common separators like : | and whitespace
            # This isolates the actual XOR data from labels
            parts = re.split(r'[:|,\s]+', decoded)
            
            for p in parts:
                if len(p.strip()) >= min_len:
                    result.append(p.strip())
    except Exception as e:
        pass
        
    return result
