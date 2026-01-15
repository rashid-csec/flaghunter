import string

def extract_strings(filepath, min_len=4):
    result = []
    with open(filepath, "rb") as f:
        data = f.read()

    current = ""
    for b in data:
        c = chr(b)
        if c in string.printable:
            current += c
        else:
            if len(current) >= min_len:
                result.append(current)
            current = ""

    # ✅ FIX: append last string if file ends with printable chars
    if len(current) >= min_len:
        result.append(current)

    return result
