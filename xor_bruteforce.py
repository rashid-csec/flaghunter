import string

def xor_bruteforce(s):
    results = []
    for key in range(1, 256):
        decoded = "".join(chr(ord(c) ^ key) for c in s)
        if all(c in string.printable for c in decoded):
            if len(decoded.strip()) > 5:
                results.append((key, decoded))
    return results[:10]
