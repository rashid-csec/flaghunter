def xor_bruteforce(s):
    results = []
    data = s.encode('ascii', errors='ignore')
    
    for key in range(1, 256):
        decoded = "".join(chr(b ^ key) for b in data)
        
        # Check if the result is printable
        if all(32 <= ord(c) <= 126 for c in decoded):
            low = decoded.lower()
            # If it contains a keyword, it's a high-priority match
            if any(k in low for k in ["flag", "ctf", "htb", "{", "}", "pico"]):
                results.insert(0, (key, decoded)) # Move to top
            else:
                results.append((key, decoded))
                
    return results[:15] # Return top candidates
