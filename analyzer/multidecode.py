import base64
import codecs
import urllib.parse

def try_decode(s):
    results = []
    s = s.strip() # Remove newlines that break Base64

    # Base64
    try:
        # Add padding if missing
        padding = len(s) % 4
        if padding: s += "=" * (4 - padding)
        decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
        if any(c.isalpha() for c in decoded): results.append(decoded)
    except: pass

    # Hex
    try:
        clean_hex = s.replace("0x", "").replace(" ", "")
        results.append(bytes.fromhex(clean_hex).decode('utf-8', errors='ignore'))
    except: pass

    # URL
    try:
        decoded = urllib.parse.unquote(s)
        if decoded != s: results.append(decoded)
    except: pass

    # ROT13
    try:
        decoded = codecs.decode(s, "rot_13")
        if "flag" in decoded.lower(): results.append(decoded)
    except: pass

    return list(set(results))

def multi_decode(s, depth=3):
    seen = {s}
    current_layer = [s]

    for _ in range(depth):
        next_layer = []
        for item in current_layer:
            for decoded in try_decode(item):
                if decoded not in seen and len(decoded) > 3:
                    seen.add(decoded)
                    next_layer.append(decoded)
        current_layer = next_layer
        
    seen.remove(s)
    return list(seen)
    
