def analyze_string(s, xor_mode=False, auto_mode=False):
    found_anything = False
    
    # ... (existing entropy and hash checks) ...

    # 1. Try normal decoding first
    for d in multi_decode(s):
        if detect_flags(d): found_anything = True

    # 2. Try XOR
    if xor_mode or (auto_mode and ent >= 4.0):
        for key, xor_out in xor_bruteforce(s):
            
            # RECURSIVE CHECK:
            # Check if the XOR output itself is Base64 or Hex
            nested_decodes = multi_decode(xor_out)
            for nd in nested_decodes:
                if detect_flags(nd):
                    print(f"  {MAGENTA}{BOLD}🔥 DEEP MATCH! XOR(Key {key}) -> DECODE -> {nd}{RESET}")
                    found_anything = True
            
            # Standard keyword check for the raw XOR output
            if any(k in xor_out.lower() for k in ["flag", "ctf"]):
                print(f"  {MAGENTA}{BOLD}✨ [XOR MATCH! Key={key}] {YELLOW}{xor_out}{RESET}")
                found_anything = True

    return found_anything
