import base64
import codecs
import urllib.parse

def try_decode(s):
    results = []

    try:
        results.append(base64.b64decode(s).decode())
    except:
        pass

    try:
        results.append(bytes.fromhex(s).decode())
    except:
        pass

    try:
        results.append(urllib.parse.unquote(s))
    except:
        pass

    try:
        results.append(codecs.decode(s, "rot_13"))
    except:
        pass

    return list(set(results))
