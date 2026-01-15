from analyzer.decoder import try_decode

def multi_decode(s, depth=3):
    seen = set()
    results = [s]

    for _ in range(depth):
        new = []
        for r in results:
            decoded = try_decode(r)
            for d in decoded:
                if d not in seen:
                    seen.add(d)
                    new.append(d)
        results.extend(new)

    return list(seen)
