import math
from collections import Counter

def calculate_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    length = len(s)
    entropy = 0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy
