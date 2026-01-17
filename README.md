

# FlagHunter v1.5.0 🚩

**FlagHunter** is a high-performance static analysis tool built for CTF players and security researchers. Unlike standard `strings` utilities, FlagHunter is designed to "peel the onion" of nested obfuscation, uncovering flags hidden behind layers of XOR, Base64, Hex, and ROT13.



## 🚀 Core Capabilities

* **Recursive Deep Scan:** Automatically detects and decodes nested layers (e.g., `XOR(Base64(Flag))`).
* **Smart XOR Brute-force:** Tests all 255 keys and uses keyword heuristics to isolate human-readable results.
* **Entropy Triggering:** High-entropy strings (random-looking data) automatically trigger deeper analysis.
* **Hash Analysis:** Identifies MD5/SHA256 hashes and provides instant `hashcat` syntax and lookup links.
* **Red-Alert Visualization:** High-visibility terminal highlighting for confirmed flag hits.
* **Advanced Tokenization:** Intelligently splits strings by delimiters (`:`, `|`, `,`) to find data hidden in logs or code.

## 🛠 Installation

```bash
# Clone the repository
git clone [https://github.com/yourusername/flaghunter.git](https://github.com/yourusername/flaghunter.git)
cd flaghunter

# Ensure you have Python 3 installed
python3 --version
