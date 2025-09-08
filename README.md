# 0BeeF 🥩

**Python Crypter & Virtual Execution Runtime**

---

## Overview

**0BeeF** is a crypter and obfuscation tool for Python scripts. It is designed to:

* Obfuscate code at a deep level
* Encrypt payloads with multiple layers
* Execute decrypted payloads fully in-memory
* Evade antivirus (AV) detection
* Bytecode-level obfuscation
* Resist static and dynamic reverse engineering
* Wipe memory after execution

---

## Features

* Obfuscation
* Multi-layer encryption
* Dynamic import injection to avoid static detection
* In-memory execution
* RAM wiping
* Anti-debugging
* Bytecode-level obfuscation
* Anti-VM
* Virtualized decryption environment

---


### Installation

First, clone the 0BeeF repository to your local machine:

```bash
git clone https://github.com/memecoder12345678/0BeeF-Python-Crypter.git
cd 0BeeF
```

Install all required libraries via:

```bash
pip install -r requirements.txt
```

---
## Usage

```bash
python ./src/0BeeF.py
```

Follow the prompt to select a `.py` file. The encrypted file will be saved with the prefix `0BeeF_`.

---

## Detection Reduction

In a real-world test using a Python-based stealer detected by 24 antivirus engines, 0BeeF reduced detection to 9 engines.
**Detection rate reduced by approximately 62.5%.**

### Before encryption:

![1.jpg](https://raw.githubusercontent.com/memecoder12345678/0BeeF-Python-Crypter/refs/heads/main/img/1.jpg)

### After encryption:

![2.jpg](https://raw.githubusercontent.com/memecoder12345678/0BeeF-Python-Crypter/refs/heads/main/img/2.jpg)

---

## Recommendations

* Do **not** use `Nuitka` after encryption &mdash; it may optimize away the encryption logic (use the commercial version with flag `--enable-plugin=data-hiding` if needed)
* If your script is detected by **fewer than 8 AV engines**, you likely don’t need 0BeeF
* You **can combine 0BeeF with PyArmor** for better protection
* Fully compatible with `PyInstaller`, `py2exe`, and similar tools **after** obfuscation
* Obfuscated imports won't be auto-detected &mdash; add them manually via `hiddenimports`, dummy `import`, or config files

---

## License

This project is licensed under the **Apache-2.0 License**.

---

## Disclaimer

0BeeF is intended for **educational and ethical research** only.
You are fully responsible for how you use this tool.
Using this software for malicious purposes may violate local, state, or international laws.

---

## Author

**MemeCoder**
GitHub: [github.com/memecoder12345678](https://github.com/memecoder12345678)
