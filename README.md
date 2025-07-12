# 0BeeF 🥩

**Python Crypter & Virtual Execution Runtime**

---

## Overview

**0BeeF** is a powerful crypter and obfuscation tool for Python scripts. It is designed to:

* Obfuscate code at a deep level
* Encrypt payloads with multiple layers (Fernet + XOR)
* Execute decrypted payloads fully in-memory
* Evade antivirus (AV) detection
* Resist static and dynamic reverse engineering
* Wipe memory to remove traces after execution

---

## Features

* Obfuscation using `marshal`, `zlib`, `base64`
* Multi-layer encryption: Fernet (AES-CBC + HMAC) + XOR key masking
* Dynamic import injection to avoid static detection
* In-memory execution via `exec` and `memoryview`
* RAM wiping using `ctypes.memset`
* Anti-debugging using `sys.gettrace()` and `_getframe`
* Virtualized decryption environment using function-index mapping

---

## Usage

```bash
python ./src/0BeeF.py
```

Follow the prompt to select a `.py` file. The encrypted file will be saved with the prefix `0BeeF_`.

---

## Example

### Before encryption:

![1.jpg](https://raw.githubusercontent.com/memecoder12345678/0BeeF-Python-Crypter/refs/heads/main/img/1.jpg)

### After encryption:

![2.jpg](https://raw.githubusercontent.com/memecoder12345678/0BeeF-Python-Crypter/refs/heads/main/img/2.jpg)

---

## Detection Reduction

In a real-world test using a Python-based stealer detected by 24 antivirus engines, 0BeeF reduced detection to 9 engines.
**Detection rate reduced by approximately 60.3%.**

---

## Recommendations

* Do **not** use `Nuitka` after encryption &mdash; it may optimize away the encryption logic (use the commercial version with flag `--enable-plugin=data-hiding` if needed)
* If your script is detected by **fewer than 12 AV engines**, you likely don’t need 0BeeF
* You **can combine 0BeeF with PyArmor** for better protection
* Fully compatible with `PyInstaller`, `py2exe`, and similar tools **after** obfuscation

---

## How It Works

```
[ Python code ]
   ↓
[ marshal → zlib → base64 → Fernet → XOR ]
   ↓
Encrypted payload
   ↓
Stub script decrypts and executes code in memory
   ↓
Decrypted memory is wiped after execution
```

All decryption and execution occurs in memory, leaving no traces on disk.

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
