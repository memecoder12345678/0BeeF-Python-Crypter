<p align="center">
  <h1 align="center">0BeeF Python Crypter 🥩</h1>
  <p align="center">
    A Crypter & Virtual Execution Runtime designed for security research and protection.
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=for-the-badge&logo=python" alt="Python 3.11+" />
    <img src="https://img.shields.io/badge/build-passing-green?style=for-the-badge&logo=githubactions" alt="Build Status" />
    <img src="https://img.shields.io/github/stars/memecoder12345678/0BeeF-Python-Crypter?style=for-the-badge&color=green&logo=github">
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=for-the-badge&logo=apache" alt="License" /></a>
  </p>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Why 0BeeF?](#why-0beef)
- [Effectiveness Demo](#effectiveness-demo)
- [Core Features](#core-features)
- [Getting Started](#getting-started)
- [Recommendations](#recommendations)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Author](#author)

---

## Overview

**0BeeF** is a crypter and obfuscator for Python, built for **security research** and **source code protection**.

This project is designed to hide and protect Python scripts from prying eyes—**0BeeF bridges the gap between simple encryption and sophisticated evasion techniques.**

It offers:

*   A multi-layer encryption mechanism to protect payloads.
*   Fully in-memory execution to evade static analysis.
*   Anti-debugging and anti-VM techniques.
*   Bytecode-level obfuscation.
*   A simple, easy-to-use command-line interface.

---

## Why 0BeeF?

*   **Great for security researchers** who want to learn about evasion techniques.
*   **Useful for developers** who must protect their intellectual property in Python scripts.
*   **Optimized for security over performance** — designed for tasks that require confidentiality rather than large-scale processing speed.

---

## Effectiveness Demo

Here is a real-world result of using 0BeeF on a Python-based stealer. The detection rate was **reduced by approximately 62.5%**.

### Before encryption:

![1.jpg](https://raw.githubusercontent.com/memecoder12345678/0BeeF-Python-Crypter/refs/heads/main/img/1.jpg)

### After encryption:

![2.jpg](https://raw.githubusercontent.com/memecoder12345678/0BeeF-Python-Crypter/refs/heads/main/img/2.jpg)

---

## Core Features

* **Multi-Layer Encryption** — Hardens the payload against decryption attempts.
* **In-Memory Execution** — The payload is decrypted and run entirely in RAM.
* **Memory Wiping** — Automatically clears traces after execution.
* **Bytecode Obfuscation** — Resists static analysis and reverse engineering.
* **Anti-Debug & Anti-VM** — Detects and evades analysis environments.
* **High Compatibility** — Works well with PyInstaller and similar tools.

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/memecoder12345678/0BeeF-Python-Crypter.git
cd 0BeeF
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run 0BeeF

```bash
python ./src/0BeeF.py
```

Then, follow the on-screen prompts to select the Python file you want to encrypt. The output file will be prefixed with `0BeeF_`.

---

## Recommendations

*   **Do not use `Nuitka`** after encryption, as its optimizations may break the encryption logic.
*   If your script is detected by **fewer than 8 AV engines**, you probably don’t need 0BeeF.
*   You **can combine 0BeeF with PyArmor** for enhanced protection.
*   When bundling with `PyInstaller`, ensure that all hidden imports are declared manually.  
    See [hidden_import.txt](hidden_import.txt) for the complete list.


---

## Contributing

Contributions are welcome! To get involved:

1.  Fork this repository.
2.  Create a new branch: `git checkout -b feature/my-feature`
3.  Commit your changes: `git commit -m "Describe your feature"`
4.  Push to the branch and open a Pull Request 🎉

---

## License

This project is released under the **Apache-2.0 License**. See the [LICENSE](LICENSE) file for details.

---

## Disclaimer

0BeeF is intended for **educational and ethical research purposes only**. You are fully responsible for how you use this tool. Using this software for malicious purposes is a violation of the law.

---

## Author

*   **MemeCoder**
*   GitHub: [@memecoder12345678](https://github.com/memecoder12345678)
