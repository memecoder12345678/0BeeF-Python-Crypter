import base64
import marshal
import os
import re
import zlib

from colorama import Fore, init
from cryptography.fernet import Fernet

init(autoreset=True)


def xor_encrypt(data, key):
    if not key:
        return data
    return bytes(
        a ^ b for a, b in zip(data, (key * ((len(data) // len(key)) + 1))[: len(data)])
    )


def fernet_encrypt(key, data):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data.encode())


def encode_b64(data):
    return base64.b64encode(data).decode()


def obfuscate_code(code):
    payload_imports = []

    seen_imports = set(payload_imports)
    for line in code.split("\n"):
        stripped_line = line.strip()
        if (
            re.match(r"^(import|from) ", stripped_line)
            and stripped_line not in seen_imports
        ):
            seen_imports.add(stripped_line)
            payload_imports.append(stripped_line)

    encoded_import_lines = []
    for imp_line in payload_imports:
        marshalled = marshal.dumps(imp_line.encode())
        compressed = zlib.compress(marshalled)
        encoded = base64.b64encode(compressed)
        encoded_import_lines.append(encoded)

    final_import_calls = "\n".join(
        [f"_x(b'{line.decode()}')" for line in encoded_import_lines]
    )

    encryption_key = Fernet.generate_key()
    mask_key = os.urandom(len(encryption_key))
    masked_key = xor_encrypt(encryption_key, mask_key)
    encrypted_data = fernet_encrypt(encryption_key, code)
    encoded_data = encode_b64(encrypted_data)
    compressed_data = zlib.compress(encoded_data.encode())
    marshalled_data = marshal.dumps(compressed_data)
    final_data = encode_b64(marshalled_data)

    stub_code = f"""'''
  ██████╗ ██████╗ ███████╗███████╗███████╗
 ██╔═████╗██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║██╔██║██████╔╝█████╗  █████╗  █████╗
 ████╔╝██║██╔══██╗██╔══╝  ██╔══╝  ██╔══╝
 ╚██████╔╝██████╔╝███████╗███████╗██║
  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝      🥩
'''

def _x(p): getattr(__import__(''.join(map(chr, [98, 117, 105, 108, 116, 105, 110, 115]))), ''.join(map(chr, [101, 120, 101, 99])))(getattr(__import__(''.join(map(chr, [109, 97, 114, 115, 104, 97, 108]))), ''.join(map(chr, [108, 111, 97, 100, 115])))(getattr(__import__(''.join(map(chr, [122, 108, 105, 98]))), ''.join(map(chr, [100, 101, 99, 111, 109, 112, 114, 101, 115, 115])))(getattr(__import__(''.join(map(chr, [98, 97, 115, 101, 54, 52]))), ''.join(map(chr, [98, 54, 52, 100, 101, 99, 111, 100, 101])))(p))), globals())
_x(b'eJwr5mJgYMjMLcgvKlEoriwGAB3+BJg=')
_x(b'eJwr5mVgYMjMLcgvKlFISixONTMBACzqBUE=')
_x(b'eJwr5mZgYMjMLcgvKlGoyslMAgAi6ATr')
_x(b'eJwr5mNgYMjMLcgvKlHITSwqzkjMAQA0GQYl')
_x(b'eJwr5mVgYMjMLcgvKlFILqksSC0GAC4lBdQ=')
_x(b'eJwrVmNgYEgrys9VSC6qLCjJTy9KLMio1EtLLcpLLVHIzC3ILypRcAPzAD/TD4s=')
_x(b'eJwr5mZgYMjMLcgvKlHITSzJAAAirwTk')
_x(b'eJwr5mVgYMjMLcgvKlEoSsxLyc8FAC3eBb0=')
{final_import_calls}
def _d(d, k):
    _m, _a, _f, _x = (getattr(getattr(__import__(''.join(map(chr, [98, 117, 105, 108, 116, 105, 110, 115]))), ''.join(map(chr, [95, 95, 105, 109, 112, 111, 114, 116, 95, 95])))(''.join(map(chr, [111, 112, 101, 114, 97, 116, 111, 114]))), ''.join(map(chr, n))) for n in [[109, 117, 108], [97, 100, 100], [102, 108, 111, 111, 114, 100, 105, 118], [120, 111, 114]])
    _k_ext = _m(k, _a(_f(len(d), len(k)), 1))
    return bytes(map(_x, d, _k_ext))
_f = []
_g = lambda m, f: getattr(__import__(''.join(map(chr, m))), ''.join(map(chr, f)))
_b = ''.join(map(chr, [98, 117, 105, 108, 116, 105, 110, 115]))
_f.append(getattr(__import__(_b), ''.join(map(chr, [98, 121, 116, 101, 115]))))
_f.append(_g([98, 97, 115, 101, 54, 52], [98, 54, 52, 100, 101, 99, 111, 100, 101]))
_f.append(_g([109, 97, 114, 115, 104, 97, 108], [108, 111, 97, 100, 115]))
_f.append(_g([122, 108, 105, 98], [100, 101, 99, 111, 109, 112, 114, 101, 115, 115]))
_f.append(getattr(__import__(''.join(map(chr, [99, 114, 121, 112, 116, 111, 103, 114, 97, 112, 104, 121, 46, 102, 101, 114, 110, 101, 116])), fromlist=[''.join(map(chr, [70, 101, 114, 110, 101, 116]))]), ''.join(map(chr, [70, 101, 114, 110, 101, 116]))))
_f.append(getattr(__import__(_b), ''.join(map(chr, [98, 121, 116, 101, 97, 114, 114, 97, 121]))))
_f.append(getattr(__import__(_b), ''.join(map(chr, [109, 101, 109, 111, 114, 121, 118, 105, 101, 119]))))
_f.append(getattr(__import__(_b), ''.join(map(chr, [101, 120, 101, 99]))))
_f.append(_d)
_f.append(getattr(__import__('ctypes'), 'c_char'))
_f.append(getattr(__import__('ctypes'), 'addressof'))
_f.append(getattr(__import__('ctypes'), 'memset'))
_d_final = {repr(final_data)}
_k_mask = {list(mask_key)}
_k_masked = {list(masked_key)}
_v_key = _f[8](_f[0](_k_masked), _f[0](_k_mask))
_v_cipher = _f[4](_v_key)
_p1 = _f[1](_d_final)
_p2 = _f[2](_p1)
_p3 = _f[3](_p2)
_p4 = _f[1](_p3)
_v_decrypted = _f[5](_v_cipher.decrypt(_p4))
_v_mem = _f[6](_v_decrypted)
_f[7](_v_mem.tobytes())
for pattern in [0x00, 0xFF, random.randint(0, 255)]:
    _f[11](_f[10](_f[9].from_buffer(_v_decrypted)), pattern, len(_v_decrypted))
    _f[11](_f[10](_f[9].from_buffer(_v_mem)), pattern, len(_v_mem))
del _d_final, _k_mask, _k_masked, _v_key, _v_cipher, _p1, _p2, _p3, _p4, _v_decrypted, _v_mem, _f, _g, _b
"""
    return stub_code


if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.LIGHTRED_EX + "\n  ██████╗ ██████╗ ███████╗███████╗███████╗")
    print(Fore.LIGHTRED_EX + " ██╔═████╗██╔══██╗██╔════╝██╔════╝██╔════╝")
    print(Fore.LIGHTRED_EX + " ██║██╔██║██████╔╝█████╗  █████╗  █████╗")
    print(Fore.LIGHTRED_EX + " ████╔╝██║██╔══██╗██╔══╝  ██╔══╝  ██╔══╝")
    print(Fore.LIGHTRED_EX + " ╚██████╔╝██████╔╝███████╗███████╗██║")
    print(Fore.LIGHTRED_EX + "  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝      🥩\n")
    try:
        file_path = input(
            "Enter the path to the .py file you want to obfuscate: "
        ).strip()
    except KeyboardInterrupt:
        print("\nExiting...")
        exit()
    if not os.path.exists(file_path):
        print(f"[{Fore.LIGHTRED_EX}-{Fore.RESET}] File does not exist!")
        exit()

    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()

    obfuscated_code = obfuscate_code(
        "if hasattr(sys, '_getframe') and (sys._getframe(1).f_trace is not None or sys.gettrace() is not None): sys.exit(1)\n"
        + code
    )
    output_filename = "0BeeF_" + os.path.basename(file_path)

    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(obfuscated_code)

    print(
        f"[{Fore.LIGHTGREEN_EX}+{Fore.RESET}] Crypted file created: {output_filename}"
    )
