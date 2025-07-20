import base64
import marshal
import os
import re
import zlib
import ast
import sys
import uuid
import math
import random
from colorama import Fore, init
from cryptography.fernet import Fernet

init(autoreset=True)
# You can customize it to create your own stub code
STUB_CODE = """'''
  ██████╗ ██████╗ ███████╗███████╗███████╗
 ██╔═████╗██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║██╔██║██████╔╝█████╗  █████╗  █████╗
 ████╔╝██║██╔══██╗██╔══╝  ██╔══╝  ██╔══╝
 ╚██████╔╝██████╔╝███████╗███████╗██║
  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝      🥩
"Once is enough. After that - burn it all."
'''
def _x(p): getattr(__import__(''.join(map(chr, [98, 117, 105, 108, 116, 105, 110, 115]))), ''.join(map(chr, [101, 120, 101, 99])))(getattr(__import__(''.join(map(chr, [109, 97, 114, 115, 104, 97, 108]))), ''.join(map(chr, [108, 111, 97, 100, 115])))(getattr(__import__(''.join(map(chr, [122, 108, 105, 98]))), ''.join(map(chr, [100, 101, 99, 111, 109, 112, 114, 101, 115, 115])))(getattr(__import__(''.join(map(chr, [98, 97, 115, 101, 54, 52]))), ''.join(map(chr, [98, 54, 52, 100, 101, 99, 111, 100, 101])))(p))), globals())
_x(b'eJwr5mJgYMjMLcgvKlEoriwGAB3+BJg=')
_x(b'eJwr5mVgYMjMLcgvKlFISixONTMBACzqBUE=')
_x(b'eJwr5mZgYMjMLcgvKlGoyslMAgAi6ATr')
_x(b'eJwr5mNgYMjMLcgvKlHITSwqzkjMAQA0GQYl')
_x(b'eJwr5mVgYMjMLcgvKlFILqksSC0GAC4lBdQ=')
_x(b'eJwrVmNgYEgrys9VSC6qLCjJTy9KLMio1EtLLcpLLVHIzC3ILypRcAPzAD/TD4s=')
_x(b'eJwr5mVgYMjMLcgvKlEoSsxLyc8FAC3eBb0=')
_x(b'eJwr5mRgYMjMLcgvKlEoSgUAGUMEDw==')
_x(b'eJwrFmRgYMjMLcgvKlEoLk0qKMpPTi0uBgBKCAeJ')
_x(b'eJwr5mZgYMjMLcgvKlEoycxNBQAi0gTp')
_x(b'eJwrNmRgYEgrys9VSM7PSy4tKkrNK9FLKy0pLUotVsjMLcgvKlEIyShKTUwJyM/Pca1ITS4tyS8CAAZAFBQ=')
_x(b'eJwr5mVgYMjMLcgvKlEoKC4tycwBAC5rBd0=')
_x(b'eJwr5mRgYMjMLcgvKlHILwYAGUsEGg==')
_x(b'eJwr5mVgYMjMLcgvKlEozigtycwBAC5GBdU=')
_x(b'eJwr5mdgYMjMLcgvKlEoSc0tSMvMSQUAOu0GlA==')
_x(b'eJwr5mVgYMjMLcgvKlEoz8wrSk0HAC40Bcg=')
_x(b'eJwr5mdgYMjMLcgvKlHIL0gtSizJLwIAOwwGqg=='){}
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
_f.append(getattr(__import__(''.join(map(chr, [99, 116, 121, 112, 101, 115]))), ''.join(map(chr, [99, 95, 99, 104, 97, 114]))))
_f.append(getattr(__import__(''.join(map(chr, [99, 116, 121, 112, 101, 115]))),''.join(map(chr, [97, 100, 100, 114, 101, 115, 115, 111, 102]))))
_f.append(getattr(__import__(''.join(map(chr, [99, 116, 121, 112, 101, 115]))),''.join(map(chr, [109, 101, 109, 115, 101, 116]))))
_f.append(getattr(__import__(''.join(map(chr, [114, 97, 110, 100, 111, 109]))), ''.join(map(chr, [114, 97, 110, 100, 105, 110, 116]))))
_d_f = {}
_k_m = {}
_k_md = {}
_v_k = _f[8](_f[0](_k_md), _f[0](_k_m))
_v_c = _f[4](_v_k)
_p1 = _f[1](_d_f)
_p2 = _f[2](_p1)
_p3 = _f[3](_p2)
_p4 = _f[1](_p3)
_v_d_b = getattr(_v_c, ''.join(map(chr, [100, 101, 99, 114, 121, 112, 116])))(_p4)
_v_m = _f[6](_v_d_b)
_f[7](_f[2](_v_m.tobytes()), globals())
try:
    for pattern in [0x00, 0xFF, _f[12](0, 255)]:
        _f[11](_f[10](_f[9].from_buffer(bytearray(_v_d_b))), pattern, len(_v_d_b))
        _f[11](_f[10](_f[9].from_buffer(bytearray(_v_m))), pattern, len(_v_m))
except:
    pass
del _d_f, _k_m, _k_md, _v_k, _v_c, _p1, _p2, _p3, _p4, _v_d_b, _v_m, _f, _g, _b"""


def is_perfect_square(n):
    if n < 0:
        return False
    if n == 0:
        return True
    x = int(math.sqrt(n))
    return x * x == n


def create_opaque_constant(n):
    transformations = []
    if is_perfect_square(n) and n > 4:
        transformations.append(
            lambda num: ast.BinOp(
                left=ast.Constant(value=int(math.sqrt(num))),
                op=ast.Pow(),
                right=ast.Constant(value=2),
            )
        )
    if n > 2 and n % 2 == 0:
        transformations.append(
            lambda num: ast.BinOp(
                left=ast.Constant(value=num // 2),
                op=ast.Mult(),
                right=ast.Constant(value=2),
            )
        )
        if n > 10:
            factor1 = random.randint(3, n // 3)
            remainder = n % factor1
            transformations.append(
                lambda num, f1=factor1, r=remainder: ast.BinOp(
                    left=ast.BinOp(
                        left=ast.Constant(value=f1),
                        op=ast.Mult(),
                        right=ast.Constant(value=num // f1),
                    ),
                    op=ast.Add(),
                    right=ast.Constant(value=r),
                )
            )
    if n > 1 and n % 2 != 0:
        transformations.append(
            lambda num: ast.BinOp(
                left=ast.BinOp(
                    left=ast.Constant(value=num // 2),
                    op=ast.Mult(),
                    right=ast.Constant(value=2),
                ),
                op=ast.Add(),
                right=ast.Constant(value=1),
            )
        )
    if n > 0:
        transformations.append(
            lambda num: ast.Call(
                func=ast.Name(id="len", ctx=ast.Load()),
                args=[ast.Constant(value="O_o" * (num // 3) + "O_o"[: num % 3])],
                keywords=[],
            )
        )
    if transformations:
        try:
            return random.choice(transformations)(n)
        except:
            return ast.Constant(value=n)
    return ast.Constant(value=n)


def flatten_control_flow(code):
    try:
        tree = ast.parse(code)
        body = tree.body
        if len(body) < 2:
            return code
        imports = []
        definitions = []
        actions = []
        for node in body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(node)
            elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                definitions.append(node)
            else:
                actions.append(node)
        if not actions:
            return ast.unparse(tree)
        num_blocks = len(actions)
        state_sequence = random.sample(range(100, 100 + num_blocks * 3), num_blocks)
        final_state_value = max(state_sequence) + random.randint(1, 10)
        initial_state = state_sequence[0]
        next_state_map = {}
        for i in range(num_blocks - 1):
            next_state_map[state_sequence[i]] = state_sequence[i + 1]
        next_state_map[state_sequence[-1]] = final_state_value
        state_var = f"_beef_state_{uuid.uuid4().hex[:8]}"
        blocks_map = dict(zip(state_sequence, actions))
        loop_body_ifs = []
        physical_order_states = list(state_sequence)
        random.shuffle(physical_order_states)
        for state_val in physical_order_states:
            if_test = ast.Compare(
                left=ast.Name(id=state_var, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[create_opaque_constant(state_val)],
            )
            next_state_assignment = ast.Assign(
                targets=[ast.Name(id=state_var, ctx=ast.Store())],
                value=create_opaque_constant(next_state_map[state_val]),
            )
            node_body = blocks_map[state_val]
            if_body = [node_body, next_state_assignment]
            loop_body_ifs.append(ast.If(test=if_test, body=if_body, orelse=[]))
        if not loop_body_ifs:
            return code
        main_if = loop_body_ifs[0]
        current_if = main_if
        for next_if in loop_body_ifs[1:]:
            current_if.orelse = [next_if]
            current_if = next_if
        new_body = list(imports)
        new_body.extend(definitions)
        new_body.append(
            ast.Assign(
                targets=[ast.Name(id=state_var, ctx=ast.Store())],
                value=create_opaque_constant(initial_state),
            )
        )
        while_condition = ast.Compare(
            left=ast.Name(id=state_var, ctx=ast.Load()),
            ops=[ast.NotEq()],
            comparators=[create_opaque_constant(final_state_value)],
        )
        new_body.append(ast.While(test=while_condition, body=[main_if], orelse=[]))
        final_tree = ast.Module(body=new_body, type_ignores=[])
        ast.fix_missing_locations(final_tree)
        return ast.unparse(final_tree)
    except Exception as e:
        print(f"[{Fore.YELLOW}!{Fore.RESET}] Control flow flattening failed: {str(e)}")
        import traceback

        traceback.print_exc()
        return code


def xor_encrypt(data, key):
    if not key:
        return data
    return bytes(
        a ^ b for a, b in zip(data, (key * ((len(data) // len(key)) + 1))[: len(data)])
    )


class StringObfuscator(ast.NodeTransformer):
    def __init__(self):
        self.in_fstring = False

    def visit_JoinedStr(self, node):
        prev = self.in_fstring
        self.in_fstring = True
        self.generic_visit(node)
        self.in_fstring = prev
        return node

    def visit_Constant(self, node):
        if isinstance(node.value, str) and not self.in_fstring:
            if len(node.value) < 3:
                return node
            if isinstance(node.parent, ast.Expr) and node.parent.value is node:
                return node
            key = os.urandom(8)

            encrypted = base64.b64encode(xor_encrypt(node.value.encode(), key)).decode()

            return ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Name(id="_d", ctx=ast.Load()),
                        args=[
                            ast.Call(
                                func=ast.Attribute(
                                    value=ast.Name(id="base64", ctx=ast.Load()),
                                    attr="b64decode",
                                    ctx=ast.Load(),
                                ),
                                args=[ast.Constant(value=encrypted)],
                                keywords=[],
                            ),
                            ast.Constant(value=key),
                        ],
                        keywords=[],
                    ),
                    attr="decode",
                    ctx=ast.Load(),
                ),
                args=[],
                keywords=[],
            )
        return node


def obfuscate_strings(code):
    try:
        tree = ast.parse(code)
        transformer = StringObfuscator()

        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                child.parent = node

        new_tree = transformer.visit(tree)
        ast.fix_missing_locations(new_tree)
        return ast.unparse(new_tree)
    except Exception as e:
        print(f"[{Fore.YELLOW}!{Fore.RESET}] String obfuscation failed: {e}")
        import traceback

        traceback.print_exc()
        return code


def fernet_encrypt(key, data):
    data_bytes = data if isinstance(data, bytes) else data.encode()
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data_bytes)


def encode_b64(data):
    return base64.b64encode(data).decode()


def obfuscate_code(code):
    main_code = []
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
        else:
            main_code.append(line)
    code_to_process = "\n".join(main_code)
    encoded_import_lines = []
    for imp_line in payload_imports:
        marshalled = marshal.dumps(imp_line.encode())
        compressed = zlib.compress(marshalled)
        encoded = base64.b64encode(compressed)
        encoded_import_lines.append(encoded)
    final_import_calls = "\n".join(
        [f"_x(b'{line.decode()}')" for line in encoded_import_lines]
    )
    final_import_calls = "\n" + final_import_calls
    try:
        enable_anti_debug = input("Enable anti-debugging? (y/n): ").strip().lower()
        print(
            f"[{Fore.YELLOW}!{Fore.RESET}] Anti-VM detection is only effective on Windows virtual machines."
        )
        enable_anti_vm = input("Enable anti-VM? (y/n): ").strip().lower()
        enable_string_obf = input("Enable string obfuscation? (y/n): ")
        enable_flatten = (
            input("Enable control flow flattening? (y/n): ").strip().lower()
        )
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    if enable_anti_vm in ["y", "yes"]:
        final_import_calls += (
            ("" if len(final_import_calls) == 0 else "\n")
            + "_x(b'eJzNVm1v2zYQ7mfvT+ibZCARlGQpVgMZ4DryYiR+qe06G+JAoKWzTUQSBZLyC9r+9x1F2ZIcAck2DBuRWMd745HP3ZFi9NOHDzRKGJfGlsYcVo1GAEuDCm8TWc1Ww8Ah+V4TarBUJqk0bgyRLhLOfBDC9tfgv3haYh011XgytxH1zTPD9FmEUuBiLyREirMCqT4RCyA0n88qdhD7LKDx6sZM5fL8F7MqlTQCXO3mqsr2ORBJWbwMyUrclOLrjN321PUGQ++xN7gdPhZmzSNFlwaJ99XoN5FB43zHFcGS8Vz4VOGrYc4olykJT2LWov6WcKiVaKPPbFcnvdsnwM9ndaIvbv9rHf9+1q9jjwgnYQihOBE+F0fSqgg4yJTHxpSnkPFh50MiDat8vMpjMNIzl3PGz8rZMdVoubuEcghK7hMixD9PMEyjiPj/iwRaMBZaJ6dnCyDcX1uvoOCm5Tgt57r18dN3RXRalxlxjX8fFXHRaV38nImuWt3ud63sOE0smpqUbP6XACZErgVCVlSD2WnN5+hxxUlkdGkIYj7X2X/4GlM8rXIa1pkMOfFDZXIsD+O3FIQ02kFAFVSvHDzSOGBbNJ1kjebqcj4PON1g40EvaJ+Z29iF/qphn6UC/o7hpFtndbLR3Ek7SXDSpz5ngi2lnbMnJA4WbOflTnSx5h2LCVsdvw07KqSwFN3MGpSiVIvKwCmhdpoQleo7ZLEvseUIG++EIAztF+AxhFeXdk/kWcJ4F2sl5TDiICCW1uWn5jsTry0lpwu8C/JMG04y4s3G8GZot7BIVyvgh5D+hYBEKjxVFirZvxWAbiKpkjkog7xBwATwDfXLDd/cYg2JNeEvZeaSBkEIvMwSGnJaMc4rck38l6P2j+x3SxHs6RobWDDCUNwd+Klk3GoaROBG9azY0DJV2FV3oY9Ea9pY/hGVVkiiRUAMtW4r+7VpvGQ29lzLjEkE6gI3m3bItoBrnWUqTa356sJUzCwfRSppaOd78Sg+Cqwn7e256GI/Tm9mHbKNUachYqs8FWgo/1pB8fPdvQG/kIRLT10FeAzqY+Mlu/R8lsYqJB2Kcuwpn5zEK7AuPMdx1H9dcmCgNW6M8/JKvxqOff3OWnyBPUamn2X2MIH4HvZWPr27d//wHoad9oPXb3fuegP39WVfGeZde3z72B678/mtO+mMe6Npbzg4NC2zOPgFZQgKolys/SUFvp+RMAV3Z2FUCLo2+4y6M2x02IjN5pPzfIqZfiMVHkvvJnwLqWhUAs164+nX9oMi9WvGMH93B5gM7ynfGhzUaJQsuiQU0GjQk2dt/uxlQpUIY0cMkbQ97KYS1Y2YKQ09L71RDizL0QdXnjf+BKeQLG0=')"
        )
    if enable_anti_debug in ["y", "yes"]:
        final_import_calls += "\n_x(b'eJx9VM1u2zAM7mGnPAV3sgwETrvdCuQwYC3Qy9ZDscswGLJFp0IdSSDlNcawV9gzT1LsxPnlwRB/P/IjYf734eZGYQOaS4VVt1ohlY6Q0XiR388gyNauzapcW9W1yLCEP8kTJXOqyuZ7NUW7fmpyvcLfamrRR0lVUJP2N311cwpaaOORGGuvrRHcczE4hi6jEPqODLxQh7Ox0Ktk6T3FjDlkKwxvWWOWgzQKYpnRJPJAAhjr4Zs1eKFosnrq9+4TiDIUbEiupxg7m7jLi6ZMeOfRjhGjjpsanQfxJYDoqvP4QGRpDj9k223fEw6cZN4pIwmWCxPQYbmEzPhsH30wyhBc+94Fvt+1UW1bvCEZbD9/Kp7463Agz4f3ca31aftPa2fJD70fznJU6WCGS3M4y3pzbZR37V/BOjQiWziy9YKxbRbspe847oahOR2gsQStNmE75px76CNGFKESeY4oInuJG6Vnre6zM6xMMsMVi222a3Wg8Ofdrxw+LuH2ctYlXo+lIpRvp6x/v3YtURLbswnKo2w53Lq++lfQaZthI5FIa3m3orCjEjfaj/c96nvQXYi4zZNxqs/+A9fVPpE=')"
    if enable_flatten in ["y", "yes"]:
        code_to_process = flatten_control_flow(code_to_process)
    if enable_string_obf in ["y", "yes"]:
        code_to_process = obfuscate_strings(code_to_process)
    print(f"[{Fore.LIGHTGREEN_EX}+{Fore.RESET}] Compiling and packing final payload...")
    try:
        compiled_bytecode = compile(code_to_process, "<obfuscated>", "exec")
    except SyntaxError as e:
        print(
            f"[{Fore.LIGHTRED_EX}-{Fore.RESET}] Syntax error in your file, could not compile: {e}"
        )
        sys.exit(2)
    marshalled_bytecode = marshal.dumps(compiled_bytecode)
    encryption_key = Fernet.generate_key()
    mask_key = os.urandom(len(encryption_key))
    masked_key = xor_encrypt(encryption_key, mask_key)
    encrypted_data = fernet_encrypt(encryption_key, marshalled_bytecode)
    encoded_data = encode_b64(encrypted_data)
    compressed_data = zlib.compress(encoded_data.encode())
    marshalled_data = marshal.dumps(compressed_data)
    final_data = encode_b64(marshalled_data)
    return STUB_CODE.format(
        final_import_calls if len(final_import_calls) != 0 else "",
        repr(final_data),
        list(mask_key),
        list(masked_key),
    )


if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.LIGHTRED_EX + "\n  ██████╗ ██████╗ ███████╗███████╗███████╗")
    print(Fore.LIGHTRED_EX + " ██╔═████╗██╔══██╗██╔════╝██╔════╝██╔════╝")
    print(Fore.LIGHTRED_EX + " ██║██╔██║██████╔╝█████╗  █████╗  █████╗")
    print(Fore.LIGHTRED_EX + " ████╔╝██║██╔══██╗██╔══╝  ██╔══╝  ██╔══╝")
    print(Fore.LIGHTRED_EX + " ╚██████╔╝██████╔╝███████╗███████╗██║")
    print(Fore.LIGHTRED_EX + "  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝      🥩\n")
    print('"Once is enough. After that - burn it all."')
    print(
        f"[{Fore.YELLOW}!{Fore.RESET}] Python 3.9+ is recommended for maximum effectiveness."
    )
    try:
        file_path = (
            input("Enter the path to the .py file you want to obfuscate: ")
            .strip()
            .strip("'\"")
        )
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    if not os.path.exists(file_path):
        print(f"[{Fore.LIGHTRED_EX}-{Fore.RESET}] File does not exist!")
        sys.exit(1)
    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()
    obfuscated_code = obfuscate_code(code)
    output_filename = "0BeeF_" + os.path.basename(file_path)
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(obfuscated_code)
    print(
        f"[{Fore.LIGHTGREEN_EX}+{Fore.RESET}] Crypted file created: {output_filename}"
    )
