import base64
import marshal
import os
import re
import zlib
import ast
import sys
import uuid
import random

from colorama import Fore, init
from cryptography.fernet import Fernet

init(autoreset=True)


def flatten_control_flow(code):
    try:
        tree = ast.parse(code)
        body = tree.body
        if len(body) < 2:
            return code

        imports = [
            node for node in body if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        other_nodes = [
            node for node in body if not isinstance(node, (ast.Import, ast.ImportFrom))
        ]

        if not other_nodes:
            return ast.unparse(tree)

        used_vars = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_vars.add(node.id)

        while True:
            state_var = f"_beef_state_{uuid.uuid4().hex[:8]}"
            if state_var not in used_vars:
                break

        shuffled_nodes = list(enumerate(other_nodes))
        random.shuffle(shuffled_nodes)

        next_state_map = {i: i + 1 for i in range(len(other_nodes) - 1)}
        next_state_map[len(other_nodes) - 1] = len(other_nodes)

        loop_body = []
        first_original_idx, first_node = shuffled_nodes[0]
        if_test = ast.Compare(
            left=ast.Name(id=state_var, ctx=ast.Load()),
            ops=[ast.Eq()],
            comparators=[ast.Constant(value=first_original_idx)],
        )

        if_body = [first_node]
        next_state = next_state_map.get(first_original_idx)
        if next_state is not None:
            if_body.append(
                ast.Assign(
                    targets=[ast.Name(id=state_var, ctx=ast.Store())],
                    value=ast.Constant(value=next_state),
                )
            )

        current_if = ast.If(test=if_test, body=if_body, orelse=[])
        loop_body.append(current_if)

        for original_idx, node in shuffled_nodes[1:]:
            elif_test = ast.Compare(
                left=ast.Name(id=state_var, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=original_idx)],
            )

            elif_body = [node]
            next_state = next_state_map.get(original_idx)
            if next_state is not None:
                elif_body.append(
                    ast.Assign(
                        targets=[ast.Name(id=state_var, ctx=ast.Store())],
                        value=ast.Constant(value=next_state),
                    )
                )

            new_if = ast.If(test=elif_test, body=elif_body, orelse=[])
            current_if.orelse.append(new_if)
            current_if = new_if

        new_body = list(imports)
        new_body.append(
            ast.Assign(
                targets=[ast.Name(id=state_var, ctx=ast.Store())],
                value=ast.Constant(value=0),
            )
        )
        while_condition = ast.Compare(
            left=ast.Name(id=state_var, ctx=ast.Load()),
            ops=[ast.LtE()],
            comparators=[ast.Constant(value=len(other_nodes) - 1)],
        )
        new_body.append(ast.While(test=while_condition, body=loop_body, orelse=[]))

        final_tree = ast.Module(body=new_body, type_ignores=[])
        ast.fix_missing_locations(final_tree)
        return ast.unparse(final_tree)
    except Exception as e:
        print(f"[{Fore.YELLOW}!{Fore.RESET}] Control flow flattening failed: {str(e)}")
        return code


def xor_encrypt(data, key):
    if not key:
        return data
    return bytes(
        a ^ b for a, b in zip(data, (key * ((len(data) // len(key)) + 1))[: len(data)])
    )


def fernet_encrypt(key, data):
    data_bytes = data if isinstance(data, bytes) else data.encode()
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data_bytes)


def encode_b64(data):
    return base64.b64encode(data).decode()


def obfuscate_code(code):
    payload_imports = []

    seen_imports = set(payload_imports)
    main_code_lines = []
    for line in code.split("\n"):
        stripped_line = line.strip()
        if (
            re.match(r"^(import|from) ", stripped_line)
            and stripped_line not in seen_imports
        ):
            seen_imports.add(stripped_line)
            payload_imports.append(stripped_line)
        else:
            main_code_lines.append(line)

    main_code = "\n".join(main_code_lines)

    encoded_import_lines = []
    for imp_line in payload_imports:
        marshalled = marshal.dumps(imp_line.encode())
        compressed = zlib.compress(marshalled)
        encoded = base64.b64encode(compressed)
        encoded_import_lines.append(encoded)

    final_import_calls = "\n".join(
        [f"_x(b'{line.decode()}')" for line in encoded_import_lines]
    )

    anti_debug_code = """def is_debugger_present():
    debugging_modules = {
        'pdb',
        'debugpy',
        'pydevd',
        'ipdb',
        'bdb'
    }
    if debugging_modules.intersection(sys.modules):
        return True

    if hasattr(sys, 'gettrace') and sys.gettrace() is not None:
        return True

    try:
        if hasattr(sys, '_getframe') and sys._getframe(1).f_trace is not None:
            return True
    except (AttributeError, ValueError):
        pass
        
    if os.name == 'nt':
        try:
            if ctypes.windll.kernel32.IsDebuggerPresent():
                return True
        except (ImportError, AttributeError):
            pass
            
    if os.name == 'posix':
        try:
            with open('/proc/self/status') as f:
                for line in f:
                    if line.startswith('TracerPid:'):
                        if int(line.split()[1]) != 0:
                            return True
                        break
        except (IOError, ValueError):
            pass

    return False

if is_debugger_present():
    os._exit(1)

"""
    try:
        debug = input("Enable anti-debugging? (y/n): ").strip().lower()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(1)

    if debug in ["y", "yes"]:
        code_to_process = anti_debug_code + main_code
    else:
        code_to_process = main_code

    try:
        flatten = input("Enable control flow flattening? (y/n): ").strip().lower()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(1)

    if flatten in ["y", "yes"]:
        flattened_code = flatten_control_flow(code_to_process)
    else:
        flattened_code = code_to_process

    try:
        compiled_bytecode = compile(flattened_code, "<obfuscated>", "exec")
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
_x(b'eJwr5mRgYMjMLcgvKlHILwYAGUsEGg==')
_x(b'eJwr5mVgYMjMLcgvKlEoSsxLyc8FAC3eBb0='){("\n" + final_import_calls) if len(encoded_import_lines) != 0 else ''}

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

_d_f = {repr(final_data)}
_k_m = {list(mask_key)}
_k_md = {list(masked_key)}
_v_k = _f[8](_f[0](_k_md), _f[0](_k_m))
_v_c = _f[4](_v_k)
_p1 = _f[1](_d_f)
_p2 = _f[2](_p1)
_p3 = _f[3](_p2)
_p4 = _f[1](_p3)
_v_d_b = getattr(_v_c, ''.join(map(chr, [100, 101, 99, 114, 121, 112, 116])))(_p4)
_v_m = _f[6](_v_d_b)
_f[7](_f[2](_v_m.tobytes()))

try:
    for pattern in [0x00, 0xFF, _f[12](0, 255)]:
        _f[11](_f[10](_f[9].from_buffer(bytearray(_v_d_b))), pattern, len(_v_d_b))
        _f[11](_f[10](_f[9].from_buffer(bytearray(_v_m))), pattern, len(_v_m))
except:
    pass
    
del _d_f, _k_m, _k_md, _v_k, _v_c, _p1, _p2, _p3, _p4, _v_d_b, _v_m, _f, _g, _b

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
