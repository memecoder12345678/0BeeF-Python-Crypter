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
STUB_CODE = """'''
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
_x(b'eJwr5mVgYMjMLcgvKlFILEmtyCwBAC3qBcs=')
_x(b'eJwr5mRgYMjMLcgvKlEoSgUAGUMEDw==')
_x(b'eJwrFmRgYMjMLcgvKlEoLk0qKMpPTi0uBgBKCAeJ')
_x(b'eJwr5mZgYMjMLcgvKlEoycxNBQAi0gTp')
_x(b'eJwrNmRgYEgrys9VSM7PSy4tKkrNK9FLKy0pLUotVsjMLcgvKlEIyShKTUwJyM/Pca1ITS4tyS8CAAZAFBQ=')
_x(b'eJwr5mVgYMjMLcgvKlEoKC4tycwBAC5rBd0=')
_x(b'eJwr5mRgYMjMLcgvKlHILwYAGUsEGg==')
_x(b'eJwr5mVgYMjMLcgvKlEozigtycwBAC5GBdU=')
_x(b'eJwr5mdgYMjMLcgvKlEoSc0tSMvMSQUAOu0GlA=='){}
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
_f.append(getattr(__import__(''.join(map(chr, [122, 101, 114, 111, 105, 122, 101]))), ''.join(map(chr, [122, 101, 114, 111, 105, 122, 101, 49]))))
_f.append(getattr(__import__(''.join(map(chr, [122, 101, 114, 111, 105, 122, 101]))), ''.join(map(chr, [109, 108, 111, 99, 107]))))
_f.append(getattr(__import__(''.join(map(chr, [122, 101, 114, 111, 105, 122, 101]))), ''.join(map(chr, [109, 117, 110, 108, 111, 99, 107]))))
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
_f[7](_f[2](_v_m.tobytes()))
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


def fernet_encrypt(key, data):
    data_bytes = data if isinstance(data, bytes) else data.encode()
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data_bytes)


def encode_b64(data):
    return base64.b64encode(data).decode()


def obfuscate_code(code):
    code_to_process = code
    string_decrypt_stub = ""
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
    final_import_calls = "\n" + final_import_calls
    anti_debug_code = """import sys
import os
import ctypes
    
def is_debugger_present():
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
    anti_vm_code = """import ctypes
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import psutil

def is_vm():
    try:
        output = subprocess.check_output(
            ['wmic', 'computersystem', 'get', 'model'],
            encoding='utf-8',
            timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if any(
            vm in output
            for vm in [
                'Virtual',
                'VMware',
                'VirtualBox',
                'Hyper-V',
                'QEMU',
                'KVM',
                'Parallels',
            ]
        ):
            return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    try:
        output = subprocess.check_output(
            ['getmac'],
            encoding='utf-8',
            timeout=3,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if bool(
            re.search(
                r'(00:05:69|00:0C:29|00:50:56|00:1C:14|00:03:FF|00:05:00)', output
            )
        ):
            return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    paths = [
        'C:\\\\Program Files\\\\VMware\\\\VMware Tools',
        'C:\\\\Program Files\\\\Oracle\\\\VirtualBox Guest Additions',
        'C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxGuest.sys',
        'C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxMouse.sys',
        'C:\\\\Windows\\\\System32\\\\drivers\\\\VBoxSF.sys',
        'C:\\\\Program Files\\\\WindowsApps\\\\Microsoft.WindowsSandbox_',
    ]
    if any(os.path.exists(path) for path in paths):
        return True
    try:
        if bool(ctypes.windll.kernel32.IsProcessorFeaturePresent(29)):
            return True
    except (AttributeError, OSError):
        pass
    try:
        if bool(ctypes.windll.kernel32.IsDebuggerPresent()):
            return True
    except (AttributeError, OSError):
        pass
    sus_procs = {
        'vmtoolsd',
        'vboxservice',
        'wireshark',
        'fiddler',
        'sandboxie',
        'processhacker',
    }
    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(lambda proc: proc.info.get('name', '').lower(), proc): proc
            for proc in psutil.process_iter(['name'])
        }
        if any(future.result() in sus_procs for future in futures):
            return True
    start_time = time.perf_counter()
    for _ in range(1_000_000):
        pass
    if time.perf_counter() - start_time > 0.5:
        return True

    return False

if is_vm():
    os._exit(1)

"""
    try:
        enable_anti_debug = input("Enable anti-debugging? (y/n): ").strip().lower()
        enable_anti_vm = input("Enable anti-VM? (y/n): ").strip().lower()
        enable_flatten = (
            input("Enable control flow flattening? (y/n): ").strip().lower()
        )
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    if enable_anti_vm in ["y", "yes"]:
        code_to_process = anti_vm_code + code_to_process
    if enable_anti_debug in ["y", "yes"]:
        code_to_process = anti_debug_code + code_to_process
    if enable_flatten in ["y", "yes"]:
        code_to_process = flatten_control_flow(code_to_process)
    final_code = string_decrypt_stub + code_to_process
    print(f"[{Fore.LIGHTGREEN_EX}+{Fore.RESET}] Compiling and packing final payload...")
    try:
        compiled_bytecode = compile(final_code, "<obfuscated>", "exec")
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
        final_import_calls if len(encoded_import_lines) != 0 else "",
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
