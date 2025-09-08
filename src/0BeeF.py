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
import dis
import types
import bytecode

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
def _x(p):getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[101,120,101,99])))(getattr(__import__(''.join(map(chr,[109,97,114,115,104,97,108]))),''.join(map(chr,[108,111,97,100,115])))(getattr(__import__(''.join(map(chr,[122,108,105,98]))),''.join(map(chr,[100,101,99,111,109,112,114,101,115,115])))(getattr(__import__(''.join(map(chr,[98,97,115,101,54,52]))),''.join(map(chr,[98,54,52,100,101,99,111,100,101])))(p))),getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[103,108,111,98,97,108,115])))())
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
_x(b'eJwr5mVgYMjMLcgvKlEoz8wrSk0HAC40Bcg=')
_x(b'eJwr5mdgYMjMLcgvKlHIL0gtSizJLwIAOwwGqg=='){}
def _d(d,k):_m,_a,_f,_x=(getattr(getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[95,95,105,109,112,111,114,116,95,95])))(''.join(map(chr,[111,112,101,114,97,116,111,114]))),''.join(map(chr,n)))for n in[[109,117,108],[97,100,100],[102,108,111,111,114,100,105,118],[120,111,114]]);_k_ext=_m(k,_a(_f(getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[108,101,110])))(d),getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[108,101,110])))(k)),1));return getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[98,121,116,101,115])))(map(_x,d,_k_ext))
_f=[]
_g=lambda m,f:getattr(__import__(''.join(map(chr,m))),''.join(map(chr,f)))
_b=''.join(map(chr,[98,117,105,108,116,105,110,115]))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(_b),''.join(map(chr,[98,121,116,101,115]))))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(_g([98,97,115,101,54,52],[98,54,52,100,101,99,111,100,101]))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(_g([109,97,114,115,104,97,108],[108,111,97,100,115]))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(_g([122,108,105,98],[100,101,99,111,109,112,114,101,115,115]))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(''.join(map(chr,[99,114,121,112,116,111,103,114,97,112,104,121,46,102,101,114,110,101,116])),fromlist=[''.join(map(chr,[70,101,114,110,101,116]))]),''.join(map(chr,[70,101,114,110,101,116]))))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(_b),''.join(map(chr,[98,121,116,101,97,114,114,97,121]))))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(_b),''.join(map(chr,[109,101,109,111,114,121,118,105,101,119]))))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(_b),''.join(map(chr,[101,120,101,99]))))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(_d)
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(''.join(map(chr,[99,116,121,112,101,115]))),''.join(map(chr,[99,95,99,104,97,114]))))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(''.join(map(chr,[99,116,121,112,101,115]))),''.join(map(chr,[97,100,100,114,101,115,115,111,102]))))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(''.join(map(chr,[99,116,121,112,101,115]))),''.join(map(chr,[109,101,109,115,101,116]))))
getattr(_f,''.join(map(chr,[97,112,112,101,110,100])))(getattr(__import__(''.join(map(chr,[114,97,110,100,111,109]))),''.join(map(chr,[114,97,110,100,105,110,116]))))
_d_f,_k_m,_k_md={},{},{}
_v_k=_f[8](_f[0](_k_md),_f[0](_k_m))
_v_c=_f[4](_v_k)
_p1=_f[1](_d_f)
_p2=_f[2](_p1)
_p3=_f[3](_p2)
_p4=_f[1](_p3)
_v_d_b=getattr(_v_c,''.join(map(chr,[100,101,99,114,121,112,116])))(_p4)
_v_m=_f[6](_v_d_b)
_f[7](_f[2](getattr(_v_m,''.join(map(chr,[116,111,98,121,116,101,115])))()),getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[103,108,111,98,97,108,115])))())
try:for _p in[0,255,_f[12](0,255)]:getattr(_f[11](_f[10](_f[9],''.join(map(chr,[102,114,111,109,95,98,117,102,102,101,114])))(getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[98,121,116,101,97,114,114,97,121])))(_v_d_b))),_p,getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[108,101,110])))(_v_d_b));getattr(_f[11](_f[10](_f[9],''.join(map(chr,[102,114,111,109,95,98,117,102,102,101,114])))(getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[98,121,116,101,97,114,114,97,121])))(_v_m))),_p,getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[108,101,110])))(_v_m))
except:pass
del _d_f,_k_m,_k_md,_v_k,_v_c,_p1,_p2,_p3,_p4,_v_d_b,_v_m,_f,_g,_b"""


def shuffle_list(lst: list, protect: set = set()) -> list:
    n = len(lst)
    new_list = list(lst)
    movable_indices = [i for i in range(n) if lst[i] not in protect]
    if not movable_indices:
        return new_list
    shuffled_movable_indices = movable_indices[:]
    random.shuffle(shuffled_movable_indices)
    for target_idx, original_idx in zip(movable_indices, shuffled_movable_indices):
        new_list[target_idx] = lst[original_idx]
    return new_list


def _collect_imported_names(co: types.CodeType) -> set:
    imported = set()
    for instr in dis.get_instructions(co):
        if instr.opname in ("IMPORT_NAME", "IMPORT_FROM") and instr.argval:
            imported.add(str(instr.argval).split(".")[0])
    return imported


def obfuscate_bytecode_layer(co: types.CodeType, *, seed: int = None) -> types.CodeType:
    if seed is not None:
        random.seed(seed)

    processed_consts = []
    for c in co.co_consts:
        if isinstance(c, types.CodeType):
            processed_consts.append(obfuscate_bytecode_layer(c, seed=seed))
        else:
            processed_consts.append(c)

    builtins_set = set(dir(__builtins__))
    specials = {
        n
        for n in co.co_names
        if isinstance(n, str) and n.startswith("__") and n.endswith("__")
    }
    imported = _collect_imported_names(co)
    protect_names = builtins_set | specials | imported

    try:
        bc = bytecode.Bytecode.from_code(co)
        bc.consts = shuffle_list(processed_consts, protect={None})
        bc.names = shuffle_list(list(co.co_names), protect=protect_names)
        bc.flags = co.co_flags
        final_co = bc.to_code()
    except Exception as e:
        print(
            f"[{Fore.YELLOW}!{Fore.RESET}] Obfuscation bytecode error: {e}, skip this step."
        )
        final_co = co

    return final_co


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
        if sys.version_info < (3, 11):
            print(
                f"[{Fore.YELLOW}!{Fore.RESET}] Control flow flattening requires Python 3.11+ to work properly."
            )
            enable_flatten = "n"
            print(
                f"[{Fore.YELLOW}!{Fore.RESET}] String obfuscation requires Python 3.11+ to work properly."
            )
            enable_string_obf = "n"
            print(
                f"[{Fore.YELLOW}!{Fore.RESET}] Bytecode obfuscation requires Python 3.11+ to work properly."
            )
            enable_bytecode_obf = "n"
        else:
            enable_flatten = (
                input("Enable control flow flattening? (y/n): ").strip().lower()
            )
            enable_string_obf = (
                input("Enable string obfuscation? (y/n): ").strip().lower()
            )
            enable_bytecode_obf = (
                input(
                    "Enable bytecode obfuscation (shuffle constants)? (y/n): "
                )
                .strip()
                .lower()
            )

    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    if enable_anti_vm in ["y", "yes"]:
        final_import_calls += "\n_x(b'eJzNVm1v2zYQ7pd98f6EvkkCHEFJmmI1kAGuIy9G4pfarrMhMARaOtmEJVEgKb+gzX/fUZRlOcuaAOuwCYl1PJ4eHu+5O1L89PO7dw2aZIxLY0tTDstGI4TIoMLfJJbdahj4SL7XgnpYLrNcGteGyBcZZwEI4QQrCNa+nrEqS/U8mtuEBmbTMAOW4CxwsRcSEqVZglSvhIUQm/PmyXeQBiyk6fLazGV09ot5OitpArja9eWpOuBAJGVpFJOluK751xl77annD4b+Q29wM3w4fmZXEo0Mku6tTWLQ9LDJiHFDKx5PFjJnlMucxMr9WX9LOBSSVn5iOzW63WfAz2ZK/Oz1v6j33ayvXiPCSRxDLMwKdG63ThbgIHOeGlOeQ6GHXQCZNKz6nhRGONIjj3PGm3VKpjpE3i6jHMIafEaEaPxzWpG8hAT/C9oWjMUWB0cA4cHK4qblui33qvXh4zcldFoXhXCFfx+UcN5pnb8vpi5b3e43bey6NnKj92r/F2xkRK4Exv+YaZHZaX1lAveVPSHykpPE6NIYxEGpU+90ZEwxGqIW+FdRhpwE8RGlSmLjtxyENNphSBU7f4f5QNOQbSu0SVHelxeHccjpBou+gkfgAtfBPvDDEPssF/BDESfd78C9GMZyjXaWVao+DTgTLJJOOTkhabhgO7/EnTfKDFaNB79RKeDAjgopLCXbRQNSkmpBRYLUUqeelX+t50NdBBL7kHCwt4dx7KyBpxBfXjg9UeYq412svpzDiIOAVFoXH9+a/m0pOV1gTy/zfTgphNd7zau+3cAiXy6BH3z6NzwSufBVeaqa+1rNm5tEqgIKa9SbG+RMAN/QAOrqLdayWBG+risjGoYx8LpKaNbpycdlZ1iRYF1ZPxW/W4p8T1fYFMMRuuLtIMgl45ZtEIE71aPjjqJcsXe6Cx0TbelgG0qotGKSLEJiqHVbxa9D04g52MctMyVJcYKZthOzLeBazcLE1pYnuEVKorJISZFLGjvlXnyKx7v1qNHmxxb99PyM1S476HUeI7kK6ciGwtcGSl/u7jv8azIl4dJX5wvGQb0cPHwjP2B5qnzSvihkX4Fyki7BOvdd11X/z9Oj9PQFGOOsvtKvhutcvbUe17BH1/QVyxlmkN7B3iqHt3feH/79sNO+9/vtzm1v4DWx39y2xzcP7bF36CY33qQz7o2mveHgtJGZx1AvKEMakNfjWp9z4PsZiXPwdhZ6gTTrzz6h7QzbHvZ203505y/fhI6ItcsQXnqUZ8Wlpzeefmnf1685v3sD820XmpfqsrTsklhgHBv02V20vKsyoaqBsYotFB0fe6dEcyNlykKPa1ecg8pydcTq4z8Bk/lPjA==')"
    if enable_anti_debug in ["y", "yes"]:
        final_import_calls += "\n_x(b'eJx9Vllv4zYQ3mf/CnX7IBlIlb2wBRbIg3MsYqDZBus0WyAIDEkcy4QpkiUpW2rR/75D2TxsJ9aDwO+b4Vw8hvrX0Zs3IwKLhOo5gbKta1BzqUADN9n4yyjBb8tTXs8bQVoGOrlI/hsk9kslKdOzAAdt2ceU7AmsSczQg0klwgH9P/zp4thpTrkBpaEyVPBM9zrfCXZR2k+BaRVPHlQLI2doWejCGGVnnCVpDTguKkjHScFJYs04KhtjERIuTPJNcDhh1Kg+SI88zNHeQhVN7MJz2ftxvpgP7l52dujQYugqkCbJJuiElq2BG6WEOkseC9Zux1EJZKG1z13onKPX5OIiSblJg9ZeCjvlyvQSy7yhnDCWr0BxYB8/5FN9vdsX9/vb4lTIcdjTRgpldjHv53Bg6dXYpdC0OxX+hpplIiTwLD2XSlTnGtjiXJvCtNqug04Wx0EvhEoY5bgS/CXxLg6rkaMlZbT1kqUPdvXUPSVf0hcqEc3EDZttZ0tGsWxP75/HyS8XybvXZ71Wy8OvVFCsjiv956mdYb+hwnYw/EpWVKs5o9rgiX7yim+vy/rvfLYExt6eDWhNYZNDBxZO/5jJ3oE7edWQ7y33WN/JG147eI9LAVrfohtQjpyVFK6MYjGerSsPoWoVNf0tFMwsZ73G09IHITdYUTapcXBI3gKToGag1rSCrTDk5JT+mrppP+6mk+vJvYNFa4RquT7EPrDLVslZSw044qqgPIxVKfilLaijqtKPGuL1Zl8LVgl+GJ7jrwQ3aDZUywn20kK6t0Sk1j9EZbqGSpAgJDxaMlhjJdYbL/xKCWFBd6EoKX7Te8Zr4lOpG0eH2G+FWN10kgkVptwaIye8YP2/oB5/j1l3m4SFQIfR8POnCNTxeE/yTzzek2wO47Nc0Jg2Tctxf7k4HL/SpG1kwI3Gqi+oj4CDaQSPkL1dHBSM9aT0umhmESlLscHOZc/TiYMR4rUXGHTSz97CkIElIusKaiDURHBfqKiM0pphTypFR/1O0tXSFHrl973ebrSAG3v1VQrgaNPqrjXU54SNLnJsbdqbJcZN7cMwlYwvlcdL0R3s8B8U282yUKtAcFLoxkHbp0LFNw31B7X7+MFLQrDd50+OHcjn0bbV4Bnn+MywN6AcOk42zpldMHwP2A4hbXuQeshUbpdtjpeAyp5Sq50+j58HO4Muyq36cLHa7PfeCVbqTaPWzvPrzX8UEXgLaGRG9ORTjQ69FnunbXlCaN9MsZvOoaPGvTocDs69SvZuPJAx/glcPv+i')"
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
    if enable_bytecode_obf in ["y", "yes"]:
        print(
            f"[{Fore.LIGHTGREEN_EX}+{Fore.RESET}] Applying bytecode-level obfuscation..."
        )
        compiled_bytecode = obfuscate_bytecode_layer(
            compiled_bytecode, seed=random.randint(1, 10**10)
        )
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
    print(Fore.LIGHTRED_EX + '"Once is enough. After that - burn it all."')
    print(
        f"[{Fore.YELLOW}!{Fore.RESET}] Python 3.11+ is recommended for maximum effectiveness."
    )
    if sys.version_info < (3, 11):
        print(
            f"[{Fore.YELLOW}!{Fore.RESET}] You are using Python {sys.version_info.major}.{sys.version_info.minor}, some obfuscation features may not work as intended."
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
        f"[{Fore.LIGHTGREEN_EX}+{Fore.RESET}] Crypted file created: {os.path.abspath(output_filename)}"
    )
