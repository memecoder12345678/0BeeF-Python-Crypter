import ast
import base64
import dis
import marshal
import math
import os
import random
import re
import sys
import types
import uuid
import zlib

import bytecode
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
_x(b'eJwr5mdgYMjMLcgvKlHIL0gtSizJLwIAOwwGqg==')
_x(b'eJwr5mdgYMjMLcgvKlFIKs3MKcnMKwYAOusGqA==')
_x(b'eJwr5mNgYMjMLcgvKlHIzCsuSE0uAQA0RwYz'){}
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
try:
 for _p in[0,255,_f[12](0,255)]:getattr(_f[11](_f[10](_f[9],''.join(map(chr,[102,114,111,109,95,98,117,102,102,101,114])))(getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[98,121,116,101,97,114,114,97,121])))(_v_d_b))),_p,getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[108,101,110])))(_v_d_b));getattr(_f[11](_f[10](_f[9],''.join(map(chr,[102,114,111,109,95,98,117,102,102,101,114])))(getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[98,121,116,101,97,114,114,97,121])))(_v_m))),_p,getattr(__import__(''.join(map(chr,[98,117,105,108,116,105,110,115]))),''.join(map(chr,[108,101,110])))(_v_m))
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
        print(f"[{Fore.YELLOW}!{Fore.RESET}] Obfuscation bytecode error: {e}")
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
        enable_anti_debug = (
            input(f"[{Fore.LIGHTCYAN_EX}?{Fore.RESET}] Enable anti-debugging? (y/n): ")
            .strip()
            .lower()
        )
        enable_anti_vm = (
            input(f"[{Fore.LIGHTCYAN_EX}?{Fore.RESET}] Enable anti-VM? (y/n): ")
            .strip()
            .lower()
        )
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
                input(
                    f"[{Fore.LIGHTCYAN_EX}?{Fore.RESET}] Enable control flow flattening? (y/n): "
                )
                .strip()
                .lower()
            )
            enable_string_obf = (
                input(
                    f"[{Fore.LIGHTCYAN_EX}?{Fore.RESET}] Enable string obfuscation? (y/n): "
                )
                .strip()
                .lower()
            )
            enable_bytecode_obf = (
                input(
                    f"[{Fore.LIGHTCYAN_EX}?{Fore.RESET}] Enable bytecode obfuscation (shuffle constants)? (y/n): "
                )
                .strip()
                .lower()
            )
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)
    if enable_anti_vm in ["y", "yes"]:
        final_import_calls += (
            (
                ""
                if len(final_import_calls) == 1 and final_import_calls[0] == "\n"
                else "\n"
            )
            + "_x(b'eJzNV+9u2zYQ7+d82DMI2odKQCK4SZqtBjJA8Z/ZqB27tpu0SAKBlmiZMCVqJOU/a/sQe4E9xp5nj7IjRduSm6HZ1mEzEvN4PP70093xjha/fPPs2VGEZxYRwTJx3PqRBZ8MybmwLq07PVMfPrM/MOHFWOJ06Twfb4TESZOTJX7ufrofchZzlFhtQrG4v+mvEMdmsCaMUWEf/y2kAUchBSTCZY7oFVtbP+ZYSMuPIiIJS5+Oe0vSiK3EfaE+O72P1AoHsoCqQT2x+UpwfZYL/PXgxu2/hFX1oEH2s0zc90nImWAz6RntGKXRlK0Dg/2gv5dJNfK28X6JgF2EtqLZhais7WwyzE9uyqo3rf7b8vz1Tb88HSKOKMWVjLGvWDivKN7htML5999+DTLOQs3c+tYSubDUHAuBhVrdb21O4yXBK/vYsru9cbZRwrAw7aBwgblSjKcENySnW3m8DLWIw5wTuelgROVc+Z0jDXDb7/pNf6hElEvGc5WZezmsvEzOs3FOJFYWDUTSYuRTll5RYKCm4VR/J5EamjhkUcErSg1jvMSpXK60sk2iiBbrM04idCIwXxbzONJAcaKmpbAwtmitM8p4YdaRMvNTRDc/Y37z3VbTxNM8jjF/21UaADbDxbkR4u240/y0HXca7ej1xXk0je09AbVQmHSTJE/BpduHKd1CRHmSFXIiQpbOiH5UimXCUiMJiaQSGaUbBQ4ibJkZg4yt4PjMMaWPxHfPQ+fIOtM7CrFgpSYGieMYQ7Ex4l7JSWYomlNEdEBFOJdILHT4VRwIPFjLCeJShBzvMlcTEOtcEs0RjrgBV/spEXIrJ7F+jAyzbeLqqlCA6+wjHIs54otikkZIJEpcgVh4ZpUQncDrs1OtKR0dyTf1HR+WyyyXcIhEPjXnxwvnOFwExYqzs1Sfux1uyBJYBY/rUqRTDmv+CWQutR+OK/twCglN0vjSzuXs5Hu7uipJguFpl2dVNbgOqZI/oygWlyV+jVHLn7SC60Fw271uDm7329ydRGYWSjdV9svEIql548rCjHGzCKVwD1avGHEsc55aE55jrcfrEGfScsrEVCGLTO61OGf8uOzXSfGecA4hfFEJPkNC/PPQQAASFP4vXD+FG4Bz4D1PYMTDeVWtl2ynVqvXXtYvXn1UQqN+qoWX8HehhBeN+otzvXRWb7c/Fsa1mgvp9kgw3f8ygCbtoFerC5WH13CqhaNkV2eZklSe6etWCeCQWyURtg4NJTRX4alDTqkHhS3F9OzU6wpDmPE2hC3neAjVAbqFc/rKfaIPfCk5mcKBNi89GGvhizn6RWrbKr+l9C8QWhHw6WQOKRsNgUtrDT0burDjWkgAXjHb75vlykXq3vChelCMpQcBT4h0KEqmEdKXirr+9kg6Y+oO5tgpSnQdtl2Pqr7juMfaxC0sPysuSqnDLlTx90w+BXAl4M5dgfawz9tPh1WsoOwB65yCCxXS/v6j8AsDpTdv9wUvQyvlMlCHH9ygBk910iBkeaooFVQUcKAwOUpj7LwIarWa+v+TvH8ExjopP+kHq+a9fGLKL/AGmEE6Qd/1BhlOX+ONY6ad1633QW/Q8HtB3290utetY6ghHX/UvPVHrftma9wYdYeT7uDa3K7tvWunhIHbIY579Dc55psbRHPcWjvwXNXf9bYrsL2BDgd10Hbvag+HUSk6xg7Ry9X1wHFL3eSuEgS4QyuCBxUYWvvg3We67mjy1u89snJwmda6d63rQ1Xn/bA1qlzDtXroj/xer9UbHy5cDRqdsvLhScf0kUQwhm1EBT4iBz8ySZIxLi1WmEKRDKBASqfmHv0BzPAy4g==')"
        )
    if enable_anti_debug in ["y", "yes"]:
        final_import_calls += (
            (
                ""
                if len(final_import_calls) == 1 and final_import_calls[0] == "\n"
                else "\n"
            )
            + "eJyFUk1LxDAQXTz2Vww9pbAUP26CB0GFvYgH8SJS0mZag20SJlPd+utN26zuslXnksc85r2XSfznyWqVKKxB+0Jh2TcNUuEIPRoW2WUCoea+Nk3RWdW36OEKnlOnynQN6US6YYRuUPiuRqQjWYbjZdLQ9bFMrg0jeaxYWyP84PNIRN+xCLknA4/U407nVXrJTONAsGgwYFlhmoE0CkaVXUtk4VZgLMO9Nfi7JtPwQx4ZFEGuJtntO3z3xFmW18Xktuy15IfbCh2DuA4muuwZb4ksreFJtv2M9xbgpPeLKSseXNjhhzaqbfM3JIPtxXm+8TfxGR8OX/G/NJvOWeIY5TDaUpwocydbj4n+8//oSRnsPGjD+nCrWZxmyRc4r8X+')"
        )
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
        final_import_calls if final_import_calls else "",
        repr(final_data),
        str(list(mask_key)).replace(" ", ""),
        str(list(masked_key)).replace(" ", ""),
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
        f"[{Fore.YELLOW}!{Fore.RESET}] Python 3.11+ is recommended for maximum effectiveness."
    )
    print(
        f"[{Fore.YELLOW}!{Fore.RESET}] Code obfuscation by {Fore.LIGHTRED_EX}0BeeF{Fore.RESET} only runs on Windows machines."
    )
    if sys.version_info < (3, 11):
        print(
            f"[{Fore.YELLOW}!{Fore.RESET}] You are using Python {sys.version_info.major}.{sys.version_info.minor}, some obfuscation features may not work as intended."
        )
    try:
        file_path = (
            input(
                f"[{Fore.LIGHTCYAN_EX}?{Fore.RESET}] Enter the path to the '.py' file you want to obfuscate: "
            )
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
