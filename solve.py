# SageMath solver for 0x41 CTF SPN (based on the provided writeup)
# - Connects to the server
# - Receives 2^16 plaintext/ciphertext pairs
# - Builds linear equations over GF(2)
# - Recovers K0 by correlation search byte-by-byte
# - Solves for the full 16-byte key (flag)
# - Verifies and prints the flag

from sage.all import *
import socket
import ast
import sys
from typing import List, Tuple

# Parameters must match the server
ROUNDS = 4
BLOCK_SIZE = 8  # bytes

sbox = [237, 172, 175, 254, 173, 168, 187, 174, 53, 188, 165, 166, 161, 162, 131, 227, 191, 152, 63, 182, 169, 136, 171, 184, 149, 148, 183, 190, 181, 177, 163, 186, 207, 140, 143, 139, 147, 138, 155, 170, 134, 132, 135, 18, 193, 128, 129, 130, 157, 156, 151, 158, 153, 24, 154, 11, 141, 144, 21, 150, 146, 145, 179, 22, 245, 124, 236, 206, 105, 232, 43, 194, 229, 244, 247, 242, 233, 224, 235, 96, 253, 189, 219, 234, 241, 248, 251, 226, 117, 252, 213, 246, 240, 176, 249, 178, 205, 77, 231, 203, 137, 200, 107, 202, 133, 204, 228, 230, 225, 196, 195, 198, 201, 221, 199, 95, 216, 217, 159, 218, 209, 214, 215, 222, 83, 208, 211, 243, 44, 40, 46, 142, 32, 36, 185, 42, 45, 38, 47, 34, 33, 164, 167, 98, 41, 56, 55, 126, 57, 120, 59, 250, 37, 180, 119, 54, 52, 160, 51, 58, 5, 14, 79, 30, 8, 12, 13, 10, 68, 0, 39, 6, 1, 16, 3, 2, 23, 28, 29, 31, 27, 9, 7, 62, 4, 60, 19, 20, 48, 17, 87, 26, 239, 110, 111, 238, 109, 104, 35, 106, 101, 102, 103, 70, 49, 100, 99, 114, 61, 121, 223, 255, 88, 108, 123, 122, 84, 92, 125, 116, 112, 113, 115, 118, 197, 76, 15, 94, 73, 72, 75, 74, 81, 212, 69, 66, 65, 64, 97, 82, 93, 220, 71, 90, 25, 89, 91, 78, 85, 86, 127, 210, 80, 192, 67, 50]
perm = [1, 57, 6, 31, 30, 7, 26, 45, 21, 19, 63, 48, 41, 2, 0, 3, 4, 15, 43, 16, 62, 49, 55, 53, 50, 25, 47, 32, 14, 38, 60, 13, 10, 23, 35, 36, 22, 52, 51, 28, 18, 39, 58, 42, 8, 20, 33, 27, 37, 11, 12, 56, 34, 29, 46, 24, 59, 54, 44, 5, 40, 9, 61, 17]

# Utilities matching the writeup's conventions

def BIT(v: int, k: int) -> int:
    """k-th bit from the left (MSB=bit 0) of 8-bit integer v."""
    cc = bin(v)[2:].zfill(8)
    return 1 if cc[k] == '1' else 0


def str64(n: int) -> str:
    return bin(n)[2:].zfill(64)


# Key bit index mapping (writeup's whi)

def whi(idx: int, i: int) -> int:
    # what key bit am I actually using?
    if idx % 2 == 0:  # K0 usage (key parts: bytes 0..3 and 8..11)
        if i < 32:
            return i
        else:
            return 32 + i  # 64..95
    else:  # K1 usage (key parts: bytes 4..7 and 12..15)
        if i < 32:
            return 32 + i  # 32..63
        else:
            return 64 + i  # 96..127


# Permutation application on 64-bit string bits

def apply_perm_bits(bits: str) -> str:
    ct = [None] * 64
    for i, c in enumerate(bits):
        ct[perm[i]] = c
    return ''.join(ct)


# Network I/O

def recv_pairs(host: str = '127.0.0.1', port: int = 4004, expected: int = 65536) -> Tuple[List[str], List[str]]:
    pt_bits: List[str] = []
    ct_bits: List[str] = []
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s_file = s.makefile('rb')
    try:
        count = 0
        while True:
            line = s_file.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                a, b = ast.literal_eval(line.decode('utf-8'))
            except Exception:
                # Fallback to simple parse if needed
                txt = line.decode('utf-8').strip()
                if txt.startswith('(') and txt.endswith(')'):
                    txt = txt[1:-1]
                parts = txt.split(',')
                a = int(parts[0].strip())
                b = int(parts[1].strip())
            pt_bits.append(str64(a))
            ct_bits.append(str64(b))
            count += 1
            if expected and count >= expected:
                break
    finally:
        try:
            s_file.close()
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
    return pt_bits, ct_bits


# Attack 1: Build linear equations using SBOX linear bias approx

def compute_invert_bits() -> List[int]:
    invert: List[int] = []
    for i in range(8):
        cnt_0 = cnt_1 = 0
        for j in range(256):
            if BIT(j, i) == BIT(sbox[j], i):
                cnt_0 += 1
            else:
                cnt_1 += 1
        invert.append(0 if cnt_0 > cnt_1 else 1)
    return invert


def build_arr_and_equations(pt_bits: List[str], ct_bits: List[str]) -> Tuple[List[List[int]], List[List[int]], List[List[int]], List[int]]:
    """
    Returns:
      - arr: per input bit i, list [kidx_0, kidx_1, kidx_2, kidx_3, kidx_4, add_bit, final_loc]
      - ZERO: list of variable-index lists with xor == 0
      - ONE: list of variable-index lists with xor == 1
      - invert: 8-bit list indicating SBOX bit flips in approximation
    """
    invert = compute_invert_bits()

    arr: List[List[int]] = []
    for i in range(64):
        loc = i
        add = 0
        myenc: List[int] = []
        myenc.append(whi(0, loc))  # pre-key XOR (keys[0])
        for j in range(1, 5):
            add += invert[loc % 8]  # sbox approx contribution
            # pbox
            loc = perm[loc]
            # post-round key XOR
            myenc.append(whi(j % 2, loc))
        myenc.append(add % 2)
        myenc.append(loc)
        arr.append(myenc)

    ZERO: List[List[int]] = []
    ONE: List[List[int]] = []

    n = len(pt_bits)
    # For each original bit position, decide if xor of collected key bits is 0 or 1 based on bias
    for i in range(64):
        fin = arr[i][-1]
        add_bit = arr[i][-2]
        cnt_0 = 0
        cnt_1 = 0
        for j in range(n):
            st = 1 if pt_bits[j][i] == '1' else 0
            en = 1 if ct_bits[j][fin] == '1' else 0
            # if st == (en + add_bit) % 2 then XOR of key bits is 0 else 1
            if st == ((en + add_bit) & 1):
                cnt_0 += 1
            else:
                cnt_1 += 1
        if cnt_0 >= cnt_1:
            ZERO.append(arr[i][:-2])  # equation sum == 0
        else:
            ONE.append(arr[i][:-2])   # equation sum == 1
    return arr, ZERO, ONE, invert


# Attack 2: Recover K0 byte-by-byte using stronger correlation of first round

def recover_k0(pt_bits: List[str], ct_bits: List[str], arr: List[List[int]], sample_limit: int = 8192) -> bytes:
    n = len(pt_bits)
    m = min(n, sample_limit)
    # Pre-extract ct bits for all 64 final positions for speed
    ct_cols: List[List[int]] = [[1 if ct_bits[row][col] == '1' else 0 for row in range(m)] for col in range(64)]

    # Precompute plaintext bytes per byte position to avoid repeated int conversions
    pt_bytes_by_col: List[List[int]] = []
    for byte_idx in range(8):
        col_vals = [int(pt_bits[row][8 * byte_idx: 8 * byte_idx + 8], 2) for row in range(n)]
        pt_bytes_by_col.append(col_vals)

    k0 = [0] * 8
    bitmasks = [0x80 >> b for b in range(8)]  # MSB-first masks matching BIT()
    for byte_idx in range(8):
        ideals = [0] * 256
        fin_locs = [arr[8 * byte_idx + bit_idx][-1] for bit_idx in range(8)]
        ct_cols_for_bits = [ct_cols[fl] for fl in fin_locs]
        pt_col = pt_bytes_by_col[byte_idx][:m]

        # For each guess value of the key byte
        for guess in range(256):
            # For each bit in this byte accumulate correlation counts
            cnt0 = [0] * 8
            cnt1 = [0] * 8
            for row in range(m):
                val = sbox[pt_col[row] ^ guess]
                # Compare each bit to corresponding final location bit
                for bit_idx in range(8):
                    bt = 1 if (val & bitmasks[bit_idx]) else 0
                    res = ct_cols_for_bits[bit_idx][row]
                    if bt == res:
                        cnt0[bit_idx] += 1
                    else:
                        cnt1[bit_idx] += 1
            ideals[guess] = sum(max(cnt0[i], cnt1[i]) for i in range(8))

        # choose argmax
        best_guess = max(range(256), key=lambda g: ideals[g])
        k0[byte_idx] = best_guess
        print(f"[K0] byte {byte_idx}: {best_guess:02x} (score={max(ideals)})")
    return bytes(k0)


# Build and solve linear system over GF(2)

def solve_linear_system(ZERO: List[List[int]], ONE: List[List[int]], k0: bytes) -> List[List[int]]:
    F2 = GF(2)

    equations: List[Tuple[List[int], int]] = []

    # From attack 1
    for L in ZERO:
        equations.append((L, 0))
    for L in ONE:
        equations.append((L, 1))

    # From recovered K0 (fix bits): indices for K0 are whi(0, loc) for loc in 0..63
    # We need bit value of K0 at each block bit position loc
    def k0_bit_at_loc(loc: int) -> int:
        b = k0[loc // 8]
        return BIT(b, loc % 8)

    for loc in range(64):
        idx = whi(0, loc)
        equations.append(([idx], k0_bit_at_loc(loc)))

    # Build matrix A and vector b
    A_rows: List[List[int]] = []
    b_vec: List[int] = []
    for L, rhs in equations:
        row = [0] * 128
        for v in L:
            row[v] ^= 1
        A_rows.append(row)
        b_vec.append(rhs)

    A = Matrix(F2, A_rows)
    b = vector(F2, b_vec)

    # Find one particular solution
    x0 = A.solve_right(b)

    # Nullspace basis
    N = A.right_kernel().basis()
    # Convert to python lists of ints
    base = [list(map(int, x0))]
    basis = [[int(val) for val in v] for v in N]

    # Generate all solutions: x = x0 + sum(c_i * basis[i])
    sols: List[List[int]] = []
    d = len(basis)
    if d == 0:
        sols.append(base[0])
        return sols
    # For dimensions > 16, brute-force is too big; but writeup suggests ~4 (16 solutions)
    if d > 16:
        print(f"[warn] Large solution space dimension d={d}; sampling 1 solution.")
        sols.append(base[0])
        return sols
    for mask in range(1 << d):
        x = base[0][:]
        for i in range(d):
            if (mask >> i) & 1:
                # x ^= basis[i]
                x = [(xi ^ bi) for xi, bi in zip(x, basis[i])]
        sols.append(x)
    return sols


# Convert 128-bit vector (key bit layout) into 16-byte master key

def keyvec_to_bytes(x: List[int]) -> bytes:
    # x indices 0..31 -> bytes 0..3
    # 32..63 -> bytes 4..7
    # 64..95 -> bytes 8..11
    # 96..127 -> bytes 12..15
    out = [0] * 16
    def set_bit(byte_idx: int, bit_idx: int, val: int):
        # bit_idx: 0..7 (MSB first per BIT()), so MSB at position 7 - bit_idx
        if val:
            out[byte_idx] |= (1 << (7 - bit_idx))

    # First quarter (0..31)
    for idx in range(0, 32):
        b = idx // 8
        k = idx % 8
        set_bit(b, k, x[idx])
    # Second quarter (32..63)
    for idx in range(32, 64):
        b = 4 + (idx - 32) // 8
        k = (idx - 32) % 8
        set_bit(b, k, x[idx])
    # Third quarter (64..95)
    for idx in range(64, 96):
        b = 8 + (idx - 64) // 8
        k = (idx - 64) % 8
        set_bit(b, k, x[idx])
    # Fourth quarter (96..127)
    for idx in range(96, 128):
        b = 12 + (idx - 96) // 8
        k = (idx - 96) % 8
        set_bit(b, k, x[idx])
    return bytes(out)


# Cipher implementation to verify candidate keys

def apply_key_bytes(pt: bytes, key: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(pt, key)])


def apply_sbox_bytes(pt: bytes) -> bytes:
    return bytes([sbox[b] for b in pt])


def apply_perm_bytes(pt: bytes) -> bytes:
    bits = bin(int.from_bytes(pt, 'big'))[2:].zfill(64)
    out = [None] * 64
    for i, c in enumerate(bits):
        out[perm[i]] = c
    out_bytes = bytes([int(''.join(out[i:i+8]), 2) for i in range(0, 64, 8)])
    return out_bytes


def encrypt_block(pt: bytes, master_key: bytes) -> bytes:
    # key schedule
    K0 = master_key[0:4] + master_key[8:12]
    K1 = master_key[4:8] + master_key[12:16]
    ct = apply_key_bytes(pt, K0)
    for rnd in range(ROUNDS):
        ct = apply_sbox_bytes(ct)
        ct = apply_perm_bytes(ct)
        ct = apply_key_bytes(ct, K1 if (rnd % 2 == 0) else K0)
    return ct


# Verify and select the correct key among candidates

def select_correct_key(candidates: List[List[int]], pt_bits: List[str], ct_bits: List[str]) -> bytes:
    tests = min(8, len(pt_bits))
    for x in candidates:
        key_bytes = keyvec_to_bytes(x)
        ok = True
        for i in range(tests):
            pt_int = int(pt_bits[i], 2)
            ct_int = int(ct_bits[i], 2)
            pt_b = pt_int.to_bytes(8, 'big')
            ct_b = ct_int.to_bytes(8, 'big')
            enc = encrypt_block(pt_b, key_bytes)
            if enc != ct_b:
                ok = False
                break
        if ok:
            return key_bytes
    raise RuntimeError("No candidate key matched the provided pairs.")


def main():
    # Host/port from args or defaults
    host = '127.0.0.1'
    port = 4004
    sample_limit = 8192  # for K0 correlation speed; can be tuned
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])
    if len(sys.argv) >= 4:
        sample_limit = int(sys.argv[3])

    print(f"[*] Connecting to {host}:{port} and receiving pairs…")
    pt_bits, ct_bits = recv_pairs(host, port, expected=65536)
    print(f"[*] Received {len(pt_bits)} pairs")

    print("[*] Building linear equations (attack 1)…")
    arr, ZERO, ONE, invert = build_arr_and_equations(pt_bits, ct_bits)
    print(f"[*] Built equations: ZERO={len(ZERO)} ONE={len(ONE)}")

    print("[*] Recovering K0 by correlation (attack 2)…")
    print(f"[*] Using up to {sample_limit} samples for K0 correlation…")
    k0 = recover_k0(pt_bits, ct_bits, arr, sample_limit=sample_limit)
    print(f"[*] K0 = {k0.hex()}")

    print("[*] Solving linear system over GF(2)…")
    candidates = solve_linear_system(ZERO, ONE, k0)
    print(f"[*] Candidate solutions: {len(candidates)}")

    print("[*] Verifying candidates against samples…")
    master_key = select_correct_key(candidates, pt_bits, ct_bits)

    # Print the flag
    print("[+] Recovered flag (master key):")
    print("flag{" + master_key.decode('utf-8') + "}")


if __name__ == '__main__':
    main()
