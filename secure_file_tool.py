# secure_file_tool.py
# pip install cryptography tqdm

import os
import sys
import secrets
import struct
import hmac
import hashlib
import base64
from pathlib import Path
from typing import Optional
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# ── Constants ─────────────────────────────────────────────────────────────────
KEY_SIZE       = 32
NONCE_SIZE     = 12
SALT_SIZE      = 32
SCRYPT_N       = 2 ** 20
SCRYPT_R       = 8
SCRYPT_P       = 2
PASSES         = 3
IV_TWEAK_SIZE  = 16
MRB_MAGIC      = b"MRB\x02"
ENCRYPTED_EXT  = ".MRB"

# Two disjoint special-char sets used to replace base64's '+' and '/'
# so the encoded key always contains uppercase, lowercase, digits, and specials.
# Allowed specials: @ # $ ! & { } [ ] |
_PLUS_CHARS  = "@#$!&"    # replaces '+'  (5 chars, cycles)
_SLASH_CHARS = "{}[]|"    # replaces '/'  (5 chars, cycles)
# The two sets are disjoint → decoding is always unambiguous.

# ── Key Encoding ──────────────────────────────────────────────────────────────

def _encode_key(raw: bytes) -> str:
    b64 = base64.b64encode(raw).decode("ascii")
    out, pi, si = [], 0, 0
    for ch in b64:
        if ch == "+":
            out.append(_PLUS_CHARS[pi % len(_PLUS_CHARS)]); pi += 1
        elif ch == "/":
            out.append(_SLASH_CHARS[si % len(_SLASH_CHARS)]); si += 1
        else:
            out.append(ch)
    return "".join(out)


def _decode_key(encoded: str) -> bytes:
    out, pi, si = [], 0, 0
    for ch in encoded:
        if ch in _PLUS_CHARS:
            if ch != _PLUS_CHARS[pi % len(_PLUS_CHARS)]:
                raise ValueError("Key encoding mismatch (+ channel).")
            out.append("+"); pi += 1
        elif ch in _SLASH_CHARS:
            if ch != _SLASH_CHARS[si % len(_SLASH_CHARS)]:
                raise ValueError("Key encoding mismatch (/ channel).")
            out.append("/"); si += 1
        else:
            out.append(ch)
    return base64.b64decode("".join(out))

# ── Helpers ───────────────────────────────────

def _cwd() -> Path:
    return Path.cwd()


def _resolve_dir(path_str: str) -> Path:
    """Return Path for given string, or cwd if blank."""
    p = Path(path_str.strip()) if path_str.strip() else _cwd()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _safe_path(directory: Path, filename: str) -> Path:
    stem, suffix = Path(filename).stem, Path(filename).suffix
    dst = directory / filename
    i = 1
    while dst.exists():
        dst = directory / f"{stem}_{i}{suffix}"; i += 1
    return dst


def _derive_keys(master: bytes, salt: bytes) -> list[bytes]:
    base = Scrypt(salt=salt, length=KEY_SIZE, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(master)
    keys = []
    for i in range(PASSES):
        s = hashlib.sha3_256(salt + i.to_bytes(4, "big")).digest()
        keys.append(HKDF(hashes.SHA3_256(), KEY_SIZE, s, f"MRB-layer-{i}-v2".encode()).derive(base))
    return keys


def _hmac_key(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha3_256).digest()


def _collect(path: str) -> list[Path]:
    p = Path(path)
    if p.is_file():  return [p]
    if p.is_dir():   return [f for f in p.rglob("*") if f.is_file()]
    raise FileNotFoundError(f"Not found: {path}")

# ── Core Crypto ───────────────────────────────────────────────────────────────

def _encrypt_bytes(plain: bytes, keys: list, nonces: list, aad: bytes) -> bytes:
    data = plain
    for i in range(PASSES):
        tweak = hashlib.sha3_256(keys[i] + nonces[i] + i.to_bytes(4, "big")).digest()[:IV_TWEAK_SIZE]
        xored = bytes(b ^ t for b, t in zip(data[:IV_TWEAK_SIZE], tweak)) + data[IV_TWEAK_SIZE:]
        data  = AESGCM(keys[i]).encrypt(nonces[i], xored, aad)
    return data


def _decrypt_bytes(cipher: bytes, keys: list, nonces: list, aad: bytes) -> bytes:
    data = cipher
    for i in reversed(range(PASSES)):
        try:
            dec = AESGCM(keys[i]).decrypt(nonces[i], data, aad)
        except InvalidTag:
            raise ValueError(f"Auth failed at layer {i}. Wrong key or corrupted file.")
        tweak = hashlib.sha3_256(keys[i] + nonces[i] + i.to_bytes(4, "big")).digest()[:IV_TWEAK_SIZE]
        data  = bytes(b ^ t for b, t in zip(dec[:IV_TWEAK_SIZE], tweak)) + dec[IV_TWEAK_SIZE:]
    return data

# ── Key Management ────────────────────────────────────────────────────────────

def create_key(output_dir: str, key_name: Optional[str] = None) -> str:
    out_dir = _resolve_dir(output_dir)
    raw     = secrets.token_bytes(KEY_SIZE)
    mac     = hmac.new(raw, raw, hashlib.sha3_256).digest()
    content = _encode_key(raw) + ":" + mac.hex()

    name = (key_name.strip() if key_name else "") or secrets.token_hex(8)
    if not name.endswith(".key"):
        name += ".key"

    dst = _safe_path(out_dir, name)
    dst.write_text(content, encoding="utf-8")
    if os.name != "nt":
        os.chmod(dst, 0o600)

    print(f"[+] Key created : {dst}")
    return str(dst)


def load_key(key_path: str) -> bytes:
    p = Path(key_path.strip())
    if not p.is_file():
        raise FileNotFoundError(f"Key file not found: {key_path}")
    if p.suffix.lower() != ".key":
        raise ValueError("Key file must have .key extension.")

    parts = p.read_text(encoding="utf-8").strip().split(":")
    if len(parts) != 2:
        raise ValueError("Malformed key file.")

    raw        = _decode_key(parts[0])
    stored_mac = bytes.fromhex(parts[1])

    if len(raw) != KEY_SIZE:
        raise ValueError(f"Wrong key size: {len(raw)} bytes.")
    if not hmac.compare_digest(stored_mac, hmac.new(raw, raw, hashlib.sha3_256).digest()):
        raise ValueError("Key integrity check FAILED — file corrupted or tampered.")

    print(f"[+] Key loaded  : {p}")
    return raw

# ── Encrypt / Decrypt Single File ─────────────────────────────────────────────

def encrypt_file(file_path: str, key: bytes, output_dir: str = "") -> str:
    src     = Path(file_path)
    out_dir = _resolve_dir(output_dir) if output_dir else src.parent

    salt   = secrets.token_bytes(SALT_SIZE)
    nonces = [secrets.token_bytes(NONCE_SIZE) for _ in range(PASSES)]
    keys   = _derive_keys(key, salt)

    fname = src.name.encode("utf-8")
    aad   = MRB_MAGIC + fname

    cipher = _encrypt_bytes(src.read_bytes(), keys, nonces, aad)

    header = (
        MRB_MAGIC
        + salt
        + b"".join(nonces)
        + struct.pack(">H", len(fname))
        + fname
        + cipher
    )
    hmac_k    = HKDF(hashes.SHA3_256(), KEY_SIZE, salt, b"MRB-hmac-v2").derive(keys[0])
    outer_mac = _hmac_key(hmac_k, header)

    dst = _safe_path(out_dir, src.stem + ENCRYPTED_EXT)
    dst.write_bytes(header + outer_mac)
    print(f"  [+] {src.name}  →  {dst.name}")
    return str(dst)


def decrypt_file(file_path: str, key: bytes, output_dir: str = "") -> str:
    src = Path(file_path)
    if src.suffix.upper() != ENCRYPTED_EXT:
        raise ValueError(f"Not a {ENCRYPTED_EXT} file: {src.name}")

    data   = src.read_bytes()
    offset = 0

    if data[offset:offset+4] != MRB_MAGIC:
        raise ValueError("Invalid magic header.")
    offset += 4

    salt   = data[offset:offset+SALT_SIZE]; offset += SALT_SIZE
    nonces = [data[offset+i*NONCE_SIZE : offset+(i+1)*NONCE_SIZE] for i in range(PASSES)]
    offset += PASSES * NONCE_SIZE

    fname_len = struct.unpack(">H", data[offset:offset+2])[0]; offset += 2
    fname     = data[offset:offset+fname_len];                  offset += fname_len
    orig_name = fname.decode("utf-8")

    cipher     = data[offset:-32]
    stored_mac = data[-32:]

    keys   = _derive_keys(key, salt)
    hmac_k = HKDF(hashes.SHA3_256(), KEY_SIZE, salt, b"MRB-hmac-v2").derive(keys[0])
    if not hmac.compare_digest(stored_mac, _hmac_key(hmac_k, data[:-32])):
        raise ValueError("Outer HMAC failed — file corrupted or tampered.")

    plain   = _decrypt_bytes(cipher, keys, nonces, MRB_MAGIC + fname)
    out_dir = _resolve_dir(output_dir) if output_dir else src.parent
    dst     = _safe_path(out_dir, orig_name)
    dst.write_bytes(plain)
    print(f"  [+] {src.name}  →  {dst.name}")
    return str(dst)

# ── Batch Operations ──────────────────────────────────────────────────────────

def encrypt_path(path: str, key: bytes, output_dir: str = ""):
    files = [f for f in _collect(path) if f.suffix.upper() != ENCRYPTED_EXT]
    if not files:
        print("[-] No files to encrypt."); return

    base = Path(path) if Path(path).is_dir() else None
    print(f"[*] Encrypting {len(files)} file(s)...")
    failed = []
    for f in tqdm(files, unit="file", desc="Encrypting", colour="green"):
        try:
            out = ""
            if base and output_dir:
                out = str(Path(output_dir) / f.parent.relative_to(base))
            elif output_dir:
                out = output_dir
            encrypt_file(str(f), key, out)
        except Exception as e:
            failed.append((f, e))
    _report_failures(failed)


def decrypt_path(path: str, key: bytes, output_dir: str = ""):
    files = [f for f in _collect(path) if f.suffix.upper() == ENCRYPTED_EXT]
    if not files:
        print("[-] No .MRB files found."); return

    base = Path(path) if Path(path).is_dir() else None
    print(f"[*] Decrypting {len(files)} file(s)...")
    failed = []
    for f in tqdm(files, unit="file", desc="Decrypting", colour="cyan"):
        try:
            out = ""
            if base and output_dir:
                out = str(Path(output_dir) / f.parent.relative_to(base))
            elif output_dir:
                out = output_dir
            decrypt_file(str(f), key, out)
        except Exception as e:
            failed.append((f, e))
    _report_failures(failed)


def _report_failures(failed: list):
    if failed:
        print(f"\n[-] {len(failed)} failure(s):")
        for f, e in failed:
            print(f"    {f.name}: {e}")

# ── CLI ───────────────────────────────────────

def _banner():
    print("""
╔══════════════════════════════════════════╗
║       MRB Secure File Tool  v2.1         ║
║  Triple-Layer AES-256-GCM · Scrypt KDF   ║
╚══════════════════════════════════════════╝""")


def _prompt_dir(label: str) -> str:
    raw = input(f"  {label} [Enter = current dir]: ").strip()
    return raw  # empty string → caller uses cwd


def main():
    _banner()
    active_key: Optional[bytes] = None

    while True:
        status = f"LOADED ({KEY_SIZE*8}-bit)" if active_key else "NOT LOADED"
        print(f"""
  1. Create Key
  2. Load Key
  3. Encrypt  (file or directory)
  4. Decrypt  (file or directory)
  0. Exit
  Key: {status}""")

        choice = input("  Select: ").strip()

        if choice == "1":
            out_dir  = _prompt_dir("Output directory for key")
            key_name = input("  Key name (Enter = random): ").strip()
            try:
                create_key(out_dir, key_name or None)
            except Exception as e:
                print(f"  [-] {e}")

        elif choice == "2":
            raw = input("  Path to .key file: ").strip()
            # If user gives just a filename, look in cwd
            p = Path(raw) if raw else Path()
            if not p.is_absolute() and not p.exists():
                p = _cwd() / p
            try:
                active_key = load_key(str(p))
            except Exception as e:
                print(f"  [-] {e}")

        elif choice == "3":
            if not active_key:
                print("  [-] Load a key first (option 2)."); continue
            path    = input("  File or directory to encrypt: ").strip()
            out_dir = _prompt_dir("Output directory")
            try:
                encrypt_path(path, active_key, out_dir)
            except Exception as e:
                print(f"  [-] {e}")

        elif choice == "4":
            if not active_key:
                print("  [-] Load a key first (option 2)."); continue
            path    = input("  File or directory to decrypt: ").strip()
            out_dir = _prompt_dir("Output directory")
            try:
                decrypt_path(path, active_key, out_dir)
            except Exception as e:
                print(f"  [-] {e}")

        elif choice == "0":
            print("  Goodbye."); sys.exit(0)

        else:
            print("  [-] Invalid option.")


if __name__ == "__main__":
    main()
