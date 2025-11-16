#!/usr/bin/env python3
import argparse
from pathlib import Path
from hashlib import md5

from Crypto.Cipher import AES  # pip install pycryptodome

HEADER_SIZE = 0x200
SECRET_SALT = b"IPCAM"

# Original lengths from the stock header (for search/replace)
ORIG_KERNEL_LEN = 0x1BB5B8
ORIG_ZIP_LEN    = 0x4A9D8D

# Offsets of ASCII MD5 hex strings in the header
KERNEL_MD5_OFFSET = 0x98
ZIP_MD5_OFFSET    = 0x110
MD5_HEX_LEN       = 32

CHUNK_SIZE = 0x400

# The three V9X AES-128 keys from the firmware
KEYS = [
    b"@Hichip+1208/pkg",
    b"$Hichip-1208%aes",
    b"#Hichip*1208=key",
]


def salted_md5_hex(data: bytes) -> str:
    """
    Firmware's salted MD5: MD5(file_bytes || "IPCAM"), returned as hex string.
    """
    h = md5()
    h.update(data)
    h.update(SECRET_SALT)
    return h.hexdigest()


def patch_all_int32_le(buf: bytearray, old_val: int, new_val: int) -> int:
    """
    Replace all little-endian 32-bit occurrences of old_val with new_val.
    Returns the number of patches applied.
    """
    old_bytes = old_val.to_bytes(4, "little")
    new_bytes = new_val.to_bytes(4, "little")

    count = 0
    i = 0
    end = len(buf) - 3
    while i <= end:
        if buf[i:i+4] == old_bytes:
            buf[i:i+4] = new_bytes
            count += 1
            i += 4
        else:
            i += 1
    return count


def v9x_encrypt_zip_for_pkg(plain_zip: bytes) -> bytes:
    """
    Exact inverse of the camera's update path for the zip section,
    ignoring the "PK 03 07" / "PK 01 08" / "PK 05 09" header fiddling.

    Decode on the camera does:
        - for every 16th 0x400-byte chunk:
              P = AES_decrypt(C) ^ 0x3F
          other chunks are copied as-is
        - then it optionally fixes 'PK 03 07' -> 'PK 03 04', etc.

    We want the final upgrade.zip on tmpfs to be exactly 'plain_zip',
    so we simply choose the pre-fix bytes X == plain_zip and solve:

        X = AES_decrypt(C) ^ 0x3F    =>    C = AES_encrypt(X ^ 0x3F)

    for the encrypted chunks. Non-encrypted chunks are left as X.
    """
    out = bytearray()
    total_len = len(plain_zip)
    offset = 0

    iVar11 = 0x0F      # matches firmware initial state
    key_index = 0      # which of the three keys to use

    while offset < total_len:
        chunk = bytearray(plain_zip[offset: offset + CHUNK_SIZE])
        s = len(chunk)
        if s == 0:
            break

        if iVar11 == 0x10:
            # This chunk gets AES-ECB treatment with the next key.
            key = KEYS[key_index]
            key_index = (key_index + 1) % len(KEYS)

            cipher = AES.new(key, AES.MODE_ECB)

            full_blocks = s // 16
            for b_idx in range(full_blocks):
                start = b_idx * 16
                end = start + 16
                P_block = bytes(chunk[start:end])

                # Camera does: P = AES_decrypt(C) ^ 0x3F
                # We invert that: C = AES_encrypt(P ^ 0x3F)
                tmp = bytes([x ^ 0x3F for x in P_block])
                C_block = cipher.encrypt(tmp)

                chunk[start:end] = C_block

            iVar11 = 1
        else:
            # This chunk is copied as-is by the firmware
            iVar11 += 1

        out += chunk
        offset += s

    return bytes(out)


def main():
    ap = argparse.ArgumentParser(
        description="Repack V9X .pkg with custom kernel.img + upgrade.zip and correct salted MD5s."
    )
    ap.add_argument("--orig-pkg", required=True, help="Original V9X .pkg from vendor")
    ap.add_argument("--kernel",   required=True, help="kernel.img to embed (plain file)")
    ap.add_argument("--zip",      required=True, help="upgrade.zip to embed (plain zip as camera should see it)")
    ap.add_argument("--out",      required=True, help="Output .pkg path")
    args = ap.parse_args()

    orig_pkg_path = Path(args.orig_pkg)
    kernel_path   = Path(args.kernel)
    zip_path      = Path(args.zip)
    out_path      = Path(args.out)

    orig_pkg = orig_pkg_path.read_bytes()
    if len(orig_pkg) < HEADER_SIZE:
        raise SystemExit("Error: original pkg is smaller than 0x200 bytes")

    header = bytearray(orig_pkg[:HEADER_SIZE])

    # Plain files: exactly what verify_zip_wrapper() hashes on the camera.
    new_kernel = kernel_path.read_bytes()
    plain_zip  = zip_path.read_bytes()

    # Encode the plain zip into the pkg format the camera expects
    pkg_zip = v9x_encrypt_zip_for_pkg(plain_zip)

    new_k_len = len(new_kernel)
    new_z_len = len(pkg_zip)

    print(f"[INFO] New kernel size:  0x{new_k_len:08X} ({new_k_len} bytes)")
    print(f"[INFO] New upgrade size: 0x{new_z_len:08X} ({new_z_len} bytes)")

    # Patch length fields in header
    k_patched = patch_all_int32_le(header, ORIG_KERNEL_LEN, new_k_len)
    z_patched = patch_all_int32_le(header, ORIG_ZIP_LEN,    new_z_len)
    print(f"[INFO] Patched kernel length fields:      {k_patched}")
    print(f"[INFO] Patched upgrade.zip length fields: {z_patched}")

    if k_patched == 0:
        print("[WARN] Did not find original kernel length in header.")
    if z_patched == 0:
        print("[WARN] Did not find original zip length in header.")

    # MD5 over the REAL files (the ones on tmpfs after decrypt + header-fix)
    kernel_md5 = salted_md5_hex(new_kernel)
    zip_md5    = salted_md5_hex(plain_zip)

    print(f"[INFO] New salted MD5 (kernel.img):  {kernel_md5}")
    print(f"[INFO] New salted MD5 (upgrade.zip): {zip_md5}")

    header[KERNEL_MD5_OFFSET:KERNEL_MD5_OFFSET+MD5_HEX_LEN] = kernel_md5.encode("ascii")
    header[ZIP_MD5_OFFSET:ZIP_MD5_OFFSET+MD5_HEX_LEN]       = zip_md5.encode("ascii")

    # Build new pkg: header + kernel + encrypted zip
    new_pkg = bytearray()
    new_pkg += header
    new_pkg += new_kernel
    new_pkg += pkg_zip

    out_path.write_bytes(new_pkg)
    print(f"[OK] Wrote repacked pkg to: {out_path}")


if __name__ == "__main__":
    main()
