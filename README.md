# v9x-firmware-repacker
Fully documented reverse-engineered repacker for Hichip/GK7205/GK7202 V9X firmware (.pkg) files, including AES encryption, PK header poisoning, salted MD5 logic, and custom upgrade.zip support.

This project documents the **V9X firmware `.pkg` format** used in many XM / Hichip / GK7205 IP cameras and provides a Python tool that can rebuild a `.pkg` using a **custom `upgrade.zip`** and/or **custom `kernel.img`**.

Used camera: HQCAM HQ-M21 - Goke GK7205 HiChip. 

<img width="450" height="450" alt="image" src="https://github.com/user-attachments/assets/d76439e7-9e80-4655-9e13-226dd5865804" />

<img width="700" height="681" alt="image" src="https://github.com/user-attachments/assets/4681cbb5-63a7-46d5-b85c-107ec336a54c" />

<img width="789" height="836" alt="image" src="https://github.com/user-attachments/assets/df590a74-045d-48d8-baae-8e7a01620467" />


---

# Repository Contents

- `v9x_pkg_repacker.py` — fully working repacker
- This README (format documentation)
- Example `upgrade.zip`
- Example repacked `.pkg`

---

# Original Firmware
Found original firmware at http://hipcam.org/goke_update.html

Each entry here can be found at http://hipcam.org/update/version.exe. The file should be renamed to .pkg (It's just stored as exe on the server, but it's really a pkg file)

Example: http://hipcam.org/update/V32.1.21.0.3-20250114.exe -> Rename to V32.1.21.0.3-20250114.pkg

# 1. PKG File Structure

A V9X `.pkg` consists of three parts:

```markdown
+----------------------+ 0x00000000
| 512-byte header     |  (0x200 bytes)
+----------------------+
| kernel.img          |
+----------------------+
| encrypted upgrade.zip|
+----------------------+ EOF
```

### Header fields
The header stores:
- Multiple file-length fields for both `kernel.img` and `upgrade.zip`
- ASCII salted MD5 strings for each file  
  - Kernel MD5 at offset **0x98**
  - Zip MD5 at offset **0x110**
- Some unused / unknown fields

---

# 2. Firmware Update Verification Process

When flashing, the camera performs this exact process:

### Step-by-step
1. Read header  
2. Extract `kernel.img` (plain)
3. Extract `upgrade.zip` (encrypted)
4. **Decrypt `upgrade.zip`:**
  P = AES_decrypt(C) ^ 0x3F
5. **Fix PK headers** inside the decrypted zip  
6. Compute salted MD5:
  MD5( kernel_img || "IPCAM" )
  MD5( upgrade_zip || "IPCAM" )
7. Compare against header  
8. Only if both match → update proceeds

---

# 3. AES Encryption Details

### AES mode
- **AES-128 ECB**

### Keys  
The firmware uses **three AES keys**, discovered inside the update binary:

```markdown
@Hichip+1208/pkg
$Hichip-1208%aes
#Hichip*1208=key
```

### Rotation pattern  
Applies only to **one block every 0x400 bytes**.

| Chunk # | Action | AES Key |
|--------:|--------|---------|
| 0–14    | no encryption | — |
| 15      | encrypt | key0 |
| 16–30   | no encryption | — |
| 31      | encrypt | key1 |
| 32–46   | no encryption | — |
| 47      | encrypt | key2 |
| 48–62   | no encryption | — |
| 63      | encrypt | key0 |
| …       | repeats | cycle |

### Per-block transformation
The camera decrypts using:
P = AES_decrypt(C) ^ 0x3F

So we must **invert** it:
C = AES_encrypt(P ^ 0x3F)

---

# 4. Poisoned PK Headers

The firmware does *not* store correct ZIP headers in the package.  
Instead, the vendor scrambles them so the camera “restores” them later.

| Real ZIP header | Stored in pkg |
|-----------------|----------------|
| `PK 03 04` | `PK 03 07` |
| `PK 01 02` | `PK 01 08` |
| `PK 05 06` | `PK 05 09` |

This mapping must be applied **before AES encryption**.

---

# 5. Salted MD5

The firmware calculates MD5 hashes as:

MD5( file_bytes || "IPCAM" )

Python equivalent:

```python
from hashlib import md5

def salted_md5_hex(data: bytes) -> str:
    h = md5()
    h.update(data)
    h.update(b"IPCAM")
    return h.hexdigest()
```

These hashes are stored as ASCII hex in the header:
Kernel MD5 at offset 0x98
Zip MD5 at offset 0x110

# 6. Correct Repack Pipeline
To rebuild a valid .pkg, you must perform:

```markdown
plain_zip
    ↓ poison PK headers
poisoned_zip
    ↓ AES encrypt specific blocks
encrypted_zip
    ↓ insert into pkg after kernel.img
.pkg
```

Finally:

Update file-length fields

Write salted MD5 values into header

# 7. Full Python Repacker Script (Python 3.9)

Usage: python v9x_pkg_repacker.py --orig-pkg V32.1.21.0.3-20250114.pkg --kernel kernel.img --zip upgrade.zip --out V32.1.21.0.3-20250114_Custom.pkg

``` python
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

```

# 8. Legal Notice
This project is provided solely for educational use, device repair and interoperability.

It does NOT contain vendor firmware.
It must NOT be used to redistribute copyrighted binaries.

# MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      
copies of the Software, and to permit persons to whom the Software is         
furnished to do so, subject to the following conditions:                      

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.                               

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
SOFTWARE.
