#!/usr/bin/env python3
"""
ELE304 Lab 5 post-build tool (replacement for the missing
ELE304_postbuild_cm7_and_cm4_fw_auth.bat).

Builds   out_app_meta.bin = [0x400-byte metadata header] + [CM7 app binary]
Flash:   out_app_meta.bin  -> 0x08020000   (header 0x08020000..0x080203FF,
                                            CM7 app starts at 0x08020400)
         CM4 app .bin      -> 0x08100000   (unchanged)
         bootloader .bin   -> 0x08000000   (unchanged)

Header layout (all integers little-endian, offsets in bytes):
  0x00  u32  magic      = 0x46574D41 ("FWMA")
  0x04  u32  cm7_size   (bytes of CM7 app binary)
  0x08  u32  cm4_size   (bytes of CM4 app binary)
  0x0C  u32  version
  0x10  32B  cm7_tag    = SHA-256(CM7 app binary)
  0x30  32B  cm4_tag    = SHA-256(CM4 app binary)
  0x50  48B  reserved   = 0x00
        ---- bytes 0x00..0x7F (128 B) are the "signed block" ----
  0x80  32B  meta_tag   = SHA-256(signed block)
  0xA0  64B  meta_sig   = raw ECDSA r||s (32B each, big-endian) over meta_tag
  0xE0  ...  0x00 stuffing up to 0x400

Curve: P-256 (openssl name prime256v1 == secp256r1).
Usage:
  python ele304_postbuild.py --cm7 app_cm7.bin --cm4 app_cm4.bin \
         --key ecc.key --version 1 [--out OUTDIR] [--check-header ecc_pub_key.h]
"""
import argparse
import hashlib
import os
import re
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)

MAGIC = 0x46574D41
HEADER_SIZE = 0x400
SIGNED_BLOCK_SIZE = 128
CM7_FLASH_START = 0x08020400
CM7_FLASH_END = 0x08100000          # CM4 image starts here
CM4_FLASH_START = 0x08100000
CM4_FLASH_END = 0x08200000          # end of 2 MB flash


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def load_key(path):
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        sys.exit("ERROR: key is not an EC key")
    if key.curve.name != "secp256r1":
        sys.exit("ERROR: key curve is %s, expected secp256r1 (prime256v1). "
                 "Bootloader constant is CMOX_ECC_SECP256R1_LOWMEM." % key.curve.name)
    return key


def pubkey_raw64(key):
    nums = key.public_key().public_numbers()
    return nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")


def header_array_bytes(path):
    with open(path, "r", errors="replace") as f:
        txt = f.read()
    body = txt.split("{", 1)[1].split("}", 1)[0]
    return bytes(int(h, 16) for h in re.findall(r"0x([0-9a-fA-F]{2})", body))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cm7", required=True, help="CM7 application .bin (linked at 0x08020400)")
    ap.add_argument("--cm4", required=True, help="CM4 application .bin (linked at 0x08100000)")
    ap.add_argument("--key", required=True, help="ECC private key PEM (prime256v1)")
    ap.add_argument("--version", type=int, default=1)
    ap.add_argument("--out", default=None, help="output folder (default: folder of CM7 bin)")
    ap.add_argument("--check-header", default=None,
                    help="path to ecc_pub_key.h; compare its bytes with the key's public key")
    a = ap.parse_args()

    cm7 = open(a.cm7, "rb").read()
    cm4 = open(a.cm4, "rb").read()
    if not cm7 or not cm4:
        sys.exit("ERROR: empty binary")
    if CM7_FLASH_START + len(cm7) > CM7_FLASH_END:
        sys.exit("ERROR: CM7 binary too large (%d bytes, max %d)"
                 % (len(cm7), CM7_FLASH_END - CM7_FLASH_START))
    if CM4_FLASH_START + len(cm4) > CM4_FLASH_END:
        sys.exit("ERROR: CM4 binary too large")

    key = load_key(a.key)
    raw_pub = pubkey_raw64(key)

    # --- signed block (128 bytes) ---
    block = struct.pack("<IIII", MAGIC, len(cm7), len(cm4), a.version)
    block += sha256(cm7) + sha256(cm4)
    block += b"\x00" * (SIGNED_BLOCK_SIZE - len(block))
    assert len(block) == SIGNED_BLOCK_SIZE

    meta_tag = sha256(block)

    # ECDSA over SHA-256(block); cmox_ecdsa_verify gets meta_tag as the digest.
    der = key.sign(block, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")   # always exactly 64 bytes

    # self-check: verify raw signature again with the public key
    key.public_key().verify(encode_dss_signature(r, s), block, ec.ECDSA(hashes.SHA256()))

    header = block + meta_tag + sig
    header += b"\x00" * (HEADER_SIZE - len(header))
    assert len(header) == HEADER_SIZE

    outdir = a.out or os.path.dirname(os.path.abspath(a.cm7))
    os.makedirs(outdir, exist_ok=True)
    out_path = os.path.join(outdir, "out_app_meta.bin")
    with open(out_path, "wb") as f:
        f.write(header + cm7)

    print("CM7 : %6d bytes  SHA256 %s" % (len(cm7), sha256(cm7).hex()))
    print("CM4 : %6d bytes  SHA256 %s" % (len(cm4), sha256(cm4).hex()))
    print("meta block SHA256 (meta_tag) %s" % meta_tag.hex())
    print("signature r||s (64 B)        %s" % sig.hex())
    print("version %d" % a.version)
    print("public key X||Y (64 B)       %s" % raw_pub.hex())
    print("wrote %s  (%d bytes)" % (out_path, HEADER_SIZE + len(cm7)))
    print("flash: out_app_meta.bin @0x08020000, CM4 .bin @0x08100000, bootloader @0x08000000")

    if a.check_header:
        hb = header_array_bytes(a.check_header)
        if hb == raw_pub:
            print("CHECK OK: %s holds the public key matching %s" % (a.check_header, a.key))
        else:
            print("CHECK FAILED: %s has %d bytes and does NOT match the key's public key"
                  % (a.check_header, len(hb)))
            sys.exit(2)


if __name__ == "__main__":
    main()
