#!/usr/bin/env python3
"""Inspect the pinned service's public RSA parameters or create an offline copy.

Only public-key data and the PE checksum may change. Verification code remains
intact. A modified copy loses the vendor Authenticode signature's validity and is
not installed or executed by this tool. Original EXE files are never distributed.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path

import pefile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SERVICE_HASH = "546efad9ab3ff85c2a50d61524d754bec94a3f3e30d6ae8addef481a1e8daa1e"
KEY_RVA = 0x11F948
KEY_SIZE = 212


def inspect(data):
    if hashlib.sha256(data).hexdigest() != SERVICE_HASH:
        raise ValueError("unsupported original RvControlSvc.exe SHA-256")
    pe = pefile.PE(data=data)
    offset = pe.get_offset_from_rva(KEY_RVA)
    blob = data[offset : offset + KEY_SIZE]
    position, fields = 0, []
    for expected in (0x0A000257, 0x0A000258):
        length, tag = struct.unpack_from(">II", blob, position)
        if tag != expected or length > len(blob) - position - 8:
            raise ValueError("unexpected embedded public-key field")
        fields.append(blob[position + 8 : position + 8 + length])
        position += 8 + length
    if position != KEY_SIZE or len(fields[0]) != 193 or len(fields[1]) != 3:
        raise ValueError("unexpected embedded RSA layout")
    n, e = (int.from_bytes(value, "big") for value in fields)
    if n.bit_length() != 1536 or e != 65537:
        raise ValueError("unexpected embedded RSA parameters")
    public = rsa.RSAPublicNumbers(e, n).public_key()
    return pe, offset, public


def fingerprint(public):
    der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def build_copy(data, public):
    pe, offset, _ = inspect(data)
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 1536:
        raise ValueError("a 1536-bit RSA public key is required for this exact layout")
    numbers = public.public_numbers()
    if numbers.e != 65537:
        raise ValueError("RSA exponent 65537 is required")
    modulus = b"\0" + numbers.n.to_bytes(192, "big")
    blob = (
        struct.pack(">II", 193, 0x0A000257)
        + modulus
        + struct.pack(">II", 3, 0x0A000258)
        + b"\x01\x00\x01"
    )
    result = bytearray(data)
    result[offset : offset + KEY_SIZE] = blob
    checksum_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
    checksum = pefile.PE(data=bytes(result)).generate_checksum()
    struct.pack_into("<I", result, checksum_offset, checksum)
    # Byte-level guard against changes outside the public-key data and checksum.
    old, new = bytearray(data), bytearray(result)
    for start, size in ((offset, KEY_SIZE), (checksum_offset, 4)):
        old[start : start + size] = new[start : start + size] = bytes(size)
    if old != new or len(result) != len(data):
        raise ValueError("unexpected binary change")
    return bytes(result), checksum_offset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--exe",
        type=Path,
        required=True,
        help="original user-supplied RvControlSvc.exe",
    )
    parser.add_argument("--replacement-public-key", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        help="NEW offline EXE copy; never an installed service path",
    )
    parser.add_argument("--report", type=Path, required=True, help="NEW JSON report")
    args = parser.parse_args()
    if bool(args.replacement_public_key) != bool(args.output):
        parser.error("--replacement-public-key and --output must be supplied together")
    if args.report.exists() or (args.output and args.output.exists()):
        parser.error("output files already exist; choose new paths")
    data = args.exe.read_bytes()
    pe, offset, public = inspect(data)
    report = {
        "original_sha256": SERVICE_HASH,
        "rsa_bits": 1536,
        "exponent": 65537,
        "public_key_spki_sha256": fingerprint(public),
        "key_rva": hex(KEY_RVA),
        "key_file_offset": offset,
        "key_blob_bytes": KEY_SIZE,
        "modified": False,
    }
    if args.output:
        replacement = serialization.load_pem_public_key(
            args.replacement_public_key.read_bytes()
        )
        result, checksum_offset = build_copy(data, replacement)
        with args.output.open("xb") as target:
            target.write(result)
        report.update(
            {
                "modified": True,
                "output_sha256": hashlib.sha256(result).hexdigest(),
                "replacement_public_key_spki_sha256": fingerprint(replacement),
                "checksum_file_offset": checksum_offset,
                "verification_code_modified": False,
                "vendor_authenticode_valid_after_change": False,
                "installed": False,
                "executed": False,
            }
        )
    with args.report.open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2)
        target.write("\n")
    print(
        "Saved public-key analysis; offline copy created"
        if args.output
        else "Saved public-key analysis"
    )


if __name__ == "__main__":
    main()
