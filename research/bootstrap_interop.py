#!/usr/bin/env python3
"""Test own-key RSA bootstrap, native CChannel and native SRP against the Go lab.

Requires a public key matching the operator's lab server private key. No real
server key material or user credentials are collected or stored.
"""

import argparse
import struct
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import rsa
from native_interop import Native, exact, write_new
from channel_interop import encrypted_srp


def bootstrap(native, connection, public):
    r = native.runtime

    def integer(value):
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return [r.data(data), len(data)]

    handle = r.call(
        "SHelper_RSession_CreateClient",
        3,
        42,
        7,
        *integer(public.n),
        *integer(public.e)
    )
    if not handle:
        raise RuntimeError("native RSession client creation failed")
    try:
        connection.sendall(struct.pack(">I", 4) + struct.pack("<I", 3))
        incoming = b""
        for turn in range(2):
            out = r.data(b"\0" * 12)
            ok = r.call(
                "SHelper_RSession_GetNextBuffer",
                handle,
                r.data(incoming) if incoming else 0,
                len(incoming),
                out,
                out + 4,
                out + 8,
            )
            ptr, size, done = r.read32(out), r.read32(out + 4), r.read32(out + 8)
            if (
                not ok
                or done != turn
                or size != (0 if turn else (public.n.bit_length() + 7) // 8)
            ):
                raise RuntimeError("unexpected native bootstrap state")
            if ptr:
                outgoing = bytes(r.u.mem_read(ptr, size))
                r.call("SHelper_FreeBuffer", ptr)
                connection.sendall(struct.pack(">I", size) + outgoing)
            if turn == 0:
                size = struct.unpack(">I", exact(connection, 4))[0]
                if size != 4:
                    raise RuntimeError("unexpected RSA server reply length")
                incoming = exact(connection, size)
                if incoming != struct.pack("<I", 3):
                    raise RuntimeError("unexpected server protocol version")
        out = r.data(b"\0" * 8)
        if r.call("SHelper_RSession_GetKey", handle, out, out + 4) != 1:
            raise RuntimeError("native transport material unavailable")
        ptr, size = r.read32(out), r.read32(out + 4)
        if not ptr or size != 64:
            raise RuntimeError("invalid native transport material")
        material = bytes(r.u.mem_read(ptr, size))
        r.call("SHelper_FreeBuffer", ptr)
        return material
    finally:
        r.call("SHelper_RSession_Delete", handle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--server-address", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    key = load_pem_public_key(args.public_key.read_bytes())
    if not isinstance(key, rsa.RSAPublicKey):
        parser.error("RSA public key required")
    public = key.public_numbers()
    native = Native(args.dll, args.mapping)
    report = {
        "scope": "Native helper RSA/CChannel/SRP with own lab key; whole Windows app not tested",
        "rsa_bits": key.key_size,
        "preamble_client_body_lengths": [4, (key.key_size + 7) // 8],
        "preamble_server_body_lengths": [4],
        "vpn_ready": False,
        "cases": [],
    }
    for case in ("correct", "wrong-password", "tampered-proof", "tampered-channel"):
        result = encrypted_srp(
            native,
            args.server_address,
            case,
            bootstrap=lambda connection: bootstrap(native, connection, public),
        )
        report["cases"].append(result)
        print("PASS RSA/channel/SRP", case, flush=True)
    write_new(args.output, report)


if __name__ == "__main__":
    main()
