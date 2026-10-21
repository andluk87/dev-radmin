#!/usr/bin/env python3
"""Observe the helper RSession API using a freshly generated synthetic RSA key.

No original server private keys, captured packets or actual credentials are used.
The output reports lengths and comparisons only, never keys or ciphertext.
"""

import argparse
import struct
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from native_interop import Native, write_new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    native = Native(args.dll, args.mapping)
    r = native.runtime
    # 1536 bits reproduces the observed helper output length; research only.
    private = rsa.generate_private_key(public_exponent=65537, key_size=1536)
    numbers = private.private_numbers()
    public = numbers.public_numbers

    def integer(value):
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return [r.data(data), len(data)]

    client = r.call(
        "SHelper_RSession_CreateClient",
        42,
        7,
        3,
        *integer(public.n),
        *integer(public.e)
    )
    params = [3]
    for value in (
        public.n,
        public.e,
        numbers.d,
        numbers.p,
        numbers.q,
        numbers.dmp1,
        numbers.dmq1,
        numbers.iqmp,
    ):
        params.extend(integer(value))
    server = r.call("SHelper_RSession_CreateServer", *params)
    if not client or not server:
        raise RuntimeError("RSession context creation failed")
    try:
        incoming = b""
        trace = []
        decoded = None
        for turn, handle in enumerate((client, server, client)):
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
            ptr, size, complete = r.read32(out), r.read32(out + 4), r.read32(out + 8)
            if not ok or size > 4096 or complete != (0 if turn == 0 else 1):
                raise RuntimeError("unexpected native RSession outcome")
            incoming = bytes(r.u.mem_read(ptr, size)) if ptr and size else b""
            if ptr:
                r.call("SHelper_FreeBuffer", ptr)
            trace.append(
                {"turn": turn, "output_bytes": size, "complete": bool(complete)}
            )
            if turn == 0:
                decoded = private.decrypt(incoming, padding.PKCS1v15())
                if len(decoded) != 76 or struct.unpack("<3I", decoded[:12]) != (
                    42,
                    7,
                    3,
                ):
                    raise RuntimeError("unexpected RSA plaintext layout")
            if turn == 1 and incoming != struct.pack("<I", 3):
                raise RuntimeError("unexpected server reply")
        keys = []
        for handle in (client, server):
            out = r.data(b"\0" * 8)
            if r.call("SHelper_RSession_GetKey", handle, out, out + 4) != 1:
                raise RuntimeError("native session key unavailable")
            ptr, size = r.read32(out), r.read32(out + 4)
            if not ptr or size != 64:
                raise RuntimeError("unexpected RSession key length")
            keys.append(bytes(r.u.mem_read(ptr, size)))
            r.call("SHelper_FreeBuffer", ptr)
        if keys[0] != keys[1] or decoded[12:] != keys[0]:
            raise RuntimeError("RSession key comparison failed")
        write_new(
            args.output,
            {
                "scope": "Synthetic native RSession API, not established as the captured control bootstrap",
                "rsa_bits": 1536,
                "padding": "PKCS1-v1_5",
                "plaintext_bytes": 76,
                "metadata": "three little-endian uint32 values",
                "key_bytes": 64,
                "keys_match": True,
                "decrypted_key_matches": True,
                "trace": trace,
                "vpn_ready": False,
            },
        )
        print(
            "PASS native RSession: 192-byte RSA request, 4-byte reply, matching 64-byte keys"
        )
    finally:
        r.call("SHelper_RSession_Delete", client)
        r.call("SHelper_RSession_Delete", server)


if __name__ == "__main__":
    main()
