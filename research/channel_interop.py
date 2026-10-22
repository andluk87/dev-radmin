#!/usr/bin/env python3
"""Generate synthetic native CChannel vectors and test the encrypted SRP lab.

Keys here are deliberately public test constants, never real session keys.
The original pinned helper DLL must be supplied by the operator.
"""

import argparse
import json
import socket
import struct
from pathlib import Path

from native_interop import Native, PASSWORD, exact, write_new

CLIENT_KEY = bytes(range(32))
SERVER_KEY = bytes(reversed(range(32)))


class NativeChannel:
    def __init__(self, native, client=True, keys=None):
        self.r = native.runtime
        enc, dec = (
            keys
            if keys
            else ((CLIENT_KEY, SERVER_KEY) if client else (SERVER_KEY, CLIENT_KEY))
        )
        name = (
            "SHelper_CChannel_CreateClient"
            if client
            else "SHelper_CChannel_CreateServer"
        )
        self.handle = self.r.call(name, self.r.data(enc), 32, self.r.data(dec), 32)
        if not self.handle:
            raise RuntimeError("native channel initialization failed")

    def transform(self, data, encrypt=True):
        r = self.r
        out = r.data(b"\0" * 8)
        name = (
            "SHelper_CChannel_EncryptBuffer"
            if encrypt
            else "SHelper_CChannel_DecryptBuffer"
        )
        ok = r.call(name, self.handle, r.data(data), len(data), out, out + 4)
        ptr, size = r.read32(out), r.read32(out + 4)
        if not ok:
            if ptr:
                r.call("SHelper_FreeBuffer", ptr)
            return None
        if not ptr or not 0 < size <= (1 << 20) + 24:
            raise RuntimeError("invalid native channel output")
        result = bytes(r.u.mem_read(ptr, size))
        r.call("SHelper_FreeBuffer", ptr)
        return result

    def rekey(self, enc, dec):
        for name, key in (
            ("SHelper_CChannel_SetKeyEnc", enc),
            ("SHelper_CChannel_SetKeyDec", dec),
        ):
            if self.r.call(name, self.handle, self.r.data(key), len(key)) != 1:
                raise RuntimeError("native channel rekey failed")

    def close(self):
        self.r.call("SHelper_CChannel_Delete", self.handle)


def vectors(native):
    client, server = NativeChannel(native), NativeChannel(native, False)
    streams = []
    try:
        for sender, receiver, direction in [
            (client, server, "client_to_server"),
            (server, client, "server_to_client"),
        ]:
            messages = []
            for length in (1, 6, 7, 8, 15, 16, 20, 31, 32, 192, 204, 245, 1024):
                plain = bytes((i * 37 + length) % 256 for i in range(length))
                encrypted = sender.transform(plain)
                if encrypted is None or receiver.transform(encrypted, False) != plain:
                    raise RuntimeError("native channel roundtrip failed")
                messages.append(
                    {"plaintext_hex": plain.hex(), "ciphertext_hex": encrypted.hex()}
                )
            streams.append({"direction": direction, "messages": messages})
        rekey_key = bytes((i * 11 + 3) % 256 for i in range(32))
        client.rekey(rekey_key, rekey_key)
        server.rekey(rekey_key, rekey_key)
        rekey_streams = []
        for sender, receiver, direction in [
            (client, server, "client_to_server"),
            (server, client, "server_to_client"),
        ]:
            messages = []
            for length in (7, 32, 289):
                plain = bytes((i * 13 + length) % 256 for i in range(length))
                encrypted = sender.transform(plain)
                if receiver.transform(encrypted, False) != plain:
                    raise RuntimeError("native rekey roundtrip failed")
                messages.append(
                    {"plaintext_hex": plain.hex(), "ciphertext_hex": encrypted.hex()}
                )
            rekey_streams.append({"direction": direction, "messages": messages})
    finally:
        client.close()
        server.close()
    first = bytes.fromhex(streams[0]["messages"][0]["ciphertext_hex"])
    rejected = []
    for data in (first[:15], bytes(16), bytes([first[0] ^ 1]) + first[1:]):
        receiver = NativeChannel(native, False)
        try:
            if receiver.transform(data, False) is not None:
                raise RuntimeError("native accepted the malformed fixture")
            rejected.append(data.hex())
        finally:
            receiver.close()
    return {
        "source": "Pinned original helper DLL executed by the bounded research runtime",
        "dll_sha256": "d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4",
        "rejected_records_hex": rejected,
        "synthetic_only": True,
        "client_key_hex": CLIENT_KEY.hex(),
        "server_key_hex": SERVER_KEY.hex(),
        "streams": streams,
        "rekey_key_hex": rekey_key.hex(),
        "rekey_streams": rekey_streams,
    }


def encrypted_srp(native, address, case, bootstrap=None, post_auth_echo=False, post_auth_check=None):
    channel = None if bootstrap else NativeChannel(native)
    password = b"wrong-research-password" if case == "wrong-password" else PASSWORD
    client = native.client(password=password)
    host, port = address.rsplit(":", 1)
    rejected, complete = False, 0
    post_auth_result = None
    trace = []
    try:
        with socket.create_connection((host, int(port)), timeout=5) as connection:
            if bootstrap:
                material = bootstrap(connection)
                channel = NativeChannel(native, keys=(material[:32], material[:32]))
                del material
            incoming = b""
            for turn in range(3):
                ok, outgoing, complete, error = native.step(client, incoming)
                if not ok or complete or error:
                    raise RuntimeError("unexpected native SRP state")
                if case == "tampered-proof" and turn == 2:
                    outgoing = outgoing[:-1] + bytes([outgoing[-1] ^ 1])
                outgoing = channel.transform(outgoing)
                if case == "tampered-channel" and turn == 2:
                    outgoing = bytes([outgoing[0] ^ 1]) + outgoing[1:]
                trace.append({"client_body_bytes": len(outgoing)})
                connection.sendall(struct.pack(">I", len(outgoing)) + outgoing)
                try:
                    size = struct.unpack(">I", exact(connection, 4))[0]
                    if not 0 < size <= 4096:
                        raise RuntimeError("invalid server frame length")
                    trace[-1]["server_body_bytes"] = size
                    incoming = channel.transform(exact(connection, size), False)
                    if incoming is None:
                        raise RuntimeError(
                            "native client rejected server channel record"
                        )
                except EOFError:
                    if turn != 2:
                        raise RuntimeError("server rejected before SRP proof")
                    rejected = True
                    break
            if not rejected:
                ok, output, complete, error = native.step(client, incoming)
                if (
                    not ok
                    or complete != 1
                    or error
                    or output
                    or len(native.key(client)) != 40
                ):
                    raise RuntimeError("native client did not authenticate")
                if post_auth_echo:
                    key = native.key(client)
                    channel.rekey(key[:32], key[:32])
                    del key
                    payload = b"synthetic post-SRP echo; no VPN command"
                    outgoing = channel.transform(payload)
                    connection.sendall(struct.pack(">I", len(outgoing)) + outgoing)
                    size = struct.unpack(">I", exact(connection, 4))[0]
                    if not 0 < size <= 4096:
                        raise RuntimeError("invalid post-auth frame length")
                    if channel.transform(exact(connection, size), False) != payload:
                        raise RuntimeError("post-auth echo mismatch")
                    if connection.recv(1) != b"":
                        raise RuntimeError("unexpected extra post-auth data")
                if post_auth_check:
                    if post_auth_echo:
                        raise RuntimeError("post-auth checks are mutually exclusive")
                    key = native.key(client)
                    channel.rekey(key[:32], key[:32])
                    del key
                    post_auth_result = post_auth_check(connection, channel)
        passed = (
            (complete == 1 and not rejected)
            if case == "correct"
            else (rejected and not complete)
        )
        if not passed:
            raise RuntimeError("unexpected authentication outcome")
        return {
            "case": case,
            "passed": True,
            "authenticated": complete == 1,
            "server_rejected": rejected,
            "encrypted_trace": trace,
            "post_auth_echo": post_auth_echo and complete == 1,
            "post_auth_check": post_auth_result,
        }
    finally:
        if channel:
            channel.close()
        native.delete(client)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--write-vectors", type=Path)
    parser.add_argument("--write-channel-record", type=Path)
    parser.add_argument("--server-address")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    native = Native(args.dll, args.mapping)
    report = {
        "scope": "Synthetic helper CChannel and inner SRP; not complete Radmin wire compatibility",
        "vpn_ready": False,
    }
    fixture = vectors(native)
    report["native_rekey_roundtrips"] = sum(
        len(s["messages"]) for s in fixture["rekey_streams"]
    )
    report["native_roundtrips"] = sum(len(s["messages"]) for s in fixture["streams"])
    if args.write_vectors:
        write_new(args.write_vectors, fixture)
    if args.write_channel_record:
        write_new(
            args.write_channel_record,
            {"enc_key_hex": SERVER_KEY.hex(), "dec_key_hex": CLIENT_KEY.hex()},
        )
    if args.server_address:
        report["encrypted_srp"] = []
        for case in ("correct", "wrong-password", "tampered-proof", "tampered-channel"):
            report["encrypted_srp"].append(
                encrypted_srp(native, args.server_address, case)
            )
            print("PASS encrypted helper/Go", case, flush=True)
    write_new(args.output, report)
    print("PASS native CChannel roundtrips:", report["native_roundtrips"], flush=True)


if __name__ == "__main__":
    main()
