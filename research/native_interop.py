#!/usr/bin/env python3
"""Run synthetic helper authentication tests, optionally against the Go lab server.

Requires the user's original pinned helper DLL; it is never bundled or downloaded.
Only test credentials are generated. Report files contain no keys or passwords.
"""

import argparse
import json
import select
import socket
import struct
import subprocess
import tempfile
from pathlib import Path

from helper_runtime import Emulator

PASSWORD = b"research-only-password"  # Public synthetic fixture, never a default server account.


class Native:
    def __init__(self, dll, mapping):
        self.runtime = Emulator(dll, mapping)
        r = self.runtime
        if r.call(r.base + r.pe.OPTIONAL_HEADER.AddressOfEntryPoint, r.base, 1, 0) != 1:
            raise RuntimeError("helper process initialization failed")
        if r.call("SHelper_Init") != 1:
            raise RuntimeError("helper initialization failed")
        if not r.calls["CryptGenRandom"]:
            raise RuntimeError("the modeled CSPRNG was not used")

    def record(self, identity=42, password=PASSWORD):
        r = self.runtime
        p, out = r.data(password), r.data(b"\0" * 16)
        if (
            r.call(
                "SHelper_GenerateUserParams",
                identity & 0xFFFFFFFF,
                identity >> 32,
                p,
                len(password),
                out,
                out + 4,
                out + 8,
                out + 12,
            )
            != 1
        ):
            raise RuntimeError("credential generation failed")
        result = []
        for offset in (0, 8):
            ptr, size = r.read32(out + offset), r.read32(out + offset + 4)
            if not ptr or not 0 < size <= 4096:
                raise RuntimeError("invalid credential output")
            result.append(bytes(r.u.mem_read(ptr, size)))
            r.call("SHelper_FreeBuffer", ptr)
        return {
            "user_id": identity,
            "salt_hex": result[0].hex(),
            "verifier_hex": result[1].hex(),
        }

    def client(self, identity=42, password=PASSWORD):
        r = self.runtime
        p = r.data(password)
        handle = r.call(
            "SHelper_CreateClient",
            identity & 0xFFFFFFFF,
            identity >> 32,
            p,
            len(password),
        )
        if not handle:
            raise RuntimeError("client context creation failed")
        return handle

    def server(self, record):
        r = self.runtime
        handle = r.call("SHelper_CreateServer")
        salt, verifier = bytes.fromhex(record["salt_hex"]), bytes.fromhex(
            record["verifier_hex"]
        )
        identity = record["user_id"]
        if (
            not handle
            or r.call(
                "SHelper_SetUserParams",
                handle,
                identity & 0xFFFFFFFF,
                identity >> 32,
                r.data(salt),
                len(salt),
                r.data(verifier),
                len(verifier),
            )
            != 1
        ):
            raise RuntimeError("server context setup failed")
        return handle

    def step(self, context, data):
        r = self.runtime
        p = r.data(data) if data else 0
        out = r.data(b"\0" * 16)
        ok = r.call(
            "SHelper_GetNextBuffer",
            context,
            p,
            len(data),
            out,
            out + 4,
            out + 8,
            out + 12,
        )
        ptr, size, complete, error = [r.read32(out + 4 * i) for i in range(4)]
        if size > 1 << 20 or (size and not ptr):
            raise RuntimeError("invalid helper output bounds")
        body = bytes(r.u.mem_read(ptr, size)) if ptr and size else b""
        if ptr:
            r.call("SHelper_FreeBuffer", ptr)
        return ok, body, complete, error

    def key(self, context):
        r = self.runtime
        out = r.data(b"\0" * 8)
        if r.call("SHelper_GetKey", context, out, out + 4) != 1:
            return b""
        ptr, size = r.read32(out), r.read32(out + 4)
        if not ptr or not 0 < size <= 4096:
            raise RuntimeError("invalid key output bounds")
        key = bytes(r.u.mem_read(ptr, size))
        r.call("SHelper_FreeBuffer", ptr)
        return key

    def delete(self, context):
        self.runtime.call("SHelper_Delete", context)


def native_case(native, case):
    record = native.record()
    password = b"wrong-research-password" if case == "wrong-password" else PASSWORD
    client, server = native.client(password=password), native.server(record)
    trace = []
    incoming = b""
    done = {"client": False, "server": False}
    rejected = False
    try:
        for turn in range(8):
            side = "client" if turn % 2 == 0 else "server"
            ok, output, complete, error = native.step(
                client if side == "client" else server, incoming
            )
            trace.append(
                {
                    "side": side,
                    "ok": bool(ok),
                    "body_bytes": len(output),
                    "complete": complete,
                    "error": error,
                }
            )
            if not ok or error:
                rejected = True
                break
            done[side] = complete == 1
            if all(done.values()):
                break
            if case == "tampered-proof" and turn == 4:
                output = output[:-1] + bytes([output[-1] ^ 1])
            incoming = output
        client_key, server_key = native.key(client), native.key(server)
        if case == "correct":
            assert (
                all(done.values())
                and not rejected
                and len(client_key) == 40
                and client_key == server_key
            )
        else:
            assert rejected and not all(done.values())
        return {
            "case": case,
            "passed": True,
            "authenticated": all(done.values()),
            "rejected": rejected,
            "client_derived_key_bytes": len(client_key),
            "server_derived_key_bytes": len(server_key),
            "derived_keys_equal": client_key == server_key,
            "trace": trace,
        }
    finally:
        native.delete(client)
        native.delete(server)


def exact(connection, count):
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise EOFError("peer closed the connection")
        data.extend(part)
    return bytes(data)


def go_case(native, binary, record_path, case, address=None):
    process = (
        None
        if address
        else subprocess.Popen(
            [
                str(binary),
                "-listen",
                "127.0.0.1:0",
                "-record",
                str(record_path),
                "-once",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    )
    client = None
    try:
        if address:
            host, port = address.rsplit(":", 1)
        else:
            if not select.select([process.stdout], [], [], 5)[0]:
                raise TimeoutError("lab server did not announce readiness")
            ready = json.loads(process.stdout.readline())
            if ready.get("event") != "listening":
                raise RuntimeError("unexpected lab readiness message")
            host, port = ready["address"].rsplit(":", 1)
        password = b"wrong-research-password" if case == "wrong-password" else PASSWORD
        client = native.client(password=password)
        complete = 0
        rejected = False
        trace = []
        with socket.create_connection((host, int(port)), timeout=5) as connection:
            incoming = b""
            for turn in range(3):
                ok, outgoing, complete, error = native.step(client, incoming)
                assert ok and not error and not complete
                if case == "tampered-proof" and turn == 2:
                    outgoing = outgoing[:-1] + bytes([outgoing[-1] ^ 1])
                connection.sendall(struct.pack(">I", len(outgoing)) + outgoing)
                try:
                    count = struct.unpack(">I", exact(connection, 4))[0]
                    if count > 4096:
                        raise ValueError("oversized lab response")
                    incoming = exact(connection, count)
                except EOFError:
                    assert turn == 2, "server rejected before proof verification"
                    rejected = True
                    break
                trace.append(
                    {
                        "client_body_bytes": len(outgoing),
                        "server_body_bytes": len(incoming),
                    }
                )
            if not rejected:
                ok, output, complete, error = native.step(client, incoming)
                assert (
                    ok
                    and complete == 1
                    and not error
                    and not output
                    and len(native.key(client)) == 40
                )
        events = []
        if process:
            rest, stderr = process.communicate(timeout=5)
            if process.returncode != 0:
                raise RuntimeError("lab server failed: " + stderr)
            events = [json.loads(line) for line in rest.splitlines() if line]
        if case == "correct":
            assert (
                complete == 1
                and not rejected
                and (
                    address
                    or any(
                        item["event"] == "authentication_complete" for item in events
                    )
                )
            )
        else:
            assert (
                rejected
                and not complete
                and (
                    address
                    or any(
                        item["event"] == "rejected"
                        and item.get("reason") == "authentication"
                        for item in events
                    )
                )
            )
        return {
            "case": case,
            "passed": True,
            "native_client_authenticated": complete == 1,
            "server_rejected": rejected,
            "trace": trace,
        }
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait()
        if client:
            native.delete(client)


def write_new(path, data):
    with path.open("x", encoding="utf-8") as output:
        json.dump(data, output, indent=2)
        output.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    servers = parser.add_mutually_exclusive_group()
    servers.add_argument(
        "--server-address",
        help="existing lab host:port with synthetic identity 42 and fixture password",
    )
    servers.add_argument(
        "--server-bin", type=Path, help="optional Linux srp-lab binary to test"
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--write-vectors",
        type=Path,
        help="write NEW public synthetic verifier fixtures",
    )
    parser.add_argument(
        "--write-lab-record",
        type=Path,
        help="write NEW record for the public fixture password, for local Docker testing only",
    )
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; use a new path")
    native = Native(args.dll, args.mapping)
    report = {
        "schema_version": 1,
        "environment": "Unicorn x86 with a restricted WinAPI shim; not Windows",
        "protocol_version": native.runtime.call("SHelper_GetNetworkProtocolVersion"),
        "native_to_native": [],
        "native_to_go": [],
        "scope": "Inner helper SRP only; not the captured Radmin outer handshake or VPN data plane",
    }
    for case in ("correct", "wrong-password", "tampered-proof"):
        report["native_to_native"].append(native_case(native, case))
        print("PASS helper/helper", case, flush=True)
    record = native.record()
    if args.write_lab_record:
        write_new(args.write_lab_record, record)
    if args.server_bin:
        with tempfile.TemporaryDirectory(prefix="radmin-synthetic-") as directory:
            path = Path(directory) / "record.json"
            write_new(path, record)
            for case in ("correct", "wrong-password", "tampered-proof"):
                report["native_to_go"].append(
                    go_case(native, args.server_bin.resolve(), path, case)
                )
                print("PASS helper/Go", case, flush=True)
    if args.server_address:
        for case in ("correct", "wrong-password", "tampered-proof"):
            report["native_to_go"].append(
                go_case(native, None, None, case, args.server_address)
            )
            print("PASS helper/external Go", case, flush=True)
    if args.write_vectors:
        vectors = [
            dict(native.record(identity), password_hex=PASSWORD.hex())
            for identity in (42, 0x1122334455667788, 0xFFFFFFFFFFFFFFFF)
        ]
        write_new(
            args.write_vectors,
            {
                "synthetic_only": True,
                "source": "Pinned native helper in the research emulator",
                "dll_sha256": "d89daf6bcd5cafa3c7f6173f835ccf045baf8e7134f868819db6fd7615959ac4",
                "vectors": vectors,
            },
        )
    report["modeled_csprng_calls"] = native.runtime.calls["CryptGenRandom"]
    write_new(args.output, report)
    print("Saved", args.output, flush=True)


if __name__ == "__main__":
    main()
