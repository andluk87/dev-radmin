#!/usr/bin/env python3
"""Run the Go TCP lab and original helper together using ephemeral synthetic keys.

Local Linux test only. No installed VPN, remote service or real account is used.
"""
import argparse
import json
import select
import os
import uuid
import struct
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from bootstrap_interop import bootstrap
from channel_interop import encrypted_srp
from native_interop import Native, write_new, exact


def start_server(binary, record, key, extra, image=None):
    name = 'radmin-check-' + uuid.uuid4().hex[:12] if image else None
    if image:
        command = ['docker', 'run', '--rm', '--name', name, '--read-only', '--cap-drop=ALL',
                   '--security-opt=no-new-privileges:true', '--pids-limit=32', '--memory=128m',
                   '--user', str(os.getuid())+':'+str(os.getgid()),
                   '-p', '127.0.0.1::17302',
                   '-v', str(record.resolve())+':/run/record.json:ro',
                   '-v', str(key.resolve())+':/run/key.pem:ro',
                   '--entrypoint', '/srp-lab', image, '-listen', ':17302',
                   '-record', '/run/record.json', '-rsa-key', '/run/key.pem', '-once', *extra]
    else:
        command = [str(binary.resolve()), '-listen', '127.0.0.1:0', '-record', str(record),
                   '-rsa-key', str(key), '-once', *extra]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    process.lab_container = name
    try:
        if not select.select([process.stdout], [], [], 10)[0]:
            raise RuntimeError('lab startup timed out')
        first = process.stdout.readline()
        event = json.loads(first)
        if event.get('event') != 'listening' or event.get('vpn_ready') is not False:
            raise RuntimeError('unexpected lab startup event')
        if name:
            address = subprocess.check_output(['docker', 'port', name, '17302/tcp'], text=True).strip()
        else:
            address = event['address']
        return process, address
    except BaseException:
        process.kill()
        process.communicate(timeout=5)
        if name:
            subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dll', type=Path, required=True)
    parser.add_argument('--rol-dll', type=Path, help='also test native control request/error interoperability')
    parser.add_argument('--mapping', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--server-bin', type=Path)
    mode.add_argument('--docker-image', help='run each TCP scenario in this existing local image')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output already exists; use a new path')
    native = Native(args.dll, args.mapping)
    private = rsa.generate_private_key(public_exponent=65537, key_size=1536)
    public = private.public_key().public_numbers()
    report = {
        'schema_version': 1, 'synthetic_only': True, 'vpn_ready': False,
        'environment': 'Original pinned helper instructions in Linux Unicorn emulator; not Windows',
        'server_transport': 'docker' if args.docker_image else 'local process',
        'scope': 'Go TCP RSA/CChannel/SRP, negative authentication cases, rekey/echo, native control/network request error replies and IsAlive; no VPN login or data plane',
        'cases': [],
    }
    with tempfile.TemporaryDirectory(prefix='radmin-lab-') as directory:
        root = Path(directory)
        record, key = root / 'record.json', root / 'rsa.pem'
        write_new(record, native.record())
        record.chmod(0o600)
        key.write_bytes(private.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        key.chmod(0o600)
        for echo in (False, True):
            for case in ('correct', 'wrong-password', 'tampered-proof', 'tampered-channel'):
                proc, address = start_server(args.server_bin, record, key, ['-post-auth-echo'] if echo else [], image=args.docker_image)
                try:
                    result = encrypted_srp(native, address, case,
                        bootstrap=lambda c: bootstrap(native, c, public), post_auth_echo=echo)
                    output, stderr = proc.communicate(timeout=10)
                    if proc.returncode or stderr:
                        raise RuntimeError('lab process failed')
                    events = [json.loads(line) for line in output.splitlines()]
                    expected = ('post_auth_echo_complete' if echo else 'authentication_complete') if case == 'correct' else 'rejected'
                    if not events or events[-1].get('event') != expected:
                        raise RuntimeError('lab outcome does not match native outcome')
                    result.update(echo_enabled=echo, server_event=expected)
                    report['cases'].append(result)
                    print('PASS', 'echo' if echo else 'authentication', case, flush=True)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
                    if proc.lab_container:
                        subprocess.run(['docker', 'rm', '-f', proc.lab_container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if args.rol_dll:
            from request_interop import generate
            from network_interop import generate as generate_network
            from response_interop import NativeResponses
            response_native = NativeResponses(args.rol_dll)
            requests = generate(args.rol_dll)['cases']
            requests += [dict(c, mode=4) for c in generate_network(args.rol_dll)['cases']]
            for fixture in requests:
                for corrupt in (False, True):
                    def check_control(connection, channel):
                        raw = bytes.fromhex(fixture['request_hex'])
                        if corrupt:
                            raw += b'\x01'
                        outgoing = channel.transform(raw)
                        connection.sendall(struct.pack('>I', len(outgoing)) + outgoing)
                        if corrupt:
                            try:
                                exact(connection, 4)
                            except EOFError:
                                return {'malformed_request_rejected': True}
                            raise RuntimeError('malformed control request received a reply')
                        size = struct.unpack('>I', exact(connection, 4))[0]
                        if not 0 < size <= 4096:
                            raise RuntimeError('invalid control response length')
                        raw = channel.transform(exact(connection, size), False)
                        if raw is None:
                            raise RuntimeError('native channel rejected control response')
                        result = response_native.factory(raw, mode=fixture['mode'])
                        if result.get('packet_type') != 16 or result.get('code') != 1:
                            raise RuntimeError('original packet factory rejected Go error response')
                        return {'packet_type': 16, 'error_code': 1, 'native_factory_verified': True}
                    proc, address = start_server(args.server_bin, record, key, ['-control-error-code', '1'], image=args.docker_image)
                    try:
                        result = encrypted_srp(native, address, 'correct',
                            bootstrap=lambda c: bootstrap(native, c, public), post_auth_check=check_control)
                        output, stderr = proc.communicate(timeout=10)
                        events = [json.loads(line) for line in output.splitlines()]
                        expected = 'control_rejected' if corrupt else 'control_error_sent'
                        if proc.returncode or stderr or not events or events[-1].get('event') != expected:
                            raise RuntimeError('unexpected control lab outcome')
                        result.update(control_mode=fixture['mode'], command=fixture.get('command',20), malformed_control=corrupt, server_event=expected)
                        report['cases'].append(result)
                        print('PASS native control command', fixture.get('command',20), 'mode', fixture['mode'], 'malformed' if corrupt else 'error-reply', flush=True)
                    finally:
                        if proc.poll() is None:
                            proc.kill()
                            proc.communicate(timeout=5)
                        if proc.lab_container:
                            subprocess.run(['docker', 'rm', '-f', proc.lab_container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for wrong_nonce in (False, True):
                def check_keepalive(connection, channel):
                    size = struct.unpack('>I', exact(connection, 4))[0]
                    if not 0 < size <= 4096:
                        raise RuntimeError('invalid IsAlive challenge size')
                    raw = channel.transform(exact(connection, size), False)
                    if raw is None:
                        raise RuntimeError('native channel rejected IsAlive challenge')
                    result = response_native.factory(raw)
                    if result.get('packet_type') != 18:
                        raise RuntimeError('original factory rejected IsAlive challenge')
                    nonce = result['nonce'] ^ (1 if wrong_nonce else 0)
                    raw = response_native.alive_reply(nonce)
                    outgoing = channel.transform(raw)
                    connection.sendall(struct.pack('>I', len(outgoing)) + outgoing)
                    if connection.recv(1) != b'':
                        raise RuntimeError('unexpected data after keepalive exchange')
                    return {'native_factory_verified': True, 'native_reply_serializer_verified': True,
                            'wrong_nonce': wrong_nonce}
                proc, address = start_server(args.server_bin, record, key, ['-post-auth-keepalive'], image=args.docker_image)
                try:
                    result = encrypted_srp(native, address, 'correct',
                        bootstrap=lambda c: bootstrap(native, c, public), post_auth_check=check_keepalive)
                    output, stderr = proc.communicate(timeout=10)
                    events = [json.loads(line) for line in output.splitlines()]
                    expected = 'keepalive_rejected' if wrong_nonce else 'keepalive_complete'
                    if proc.returncode or stderr or not events or events[-1].get('event') != expected:
                        raise RuntimeError('unexpected keepalive lab outcome')
                    result.update(keepalive=True, server_event=expected)
                    report['cases'].append(result)
                    print('PASS native keepalive', 'wrong-nonce' if wrong_nonce else 'correct', flush=True)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
                    if proc.lab_container:
                        subprocess.run(['docker', 'rm', '-f', proc.lab_container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            from login_interop import NativeLogin
            native_login = NativeLogin(args.rol_dll)
            for wrong_nonce in (False, True):
                def check_login(connection, channel):
                    outgoing = channel.transform(bytes.fromhex(requests[0]['request_hex']))
                    connection.sendall(struct.pack('>I', len(outgoing)) + outgoing)
                    size = struct.unpack('>I', exact(connection, 4))[0]
                    if not 0 < size <= 4096:
                        raise RuntimeError('invalid modern login size')
                    raw = channel.transform(exact(connection, size), False)
                    if raw is None:
                        raise RuntimeError('native channel rejected modern login')
                    login = native_login.factory(raw)
                    if login.get('packet_type') != 21 or login.get('version') != 75:
                        raise RuntimeError('original factory rejected modern login')
                    keepalive = check_keepalive(connection, channel)
                    return {'modern_login_factory_verified': True, **keepalive}
                proc, address = start_server(args.server_bin, record, key,
                    ['-post-auth-login', '127.0.0.1'], image=args.docker_image)
                try:
                    result = encrypted_srp(native, address, 'correct',
                        bootstrap=lambda c: bootstrap(native, c, public), post_auth_check=check_login)
                    output, stderr = proc.communicate(timeout=10)
                    events = [json.loads(line) for line in output.splitlines()]
                    expected = 'login_record_rejected' if wrong_nonce else 'login_record_complete'
                    if proc.returncode or stderr or not events or events[-1].get('event') != expected:
                        raise RuntimeError('unexpected modern login outcome')
                    result.update(modern_login=True, server_event=expected)
                    report['cases'].append(result)
                    print('PASS native modern login', 'wrong-nonce' if wrong_nonce else 'correct', flush=True)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
                    if proc.lab_container:
                        subprocess.run(['docker', 'rm', '-f', proc.lab_container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    write_new(args.output, report)
    print('Saved', args.output, flush=True)


if __name__ == '__main__':
    main()
