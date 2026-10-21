#!/usr/bin/env python3
"""Exercise the running Compose probe with synthetic traffic only."""
import json
import os
import secrets
import socket
import subprocess
import time

project = os.environ.get('COMPOSE_PROJECT_NAME', 'dev-radmin-research')
container = f'{project}-probe-1'
port = int(os.environ.get('PROBE_PORT', '4899'))
subprocess.run(['docker', 'exec', container, '/probe', '-healthcheck'], check=True)
nonce = secrets.token_bytes(16)
tcp_payload = b'TCP-PROBE:' + nonce + bytes(range(70))
udp_payload = b'UDP-PROBE:' + nonce + bytes(range(70))
with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
    client.sendall(tcp_payload[:7])
    client.sendall(tcp_payload[7:])
    client.shutdown(socket.SHUT_WR)
    # The diagnostic service never responds with a successful VPN handshake.
    try:
        assert client.recv(1) == b'', 'unexpected protocol response'
    except ConnectionResetError:
        # Closing after the prefix limit may reset unread TCP input.
        pass
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    client.sendto(udp_payload, ('127.0.0.1', port))
expected = {tcp_payload[:64].hex(): ('tcp', 'prefix_limit'),
            udp_payload[:64].hex(): ('udp', 'truncated_datagram')}
seen = {}
for _ in range(20):
    result = subprocess.run(['docker','logs',container], capture_output=True, text=True, check=True)
    for line in result.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        prefix = entry.get('prefix_hex')
        if prefix in expected:
            assert entry['bytes_observed'] == 64
            assert (entry['transport'],entry['read_result']) == expected[prefix]
            seen[prefix] = entry
    if len(seen) == 2:
        break
    time.sleep(0.1)
assert len(seen) == 2, f'missing observations: {set(expected)-set(seen)}'
print('PASS: container health, fragmented TCP input, UDP truncation, 64-byte bound, no protocol response')
