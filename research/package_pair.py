#!/usr/bin/env python3
"""Build a private own-key Docker/client research pair from operator-supplied files.

The client executable changes only public RSA data and the PE checksum. This
package does not install, execute or assert Windows/full VPN compatibility.
"""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from client_key import build_copy, fingerprint, SERVICE_HASH


def write(path, data, mode=0o600):
    with path.open('xb') as f:
        f.write(data)
    path.chmod(mode)


def package(original_dir, record_path, output):
    root = Path(__file__).resolve().parent.parent
    record_data = record_path.read_bytes()
    record = json.loads(record_data)
    if set(record) != {'user_id', 'salt_hex', 'verifier_hex'} or not isinstance(record['user_id'], int):
        raise ValueError('expected an SRP credential record')
    if not 0 <= record['user_id'] < 2**64 or len(bytes.fromhex(record['salt_hex'])) != 32:
        raise ValueError('invalid SRP identity or salt')
    verifier = bytes.fromhex(record['verifier_hex'])
    if not 0 < len(verifier) <= 192:
        raise ValueError('invalid SRP verifier')
    original = (original_dir / 'RvControlSvc.exe').read_bytes()
    private = rsa.generate_private_key(public_exponent=65537, key_size=1536)
    modified, checksum_offset = build_copy(original, private.public_key())
    output.mkdir(mode=0o700)
    server, client = output / 'server', output / 'client'
    server.mkdir(mode=0o700); client.mkdir(mode=0o700)
    (server/'config').mkdir(mode=0o700)
    write(server/'config'/'rsa-key.pem', private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public_pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    write(client/'server-public.pem', public_pem)
    write(server/'config'/'srp-record.json', record_data)
    binary = (root/'bin'/'srp-lab').read_bytes()
    write(server/'srp-lab', binary, 0o755)
    write(server/'srp-lab.sha256', (hashlib.sha256(binary).hexdigest()+'  srp-lab\n').encode())
    write(server/'Dockerfile', b'FROM scratch\nCOPY --chmod=0555 srp-lab /srp-lab\nUSER 65532:65532\nENTRYPOINT ["/srp-lab"]\n')
    write(server/'compose.yaml', b'''services:
  control:
    build: .
    image: dev-radmin-control:own-key
    user: "${SERVER_UID:-1000}:${SERVER_GID:-1000}"
    command: ["-listen", ":17301", "-record", "/run/srp-record.json", "-rsa-key", "/run/rsa-key.pem", "-post-auth-login", "${LAB_ENDPOINT:-127.0.0.1}"]
    ports: ["${BIND_ADDRESS:-127.0.0.1}:${CONTROL_PORT:-17301}:17301/tcp"]
    volumes:
      - ./config/srp-record.json:/run/srp-record.json:ro
      - ./config/rsa-key.pem:/run/rsa-key.pem:ro
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    pids_limit: 32
    mem_limit: 128m
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "2"
''')
    write(server/'start.sh', b'''#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
sha256sum -c srp-lab.sha256
export SERVER_UID="$(id -u)"
export SERVER_GID="$(id -g)"
docker compose -p radmin-own-key up --build -d
docker compose -p radmin-own-key ps
''', 0o755)
    report = {
        'original_sha256': SERVICE_HASH, 'modified': True,
        'output_sha256': hashlib.sha256(modified).hexdigest(),
        'replacement_public_key_spki_sha256': fingerprint(private.public_key()),
        'checksum_file_offset': checksum_offset, 'verification_code_modified': False,
        'vendor_authenticode_valid_after_change': False, 'installed': False, 'executed': False,
    }
    write(client/'RvControlSvc-own-key-research.exe', modified)
    write(client/'client-key-copy.json', (json.dumps(report, indent=2)+'\n').encode())
    shutil.copyfile(root/'windows'/'Start-RadminLabClient.ps1', client/'Start-RadminLabClient.ps1')
    shutil.copyfile(root/'research'/'modified-client.md', client/'modified-client.md')
    shutil.copyfile(root/'windows'/'Set-RadminLabAddress.ps1', client/'Set-RadminLabAddress.ps1')
    runtime = client/'runtime'
    runtime.mkdir(mode=0o700)
    write(runtime/'RvControlSvc.exe', modified)
    aliases = {'RvROLClient.dll':'RvROLClient.dll', 'shelper.dll':'shelper.dll',
               'RvUESClient.dll':'RvUESClient.dll', 'libcurl.dll':'libcurl_dll',
               'libssl-3.dll':'libssl_3_dll', 'libcrypto-3.dll':'libcrypto_3_dll',
               'vcruntime140.dll':'vcruntime140.dll'}
    for target, source in aliases.items():
        write(runtime/target, (original_dir/source).read_bytes())
    manifest = {'schema_version': 1, 'vpn_ready': False, 'windows_tested': False,
                'scope': 'RSA/SRP and native-decodable modern login/IsAlive prototype; network operations/data plane incomplete',
                'public_key_spki_sha256': fingerprint(private.public_key()),
                'client_exe_sha256': report['output_sha256'],
                'server_binary_sha256': hashlib.sha256(binary).hexdigest()}
    write(output/'pair-manifest.json', (json.dumps(manifest,indent=2)+'\n').encode())
    write(server/'README.txt', '''Docker-сервер исследования Radmin VPN

Запуск Linux amd64: bash start.sh
Для подключения с другого компьютера задайте BIND_ADDRESS=<IP Linux-сервера>
и LAB_ENDPOINT=<тот же доступный IP>. Порт по умолчанию TCP/17301.
Пример: BIND_ADDRESS=192.0.2.10 LAB_ENDPOINT=192.0.2.10 bash start.sh
192.0.2.10 замените адресом своего сервера.
Логи: docker compose -p radmin-own-key logs -f control
Остановка: docker compose -p radmin-own-key down

Это серверный прототип: RSA, SRP, LoginComplete75 и один IsAlive.
Контейнер не создаёт VPN-интерфейс, сеть, NAT или relay.
После одного проверенного IsAlive экспериментальное соединение закрывается.
config содержит собственный приватный RSA-ключ и SRP-запись: оставьте на сервере.
SRP-запись не переносит облачную регистрацию установленного клиента.
Для реальной Windows-службы автоматическая регистрация ещё не реализована.
Готовность полного VPN не заявляется.
'''.encode())
    write(client/'README.txt', '''Клиентская копия Radmin VPN с собственным публичным ключом

Нужен установленный Radmin VPN 2.1.4951.1 из вашего установщика.
Изменённый EXE и неизменённые DLL собираются в отдельную папку командой:

powershell -NoProfile -File .\\Start-RadminLabClient.ps1 -PatchedServicePath .\\RvControlSvc-own-key-research.exe -PatchReportPath .\\client-key-copy.json

Это подготовка без запуска. /run и требования к отдельной тестовой Windows
описаны в modified-client.md. Подпись изготовителя изменённого EXE недействительна.
Проверки Windows и проверки аутентификации в коде не отключались.
Приватного серверного RSA-ключа в этом клиентском архиве нет.
Существующая облачная регистрация не соответствует автоматически SRP-записи сервера.
На настоящей Windows эта копия ещё не запускалась; полный VPN пока не работает.
'''.encode())
    print('Created own-key pair; full VPN not ready:', output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-dir', type=Path, required=True)
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    package(args.original_dir, args.record, args.output)


if __name__ == '__main__':
    main()
