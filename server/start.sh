#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if [[ ! -f config/rsa-key.pem || ! -f config/srp-record.json ]]; then
  echo 'Run bash setup.sh first and enter the delivery passphrase.' >&2
  exit 1
fi
(cd .. && sha256sum -c bin/srp-lab.sha256)
export SERVER_UID="$(id -u)"
export SERVER_GID="$(id -g)"
docker compose -p "${LAB_PROJECT_NAME:-radmin-own-key}" up --build -d
docker compose -p "${LAB_PROJECT_NAME:-radmin-own-key}" ps
