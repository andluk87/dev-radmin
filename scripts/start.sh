#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) ;;
  *) echo 'The included binary requires Linux amd64. Build from source for another platform.' >&2; exit 1 ;;
esac
sha256sum -c bin/probe.sha256
docker compose -p dev-radmin-research up --build -d --wait --wait-timeout 45
echo 'Diagnostic probe is running. This is not a working Radmin VPN server.'
docker compose -p dev-radmin-research ps
