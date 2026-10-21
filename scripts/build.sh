#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
go_binary="${GO_BINARY:-go}"
if ! "$go_binary" version >/dev/null 2>&1; then
  echo 'Go compiler unavailable. Set GO_BINARY to the path of a Go 1.22+ compiler.' >&2
  exit 1
fi
"$go_binary" test ./...
mkdir -p bin
CGO_ENABLED=0 "$go_binary" build -trimpath -o bin/probe ./cmd/probe
sha256sum bin/probe > bin/probe.sha256
docker compose build
