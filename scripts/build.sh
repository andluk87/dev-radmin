#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
build_docker=true
case "${1:-}" in
  '') ;;
  --no-docker) build_docker=false ;;
  *) echo 'Usage: scripts/build.sh [--no-docker]' >&2; exit 2 ;;
esac
if (( $# > 1 )); then
  echo 'Usage: scripts/build.sh [--no-docker]' >&2
  exit 2
fi
go_binary="${GO_BINARY:-go}"
if ! "$go_binary" version >/dev/null 2>&1; then
  echo 'Go compiler unavailable. Set GO_BINARY to the path of a Go 1.22+ compiler.' >&2
  exit 1
fi
"$go_binary" test ./...
mkdir -p bin
CGO_ENABLED=0 "$go_binary" build -trimpath -o bin/probe ./cmd/probe
sha256sum bin/probe > bin/probe.sha256
CGO_ENABLED=0 "$go_binary" build -trimpath -o bin/srp-lab ./cmd/srp-lab
sha256sum bin/srp-lab > bin/srp-lab.sha256
GOOS=windows GOARCH=386 "$go_binary" vet ./cmd/native-check
GOOS=windows GOARCH=386 CGO_ENABLED=0 "$go_binary" build -trimpath -o bin/native-check-windows-386.exe ./cmd/native-check
sha256sum bin/native-check-windows-386.exe > bin/native-check-windows-386.exe.sha256
if "$build_docker"; then
  docker compose build
fi
