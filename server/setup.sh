#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
command -v openssl >/dev/null || { echo 'Install OpenSSL before setup.' >&2; exit 1; }
expected_fingerprint="$(cat public-key.sha256)"
check_config() {
  local fingerprint
  fingerprint="$(openssl pkey -in "$1/rsa-key.pem" -pubout -outform DER 2>/dev/null | sha256sum)"
  [[ "${fingerprint%% *}" == "$expected_fingerprint" ]] && cmp -s "$1/srp-record.json" demo-record.json
}
if [[ -e config ]]; then
  if [[ -d config ]] && check_config config; then
    echo 'Matching server configuration already exists.'
    exit 0
  fi
  echo 'Existing config does not match this client pair; it was not changed.' >&2
  exit 1
fi
umask 077
stage="$(mktemp -d .config.setup.XXXXXXXX)"
trap 'rm -rf -- "$stage"' EXIT
openssl pkey -in paired-key.encrypted.pem -out "$stage/rsa-key.pem"
cp demo-record.json "$stage/srp-record.json"
if ! check_config "$stage"; then
  echo 'Decrypted key or SRP record does not match this pair.' >&2
  exit 1
fi
chmod 0600 "$stage/rsa-key.pem" "$stage/srp-record.json"
mv -T "$stage" config
trap - EXIT
echo 'Server configuration decrypted and matched to the client public key.'
