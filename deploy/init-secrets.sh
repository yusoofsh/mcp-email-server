#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
umask 077
mkdir -p secrets
chmod 700 secrets
if [[ -e secrets/mcp-password.hash ]]; then
  printf '%s\n' 'Hash file already exists; move it aside explicitly before rotating.' >&2
  exit 1
fi
read -r -s -p 'New MCP password (at least 16 characters): ' password </dev/tty
printf '\n' >/dev/tty
read -r -s -p 'Repeat password: ' repeated </dev/tty
printf '\n' >/dev/tty
if [[ "$password" != "$repeated" ]]; then
  unset password repeated
  printf '%s\n' 'Passwords do not match.' >&2
  exit 1
fi
tmp=$(mktemp secrets/hash.XXXXXX)
trap 'rm -f "$tmp"; unset password repeated' EXIT
printf '%s\n' "$password" | docker run --rm -i \
  "${MCP_IMAGE:-ghcr.io/yusoofsh/mcp-email-server:latest}" hash-password --stdin > "$tmp"
unset password repeated
grep -q '^\$argon2id\$' "$tmp"
# The containing directory is owner-only. The mounted file must be readable by
# container UID 10001; Compose file-backed secrets do not reliably remap UID.
chmod 444 "$tmp"
mv "$tmp" secrets/mcp-password.hash
printf '%s\n' 'Argon2id hash saved. No plaintext password was written.'
