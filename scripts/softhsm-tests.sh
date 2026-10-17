#!/usr/bin/env bash
# Runs the test suite with a SoftHSM2 token holding a CIE-shaped RSA key and certificate, so the PKCS#11 tests run.
# Needs softhsm2, opensc (pkcs11-tool) and openssl installed: CI calls it directly, ./scripts/test-softhsm.sh in Docker.
# Extra arguments go to `go test`.
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export SOFTHSM2_CONF="$work/softhsm2.conf"
mkdir -p "$work/tokens"
echo "directories.tokendir = $work/tokens" >"$SOFTHSM2_CONF"
module="${SOFTHSM2_MODULE:-}"
for m in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so /opt/homebrew/lib/softhsm/libsofthsm2.so; do
	[ -z "$module" ] && [ -f "$m" ] && module="$m"
done
[ -n "$module" ] || { echo "libsofthsm2.so not found; set SOFTHSM2_MODULE" >&2; exit 1; }

softhsm2-util --init-token --free --label CIE-TEST --pin 12345678 --so-pin 87654321 >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/k.pem" -out "$work/c.pem" -days 30 \
	-addext basicConstraints=critical,CA:FALSE -addext keyUsage=critical,digitalSignature,nonRepudiation \
	-subj "/C=IT/SN=ROSSI/GN=MARIO/serialNumber=TINIT-RSSMRA80A01F205X/CN=ROSSI MARIO" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in "$work/k.pem" -outform DER -out "$work/k.der"
openssl x509 -in "$work/c.pem" -outform DER -out "$work/c.der"
pkcs11-tool --module "$module" --login --pin 12345678 --write-object "$work/k.der" --type privkey --id 01 --label key >/dev/null
pkcs11-tool --module "$module" --login --pin 12345678 --write-object "$work/c.der" --type cert --id 01 --label cert >/dev/null

SIGN_AGENT_TEST_PKCS11="$module" SIGN_AGENT_TEST_PIN=12345678 go test -count=1 "$@" ./...
