#!/usr/bin/env bash
# Runs the whole test suite on Linux against SoftHSM2, in Docker: ./scripts/test-softhsm.sh
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -v "$PWD":/src -w /src -v sign-agent-gomod:/go/pkg/mod golang:1.26-bookworm bash -c '
set -euo pipefail
apt-get update -qq && apt-get install -y -qq softhsm2 opensc libpcsclite-dev >/dev/null
export SOFTHSM2_CONF=/tmp/softhsm2.conf
mkdir -p /tmp/tokens && echo "directories.tokendir = /tmp/tokens" > $SOFTHSM2_CONF
MOD=/usr/lib/softhsm/libsofthsm2.so
softhsm2-util --init-token --free --label CIE-TEST --pin 12345678 --so-pin 87654321 >/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k.pem -out /tmp/c.pem -days 30 -addext basicConstraints=critical,CA:FALSE -addext keyUsage=critical,digitalSignature,nonRepudiation -subj "/C=IT/SN=ROSSI/GN=MARIO/serialNumber=TINIT-RSSMRA80A01F205X/CN=ROSSI MARIO" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in /tmp/k.pem -outform DER -out /tmp/k.der
openssl x509 -in /tmp/c.pem -outform DER -out /tmp/c.der
pkcs11-tool --module $MOD --login --pin 12345678 --write-object /tmp/k.der --type privkey --id 01 --label key >/dev/null
pkcs11-tool --module $MOD --login --pin 12345678 --write-object /tmp/c.der --type cert --id 01 --label cert >/dev/null
SIGN_AGENT_TEST_PKCS11=$MOD SIGN_AGENT_TEST_PIN=12345678 go test -count=1 ./...
'
