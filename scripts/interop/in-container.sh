#!/usr/bin/env bash
# Runs inside the interop image (see run.sh): pcsc-lite with the vpcd virtual reader, the simulated CIE served by
# cmd/cie-vcard, then four checks. Each check starts from a fresh card so PIN counters are known.
set -euo pipefail
cd /src
PIN=12345678
CONTROL=http://127.0.0.1:35999
export SIGN_AGENT_TEST_PIN=$PIN SIGN_AGENT_TEST_VCARD=$CONTROL
MIEKG=$(go list -m -f '{{.Dir}}' github.com/miekg/pkcs11)

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

mkdir -p /run/pcscd
pcscd --foreground --disable-polkit >/tmp/pcscd.log 2>&1 &

go build -o /tmp/cie-vcard ./cmd/cie-vcard
cc -I"$MIEKG" -o /tmp/p11check scripts/interop/p11check.c -ldl

vcard_pid=
start_card() {
	[ -n "$vcard_pid" ] && kill "$vcard_pid" && wait "$vcard_pid" 2>/dev/null || true
	rm -f ~/.CIEPKI/*.cache
	/tmp/cie-vcard -pin $PIN -cert-out /tmp/card.pem "$@" >/tmp/vcard.log 2>&1 &
	vcard_pid=$!
	for _ in $(seq 50); do
		grep -q "card inserted" /tmp/vcard.log 2>/dev/null && break
		sleep 0.2
	done
	sleep 1
	echo "card: $(curl -fs $CONTROL/status)"
}
tries() { curl -fs $CONTROL/status | sed 's/.*"pinTriesLeft":\([0-9]*\).*/\1/'; }

step "a. Official middleware (built from source): AbilitaCIE pairing and a PKCS#11 signature"
start_card
mod=$CIE_MW_MODULE
echo "-- unpaired: what the module answers"
/tmp/p11check "$mod" probe 2>/dev/null | grep -oE '(slots|C_GetTokenInfo|C_OpenSession|certificates)[:,].*'
echo "-- AbilitaCIE with a wrong PIN"
/tmp/p11check "$mod" pair AbilitaCIE 00000000 2>/dev/null | grep -o 'AbilitaCIE: .*'
echo "   card PIN tries left: $(tries)"
echo "-- AbilitaCIE with the PIN"
/tmp/p11check "$mod" pair AbilitaCIE $PIN 2>/dev/null | grep -oE '(AbilitaCIE: |paired card).*'
echo "   cache: $(ls ~/.CIEPKI/*.cache)"
echo "-- AbilitaCIE again"
/tmp/p11check "$mod" pair AbilitaCIE $PIN 2>/dev/null | grep -o 'AbilitaCIE: .*'
echo "-- paired: what the module answers"
/tmp/p11check "$mod" probe 2>/dev/null | grep -oE '(C_OpenSession|certificates): .*'
echo "-- C_Login with the last four digits, C_Sign(CKM_RSA_PKCS) over a SHA-256 DigestInfo"
printf 'PoliNetwork interop %s' "$(date)" >/tmp/data
digest=$(openssl dgst -sha256 -r /tmp/data | cut -c1-64)
/tmp/p11check "$mod" sign ${PIN:4} "$digest" /tmp/sig /tmp/cert.der 2>/dev/null | grep -oE '(certificate object|C_Login|C_Sign).*'
openssl x509 -inform DER -in /tmp/cert.der -noout -subject
openssl x509 -inform DER -in /tmp/cert.der -pubkey -noout >/tmp/pub.pem
openssl dgst -sha256 -verify /tmp/pub.pem -signature /tmp/sig /tmp/data
cmp <(openssl x509 -in /tmp/card.pem -outform DER) /tmp/cert.der && echo "certificate object = the card's EF 1003"
echo "-- C_Login with a wrong suffix"
/tmp/p11check "$mod" sign 0000 "$digest" /tmp/sig /tmp/cert.der 2>/dev/null | grep -oE "C_Login\(.*" || true
echo "   card PIN tries left: $(tries)"

step "b. Agent's cie provider through pcsc-lite"
start_card
SIGN_AGENT_TEST_PCSC=1 go test -count=1 -v -run 'TestPCSCInterop' ./internal/token/cie/ 2>&1 | grep -E '^(=== RUN|--- |\s+pcsc_interop_test|ok|FAIL|PASS)'

step "c. Agent's p11 provider (cie-mw) on the official module, pairing automatically"
start_card
SIGN_AGENT_TEST_CIEMW=$CIE_MW_MODULE go test -count=1 -v -run 'TestOfficialMiddlewareInterop' ./internal/token/p11/ 2>/dev/null \
	| grep -E '^(=== RUN|--- |\s+cie_interop_test|ok|FAIL|PASS)'

step "c2. The same, with the module in a worker process (sign-agent worker), pairing inside the worker"
start_card
SIGN_AGENT_TEST_CIEMW=$CIE_MW_MODULE go test -count=1 -v -run 'TestWorkerPairsCIE' ./cmd/sign-agent/ 2>/dev/null \
	| grep -E '^(=== RUN|--- |\s+main_test|ok|FAIL|PASS)'

step "d. Agent's p11 provider (opencie) on OpenCIE's released module, pairing automatically"
start_card
SIGN_AGENT_TEST_OPENCIE=$OPENCIE_MODULE go test -count=1 -v -run 'TestOpenCIEInterop' ./internal/token/p11/ 2>/dev/null \
	| grep -E '^(=== RUN|--- |\s+cie_interop_test|ok|FAIL|PASS)'

step "e. The agent's status command sees all three providers"
start_card
go run ./cmd/sign-agent status 2>/dev/null
