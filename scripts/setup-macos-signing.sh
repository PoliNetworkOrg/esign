#!/usr/bin/env bash
# Sets up macOS signing and notarization for releases, with PoliNetwork APS's Apple Developer account.
#
#   ./scripts/setup-macos-signing.sh csr
#       Creates a private key and a certificate signing request in $SIGNING_DIR
#       (default ~/dev/polinetwork/.signing/esign, outside any repository).
#
#   ./scripts/setup-macos-signing.sh secrets <developer_id.cer> <AuthKey_XXXXXXXXXX.p8> <key-id> <issuer-id>
#       Builds a .p12 from the key and the Developer ID Application certificate downloaded from Apple, then stores the
#       GitHub Actions secrets the Release workflow uses. Needs `gh` signed in with admin rights on the repository.
#
# See docs/code-signing.md.
set -euo pipefail
dir="${SIGNING_DIR:-$HOME/dev/polinetwork/.signing/esign}"
repo="${REPO:-PoliNetworkOrg/esign}"
key="$dir/developer-id.key"

case "${1:-}" in
csr)
	mkdir -p "$dir"
	chmod 700 "$dir"
	if [ ! -f "$key" ]; then
		openssl genrsa -out "$key" 2048 2>/dev/null
		chmod 600 "$key"
	fi
	openssl req -new -key "$key" -out "$dir/developer-id.certSigningRequest" \
		-subj "/emailAddress=it@polinetwork.org/CN=PoliNetwork APS/C=IT"
	echo "Certificate signing request: $dir/developer-id.certSigningRequest"
	echo "Upload it at https://developer.apple.com/account/resources/certificates/add (Developer ID > Developer ID Application, G2)."
	;;
secrets)
	cer="${2:?developer_id.cer}" p8="${3:?AuthKey.p8}" key_id="${4:?key id}" issuer="${5:?issuer id}"
	[ -f "$key" ] || { echo "No private key in $dir: run '$0 csr' first" >&2; exit 1; }
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
	openssl x509 -inform DER -in "$cer" -out "$work/cert.pem" 2>/dev/null || cp "$cer" "$work/cert.pem"
	subject="$(openssl x509 -in "$work/cert.pem" -noout -subject)"
	case "$subject" in *"Developer ID Application"*) ;; *) echo "Not a Developer ID Application certificate: $subject" >&2; exit 1 ;; esac
	# The Developer ID intermediate goes in the .p12, so the CI keychain can build the chain.
	curl -fsSL https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer -o "$work/intermediate.cer"
	openssl x509 -inform DER -in "$work/intermediate.cer" -out "$work/intermediate.pem"
	password="$(openssl rand -hex 24)"
	openssl pkcs12 -export -legacy -inkey "$key" -in "$work/cert.pem" -certfile "$work/intermediate.pem" \
		-name "Developer ID Application" -out "$work/certificate.p12" -passout "pass:$password" 2>/dev/null ||
		openssl pkcs12 -export -inkey "$key" -in "$work/cert.pem" -certfile "$work/intermediate.pem" \
			-name "Developer ID Application" -out "$work/certificate.p12" -passout "pass:$password"
	base64 < "$work/certificate.p12" | tr -d '\n' | gh secret set MACOS_CERTIFICATE_P12 --repo "$repo"
	printf '%s' "$password" | gh secret set MACOS_CERTIFICATE_PASSWORD --repo "$repo"
	gh secret set APPLE_API_KEY_P8 --repo "$repo" < "$p8"
	printf '%s' "$key_id" | gh secret set APPLE_API_KEY_ID --repo "$repo"
	printf '%s' "$issuer" | gh secret set APPLE_API_ISSUER_ID --repo "$repo"
	echo "Signing secrets stored on $repo ($subject). The next tagged release is signed and notarized."
	;;
*)
	sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
	;;
esac
