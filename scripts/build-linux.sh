#!/usr/bin/env bash
# Builds the Linux release for this machine's architecture: ./scripts/build-linux.sh [version]
# Needs Go, a C compiler and libpcsclite-dev; makes a .deb too when nfpm is installed.
# Writes dist/polinetwork-sign-agent-<version>-linux-<arch>.tar.gz (and .deb).
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
arch="$(go env GOARCH)"
name="polinetwork-sign-agent-$version-linux-$arch"
work="dist/linux-$arch/$name"
rm -rf "dist/linux-$arch"
mkdir -p "$work"
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$work/polinetwork-sign-agent" ./cmd/sign-agent
cp README.md LICENSE "$work/"
tar -C "dist/linux-$arch" -czf "dist/$name.tar.gz" "$name"
echo "dist/$name.tar.gz"

if command -v nfpm >/dev/null; then
	# Debian versions start with a digit.
	deb_version="${version#v}"
	[[ "$deb_version" =~ ^[0-9] ]] || deb_version="0.0.0~$deb_version"
	rm -rf dist/deb && mkdir -p dist/deb && cp "$work/polinetwork-sign-agent" dist/deb/
	ARCH="$arch" VERSION="$deb_version" nfpm package --config packaging/linux/nfpm.yaml --packager deb --target "dist/polinetwork-sign-agent_${deb_version}_$arch.deb"
	rm -rf dist/deb
fi
