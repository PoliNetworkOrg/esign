#!/usr/bin/env bash
# Builds the Linux release for this machine's architecture: ./scripts/build-linux.sh [version]
# Needs Go, a C compiler and libpcsclite-dev; makes the .deb, .rpm and Arch package too when nfpm is installed.
# Writes dist/polinetwork-esign-<version>-linux-<arch>.tar.gz (and the packages).
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
arch="$(go env GOARCH)"
name="polinetwork-esign-$version-linux-$arch"
work="dist/linux-$arch/$name"
rm -rf "dist/linux-$arch"
mkdir -p "$work"
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$work/polinetwork-esign" ./cmd/esign
cp README.md LICENSE "$work/"
tar -C "dist/linux-$arch" -czf "dist/$name.tar.gz" "$name"
echo "dist/$name.tar.gz"

if command -v nfpm >/dev/null; then
	# Package versions start with a digit; "~" sorts a pre-release before its release in dpkg and rpm, pacman wants "_".
	pkg_version="${version#v}"
	[[ "$pkg_version" =~ ^[0-9] ]] || pkg_version="0.0.0-$pkg_version"
	pkg_version="${pkg_version//-/\~}"
	arch_version="${pkg_version//\~/_}"
	case "$arch" in amd64) march=x86_64 ;; arm64) march=aarch64 ;; *) march="$arch" ;; esac
	rm -rf dist/pkg && mkdir -p dist/pkg && cp "$work/polinetwork-esign" dist/pkg/
	config=dist/pkg/nfpm.yaml
	cp packaging/linux/nfpm.yaml "$config"
	if [ -f packaging/linux/repository-key.asc ]; then
		cat packaging/linux/nfpm-repository.yaml >> "$config"
	fi
	package() { ARCH="$arch" VERSION="$1" nfpm package --config "$config" --packager "$2" --target "dist/$3"; }
	package "$pkg_version" deb "polinetwork-esign_${pkg_version}_$arch.deb"
	package "$pkg_version" rpm "polinetwork-esign-$pkg_version-1.$march.rpm"
	package "$arch_version" archlinux "polinetwork-esign-$arch_version-1-$march.pkg.tar.zst"
	rm -rf dist/pkg
fi
