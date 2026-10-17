#!/usr/bin/env bash
# Cross-builds the Windows release with MinGW-w64: ./scripts/build-windows.sh [version]
# Writes dist/PoliNetwork-eSign-<version>-windows-amd64.zip holding esign.exe, a GUI-subsystem program (no
# console window) that attaches to the console of the terminal it is started from.
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
work="dist/windows-amd64"
rm -rf "$work"
mkdir -p "$work"
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC="${CC:-x86_64-w64-mingw32-gcc}" \
	go build -trimpath -ldflags "-H=windowsgui -s -w -X main.version=$version" -o "$work/esign.exe" ./cmd/esign
cp README.md LICENSE "$work/"
zip="dist/PoliNetwork-eSign-$version-windows-amd64.zip"
rm -f "$zip"
(cd "$work" && zip -q -9 "../$(basename "$zip")" esign.exe README.md LICENSE)
echo "$zip"
