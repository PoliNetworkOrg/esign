#!/usr/bin/env bash
# Builds the macOS app on a Mac: ./scripts/build-macos.sh [version]
#
# dist/PoliNetwork Sign Agent.app holds a universal binary (arm64 + x86_64): the agent runs natively, and its x86_64
# half runs the Intel-only official CIE middleware through Rosetta. The bundle is signed ad hoc only; see the README
# for notarization. Also writes dist/PoliNetwork-Sign-Agent-<version>-macos.zip and, when hdiutil works, a .dmg.
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
export CGO_ENABLED=1 MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
ldflags="-s -w -X main.version=$version"
app="dist/PoliNetwork Sign Agent.app"
work="dist/macos-build"
rm -rf "$work" "$app"
mkdir -p "$work"

for arch in arm64 amd64; do
	clang_arch=$([ "$arch" = amd64 ] && echo x86_64 || echo arm64)
	GOOS=darwin GOARCH=$arch CC="clang -arch $clang_arch" go build -trimpath -ldflags "$ldflags" -o "$work/sign-agent-$arch" ./cmd/sign-agent
done
lipo -create -output "$work/sign-agent" "$work/sign-agent-arm64" "$work/sign-agent-amd64"
lipo -info "$work/sign-agent"

# The bundle layout and Info.plist come from the agent itself (internal/install), like `sign-agent install` makes them.
"$work/sign-agent" bundle --out "$app"

iconset="$work/AppIcon.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
	sips -z "$size" "$size" internal/server/web/assets/logo.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
	double=$((size * 2))
	sips -z "$double" "$double" internal/server/web/assets/logo.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"

# Ad-hoc signature. Notarization needs a Developer ID, the hardened runtime and the
# com.apple.security.cs.disable-library-validation entitlement (the CIE middleware is signed by another team).
codesign --force --sign - --timestamp=none "$app"
codesign --verify --strict --verbose=2 "$app"

zip="dist/PoliNetwork-Sign-Agent-$version-macos.zip"
rm -f "$zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"
echo "$zip"

dmg="dist/PoliNetwork-Sign-Agent-$version-macos.dmg"
rm -f "$dmg"
staging="$work/dmg"
mkdir -p "$staging"
ditto "$app" "$staging/PoliNetwork Sign Agent.app"
if hdiutil create -quiet -volname "PoliNetwork Sign Agent" -srcfolder "$staging" -ov -format UDZO "$dmg"; then
	echo "$dmg"
else
	echo "hdiutil failed: no .dmg" >&2
fi
rm -rf "$work"
