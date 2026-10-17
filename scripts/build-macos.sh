#!/usr/bin/env bash
# Builds the macOS app on a Mac: ./scripts/build-macos.sh [version]
#
# dist/PoliNetwork eSign.app holds a universal binary (arm64 + x86_64): the agent runs natively, and its x86_64
# half runs the Intel-only official CIE middleware through Rosetta. Also writes
# dist/PoliNetwork-eSign-<version>-macos.zip and, when hdiutil works, a .dmg.
#
# Signing: with MACOS_SIGN_IDENTITY set (a "Developer ID Application: …" identity in the keychain) the app is signed
# with the hardened runtime; with APPLE_API_KEY_PATH, APPLE_API_KEY_ID and APPLE_API_ISSUER_ID also set, the zip and
# the dmg are notarized and stapled. Without them the app is signed ad hoc, which macOS only runs after a warning.
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
export CGO_ENABLED=1 MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
ldflags="-s -w -X main.version=$version"
app="dist/PoliNetwork eSign.app"
work="dist/macos-build"
rm -rf "$work" "$app"
mkdir -p "$work"

for arch in arm64 amd64; do
	clang_arch=$([ "$arch" = amd64 ] && echo x86_64 || echo arm64)
	GOOS=darwin GOARCH=$arch CC="clang -arch $clang_arch" go build -trimpath -ldflags "$ldflags" -o "$work/esign-$arch" ./cmd/esign
done
lipo -create -output "$work/esign" "$work/esign-arm64" "$work/esign-amd64"
lipo -info "$work/esign"

# The bundle layout and Info.plist come from the agent itself (internal/install), like `esign install` makes them.
"$work/esign" bundle --out "$app"

iconset="$work/AppIcon.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
	sips -z "$size" "$size" internal/server/web/assets/logo.png --out "$iconset/icon_${size}x${size}.png" >/dev/null
	double=$((size * 2))
	sips -z "$double" "$double" internal/server/web/assets/logo.png --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"

identity="${MACOS_SIGN_IDENTITY:-}"
notarize=false
if [ -n "$identity" ] && [ -n "${APPLE_API_KEY_PATH:-}" ] && [ -n "${APPLE_API_KEY_ID:-}" ] && [ -n "${APPLE_API_ISSUER_ID:-}" ]; then
	notarize=true
fi

notarize_file() {
	xcrun notarytool submit "$1" --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" \
		--issuer "$APPLE_API_ISSUER_ID" --wait --timeout 30m
}

if [ -n "$identity" ]; then
	# Developer ID with the hardened runtime, inside out. The entitlement lets the agent load the CIE middleware,
	# which another team (IPZS) signs.
	codesign --force --options runtime --timestamp --entitlements packaging/macos/entitlements.plist \
		--sign "$identity" "$app/Contents/MacOS/esign"
	codesign --force --options runtime --timestamp --entitlements packaging/macos/entitlements.plist \
		--sign "$identity" "$app"
else
	codesign --force --sign - --timestamp=none "$app"
fi
codesign --verify --strict --verbose=2 "$app"

zip="dist/PoliNetwork-eSign-$version-macos.zip"
rm -f "$zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"
if $notarize; then
	notarize_file "$zip"
	xcrun stapler staple "$app"
	# Zip again so the downloaded app carries its ticket for offline Gatekeeper checks.
	rm -f "$zip"
	ditto -c -k --sequesterRsrc --keepParent "$app" "$zip"
	spctl --assess --type execute --verbose=2 "$app"
fi
echo "$zip"

dmg="dist/PoliNetwork-eSign-$version-macos.dmg"
rm -f "$dmg"
staging="$work/dmg"
mkdir -p "$staging"
ditto "$app" "$staging/PoliNetwork eSign.app"
if hdiutil create -quiet -volname "PoliNetwork eSign" -srcfolder "$staging" -ov -format UDZO "$dmg"; then
	if [ -n "$identity" ]; then codesign --force --timestamp --sign "$identity" "$dmg"; fi
	if $notarize; then
		notarize_file "$dmg"
		xcrun stapler staple "$dmg"
	fi
	echo "$dmg"
else
	echo "hdiutil failed: no .dmg" >&2
fi
rm -rf "$work"
