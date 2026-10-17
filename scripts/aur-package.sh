#!/usr/bin/env bash
# Prepares the AUR package polinetwork-esign-bin for a published release, on Arch Linux as a user other than
# root: ./scripts/aur-package.sh <version> <directory>
# Writes PKGBUILD, polinetwork-esign.install and .SRCINFO to <directory>, and builds the package once from the
# release's files to check them. Needs base-devel and pacman-contrib.
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:?version, e.g. v1.2.3}" out="${2:?directory}"
pkgver="${version#v}"
mkdir -p "$out"
sed "s/^pkgver=.*/pkgver=$pkgver/" packaging/aur/PKGBUILD > "$out/PKGBUILD"
cd "$out"
# The release package's own install script (packaging/linux/postinstall.sh and preremove.sh, as nfpm wraps them).
pkg="polinetwork-esign-$pkgver-1-x86_64.pkg.tar.zst"
[ -f "$pkg" ] || curl -fsSLO "https://github.com/PoliNetworkOrg/esign/releases/download/$version/$pkg"
bsdtar -xOf "$pkg" .INSTALL > polinetwork-esign.install
updpkgsums
makepkg --printsrcinfo > .SRCINFO
makepkg --nodeps --force --noconfirm
rm -rf src pkg ./*.pkg.tar.zst
