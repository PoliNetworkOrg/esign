#!/usr/bin/env bash
# Builds the APT and DNF repositories served at https://polinetworkorg.github.io/esign from a release's packages:
# ./scripts/linux-repository.sh <dist> <site>
# Signs the .rpm files in <dist> in place and the repository metadata with the GPG key $GPG_KEY_ID, whose public half
# is packaging/linux/repository-key.asc (docs/linux-packages.md). Needs gnupg, apt-utils, createrepo-c and rpm.
set -euo pipefail
cd "$(dirname "$0")/.."
dist="$(realpath "${1:?dist}")" site="${2:?site}"
key="${GPG_KEY_ID:?GPG_KEY_ID}"
rm -rf "$site" && mkdir -p "$site/apt/pool/main" "$site/rpm"
site="$(realpath "$site")"
cp packaging/linux/repository-key.asc "$site/polinetwork-esign.asc"
# For `dnf config-manager addrepo` before the package, and its key, are installed.
sed 's|^gpgkey=.*|gpgkey=https://polinetworkorg.github.io/esign/polinetwork-esign.asc|' \
	packaging/linux/repository/polinetwork-esign.repo > "$site/polinetwork-esign.repo"

for rpm in "$dist"/*.rpm; do
	rpmsign --addsign --define "__gpg $(command -v gpg)" --define "_gpg_name $key" --define "_gpg_digest_algo sha256" "$rpm"
done
cp "$dist"/*.rpm "$site/rpm/"
createrepo_c --quiet "$site/rpm"
gpg --batch --yes --local-user "$key" --armor --detach-sign "$site/rpm/repodata/repomd.xml"

cp "$dist"/*.deb "$site/apt/pool/main/"
cd "$site/apt"
for arch in amd64 arm64; do
	mkdir -p "dists/stable/main/binary-$arch"
	apt-ftparchive --arch "$arch" packages pool > "dists/stable/main/binary-$arch/Packages"
	gzip -9kn "dists/stable/main/binary-$arch/Packages"
done
apt-ftparchive \
	-o APT::FTPArchive::Release::Origin="PoliNetwork" \
	-o APT::FTPArchive::Release::Label="PoliNetwork eSign" \
	-o APT::FTPArchive::Release::Suite=stable \
	-o APT::FTPArchive::Release::Codename=stable \
	-o APT::FTPArchive::Release::Architectures="amd64 arm64" \
	-o APT::FTPArchive::Release::Components=main \
	release dists/stable > dists/stable/Release.tmp
mv dists/stable/Release.tmp dists/stable/Release
gpg --batch --yes --local-user "$key" --clearsign --output dists/stable/InRelease dists/stable/Release
gpg --batch --yes --local-user "$key" --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
