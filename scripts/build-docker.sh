#!/usr/bin/env bash
# Builds the Linux (amd64, arm64) and Windows releases in Docker, from any host: ./scripts/build-docker.sh [version]
# The macOS app needs a Mac: ./scripts/build-macos.sh. VCS stamping is off: a git worktree is not usable in the container.
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
image=golang:1.26-bookworm
setup='apt-get update -qq && apt-get install -y -qq libpcsclite-dev zip gcc-mingw-w64-x86-64 >/dev/null && go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.48.0'
for platform in linux/amd64 linux/arm64; do
	docker run --rm --platform "$platform" -e GOFLAGS=-buildvcs=false -v "$PWD":/src -w /src -v "sign-agent-gomod-${platform#linux/}":/go/pkg/mod "$image" \
		bash -c "set -e; $setup; ./scripts/build-linux.sh '$version'"
done
docker run --rm --platform linux/amd64 -e GOFLAGS=-buildvcs=false -v "$PWD":/src -w /src -v sign-agent-gomod-amd64:/go/pkg/mod "$image" \
	bash -c "set -e; $setup; ./scripts/build-windows.sh '$version'"
