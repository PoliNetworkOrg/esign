#!/usr/bin/env bash
# Interop harness: the official CIE middleware (built from source), OpenCIE and the agent's own providers against
# the card simulator, through real pcsc-lite and the vsmartcard vpcd virtual reader, in Docker (linux/amd64).
# Usage: ./scripts/interop/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
docker build --platform linux/amd64 -t esign-interop scripts/interop
docker run --rm --platform linux/amd64 -v "$PWD":/src \
	-v esign-gomod-amd64:/go/pkg/mod -v esign-gocache-amd64:/root/.cache/go-build \
	esign-interop ./scripts/interop/in-container.sh
