#!/usr/bin/env bash
# Runs the whole test suite on Linux against SoftHSM2, in Docker: ./scripts/test-softhsm.sh [go test flags]
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -e GOFLAGS=-buildvcs=false -v "$PWD":/src -w /src -v sign-agent-gomod:/go/pkg/mod golang:1.26-bookworm bash -c '
set -euo pipefail
apt-get update -qq && apt-get install -y -qq softhsm2 opensc libpcsclite-dev >/dev/null
./scripts/softhsm-tests.sh "$@"
' bash "$@"
