#!/usr/bin/env bash
set -euo pipefail

VERSION="$(git describe --tags --exact-match)"

go build -trimpath \
  -ldflags="-s -w -X main.toolVersion=${VERSION}" \
  -o mvv
