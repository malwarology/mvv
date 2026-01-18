#!/usr/bin/env bash
set -euo pipefail

VERSION="$(git describe --tags --exact-match)"
LDFLAGS="-s -w -X main.toolVersion=${VERSION}"

mkdir -p dist

GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o dist/mvv-linux-amd64
GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="$LDFLAGS" -o dist/mvv-linux-arm64
GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o dist/mvv-darwin-amd64
GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="$LDFLAGS" -o dist/mvv-darwin-arm64
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o dist/mvv-windows-amd64.exe
