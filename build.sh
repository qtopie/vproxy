#!/usr/bin/env bash
# build.sh — cross-compile the vproxy binary for all release platforms.
#
# Usage: ./build.sh [version]
#
# Outputs dist/vproxy_<goos>_<goarch> (Windows: .exe) with the version
# injected via -ldflags, matching the releaser/scripts/publish.sh contract.
set -euo pipefail

VERSION="${1:-1.0.2}"
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dist"
mkdir -p "$OUT_DIR"

GOOSES="${GOOSES-linux darwin windows}"
ARCHES="${ARCHES-amd64 arm64}"

build() {
	local goos="$1" arch="$2" cc="$3" cgo="$4" out
	out="$OUT_DIR/vproxy_${goos}_${arch}"
	if [ "$goos" = "windows" ]; then out="${out}.exe"; fi
	echo ">> building ${goos}/${arch} (cgo=${cgo}) -> ${out}"
	GOOS="$goos" GOARCH="$arch" CGO_ENABLED="$cgo" ${cc:+CC="$cc"} go build \
		-ldflags "-s -w -X main.Version=${VERSION}" \
		-o "$out" ./cmd/vproxy
}

for goos in $GOOSES; do
	for arch in $ARCHES; do
		build "$goos" "$arch" "" 0
	done
done

echo "build complete: $OUT_DIR"
