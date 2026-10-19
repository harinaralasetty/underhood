#!/bin/sh
# Build release archives for every supported platform into dist/, with SHA-256 checksums.
# Usage: scripts/release-build.sh <version>      e.g. scripts/release-build.sh 0.1.0
set -eu
version=${1:?usage: scripts/release-build.sh <version>}
out=dist
rm -rf "$out"
mkdir -p "$out"
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
	goos=${target%/*}
	goarch=${target#*/}
	name="underhood_${version}_${goos}_${goarch}"
	ext=""
	[ "$goos" = windows ] && ext=".exe"
	mkdir -p "$out/$name"
	CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath \
		-ldflags "-s -w -X github.com/harinaralasetty/underhood/internal/model.Version=$version" \
		-o "$out/$name/underhood$ext" ./cmd/underhood
	cp LICENSE README.md CHANGELOG.md "$out/$name/"
	if [ "$goos" = windows ]; then
		(cd "$out" && zip -qr "$name.zip" "$name")
	else
		tar -C "$out" -czf "$out/$name.tar.gz" "$name"
	fi
	rm -rf "${out:?}/$name"
done
(cd "$out" && shasum -a 256 underhood_* >checksums.txt)
ls "$out"
