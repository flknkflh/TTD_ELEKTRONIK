#!/usr/bin/env sh
# build-aar.sh — build core/mobilebridge into apps/android/app/libs/pqcsign.aar
# (Rencana V1 §10.2). Run from anywhere; paths are resolved relative to this file.
#
# Pinned toolchain — do NOT use @latest on a release pipeline (§10.2). Bump
# these deliberately and record the change in docs/toolchain.md.
set -eu

GOMOBILE_VERSION="v0.0.0-20260821190718-4776eadac327"   # golang.org/x/mobile
ANDROID_API="29"                                        # min native API (§21)
TARGET="android/arm64"
JAVAPKG="id.example.pqcsign"                            # replace with real org before release

here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
core="$here/../../core"
out="$here/app/libs/pqcsign.aar"

: "${ANDROID_HOME:?set ANDROID_HOME to your Android SDK}"
: "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an NDK that supports API 21..35 (e.g. r27)}"

export PATH="$PATH:$(go env GOPATH)/bin"
go install "golang.org/x/mobile/cmd/gomobile@${GOMOBILE_VERSION}"
go install "golang.org/x/mobile/cmd/gobind@${GOMOBILE_VERSION}"
gomobile init

mkdir -p "$here/app/libs"
cd "$core"
# The `tool golang.org/x/mobile/cmd/gobind` directive in core/go.mod satisfies
# gomobile's "x/mobile must be in the module graph" requirement.
gomobile bind \
  -androidapi "$ANDROID_API" \
  -target="$TARGET" \
  -javapkg="$JAVAPKG" \
  -o "$out" \
  ./mobilebridge

echo "built $out"
ls -la "$here/app/libs/"
