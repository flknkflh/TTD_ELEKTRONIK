#!/usr/bin/env bash
# Build every V1 artifact that can be produced on this machine into
# dist/release/, with SBOMs and SHA256SUMS.txt (Rencana V1 §27, §30).
#
#   tools/release-local.sh [version]
#
# The release pipeline (.github/workflows/release.yml) does the same on tagged
# runners, plus the Wails installer, the signed Android release APK, and the
# server container image.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="$ROOT/dist/release"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;; *) EXE="" ;; esac

rm -rf "$OUT" && mkdir -p "$OUT"
echo ">> version $VERSION -> $OUT"

echo ">> Go binaries"
( cd apps/windows && go build -trimpath -ldflags "-s -w" -o "$OUT/pqcsign-cli$EXE" ./cmd/pqcsign-cli )
( cd tools/ca-admin && go build -trimpath -ldflags "-s -w" -o "$OUT/ca-admin$EXE" . )
( cd server && go build -trimpath -ldflags "-s -w" -o "$OUT/pqc-api$EXE" ./cmd/api )
( cd apps/windows && GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o "$OUT/PQC-PDF-Sign-CLI-x64.exe" ./cmd/pqcsign-cli )

echo ">> Android debug APK (release APK needs a signing keystore -> see release.yml)"
if command -v java >/dev/null 2>&1 && [ -n "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}" ]; then
  ( cd apps/android && ./gradlew -q :app:assembleDebug )
  cp apps/android/app/build/outputs/apk/debug/app-debug.apk "$OUT/PQC-PDF-Sign-V1-debug.apk"
else
  echo "   (skipped: JDK / ANDROID_HOME not set)"
fi

echo ">> SBOM (CycloneDX)"
if ! command -v cyclonedx-gomod >/dev/null 2>&1; then
  go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest || true
fi
if command -v cyclonedx-gomod >/dev/null 2>&1; then
  for m in core server apps/windows tools/ca-admin; do
    name=$(echo "$m" | tr '/' '-')
    ( cd "$m" && cyclonedx-gomod mod -json -output "$OUT/sbom-$name.cdx.json" ) || true
  done
else
  echo "   (skipped: cyclonedx-gomod unavailable)"
fi

echo ">> third-party notices"
cp LICENSES/THIRD_PARTY_NOTICES.md "$OUT/"

echo ">> SHA256SUMS.txt"
( cd "$OUT" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt )

echo
echo "release bundle:"
ls -la "$OUT"
echo
echo "NOTE: nothing here is code-signed. Authenticode (.exe) and the Android"
echo "release keystore are applied only by the CI release job, from secret"
echo "storage (§27) — never from the repo."
