#!/usr/bin/env bash
# Publish a versioned artifact followed by its manifest, atomically.
# Never publish an unsigned APK or one signed with a different key.
set -euo pipefail
if [ "$#" -lt 4 ]; then
  echo 'Usage: publish-app-update.sh windows|android|android-debug VERSION CODE FILE [NOTES]' >&2
  exit 2
fi
platform=$1 version=$2 code=$3 artifact=$4 notes=${5:-Pembaruan aplikasi}
case "$platform" in windows) ext=exe;; android|android-debug) ext=apk;; *) exit 2;; esac
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$code" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ -f "$artifact" && "$artifact" == *."$ext" ]] || exit 2
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
dest="$repo/release-files"
mkdir -p "$dest"
name="PQC-PDF-Sign-$platform-$version.$ext"
manifest="$dest/$platform.json"
if [[ -f "$manifest" ]]; then
  previous=$(jq -r '.version_code' "$manifest")
  (( code > previous )) || { echo 'Version code must increase' >&2; exit 1; }
fi
[[ ! -e "$dest/$name" ]] || { echo 'Versioned artifact already exists' >&2; exit 1; }
size=$(stat -c %s "$artifact")
(( size > 0 && size <= 268435456 )) || exit 2
sha=$(sha256sum "$artifact"); sha=${sha%% *}
staged=$(mktemp "$dest/.publish-XXXXXX")
trap 'rm -f -- "$staged"' EXIT
cp -- "$artifact" "$staged"
chmod 644 "$staged"
mv -- "$staged" "$dest/$name"
staged=$(mktemp "$dest/.manifest-XXXXXX")
jq -n --arg platform "$platform" --arg version "$version" --argjson code "$code" \
  --arg path "/updates/$name" --arg sha "$sha" --argjson size "$size" --arg notes "$notes" \
  '{platform:$platform,version:$version,version_code:$code,path:$path,sha256:$sha,size:$size,notes:$notes}' > "$staged"
chmod 644 "$staged"
mv -- "$staged" "$manifest"
echo "Published https://136.244.116.132/updates/$name"
