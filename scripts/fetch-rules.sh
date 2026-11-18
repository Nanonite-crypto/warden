#!/usr/bin/env bash
# Downloads the YARA Forge rule package pinned in rules/yara-forge.pin into
# rules/vendor/ and checks it against the pinned SHA-256. Nothing is kept if
# the checksum does not match.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin="$repo/rules/yara-forge.pin"
value() { sed -n "s/^$1[[:space:]]*=[[:space:]]*//p" "$pin" | tr -d '\r' | head -n 1; }
tag="$(value tag)"
package="$(value package)"
expected="$(value sha256)"
if [ -z "$tag" ] || [ -z "$package" ] || [ -z "$expected" ]; then
    echo "error: $pin does not name a tag, a package and a sha256" >&2
    exit 2
fi

target="$repo/rules/vendor/$package"
digest() { sha256sum "$1" | cut -d ' ' -f 1; }

if [ -f "$target" ] && [ "$(digest "$target")" = "$expected" ]; then
    echo "Already present: $target (YARA Forge $tag)"
    exit 0
fi

mkdir -p "$repo/rules/vendor"
url="https://github.com/YARAHQ/yara-forge/releases/download/$tag/$package"
echo "Downloading $url"
curl --fail --location --silent --show-error --output "$target.part" "$url"

actual="$(digest "$target.part")"
if [ "$actual" != "$expected" ]; then
    rm -f "$target.part"
    echo "error: the download does not match the pinned checksum" >&2
    echo "  expected $expected" >&2
    echo "  found    $actual" >&2
    echo "The package for this tag has changed, or the download was damaged. Nothing was kept." >&2
    exit 1
fi
mv "$target.part" "$target"
echo "Saved $target (YARA Forge $tag, checksum verified)"
