#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
profile=debug
universal=false
for arg in "$@"; do
  case "$arg" in
    --release) profile=release ;;
    --universal) universal=true ;;
    *) echo "Usage: $0 [--release] [--universal]" >&2; exit 2 ;;
  esac
done
args=(apk build --lib)
if [[ "$universal" == false ]]; then args+=(--target aarch64-linux-android); fi
if [[ "$profile" == release ]]; then args+=(--release); fi
command -v cargo-apk >/dev/null || { echo 'Install cargo-apk first; see README.md.' >&2; exit 1; }
[[ -n "${ANDROID_HOME:-}${ANDROID_SDK_ROOT:-}" ]] || { echo 'Configure the Android SDK first.' >&2; exit 1; }
if [[ "$profile" == release ]]; then
  : "${CARGO_APK_RELEASE_KEYSTORE:?Set the existing release keystore path}"
  : "${CARGO_APK_RELEASE_KEYSTORE_PASSWORD:?Set its password in the build environment}"
fi
cargo "${args[@]}"
test -f "target/$profile/apk/otium_flow.apk"
printf '%s\n' "$PWD/target/$profile/apk/otium_flow.apk"
