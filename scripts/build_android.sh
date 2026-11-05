#!/usr/bin/env bash
# FLOW by Otium - Android APK Automated Build Script (Bash)
# 100% Pure Rust cross-compilation using cargo-apk & Slint

set -e

echo "========================================="
echo "  FLOW by Otium - Android Build Pipeline"
echo "========================================="

# 1. Check for cargo-apk
if ! command -v cargo-apk &> /dev/null; then
    echo "[!] cargo-apk not found. Installing via cargo..."
    cargo install cargo-apk
fi

# 2. Add ARM64 Android Target
echo "[*] Adding aarch64-linux-android target..."
rustup target add aarch64-linux-android

# 3. Compile APK
echo "[*] Compiling FLOW for Android (Release mode)..."
cargo apk build --release

echo "========================================="
echo "  Build Successful! Output APK:"
echo "  target/release/apk/otium-flow.apk"
echo "========================================="
