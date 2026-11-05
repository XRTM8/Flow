# FLOW by Otium - Android APK Automated Build Script (PowerShell)
# 100% Pure Rust cross-compilation using cargo-apk & Slint

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  FLOW by Otium - Android Build Pipeline" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. التحقق من وجود أداة cargo-apk
if (-not (Get-Command "cargo-apk" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] cargo-apk not found. Installing via cargo..." -ForegroundColor Yellow
    cargo install cargo-apk
}

# 2. إضافة معمارية الهواتف الذكية الأساسية (ARM64)
Write-Host "[*] Ensuring Rust Android target (aarch64-linux-android) is installed..." -ForegroundColor Green
rustup target add aarch64-linux-android

# 3. التحقق من مسار Android NDK و SDK
if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) {
    Write-Host "[WARNING] Neither ANDROID_HOME nor ANDROID_SDK_ROOT is set." -ForegroundColor Yellow
    Write-Host "          Ensure Android SDK/NDK are configured in your environment." -ForegroundColor Yellow
}

# 4. بناء حزمة الـ APK
Write-Host "[*] Compiling FLOW for Android (Release mode)..." -ForegroundColor Green
cargo apk build --release

if ($LASTEXITCODE -eq 0) {
    Write-Host "=========================================" -ForegroundColor Green
    Write-Host "  Build Successful! Output APK:" -ForegroundColor Green
    Write-Host "  target/release/apk/otium-flow.apk" -ForegroundColor White
    Write-Host "=========================================" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Android build failed with exit code $LASTEXITCODE" -ForegroundColor Red
}
