param(
    [switch]$Release,
    [string]$Target = 'aarch64-linux-android',
    [switch]$Universal
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Join-Path $PSScriptRoot '..')
foreach ($flowTool in @('cargo', 'cargo-apk', 'rustup', 'java')) {
    if (-not (Get-Command $flowTool -ErrorAction SilentlyContinue)) {
        throw "Required build tool is missing: $flowTool. See README.md."
    }
}
if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) { throw 'Configure ANDROID_HOME or ANDROID_SDK_ROOT first.' }
if ($Release -and (-not $env:CARGO_APK_RELEASE_KEYSTORE -or -not $env:CARGO_APK_RELEASE_KEYSTORE_PASSWORD)) {
    throw 'Set CARGO_APK_RELEASE_KEYSTORE and CARGO_APK_RELEASE_KEYSTORE_PASSWORD for the existing release key.'
}
$flowArguments = @('apk', 'build', '--lib')
if (-not $Universal) { $flowArguments += @('--target', $Target) }
if ($Release) { $flowArguments += '--release' }
& cargo @flowArguments
if ($LASTEXITCODE -ne 0) { throw "Android build failed with exit code $LASTEXITCODE" }
$flowProfile = if ($Release) { 'release' } else { 'debug' }
$flowApk = Join-Path (Get-Location) "target\$flowProfile\apk\otium_flow.apk"
if (-not (Test-Path -LiteralPath $flowApk)) { throw 'Cargo completed without the expected APK.' }
Write-Output $flowApk
