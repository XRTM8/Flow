# Flow 2.4.2 validation

Base revision: `6dfab3e652dcaee20b27cf2b174a837c20cb6c39`.

## Completed checks

- Windows `cargo check --offline --locked` passed.
- `cargo test --offline --locked --lib --tests`: **37 passed, 0 failed**; one optional throughput benchmark intentionally ignored. Loopback access was allowed and TEMP/TMP pointed into `target/test-tmp`.
- Coverage includes encrypted file/text transfers and acknowledgements, wrong keys and revoked devices, legacy plaintext rejection, bounded frames, replay rejection, integrity failure cleanup, independent cancellation/concurrency, filename collisions/Unicode/empty files, history/settings persistence, and discovery echo-loop/bounded-peer regressions.
- Android ARM64 library cross-check passed against the installed SDK/NDK. Signed ARM64 and ARM64/x86_64 release packages are checked for version/code, native libraries, embedded license notices, and the same signer as 2.4.1. Android ELF LOAD segments use verified 16 KB alignment; this is an artifact check, not a physical-device test.
- Windows UI observed in English and Arabic RTL, light/dark themes, and the mobile layout. Actual Arabic text and file transfers between isolated desktop/mobile previews passed. The final AMOLED palette was checked by the headless renderer; interactive reinspection was stopped with Escape before it began.
- A headless software-rendering test draws **84 frames** across seven pages, light/dark themes, English/Arabic, desktop/mobile sizes, and empty/populated models. It exercises runtime intrinsic layout and catches recursion that UI compilation alone misses. The test passed again after the final AMOLED palette change.
- Additional tests cover stable list updates, focused device identity, and actionable connection feedback. The bundled Noto Sans Arabic font supplies Arabic glyphs without depending on installed fonts.
- Slint compilation has no layout binding-loop warnings. UI rows expose accessible controls and disabled actions.
- PowerShell build script parser, Bash `-n`, and Python packaging script parser passed.
- Binary patch validation extracts the untouched base archive, checks and applies the patch, and compares every changed file against the working tree (Git-normalized text / exact binary content). Existing Git index and user files are not modified.

## Reproduction

```powershell
cargo check --locked
cargo test --locked --lib --tests
cargo build --locked --release
python scripts/package_patch.py
```

The patch includes all new UI/controller files and the font/license assets. The pre-existing untracked `release_notes_v2.3.0.md`, private signing keys, preview/test data, and generated binaries are excluded.

## Distribution

Artifacts are prepared in `dist/` with SHA-256 checksums in `SHA256SUMS-v2.4.2.txt`. The Windows package and Android assets include the font OFL and project GPL notices. Android packages use the existing release signing identity; no replacement production key is generated.

The source patch is cumulative relative to the 2.4.0 base revision above. Apply it to a clean copy of that revision with `git apply --check Flow-v2.4.2.patch`, followed by `git apply Flow-v2.4.2.patch`.

## Practical limits

- Devices on 2.4.0 or earlier must be updated and paired again. Devices already paired on 2.4.1 remain compatible. Retry starts the file from its beginning; images are sent as files rather than the removed clipboard-image wire path.
- AMOLED is the default for new settings; existing saved appearance choices are preserved. The pure black canvas is opaque. Translucent panel styling does not imply live backdrop blur on Android or unsupported Windows systems.
- Android permissions, clipboard access, file export, keyboard/insets, and manufacturer-specific storage behavior need confirmation on a physical device. Desktop mobile preview and cross-compilation do not establish those device behaviors.
- MediaStore Downloads export is available on Android 10+; older supported devices retain received files in Flow storage. Shared-folder access remains subject to Android permissions and scoped storage.
- No throughput or memory guarantee is inferred from the tests. The new pairing protocol uses preshared secrets and makes no forward-secrecy claim.
- The checks above validate the worktree, patch, and release artifacts. GitHub publication is a separate step, performed only when requested, with the release tag pointing to the matching source commit.
