# Flow 2.4.3 — AMOLED and verified in-app updates

This release includes the AMOLED UI and usability changes prepared for 2.4.2, plus a working update flow before publication.

## Interface and usability

- Pure black AMOLED canvas, dark translucent panels, silver text, clearer actions, bundled Arabic typography and RTL.
- Dedicated device page, offline received-file browsing, pairing-code paste, connection timeouts and retry guidance, stable list models and draft preservation.
- The canvas remains opaque black; panel styling does not imply live desktop backdrop blur.

## Updates

- Settings can check the official GitHub release and install only after an explicit click.
- HTTPS in Rust replaces the external curl dependency. Package selection matches installation type and Android ABI; exact size and GitHub SHA-256 digest are required.
- Android uses native DownloadManager and the system installer with a read-granted content URI. Package name, increasing version code, supported ABI and installed signing identity are checked first. The user controls installation permission and confirmation.
- Windows preserves the existing installer AppId and folder. A Rust helper coordinates installer handoff or portable replacement with rollback on replacement/relaunch failure and cleanup of its recorded backup after the new app shows its window.
- An atomic transfer gate prevents updates from racing with incoming or outgoing transfers. Failure resumes transfers; Android keeps them paused until restart or an explicit resume action after closing a cancelled installer.

## Compatibility

Existing Android release keys and package name are retained; version code is 16909315. Windows installer identity is unchanged. Installing over an existing compatible package preserves application data; uninstalling first is unnecessary.

Old clients cannot gain the new updater without first installing this release. If their previous update action fails, install the signed APK or Setup once over the current app. Future updates use the new in-app flow.

Protocol 3 remains compatible with 2.4.1 and 2.4.2. Devices on 2.4.0 or earlier must both upgrade and exchange pairing codes again.

Android build/signature checks do not establish installation behavior on a physical device. The system may still require user permission or reject an update for device-specific reasons; Flow reports failure rather than claiming success.
