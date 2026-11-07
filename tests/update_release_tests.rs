//! Explicit release acceptance checks; ordinary tests do not contact GitHub.
use otium_flow::protocol::updater::{check_latest_release_for, UpdateTarget, CURRENT_VERSION};

#[tokio::test]
#[ignore = "Run explicitly after publishing the matching GitHub release"]
async fn published_release_updates_previous_installations_with_correct_packages() {
    for (target, suffix) in [
        (UpdateTarget::WindowsInstalled, "Setup-x64.exe"),
        (UpdateTarget::WindowsPortable, "Portable-x64.exe"),
        (UpdateTarget::AndroidArm64, "arm64-v8a.apk"),
        (UpdateTarget::AndroidX86_64, "universal.apk"),
    ] {
        let update = check_latest_release_for("2.4.0", target)
            .await
            .expect("Real GitHub HTTPS check must succeed")
            .expect("Published release must upgrade the previous release");
        assert_eq!(update.version, CURRENT_VERSION);
        assert!(update.asset_name.ends_with(suffix), "{}", update.asset_name);
        assert_eq!(update.sha256.len(), 64);
        assert!(update.asset_size > 0);
    }
    assert!(
        check_latest_release_for(CURRENT_VERSION, UpdateTarget::AndroidArm64)
            .await
            .expect("Check the running version against the real release")
            .is_none()
    );
}
