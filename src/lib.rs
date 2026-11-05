pub mod clipboard;
pub mod protocol;

#[cfg(target_os = "android")]
slint::include_modules!();

#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    let _ = slint::android::init(app);
    if let Ok(main_window) = MobileApp::new() {
        let _ = main_window.run();
    }
}
