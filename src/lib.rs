pub mod app;
pub mod clipboard;
pub mod platform;
pub mod protocol;
pub mod settings;
#[cfg(target_os = "android")]
mod update_android;
#[cfg(target_os = "windows")]
mod update_windows;
mod ux;
pub mod window_effects;

slint::include_modules!();

#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    if let Err(e) = slint::android::init(app) {
        eprintln!("[Flow Android] UI initialization failed: {e}");
        return;
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[Flow Android] Failed to create Tokio runtime: {:?}", e);
            return;
        }
    };

    let _guard = rt.enter();
    if let Err(e) = app::run(true) {
        eprintln!("[Flow Android] Mobile engine error: {:?}", e);
    }
}
