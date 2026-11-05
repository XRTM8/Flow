pub mod clipboard;
pub mod mobile_engine;
pub mod protocol;

slint::include_modules!();

#[cfg(target_os = "android")]
#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    let _ = slint::android::init(app);
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
    if let Err(e) = mobile_engine::start_mobile_engine() {
        eprintln!("[Flow Android] Mobile engine error: {:?}", e);
    }
}
