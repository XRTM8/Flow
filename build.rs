fn main() {
    // NDK r27 and earlier need explicit alignment for Android 16 KB pages.
    // These affect Android binaries only; shared dependencies are linked statically.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-link-arg=-Wl,-z,max-page-size=16384");
        println!("cargo:rustc-link-arg=-Wl,-z,common-page-size=16384");
    }
    slint_build::compile("ui/main.slint").unwrap();

    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "FLOW by Otium");
        res.set("FileDescription", "FLOW by Otium Peer-to-Peer Sync");
        res.set("LegalCopyright", "Copyright (c) 2026 Otium");
        let _ = res.compile();
    }
}
