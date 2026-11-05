fn main() {
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
