fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_owned());
        let mut res = winres::WindowsResource::new();
        res.set("CompanyName", "SysRemote");
        res.set("ProductName", "SysRemote");
        res.set("FileDescription", "SysRemote Viewer");
        res.set("OriginalFilename", "viewer.exe");
        res.set("InternalName", "viewer");
        res.set("ProductVersion", &version);
        res.set("FileVersion", &version);
        res.compile().unwrap();
    }
}
