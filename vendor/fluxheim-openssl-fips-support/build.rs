use std::env;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ossl300)");

    let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") else {
        return;
    };
    let Ok(version) = u64::from_str_radix(&version, 16) else {
        return;
    };
    if version >= 0x3_00_00_00_0 {
        println!("cargo:rustc-cfg=ossl300");
    }
}
