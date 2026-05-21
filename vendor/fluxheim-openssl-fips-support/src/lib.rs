#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(ossl300))]
compile_error!("fluxheim-openssl-fips-support requires OpenSSL 3.0 or newer");

pub fn enable_default_properties_fips() -> Result<(), &'static str> {
    // SAFETY: Passing a null libctx selects OpenSSL's process-default library
    // context, which is the context used by Fluxheim's OpenSSL/Pingora TLS
    // setup. The call mutates OpenSSL's default property query and returns an
    // integer success code; no Rust references or owned buffers cross the FFI
    // boundary.
    let result =
        unsafe { openssl_sys::EVP_default_properties_enable_fips(std::ptr::null_mut(), 1) };
    if result == 1 {
        Ok(())
    } else {
        Err("EVP_default_properties_enable_fips returned failure")
    }
}

pub fn default_properties_fips_enabled() -> bool {
    // SAFETY: Passing a null libctx asks OpenSSL about the process-default
    // library context. The function is read-only from Rust's perspective and
    // returns a plain integer flag.
    unsafe { openssl_sys::EVP_default_properties_is_fips_enabled(std::ptr::null_mut()) == 1 }
}
