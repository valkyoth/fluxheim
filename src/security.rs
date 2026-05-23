/// Marker for builds compiled with Fluxheim's security profile feature.
///
/// This is intentionally not a runtime enforcement decision. Concrete
/// hardening remains in the modules that validate configuration, filesystem
/// trust, TLS policy, admin auth, and request handling.
pub fn feature_compiled_in() -> bool {
    true
}
