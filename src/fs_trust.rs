#[cfg(unix)]
#[allow(unused_imports)]
pub(crate) use fluxheim_config::fs_trust::{
    existing_parent_has_insecure_write_permissions,
    existing_path_or_parent_has_insecure_write_permissions,
};

#[cfg(not(unix))]
compile_error!(
    "Fluxheim filesystem trust checks require a Unix target; implement platform ACL and ownership checks before enabling non-Unix builds"
);
