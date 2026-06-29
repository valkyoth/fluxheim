#[cfg(any())]
pub(crate) use fluxheim_common::path_safety::safe_forward_path;
#[cfg(feature = "cache")]
pub(crate) use fluxheim_common::path_safety::safe_forward_path_and_query;
