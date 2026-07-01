use super::backend::{BackendIdentity, RuntimeBackend as Backend};

pub(super) fn weighted_backend_indices(backends: &[Backend]) -> Vec<usize> {
    let mut weighted = Vec::new();
    for (index, backend) in backends.iter().enumerate() {
        weighted.extend(std::iter::repeat_n(index, backend.weight().max(1)));
    }
    weighted
}
