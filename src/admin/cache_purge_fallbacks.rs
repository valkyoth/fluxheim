use super::*;

impl AdminApp {
    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_purge_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _host: Option<&str>,
        _method: Option<&str>,
        _path: Option<&str>,
        _query: Option<&str>,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_purge_bulk_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _host: Option<&str>,
        _method: Option<&str>,
        _paths: Vec<&str>,
        _query: Option<&str>,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_purge_index_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _soft: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_purge_prefix_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _path_prefix: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _soft: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_purge_tag_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _cache_tag: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _soft: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_purge_stale_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _dry_run: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }

    #[cfg(not(feature = "cache"))]
    pub(super) fn cache_purge_wildcard_response(
        &self,
        _vhost: Option<&str>,
        _route: Option<&str>,
        _path_pattern: Option<&str>,
        _limit: Option<&str>,
        _batches: Option<&str>,
        _soft: bool,
    ) -> AdminResponse {
        error_response(StatusCode::BAD_REQUEST, "cache support is not compiled in")
    }
}
