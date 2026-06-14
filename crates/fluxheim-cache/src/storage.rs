use std::any::Any;
use std::io;

use async_trait::async_trait;
use bytes::Bytes;

use crate::{FluxCacheKeyParts, FluxCacheMissFinish, FluxCachePurgeType};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SerializedCacheMeta {
    pub internal_meta: Vec<u8>,
    pub response_header: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct FluxCacheTrace;

pub type FluxCacheHitHandler = Box<dyn FluxHandleHit + Sync + Send>;
pub type FluxCacheMissHandler = Box<dyn FluxHandleMiss + Sync + Send>;

#[async_trait]
pub trait FluxCacheStorage {
    async fn lookup(
        &'static self,
        key: &FluxCacheKeyParts,
        trace: FluxCacheTrace,
    ) -> io::Result<Option<(SerializedCacheMeta, FluxCacheHitHandler)>>;

    async fn get_miss_handler(
        &'static self,
        key: &FluxCacheKeyParts,
        meta: &SerializedCacheMeta,
        trace: FluxCacheTrace,
    ) -> io::Result<FluxCacheMissHandler>;

    async fn purge(
        &'static self,
        combined_key: &str,
        purge_type: FluxCachePurgeType,
        trace: FluxCacheTrace,
    ) -> io::Result<bool>;

    async fn update_meta(
        &'static self,
        key: &FluxCacheKeyParts,
        meta: &SerializedCacheMeta,
        trace: FluxCacheTrace,
    ) -> io::Result<bool>;

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static);
}

#[async_trait]
pub trait FluxHandleHit {
    async fn read_body(&mut self) -> io::Result<Option<Bytes>>;

    async fn finish(
        self: Box<Self>,
        key: &FluxCacheKeyParts,
        trace: FluxCacheTrace,
    ) -> io::Result<()>;

    fn can_seek(&self) -> bool {
        false
    }

    fn can_seek_multipart(&self) -> bool {
        self.can_seek()
    }

    fn seek(&mut self, _start: usize, _end: Option<usize>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cache hit handler does not support seek",
        ))
    }

    fn seek_multipart(&mut self, start: usize, end: Option<usize>) -> io::Result<()> {
        self.seek(start, end)
    }

    fn should_count_access(&self) -> bool {
        true
    }

    fn get_eviction_weight(&self) -> usize {
        0
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync);

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync);
}

#[async_trait]
pub trait FluxHandleMiss {
    async fn write_body(&mut self, data: Bytes, eof: bool) -> io::Result<()>;

    async fn finish(self: Box<Self>) -> io::Result<FluxCacheMissFinish>;

    fn streaming_write_tag(&self) -> Option<&[u8]> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FluxCacheHitHandler, FluxCacheMissHandler, FluxCacheStorage, FluxCacheTrace, FluxHandleHit,
        FluxHandleMiss, SerializedCacheMeta,
    };
    use crate::{FluxCacheKeyParts, FluxCacheMissFinish, FluxCachePurgeType};
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::io;

    struct EmptyHit;

    #[async_trait]
    impl FluxHandleHit for EmptyHit {
        async fn read_body(&mut self) -> io::Result<Option<Bytes>> {
            Ok(None)
        }

        async fn finish(
            self: Box<Self>,
            _key: &FluxCacheKeyParts,
            _trace: FluxCacheTrace,
        ) -> io::Result<()> {
            Ok(())
        }

        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }

        fn as_any_mut(&mut self) -> &mut (dyn std::any::Any + Send + Sync) {
            self
        }
    }

    struct EmptyMiss;

    #[async_trait]
    impl FluxHandleMiss for EmptyMiss {
        async fn write_body(&mut self, _data: Bytes, _eof: bool) -> io::Result<()> {
            Ok(())
        }

        async fn finish(self: Box<Self>) -> io::Result<FluxCacheMissFinish> {
            Ok(FluxCacheMissFinish::Created(0))
        }
    }

    struct MemoryOnlyStorage;

    #[async_trait]
    impl FluxCacheStorage for MemoryOnlyStorage {
        async fn lookup(
            &'static self,
            _key: &FluxCacheKeyParts,
            _trace: FluxCacheTrace,
        ) -> io::Result<Option<(SerializedCacheMeta, FluxCacheHitHandler)>> {
            Ok(Some((
                SerializedCacheMeta {
                    internal_meta: vec![1],
                    response_header: vec![2],
                },
                Box::new(EmptyHit),
            )))
        }

        async fn get_miss_handler(
            &'static self,
            _key: &FluxCacheKeyParts,
            _meta: &SerializedCacheMeta,
            _trace: FluxCacheTrace,
        ) -> io::Result<FluxCacheMissHandler> {
            Ok(Box::new(EmptyMiss))
        }

        async fn purge(
            &'static self,
            _combined_key: &str,
            _purge_type: FluxCachePurgeType,
            _trace: FluxCacheTrace,
        ) -> io::Result<bool> {
            Ok(true)
        }

        async fn update_meta(
            &'static self,
            _key: &FluxCacheKeyParts,
            _meta: &SerializedCacheMeta,
            _trace: FluxCacheTrace,
        ) -> io::Result<bool> {
            Ok(true)
        }

        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync + 'static) {
            self
        }
    }

    static STORAGE: MemoryOnlyStorage = MemoryOnlyStorage;

    #[tokio::test]
    async fn storage_trait_is_transport_neutral() {
        let key = FluxCacheKeyParts::new("primary", "combined", "tag");
        let (meta, mut hit) = STORAGE
            .lookup(&key, FluxCacheTrace)
            .await
            .unwrap()
            .expect("hit");
        assert_eq!(meta.internal_meta, [1]);
        assert_eq!(meta.response_header, [2]);
        assert_eq!(hit.read_body().await.unwrap(), None);
        hit.finish(&key, FluxCacheTrace).await.unwrap();

        let mut miss = STORAGE
            .get_miss_handler(&key, &meta, FluxCacheTrace)
            .await
            .unwrap();
        miss.write_body(Bytes::from_static(b"body"), true)
            .await
            .unwrap();
        assert_eq!(
            miss.finish().await.unwrap(),
            FluxCacheMissFinish::Created(0)
        );
        assert!(
            STORAGE
                .purge("combined", FluxCachePurgeType::Invalidation, FluxCacheTrace)
                .await
                .unwrap()
        );
        assert!(
            STORAGE
                .update_meta(&key, &meta, FluxCacheTrace)
                .await
                .unwrap()
        );
    }
}
