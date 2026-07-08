(module
  (import "fluxheim_policy_v1" "context" (func $context (param i32 i32) (result i32)))
  (import "fluxheim_policy_v1" "set_cache_ttl" (func $set_cache_ttl (param i32 i32) (result i32)))
  (import "fluxheim_policy_v1" "add_cache_tag" (func $add_cache_tag (param i32 i32) (result i32)))
  (import "fluxheim_policy_v1" "set_cache_store_header" (func $set_cache_store_header (param i32 i32) (result i32)))

  (func (export "fluxheim_cache_store") (result i32)
    i32.const 6
    i32.const 0
    call $context
    i32.const 7
    i32.eq
    if
      i32.const 1
      i32.const 0
      call $set_cache_ttl
      drop

      i32.const 1
      i32.const 0
      call $add_cache_tag
      drop

      i32.const 1
      i32.const 1
      call $set_cache_store_header
      drop
    end

    i32.const 0))
