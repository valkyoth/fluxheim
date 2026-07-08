(module
  (import "fluxheim_policy_v1" "context" (func $context (param i32 i32) (result i32)))
  (import "fluxheim_policy_v1" "set_cache_key_component" (func $set_cache_key_component (param i32 i32) (result i32)))

  (func (export "fluxheim_cache_lookup") (result i32)
    (local $device_class i32)
    i32.const 5
    i32.const 0
    call $context
    local.set $device_class

    local.get $device_class
    i32.const 0
    i32.ne
    if
      i32.const 1
      local.get $device_class
      call $set_cache_key_component
      drop
    end

    i32.const 0))
