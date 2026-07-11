(module
  (import "wasi_snapshot_preview1" "random_get"
    (func $random_get (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "fluxheim_access_decision") (result i32)
    i32.const 0
    i32.const 16
    call $random_get))
