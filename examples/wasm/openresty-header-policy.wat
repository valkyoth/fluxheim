(module
  (import "fluxheim_policy_v1" "context"
    (func $context (param i32 i32) (result i32)))
  (import "fluxheim_policy_v1" "set_request_header"
    (func $set_request_header (param i32 i32) (result i32)))
  (import "fluxheim_policy_v1" "set_response_header"
    (func $set_response_header (param i32 i32) (result i32)))
  (import "fluxheim_policy_v1" "remove_response_header"
    (func $remove_response_header (param i32 i32) (result i32)))

  (func (export "fluxheim_request_headers") (result i32)
    ;; Context field 1 is Fluxheim's bounded path class. Class 3 is /gold.
    i32.const 1
    i32.const 0
    call $context
    i32.const 3
    i32.eq
    if
      ;; Header ID 1 is x-policy-tier; value ID 4 is gold.
      i32.const 1
      i32.const 4
      call $set_request_header
      drop
    else
      ;; Value ID 1 is standard.
      i32.const 1
      i32.const 1
      call $set_request_header
      drop
    end
    i32.const 0)

  (func (export "fluxheim_response_headers") (result i32)
    ;; Header ID 2 is x-fluxheim-policy-branch; value ID 4 is gold.
    i32.const 2
    i32.const 4
    call $set_response_header
    drop
    ;; Removable response-header ID 3 is x-powered-by.
    i32.const 3
    i32.const 0
    call $remove_response_header
    drop
    i32.const 0))
