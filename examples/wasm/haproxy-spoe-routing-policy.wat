(module
  (import "fluxheim_policy_v1" "context"
    (func $context (param i32 i32) (result i32)))

  (func (export "fluxheim_route_decision") (result i32)
    ;; Context field 3 reports the bounded x-mirror: 1 signal. Decision 3
    ;; selects only an already configured matching route named "mirror".
    i32.const 3
    i32.const 0
    call $context
    i32.const 1
    i32.eq
    if (result i32)
      i32.const 3
    else
      ;; Context field 2 reports x-canary: 1. Decision 1 selects only an
      ;; already configured matching route named "canary".
      i32.const 2
      i32.const 0
      call $context
      i32.const 1
      i32.eq
      if (result i32)
        i32.const 1
      else
        i32.const 0
      end
    end))
