(module
  ;; This policy is attached only to the configured admin route. Fluxheim
  ;; performs path and client classification before invoking the module.
  (func (export "fluxheim_access_decision") (result i32)
    i32.const 2))
