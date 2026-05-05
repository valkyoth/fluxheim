# Pull Request

## Summary

Describe what changed and why.

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Refactor
- [ ] Dependency update
- [ ] Security hardening

## Checklist

- [ ] I kept the change scoped to Fluxheim's existing architecture.
- [ ] I updated docs, examples, or roadmap entries when behavior changed.
- [ ] I added or updated tests for behavior changes.
- [ ] I ran `cargo fmt --all --check`.
- [ ] I ran `cargo clippy --all-targets -- -D warnings`.
- [ ] I ran `cargo test`.
- [ ] I ran relevant feature builds or tests.
- [ ] I checked dependency/license impact when adding or updating crates.
- [ ] I did not commit secrets, private keys, tokens, local runtime data, or
      generated artifacts.

## Security Notes

Describe any security-sensitive impact. Mention request parsing, TLS, cache,
proxy routing, admin endpoints, logging, metrics, or dependency changes if they
are touched.

## Follow-Up

List any known remaining work or intentionally deferred tasks.
