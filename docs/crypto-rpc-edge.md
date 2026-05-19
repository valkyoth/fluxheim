# Crypto RPC Edge

Status: future optional module family.

The crypto RPC edge track is a future Fluxheim module family for running
blockchain-aware RPC gateways in front of local nodes or hosted-compatible
upstreams. It should be designed as focused compile-time modules, not as part of
the default web/proxy build.

The first concrete target is `eth`: native Ethereum/EVM JSON-RPC reverse
proxying, bounded caching, and node-health-aware routing. A later `eth-ens`
review can evaluate ENS contenthash routing, but that should remain separate
until the Ethereum RPC edge module is stable. Bitcoin, Cardano, and XRPL can use
the same broad architecture later, but their finality, method policy, and
transport models are different enough that they should be separate modules.

## Family Shape

Long-term feature shape:

```toml
chain-edge-core = ["proxy", "cache", "dep:serde_json", "dep:sha2"]
eth = ["chain-edge-core"]
eth-ens = ["eth"] # planned review only; exact dependencies not selected yet
eth-verify = ["eth"] # future proof-verification/co-processing review
btc = ["chain-edge-core"] # future review
ada = ["chain-edge-core"] # future review
xrpl = ["chain-edge-core"] # future review
profile-ethereum-rpc = ["proxy", "cache", "eth", "tls-rustls", "security"]
profile-ethereum-verified-rpc = [
  "proxy",
  "cache",
  "eth",
  "eth-verify",
  "tls-rustls",
  "security",
]
```

`chain-edge-core` should hold only shared primitives:

- bounded JSON-RPC request parsing;
- batch limits;
- method policy dispatch;
- cache-key framework;
- upstream health snapshots;
- retry safety classification;
- no-secret logging/tracing helpers;
- WebSocket sticky-routing primitives.

It must not contain Ethereum-, Bitcoin-, Cardano-, or XRPL-specific cache
rules. Each chain module owns its own method allow-list, finality model, cache
admission rules, health probes, and WebSocket/subscription behavior.

## Why Ethereum First

Ethereum/EVM is the cleanest first target because dApps commonly use standard
HTTP/WebSocket JSON-RPC, redundant POST traffic is common, and the execution API
exposes block tags such as `finalized`, `safe`, `latest`, and `pending`. Those
tags make cache safety easier to reason about than a generic blockchain proxy.

## Compile-Time Shape

Initial Ethereum-focused feature shape:

```toml
eth = ["proxy", "cache", "dep:serde_json", "dep:sha2"]
eth-ens = ["eth"] # planned review only; exact dependencies not selected yet
profile-ethereum-rpc = ["proxy", "cache", "eth", "tls-rustls", "security"]
```

`eth` and any future crypto RPC module must remain absent from default, PHP,
static-site, cache-edge, proxy-edge, privacy, and load-balancer builds unless
selected explicitly. The default reverse proxy must not parse JSON-RPC bodies or
pull chain-specific dependencies.

Possible later dependencies, after license/advisory review:

- `alloy-rpc-types` or narrow Alloy crates for Ethereum JSON-RPC types;
- `alloy-provider` only if Fluxheim needs client-side calls beyond simple
  health probes;
- a small local JSON-RPC classifier if the supported cacheable method set
  stays narrow enough to audit.

Avoid exposing third-party Ethereum types in public Fluxheim config. Config
should stay plain TOML with strings, numbers, durations, and byte sizes.

`eth-verify` must be a separate compile-time feature because proof verification
adds consensus, trie, precompile, and ZK-related dependencies that should not be
pulled into a normal RPC cache/proxy build.

## Basic Config Model

Candidate vhost-level config:

```toml
[[vhosts]]
name = "eth-mainnet"
hosts = ["rpc.example.test"]

[vhosts.eth]
enabled = true
chain_id = 1
upstreams = ["reth-a:8545", "erigon-b:8545"]
max_json_body_bytes = "2MiB"
cache_enabled = true
cache_finalized = true
finality_depth = 64
health_poll_secs = 5
health_max_block_lag = 3
retry_on_rpc_error = true
websocket_enabled = false
```

Route-scoped `eth` config may be useful later, but the first implementation
should keep one `eth` policy per vhost to reduce routing ambiguity and cache
key mistakes.

## HTTP JSON-RPC Request Handling

Stable first scope:

- Accept `POST` requests with bounded JSON bodies only.
- Require `Content-Type` compatible with JSON unless an explicit compatibility
  flag is enabled.
- Parse JSON-RPC 2.0 single calls and batched calls.
- Reject or pass through malformed JSON according to policy:
  - strict mode rejects malformed JSON before upstream;
  - compatibility mode passes malformed requests to upstream without caching.
- Build cache keys from chain id, method, normalized params, and finality state.
- Never cache responses with JSON-RPC `error` unless an explicit method policy
  says the error is immutable and safe.
- Normalize upstream response handling so Fluxheim can remove hop-by-hop
  headers and apply existing response policy.
- Support multi-provider upstream pools so applications are not coupled to one
  centralized RPC provider.

Batch behavior should be conservative. A batch is cacheable only when every
call in the batch is individually cacheable under the current policy. Mixed
cacheable/non-cacheable batches should pass through without storing, or be split
only after a later design proves response ordering and error behavior.

## Cacheable Method Policy

Ethereum JSON-RPC is POST-heavy, so normal HTTP cache semantics are not enough.
The `eth` module should cache only methods whose result can be tied to an
immutable identifier, a finalized/safe tag, or an old-enough block number.

Initial cacheable candidates:

- `eth_getBlockByHash`
- `eth_getBlockByNumber` when the block parameter is:
  - an explicit block number older than the configured finality depth;
  - `finalized`;
  - optionally `safe`, with a shorter TTL than finalized;
- `eth_getBlockTransactionCountByHash`
- `eth_getBlockTransactionCountByNumber` under the same block-number policy;
- `eth_getTransactionByHash`, with conservative TTL and optional negative-cache
  controls;
- `eth_getTransactionReceipt`, with conservative TTL until finalized and long
  TTL after the containing block is known finalized;
- `eth_getLogs` only when the block range is bounded and entirely finalized or
  older than the configured finality depth.

Do not cache in the first stable implementation:

- `eth_sendRawTransaction`, `eth_sendTransaction`, signing methods, account
  methods, txpool/debug/admin methods;
- `eth_call`, `eth_estimateGas`, `eth_feeHistory`, `eth_gasPrice`, and
  priority-fee methods, unless a later method policy includes explicit block
  tags and TTL rules;
- requests using `latest` or `pending`, except where a method has an explicit
  short-lived local policy;
- WebSocket subscription messages.

The execution API distinguishes `finalized`, `safe`, `latest`, and `pending`.
The `eth` cache policy should use those tags directly instead of guessing that
all block-number queries are immutable.

## Finality And Reorg Safety

The module should maintain a small per-upstream view of:

- `chain_id`;
- latest observed block number;
- finalized block number when available;
- safe block number when available;
- sync status from `eth_syncing`;
- last successful probe time;
- current health state and error counters.

Cache admission should prefer response-derived block numbers when available. If
the module cannot determine whether a response is finality-safe, it should pass
through without storing. For chains that do not expose useful `finalized` data,
operators may configure a `finality_depth` fallback, but this should be clearly
documented as chain-specific risk.

## Upstream Selection And Failover

Initial selection should integrate with the `1.5` load-balancer line when
available, but the `eth` module can still start with a small local health model:

- reject unhealthy upstreams when `eth_syncing` reports active syncing;
- reject or de-prioritize upstreams whose `eth_blockNumber` lags the vhost
  median or best upstream by more than `health_max_block_lag`;
- verify `eth_chainId` matches config before serving traffic;
- retry idempotent read-only calls on transport errors, timeout, HTTP 5xx, or
  JSON-RPC error classes selected by policy;
- never retry transaction-submission methods by default.

Selection policies:

- round-robin among healthy nodes;
- power-of-two choices with active request count;
- sticky selection for WebSocket sessions;
- optional fallback to hosted providers only when explicitly configured.

Decentralization goals:

- let operators mix local execution clients, community RPC nodes, and hosted
  providers in one policy;
- verify upstream `chain_id`, sync state, and block lag before serving traffic;
- detect repeated provider-side denial, lag, or method-specific failure and
  route read traffic to healthier alternatives;
- support optional quorum/compare mode for selected immutable reads, where
  Fluxheim asks multiple upstreams and only caches/returns data when responses
  agree;
- keep hosted-provider fallback explicit so Fluxheim does not silently
  centralize traffic that was meant to stay local.

## WebSocket Scope

WebSocket support should be beta after HTTP JSON-RPC caching is stable.

Rules:

- `eth_subscribe` sessions are never cacheable.
- A WebSocket connection must stay pinned to one upstream.
- If the upstream disconnects, Fluxheim should close the downstream connection
  rather than silently resubscribe unless an explicit resubscribe policy exists.
- Health and load-balancer state can influence new WebSocket connection
  placement, not in-flight subscription routing.

## Security Controls

The module must include:

- max JSON body size;
- max batch length;
- max method name length;
- max params depth/size where practical;
- method allow/deny lists;
- per-method rate limits where `security` or a future rate-limit module is
  enabled;
- request and response timeout controls;
- response size limit;
- cache-key length and cardinality bounds;
- optional stripping of sensitive request headers before upstream;
- no logging of full request params by default, because params may include
  addresses, calldata, signatures, or business-sensitive contract state.

Do not expose upstream execution clients directly to arbitrary debug/admin
namespaces through a broad allow-list. The default policy should allow only
standard public read methods and explicitly selected write methods.

## Privacy And Anonymity Research

Crypto RPC privacy is a separate problem from caching and load balancing. A
normal reverse proxy can hide the user's IP address from the upstream provider,
but the gateway itself can still see the requester, method, params, timing, and
response unless the design deliberately removes or blinds that information.

Initial privacy-preserving controls should be practical and honest:

- never log full params, responses, calldata, signatures, addresses, or
  transaction hashes by default;
- strip client-identifying headers before upstream unless explicitly allowed;
- support cache-only answers for finalized/immutable data, where Fluxheim can
  answer without contacting an upstream for that request;
- provide a privacy mode that rejects non-cacheable or identifying methods
  rather than forwarding them;
- keep metrics cardinality-safe and avoid labels for addresses, hashes,
  contracts, ENS names, or raw method params;
- document retention behavior for access logs, traces, cache metadata, and
  upstream health probes.

"Verifiably anonymized" RPC should remain research/beta until Fluxheim can
state and test a real threat model. Candidate future designs:

- blind or relay-based read queries where the public gateway cannot link the
  external client identity to the upstream query;
- split trust between a privacy relay and a cache/proxy node;
- anonymous credential or token-bucket rate limiting that does not identify the
  caller to the RPC gateway;
- differential privacy or aggregation for high-level metrics;
- privacy-preserving audit proofs showing that request bodies and identifying
  headers were not logged.

Fluxheim must not claim that a deployment is fully anonymous merely because it
uses multiple upstreams or strips logs. The hard claim is: can the gateway
operator, upstream provider, and observers link user, query, timing, and
response? Until the answer is defensible, the feature should be documented as
privacy-reducing or privacy-preserving, not verifiably anonymous.

## Verification Co-Processing

`eth-verify` is a later Ethereum-specific verification track. It should not be
part of the first stable `eth` cache/proxy release.

Goal: allow Fluxheim to verify selected blockchain-derived data at the edge
before returning or caching it. Instead of trusting one RPC provider's response,
Fluxheim can fetch proofs, verify them against a trusted block header or
light-client state, and then return data with stronger integrity guarantees.

Candidate verification modes:

- Ethereum account/storage proof verification through `eth_getProof` using
  Merkle-Patricia trie proofs against a known state root.
- Receipt or transaction inclusion checks against block bodies/receipts roots
  where proof material is available and bounded.
- Header verification through an embedded or sidecar light client such as a
  Helios-style model.
- ZK proof verification for application-specific state claims where a mature
  verifier and proof format exist.
- Quorum plus proof mode, where Fluxheim compares multiple upstream responses
  and verifies proof material before cache admission.

Candidate config shape:

```toml
[vhosts.eth.verify]
enabled = true
mode = "light-client"
require_proofs_for = ["eth_getProof"]
trusted_checkpoint = "0x..."
max_proof_bytes = "1MiB"
max_verification_time_ms = 50
fail_closed = true
```

Security model:

- Verification must be explicit per method or route.
- Verification failure must default to fail-closed for protected methods.
- Proof size, proof depth, execution time, and cache memory impact must be
  bounded.
- Verified cache entries must record the verified block hash/number, state root,
  proof type, and verification policy version.
- Stale light-client checkpoints must make protected verification unavailable
  rather than silently falling back to provider trust.
- Metrics must report verification result classes without labeling addresses,
  storage slots, transaction hashes, or raw proof identifiers.

Dependency guidance:

- Do not implement cryptographic proof systems from scratch.
- Prefer mature, reviewed Ethereum/light-client libraries once their license,
  advisory, maintenance, and `unsafe` profile are acceptable.
- Keep proof engines behind Fluxheim-owned interfaces so `eth` can remain a
  lightweight RPC cache/proxy when `eth-verify` is not compiled.

Open questions:

- Whether verification should run in-process, in a worker pool, or in a
  separate sidecar to isolate expensive proof work.
- How to represent verified responses to downstream clients without inventing a
  misleading trust signal.
- How to combine proof verification with privacy-preserving RPC modes, since
  proof requests can themselves reveal the queried account/storage key.
- Whether ZK proof verification belongs in `eth-verify` or a later generic
  `proof-verify` module that can be shared by non-Ethereum chains.

Exit criteria before stable `eth-verify`:

- Light-client/header trust model is documented and tested.
- Malformed, oversized, deeply nested, and inconsistent proofs fail safely.
- Verification timeout/cancellation is covered by tests.
- Verified cache admission rejects mismatched state roots, wrong block headers,
  stale checkpoints, and unverified provider responses.
- Default and `eth`-only builds prove verification code and dependencies are
  absent.

## Metrics And Observability

Metrics should be cardinality-safe:

- requests by method, vhost, route, result class, and cache outcome;
- upstream health state and block lag;
- retry count and selected retry reason;
- JSON parse failures;
- cache admission/rejection reason;
- WebSocket active sessions, if enabled.

Avoid labels for account addresses, transaction hashes, block hashes, raw
contract addresses, or ENS names.

Tracing should record method names and policy decisions only. Full params and
responses should be redacted unless an explicit local debug mode is enabled.

## Release Plan

Recommended sequence:

1. Documentation-only design and config schema stub.
2. HTTP JSON-RPC classifier with no caching, only pass-through and metrics.
3. Chain health probes and upstream failover for read-only calls.
4. Cache key generation and memory/disk cache integration for whitelisted
   finalized/immutable methods.
5. Conservative `eth_getLogs` support with bounded finalized ranges.
6. WebSocket pass-through and sticky upstream selection as beta.
7. Hosted-provider fallback and quota-aware routing.

Exit criteria for stable `eth`:

- default builds prove `eth` is absent;
- `--features eth` and `profile-ethereum-rpc` builds pass;
- malformed JSON, oversized batches, unknown methods, and oversized responses
  are covered by tests;
- cache tests prove `latest` and `pending` are not stored by default;
- finalized/old block responses are cached with stable cache keys;
- transaction submission methods are never retried or cached by default;
- upstream chain-id mismatch rejects traffic before serving requests;
- health probes eject syncing or lagging nodes;
- docs include migration examples for Geth, Erigon, Reth, and hosted fallback.

## Future `eth-ens` Review

`eth-ens` is intentionally separate from `eth`.

Concept:

- resolve ENS names through the registry/resolver path;
- read `contenthash()` records;
- decode IPFS, Arweave, or other supported contenthash values;
- proxy to a configured local gateway or redirect to a configured public
  gateway;
- cache resolver/contenthash answers with TTL and block/finality awareness.

Open design constraints:

- Browsers do not normally resolve raw `.eth` names through DNS.
- Public ACME certificates are not issued for raw `.eth` names.
- Fluxheim can only route a `.eth` host when traffic reaches Fluxheim with that
  Host header, or when an operator uses a gateway domain pattern such as
  `{name}.eth.example.test`.
- ENS resolution adds more dependencies, ABI handling, name normalization, and
  phishing/confusable-name risks than the basic RPC proxy.
- Gatewaying IPFS/Arweave introduces content-type, range, cache, abuse, and
  origin-authenticity questions.

For that reason, `eth-ens` should be reviewed after the `eth` module is stable.
It should not block the first Ethereum RPC proxy/cache release.

## Future `btc` Review

Bitcoin Core also exposes JSON-RPC, so a Fluxheim edge module could proxy,
cache, and health-check selected Bitcoin RPC methods. This should be separate
from `eth` because Bitcoin's safety model is based on confirmations and chain
depth, not Ethereum's `finalized`/`safe` tags.

Potential cacheable candidates:

- `getblockhash`;
- `getblock`;
- `getblockheader`;
- `getrawtransaction` when the operator understands `txindex` and historical
  availability;
- selected mempool-independent chain metadata.

Default deny/pass-through candidates:

- wallet methods;
- mining/template methods;
- node/admin/network-control methods;
- raw transaction submission unless explicitly enabled and never retried by
  default.

Open design points:

- confirmation-depth policy for cache admission;
- handling pruned nodes and missing historical data;
- optional ZMQ integration for invalidation or tip tracking;
- authentication to local Bitcoin Core RPC without leaking credentials in logs
  or metrics.

## Future `ada` Review

Cardano support is feasible, but it is not a small variation of Ethereum RPC.
Cardano infrastructure commonly exposes Ogmios, cardano-db-sync, GraphQL,
Blockfrost/Koios-compatible APIs, or custom provider APIs. Ogmios is the most
natural low-level candidate because it exposes a WebSocket JSON interface to
Cardano node mini-protocols.

Potential cacheable areas:

- block queries at known chain points;
- transaction lookup;
- protocol parameters at stable epochs;
- selected UTXO queries when tied to a known point.

Open design points:

- chain points, slots, epochs, and rollback handling;
- WebSocket session semantics for Ogmios;
- UTXO-state cache invalidation;
- whether Fluxheim should target Ogmios first or a higher-level provider API.

For that reason, `ada` should be reviewed after `eth` proves the shared
chain-edge core abstractions.

## Future `xrpl` Review

XRPL exposes HTTP JSON-RPC and WebSocket APIs and has a useful distinction
between current/open ledgers and validated ledgers. That makes it a good future
candidate for the chain-edge family, but it should own XRPL-specific method and
ledger validation policy.

Potential cacheable candidates:

- ledger lookups for validated ledger indexes;
- transaction lookup in validated ledgers;
- account/object queries pinned to validated ledger indexes.

Default non-cacheable or sticky behavior:

- transaction submission;
- current/open ledger queries;
- WebSocket subscriptions and pushed events.

Open design points:

- validated-ledger health probes;
- sticky WebSocket subscription placement;
- full-history vs non-full-history node behavior;
- preventing account/ledger identifiers from becoming high-cardinality metrics
  labels.

## References

- Ethereum JSON-RPC API overview:
  <https://ethereum.org/developers/docs/apis/json-rpc/>
- Ethereum execution API block tags and `eth_getBlockByNumber`:
  <https://ethereum.github.io/execution-apis/api/methods/eth_getBlockByNumber/>
- ENS resolver interfaces and `contenthash`:
  <https://docs.ens.domains/resolvers/interfaces/>
- ENS decentralized website hosting:
  <https://docs.ens.domains/dweb/intro/>
- ENS public resolver and EIP-1577 contenthash support:
  <https://docs.ens.domains/resolvers/public/>
