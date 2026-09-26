# ADR-0006: nftables with batch transactions and named sets

- **Status**: Accepted
- **Date**: 2026-09-25
- **Applies to**: `r3s-net`

## Context

Each container needs: its own network namespace, a veth pair, an address, DNS, egress policy, and optional port publishing. The naive model — one nftables rule per container per direction — produces ~6 objects per container, so 200 containers is 1 200 rules and a chain walk proportional to container count, on a softirq budget that is already the most contended resource on a Cortex-A53.

There is also a correctness requirement: a rule set is never observable in a partial state. If the engine is killed between two `nft` calls, the node must not be left with a container that has an address but no NAT, or worse, an `accept` rule with no matching `masquerade`.

The options:

| Approach | Atomic | Scalable | Maintained |
|---|---|---|---|
| `nftables 0.6` crate (JSON netlink API) | Yes, via `NFT_MSG_BATCH_BEGIN`/`COMMIT` | Yes, if the ruleset is written as a set/chain hybrid | Yes |
| `iptables` (legacy or `iptables-nft`) | Per-chain only | No | The `iptables` crates are deprecated; kernel `xt_*` compat is a compatibility layer with a shrinking future |
| libnftnl (C) | Yes | Yes | Adds a C dependency to a Rust-only binary |
| shelling out to `nft` | No | — | Violates the no-shelling-out rule outright |

## Decision

Use the `nftables 0.6` crate against the kernel's native netfilter API, with the ruleset shaped as a **set + chain hybrid**:

- A single `table inet r3s` with a fixed skeleton: `chain r3s-pre (input)`, `chain r3s-forward`, `chain r3s-postrouting`, `chain r3s-input-host`.
- Container *identities* (subnets, addresses, published ports) are **`set`s** — `r3s-containers`, `r3s-published-ports` — populated by `add element`. One set update for 50 containers is 1 netlink message, not 300 rules.
- The **policy** lives in a small, fixed number of chains (typically 6–8 total) so the packet walk is O(1) in container count.
- **One** `masquerade` rule for the whole CIDR, not one per container.
- Per-container exceptions (egress deny, extra ports) are set elements and named chains only where a container genuinely needs its own policy — not by default.
- Every mutation is a `Transaction::begin()` … `commit()` batch. There is no code path that issues a bare `nft` add; a test asserts that a partially-applied table is never observable (invariant `I8`).
- If another agent owns netfilter (docker, ufw, firewalld), preflight detects it and refuses to start rather than fighting over the ruleset. One owner, or the node is unmanageable.

`rtnetlink 0.23` handles link/address/route creation; the `nftables` crate handles policy. The engine never calls `ip` or `nft`.

## Consequences

### Positive
- Rule count is independent of container count, so the network plane stays flat as the node scales. This is the single most important performance property of the design.
- Batch transactions give us atomicity for free from the kernel; no two-phase bookkeeping on our side.
- Native nftables, not an `xt_*` compatibility layer, so it works on a 6.x kernel without `nft_compat`.
- The table is small enough to `diff` mentally, which matters at 3 a.m.

### Negative / costs accepted
- The `nftables` crate is JSON-based: a full ruleset round-trip costs ~200 KB of transient allocation and a few ms. Measured in BASELINE; acceptable at 1 Hz, and we never do it in a hot path.
- A set/chain hybrid is more complex to read than "one rule per container". This is a real cost, paid by whoever debugs the ruleset next. Mitigated by a `r3s network dump` command that prints the resolved table with set contents.
- In-memory shadow state of the ruleset is required to compute diffs. It is a cache, not a source of truth: the reconciler re-reads the real table at boot and every 30 s.

### Follow-up work
- `tc` for per-container bandwidth limits (Stage 4). Same netlink family, same hybrid philosophy.
- Egress accounting per container (`nft` counters) feeding the telemetry ring.

## Alternatives considered

- **One rule per container** — rejected: O(n) packet walk, hundreds of rules, 1 200 objects at 200 containers, and it does not fit the measured softirq budget on a Cortex-A53.
- **`iptables`** — rejected: deprecated crates, `xt_compat` is a compatibility path, per-chain atomicity only.
- **libnftnl via FFI** — rejected: C dependency in a Rust-only binary, with no functional gain over the crate.
- **Shelling out to `nft`/`iptables`** — rejected: violates a core non-negotiable, and it makes atomicity and error handling depend on parsing stdout.
- **A userspace proxy per container (Caddy/HAProxy style)** — rejected: a whole extra process and a data path in user space, on hardware where the softirq path is already the bottleneck.

## Revisit when

- The crate is unmaintained for 6 months → re-evaluate direct netlink (netfilter netlink) implementation, which is ~400 lines and already partly unsafe territory ([UNSAFE.md J-08](../UNSAFE.md)).
- The JSON round-trip cost exceeds the BASELINE target at 1 Hz → cache the encoded document and only re-encode on change.
