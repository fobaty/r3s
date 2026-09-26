# BASELINE.md

**Rule: no performance number appears anywhere in this repository unless it appears here with a reproduction command.**

A measurement is admissible only if it was produced by `./scripts/bench.sh <host>` or `./scripts/bench-ondevice.sh <host>`, and the commit records the git SHA of the engine, the kernel, and the SD card model.

## 1. Why this file exists

The design makes claims — "≤ 24 MiB RSS", "≤ 45 ms container start", "5 ms group commit" — in `docs/ARCHITECTURE.md`. Those are **targets until measured**. The purpose of this file is to convert them into facts or to delete them. A target that cannot be met is deleted from the architecture doc, not quietly re-labelled.

## 2. Status

| Metric | Target | Pi 5 (4×A76) | Pi 4 (4×A72) | Pi 3 (4×A53) |
|---|---|---|---|---|
| Engine RSS at idle | ≤ 24 MiB | TBD | TBD | TBD |
| Engine RSS, 16 containers, 1 Hz telemetry | ≤ 48 MiB | TBD | TBD | TBD |
| Boot: `r3sd` → preflight complete | ≤ 120 ms | TBD | TBD | TBD |
| Boot: → first CLI command answered | ≤ 60 ms (post-boot) | TBD | TBD | TBD |
| `container run` p50 (image present) | ≤ 45 ms | TBD | TBD | TBD |
| `container run` p99 (image present) | ≤ 150 ms | TBD | TBD | TBD |
| `container run` p50 cold (`alpine:3`, pull included) | ≤ 90 s | TBD | TBD | TBD |
| `r3s ps` render, 16 containers | ≤ 8 ms | TBD | TBD | TBD |
| `r3s stats`, 16 containers | ≤ 40 ms | TBD | TBD | TBD |
| SSH handshake (ed25519, local) | ≤ 35 ms | TBD | TBD | TBD |
| WAL append (1 record) | ≤ 4 µs | TBD | TBD | TBD |
| WAL group commit (5 ms window) | ≤ 6 ms | TBD | TBD | TBD |
| Snapshot archive, 16 containers | ≤ 8 ms | TBD | TBD | TBD |
| cgroup limit write, per container | ≤ 250 µs | TBD | TBD | TBD |
| overlay mount (16 lower layers) | ≤ 60 ms | TBD | TBD | TBD |
| nftables batch commit (full table) | ≤ 40 ms | TBD | TBD | TBD |
| RSS drift, 72 h soak | ≤ 1 MiB/h | TBD | TBD | TBD |

TBD means **not yet measured**. Do not replace a TBD with an estimate.

## 3. Definitions (so the numbers are comparable)

- **Engine RSS**: `VmRSS` from `/proc/<pid>/status` of `r3sd`, sampled 30 s after boot with zero containers. Not `ps rss` (that is VSZ-adjacent and lies about sharing).
- **Boot**: measured from `execve` of the daemon to the `engine ready` log line, using the engine's own monotonic timer (`t0` in `bootstrap`), not wall-clock in the shell.
- **`container run` p50/p99**: from `Command::CreateContainer` accepted to `Phase::Running` observed, 500 iterations, warm page cache, image already unpacked. Includes cgroup creation, namespace setup, `execve`, and the first `cgroup.events` `populated 1`.
- **Cold pull**: with the image CAS present but the layer blobs deleted; the reference number always names the image (`alpine:3` pinned by digest, not a mutable tag).
- **WAL append**: `cargo bench -p r3s-store --bench wal`, `criterion`, 10 000 records, measured after the WAL reaches 8 MiB (steady state, not the first page-cache fill).
- **RSS drift**: linear regression slope of `VmRSS` over a 72 h run, not max−min. A sawtooth that returns to baseline has zero drift; a slow climb is a leak even if the range is small.
- **All timings**: best of 3 runs of the whole script, N=30 samples each unless stated; the reported figure is the median of the N, and the full sample set goes in the appendix.

## 4. Environment record (fill on first run)

```
Engine commit:  <git sha>
rustc:          1.98.1 (48a229cea 2026-09-01)
Target:         aarch64-unknown-linux-gnu, cortex-a76
Profile:        release (lto=fat, codegen-units=1, panic=unwind)
Kernel:         Linux 6.12.x
Board:          Raspberry Pi 5 Model B Rev 1.0, 8 GB
Storage:        <SD card model> (class A1/A2 matters enormously for this table)
Filesystem:     ext4, noatime,data=writeback
Governor:       performance (ondemand for the "power" variant)
Swap:           disabled
```

Storage is the variable that invalidates comparisons more often than the CPU is. Always record the card.

## 5. How to run

```bash
# Host-safe micro-benchmarks (no root, no device)
cargo bench --workspace

# Full device suite — populates section 2
./scripts/bench-ondevice.sh pi.local        # requires the on-device runner

# Long-running stability
./scripts/soak.sh pi.local 72               # writes a CSV of RSS/load/PSI
```

`scripts/bench-ondevice.sh` runs each measurement three times and refuses to write the table if a prior row is unfilled without a note. It emits a markdown fragment to paste here; it never edits this file itself (so a human owns every claim).

## 6. Regression policy

- Any bench whose median regresses **> 5 %** against `main` blocks the merge. Noise budget is handled by N=30 + a Mann–Whitney U test at p < 0.01, not by a hand-wave.
- Regressions above **20 %**, or any new measurement that crosses a target in §2, require a written cause in the PR description — including "SD card changed, not comparable" if that is the truth.
- Improvements get recorded too, with the same rigour, because a target that turns out to be 10× too conservative hides real regressions later.

## 7. A/B experiments already mandated by the design

These are design decisions that are *unproven* and must be measured before being called correct:

| Experiment | Claim under test | Method |
|---|---|---|
| overlayfs `index=off` | ≥ 20 % faster container start on Pi 3 | Mount the same image with `index=on`/`index=off`, 100 starts each, 3 runs |
| `io_uring` (feature-gated) | better than epoll for image extraction | `cargo bench -p r3s-image --features experimental-io-uring` on Pi 4/5; expected to be neutral-to-negative on Pi 3 |
| `ring` vs `aws-lc-rs` | measurable SSH handshake difference | Criterion bench, both features, n=200 handshakes |
| `mimalloc` | worth the ~200 KiB RSS on 64-bit | Allocator bench under 200-container load; adopt only if p99 improves ≥ 8 % |
| Telemetry at 0.2 Hz vs 1 Hz for 16+ containers | acceptable data resolution for the memory saving | Compare `r3s stats` accuracy against a 1 Hz reference; adopt if error < 5 % |

If an experiment contradicts the architecture document, the architecture document is wrong and gets updated with the measurement attached.

## 8. Appendix: raw samples

One CSV per run, committed to `bench/results/<date>-<board>.csv`, one row per sample, no aggregates. Aggregates live in §2; raw data lives here.
