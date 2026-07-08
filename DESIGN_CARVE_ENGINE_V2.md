# DeepScan Carve Engine v2 — Clean-Room Design

An original design for a file-carving engine. Same problem statement as
PhotoRec; independent architecture, derived from the problem itself and
from published file-format specifications — not from any GPL source code.

## 0. Provenance rules (read first)

For this design to yield a genuinely non-derivative implementation:

1. Implement **from this document and from public format specs only**
   (ITU-T T.81/ISO 10918 for JPEG, TIFF 6.0 spec, ISO/IEC 14496-12 for
   MP4/MOV, RIFC/RIFF spec, POSIX ustar for tar, etc.). Do not open
   PhotoRec/TestDisk source while implementing.
2. Ideally the person implementing has **not read PhotoRec's source**.
   A developer who ported PhotoRec can still contribute (ideas are not
   copyrightable), but the safest split is: one person writes format
   *specs sheets* (offsets, invariants, size rules — facts), another
   implements against them.
3. Keep provenance notes: commit messages and this doc cite the public
   spec each validator was written from.
4. Do not copy PhotoRec's test fixtures, signature tables verbatim, file
   names, or function names. Magic numbers themselves are facts (a JPEG
   starts `FF D8 FF` because the spec says so) and are fine.

## 1. Problem statement

Given a block device or disk image with unknown/damaged filesystem
structures, recover files by recognizing their content:

- Detect file starts by **content signatures** at plausible offsets.
- Determine each file's **extent**: exact size from internal structure
  when the format encodes it; otherwise footer search or validity-driven
  truncation.
- Handle **allocation-unit alignment** (files start on cluster
  boundaries; cluster size unknown a priori).
- Tolerate **fragmentation** at least to the extent of not corrupting
  other recoveries; optionally reassemble simple fragmentation.
- Never write to the source medium; stream terabyte-scale inputs with
  bounded memory; be **resumable**; report progress and per-format stats.
- Be **extensible**: adding a file format must not require touching the
  engine.

## 2. Architectural overview

The single biggest structural decision — and the main departure from the
classic single-pass design — is a **multi-phase pipeline with an
intermediate candidate index**, rather than carving inline while
scanning:

```
            ┌──────────────┐
 medium ──▶ │ A. SURVEY    │  sample scan → cluster-size & layout inference
            └──────┬───────┘
                   ▼
            ┌──────────────┐
            │ B. INDEX     │  full sequential sweep → candidate records
            └──────┬───────┘  (no files written yet; JSONL index on disk)
                   ▼
            ┌──────────────┐
            │ C. ARBITRATE │  resolve overlaps, score candidates,
            └──────┬───────┘  plan extraction (pure computation)
                   ▼
            ┌──────────────┐
            │ D. EXTRACT   │  second sequential sweep → write files,
            └──────────────┘  deep validation, truncation, metadata
```

Why this shape:

- **Crash-safety and resume for free**: each phase's output is an
  append-only file; resume = replay the index and continue the sweep
  from the last journaled offset.
- **Arbitration is global, not greedy**: with all candidates known
  before extraction, overlapping claims are resolved by score, not by
  whichever header happened to be seen first.
- **Two sequential sweeps beat one seeky pass** on spinning disks and
  damaged media: phase B never seeks backwards; phase D visits carve
  targets in ascending order.
- **Parallelism**: phase B chunks are independent (with overlap), so the
  scan fans out across cores; the classic inline design is inherently
  serial because carving mutates shared state.
- A `--one-pass` degraded mode (index+extract fused) can exist for
  media that are dying and may only survive one read; it reuses the same
  components.

## 3. Core components

### 3.1 MediaSource

```cpp
class MediaSource {            // image file, raw device, E01 later
public:
  virtual uint64_t size() const = 0;
  virtual size_t   read_at(uint64_t off, std::span<std::byte> out) = 0;
  // returns bytes actually read; short reads mark BadRanges, never abort
};
```

Wrapped by `ChunkReader`: fixed-size chunks (default 16 MiB) with a
trailing **overlap window** (= max header probe length, e.g. 64 KiB) so
a signature spanning a chunk boundary is seen exactly once. Unreadable
sectors go into a `BadRangeMap`; carving continues around them and
affected recoveries are flagged `degraded` in the report.

### 3.2 CoverageMap

An interval set over the medium: `unknown | indexed | claimed | bad`.
Backed by an ordered map of half-open ranges. Used for progress, for
"carve free space only" (future: subtract FS-allocated ranges), and by
arbitration to prevent double-claiming. Purely an interval-algebra
utility — no engine logic hides in it.

### 3.3 PatternBank + AnchorScanner (phase B inner loop)

Each format plugin contributes **anchor patterns**: `(byte string,
offset-in-cluster constraint, plugin id)`. All patterns are compiled
into one **Aho–Corasick automaton** at startup, so the sweep is a
single pass of the automaton over each chunk — O(bytes) regardless of
pattern count. Two scanning policies, chosen by survey results:

- `aligned`: automaton runs only at cluster-start offsets (fast path
  once cluster size is known — most real files start on cluster
  boundaries);
- `saturating`: automaton runs over every byte (slow path for the
  survey phase, for `cluster=1` media like some archives/pipes, and for
  an optional "deep scan" mode).

On an automaton hit, the plugin's **Sniffer** runs: a cheap, allocation-
free predicate over the surrounding bytes (up to the overlap window)
that filters false anchors and, when possible, emits a size hint. Only
sniffed-positive hits become candidate records.

### 3.4 Candidate records (the phase B output)

```jsonl
{"anchor":123456789,"plugin":"jpeg","conf":0.9,"size_hint":8388608,
 "meta":{"exif_ts":"2025-11-02T10:11:12"}}
```

Append-only JSONL (or a compact binary log with a JSONL exporter).
This *is* the session file: index + last swept offset = full resume
state. It is also independently useful — a forensic "what's on this
disk" report before anything is written.

### 3.5 FormatPlugin: Sniffer + Validator

The plugin API is deliberately **pull/event-based**, not
callback-mutates-engine-state:

```cpp
struct SniffResult { bool plausible; float confidence;
                     std::optional<uint64_t> size_hint; MetaMap meta; };

class FormatPlugin {
public:
  virtual std::vector<AnchorPattern> anchors() const = 0;
  virtual SniffResult sniff(ByteView window, uint64_t cluster_off) const = 0;
  virtual std::unique_ptr<Validator> make_validator() const = 0;
  virtual const FormatInfo& info() const = 0;   // ext, name, max size
};

class Validator {               // incremental push-parser, phase D
public:
  enum class Verdict { NeedMore, Done, Truncate, Reject };
  struct Step { Verdict v; uint64_t at; /* size when Done/Truncate */ };
  virtual Step feed(ByteView data, uint64_t stream_off) = 0;
  virtual Step finish() = 0;    // stream ended (end of claim/media)
  virtual MetaMap metadata() const = 0;   // timestamps, dimensions, name
};
```

The engine owns all I/O and all files; a validator is a pure state
machine that consumes bytes and returns verdicts. Consequences:

- Validators are trivially unit-testable (feed byte slices, assert
  verdicts) with no engine, no disk, no FILE*.
- No shared mutable recovery object, no function-pointer swapping —
  a format that switches strategy mid-file (e.g. "found the declared
  size, now just count bytes") does so *inside its own state machine*.
- The same validator runs in "carve" mode (phase D) and in "verify an
  existing file" mode (CLI utility, test harness) unchanged.

### 3.6 Arbitration (phase C)

Pure function: candidate list + coverage map → extraction plan.

- Sort candidates by anchor offset.
- Overlap resolution by **score** = plugin confidence × structural
  evidence (size known exactly > footer found > heuristic) × plugin
  priority (container formats outrank formats they commonly embed —
  e.g. a JPEG anchor *inside* a claimed MP4/TIFF region is suppressed
  unless the container's validator later rejects).
- Emits a deterministic, ascending-offset `ExtractionPlan`. Determinism
  makes runs reproducible and diffs between engine versions meaningful.

### 3.7 Extractor (phase D)

Walks the plan; for each claim, streams the claimed range through the
plugin's validator and a `FileSink`:

- `Done(size)` → truncate sink to size, finalize, record `recovered`.
- `Truncate(size)` → keep prefix if ≥ plugin minimum, flag `truncated`.
- `Reject` → delete sink, record `false_positive`, release the range
  back to the coverage map (a later-phase re-arbitration may hand it to
  the runner-up candidate).
- Validator verdicts can also *shrink* a claim, releasing the tail for
  the next candidate.

Output naming: `<out>/<batch>/<format>/<anchor-offset>.<ext>` with an
optional renamer using validator metadata (original name, EXIF date).
Sinks pre-allocate when a size hint exists and fsync on finalize.

### 3.8 Survey phase (A): cluster-size inference

Sample N windows spread across the medium, run the automaton in
`saturating` mode, collect sniffed-positive anchor offsets, and infer
the allocation unit as the largest power-of-two b (512 ≤ b ≤ 64 KiB)
such that a supermajority of anchors satisfy `offset % b == r` for a
common residue r (residue also recovers partition offset). Falls back
to sector size when evidence is weak. This is plain statistics on our
own observations — nothing format-specific lives here.

### 3.9 Journal, reporting, control

- Append-only JSONL journal per run: phase transitions, swept-offset
  heartbeats, per-claim outcomes. Resume = last heartbeat.
- Final report: per-format recovered / truncated / false-positive
  counts, bad ranges, timing. (The existing `json_log` concept carries
  over — that module is DeepScan-original already.)
- Cooperative cancellation: an atomic stop flag checked between chunks;
  SIGINT/console handler sets it; journal makes the interrupted run
  resumable.

### 3.10 Concurrency model

Phase B: reader thread produces chunks → worker pool runs
automaton+sniffers → collector merges candidate records in offset
order. Workers share nothing but the read-only automaton. Phase D is
I/O-bound and stays single-writer (optionally: validator pipelining).
The classic inline-carving design cannot parallelize this way; it is a
concrete payoff of the index/extract split.

## 4. Format plugins: spec-driven examples

Each plugin ships a `SPEC.md` citing its public sources. Sketches:

**JPEG (from ITU-T T.81 + EXIF/JFIF specs).** Anchor `FF D8 FF`.
Sniffer: 4th byte ∈ {E0,E1,DB,C4,EE,FE}. Validator: marker-segment
walk — read marker, read 16-bit big-endian length, validate segment
type transitions (tables → frame header → scans); entropy-coded data
skipped by scanning for the next `FF xx, xx∉{00, D0–D7}`; `FF D9` →
`Done(offset+2)`. Structural failure after a valid frame header →
`Truncate` at last good marker; before it → `Reject`.

**TIFF-family (TIFF 6.0 spec; covers many camera RAWs).** Anchor
`II 2A 00` / `MM 00 2A`. Validator walks the IFD chain, tracks the
maximum extent referenced by any (offset,length) tag pair, verifies
entry counts and tag ordering per spec; `Done(max_extent)` when the
chain terminates. Vendor RAW extensions differ only in extension
naming rules → data-driven subtable, not new code.

**ISO BMFF (ISO/IEC 14496-12; mp4/mov/heic/jp2/3gp).** Anchor
`xx xx xx xx 'ftyp'` at cluster offset 0. Validator: box walk (size,
fourcc), 64-bit `size==1` handling, brand table maps `ftyp` major
brand → extension; `Done` at the end of the last top-level box.

**tar (POSIX ustar).** Anchor `'ustar'` at offset 257 within a
512-byte record. Validator: header checksum per spec, octal size
fields, 512-byte record arithmetic; two zero records → `Done`.
Also implements the "interior suppression" need: the *arbitration*
score of candidates inside a tar claim is set by policy (§3.6), not by
a special case in the scan loop.

Adding a format = one class + one anchors() table + a SPEC.md. Target
first wave: jpeg, tiff-family, bmff, riff, png, tar, ole2, zip
(zip's central-directory-at-end structure exercises the footer path).

## 5. What this design deliberately does differently

Documented to evidence independence (idea-level comparison only):

| Concern | Classic inline design | This design |
|---|---|---|
| Overall flow | one pass, carve while scanning | survey → index → arbitrate → extract |
| Overlapping headers | greedy, first-seen wins | global scoring after full index |
| Signature dispatch | per-offset first-byte buckets | single Aho–Corasick automaton |
| Format API | callbacks mutating a shared recovery struct; swappable function pointers | pull-based Sniffer + Validator state machines, engine owns all I/O |
| Container-interior headers | hard-coded/virtual special case in scan loop | generic arbitration priority |
| Cluster size | dedicated carve-10-files pass | statistical inference on sampled anchors |
| Resume | session file of remaining ranges | append-only index + journal replay |
| Parallelism | serial | parallel index phase |
| Verify-only mode | not separable | validators run standalone |

## 6. Testing strategy

- **Validator unit tests**: hand-built byte sequences per spec clause
  (valid, truncated, corrupt-length, boundary-spanning) — no disk.
- **Synthetic media**: generator composes known files onto a blank
  image with chosen cluster size, gaps, interleaving, and bad sectors;
  assertions on exact recovery set. Fixtures are generated or
  self-created files — never another tool's test corpus.
- **Differential smoke test**: run engine v2 and the GPL port on the
  same synthetic image and compare *recovery manifests* (offsets/sizes
  only). Comparing outputs is fine; it is behavior, not code.
- **Fuzzing**: validators are pure `feed(bytes)` machines — ideal
  libFuzzer targets.

## 7. Migration & licensing posture

- Engine v2 code is original: license it as the product requires
  (proprietary, Apache-2.0, dual — your choice).
- Until v2 reaches parity, the GPL CoreLogic port can continue to exist
  as a separate GPL-compliant tool; keep the two trees and teams
  separated per §0.
- The JSONL index/report format is shared surface: design it once here
  and have both engines emit it, so the front-end doesn't care which
  engine produced the results.
