# 02. Match Viewer

## Overview

[01](01-sandbox.md) produces two artifacts a person actually wants to look
at: `report.jsonl` (one JSON object per line — every action/observation/
error any role emitted, in the shape `chaos/lib/log.mjs`'s `record()`
writes) and `verifier-result.json` (the final three-invariant audit).
Neither is meant to be read raw. This spec covers `chaos/viewer/index.html`
— a single self-contained HTML file, no build step and no server, that
turns either of those files into a game-like replay: three "friendly
systems" (the legitimate actors) weathering three "hostile contacts" (the
chaos agents), a scrolling commit-style event log, and the three hard
invariants from [01](01-sandbox.md) as gauges that resolve once the match
ends.

It exists so the answer to "did anything bad happen during that run" is a
90-second skim, not a manual `grep` through several thousand JSONL lines —
and, since Docker was never run in the environment this was built in (see
[01](01-sandbox.md)'s Status note), so the *shape* of a match is visible
immediately, before a real run ever produces a real `report.jsonl`.

**Status: BUILT, self-reviewed, not seen in a real browser by the AI
session that wrote it** (no browser available in that environment either).
The event-classification logic (`classifyRealEvent()`) was checked by hand
against `chaos/lib/log.mjs`'s actual `record()` call sites across
`chaos/actors/driver.mjs` and `chaos/agents/*.mjs`, and the generated
`<script>` was validated with `node --check` after every edit, but nothing
here has been exercised against a real `report.jsonl` from an actual
Docker run — because none exists yet. First thing to re-check once [01](
01-sandbox.md) is actually run once.

## Non-goals

- **Not a dashboard for live/in-progress runs.** It reads a file the user
  picks (or a demo it generates itself) — no polling, no server, no
  connection to a running sandbox. Watching a match live would mean
  streaming `report.jsonl` out of the `report-data` volume, which is a
  separate, unbuilt feature.
- **Not a substitute for `verifier-result.json`'s exit code.** The viewer
  renders whatever it's given; it does not re-derive or double-check the
  invariants itself. A `report.jsonl`-only replay explicitly cannot show
  the containment/integrity gauges (see "Two input shapes, two views"
  below) — only the verifier's own audit can.
- **Not networked.** No fetch, no upload, no analytics. A loaded file is
  read by the browser's `FileReader` and never leaves it — the footnote in
  the page says so, and it should stay true.

## Two input shapes, two views

The viewer accepts exactly two file shapes via its "Load report" picker,
distinguished by sniffing the first non-whitespace character and whether a
second line starts with `{`:

1. **`report.jsonl`** (one JSON object per line) → **replay mode**. Every
   line is parsed, sorted by its `ts` field, filtered to lines whose
   `role` is one of the six known role ids, and classified into a game
   event (see "Event classification" below). The transport controls
   (play/pause/scrub/speed) step through these events one at a time.
   Because the unprivileged parts of the three hard invariants
   (containment, integrity) are things only `verifier` — with a fresh
   clone and no key — can check, a `report.jsonl`-only replay can only
   ever populate the **data-recovery** gauge, from the operator's own
   `final integrity self-check` event ([01](01-sandbox.md)'s "Verifying
   the invariants" explains why that one self-report is trusted). The
   other two gauges stay in `AWAITING AUDIT` and the end-of-match banner
   says so explicitly (`MATCH COMPLETE — AUDIT INCOMPLETE`), rather than
   silently rendering as if the full audit had run.
2. **`verifier-result.json`** (a single JSON object with an `invariants`
   key) → **snapshot mode**. No event timeline exists in this file — it's
   the final audit only — so the viewer shows the roster in its final
   state (from `reportSummary.byRole`, if present) and all three gauges
   populated directly from `invariants.{noPlaintextLeaked,
   repositoryIntact, zeroDataLoss}`, with the resolution banner shown
   immediately.

A file that matches neither shape (unparseable, or valid JSON but missing
both an `invariants` key and any recognizable role lines) shows an alert
rather than a blank or misleading board.

## Demo match

With no file loaded, the viewer boots straight into an auto-playing
**synthetic demo** (`generateDemo()`) — 9 rounds built from the exact same
event shapes `classifyRealEvent()` produces from a real report, so what a
match looks like is visible before Docker is ever touched. It is
unambiguously labeled: the source readout in the header reads "demo
match — simulated data" for the whole match (never switches to a "live"
style), and it always resolves with all three gauges secure — a demo is
meant to show the *shape* of a match, not to simulate a finding. "↻ New
demo match" regenerates it with fresh random rolls (which corruption
techniques landed, which rounds rotated, etc.) without touching any real
data.

## Roster and combat framing

Six fixed combatants, three friendly and three hostile — this list is
closed, not data-driven, because it mirrors [01](01-sandbox.md)'s fixed
cast exactly:

| id | side | framing |
|---|---|---|
| `collaborator-a` | friendly | collaborator |
| `collaborator-b` | friendly | collaborator |
| `operator` | friendly | key rotation & audit |
| `chaos-4-virus` | hostile | file corruption |
| `chaos-5-attacker` | hostile | hostile push access |
| `chaos-6-infra` | hostile | process / disk / network faults |

Each combatant card tracks a round counter, a health-style bar (cosmetic —
see below), a status line, and the text of its most recent event. A
friendly combatant's bar rises on a successful push or rotation (a
"heal"); a hostile combatant's bar has no independent meaning of its own —
instead, landing a hit against its mapped target (`chaos-4-virus` →
`collaborator-a`, `chaos-6-infra` → `collaborator-b`, per [01](
01-sandbox.md)'s pairing; `chaos-5-attacker` has no paired target, since it
only ever acts through ordinary `git push` against the shared remote, not
against any one collaborator's own systems) drains *that target's* bar and
flashes both cards. **The bar is a legibility device, not a scored metric**
— nothing here computes a win condition from it, and it is never read by
`resolveMatch()`. The three invariant gauges are the only outcome that
matters; the roster is how the log reads as a narrative while it's
happening.

## Event classification (`classifyRealEvent`)

Maps one parsed `report.jsonl` line (`{ts, role, kind, message, ...data}`,
per `chaos/lib/log.mjs`'s `record()`) to a game event. Matched by message
prefix, mirroring each script's actual `record()` call sites:

- `chaos-4-virus` / `chaos-6-infra`: `"virus round …"` / `"infra round …"`
  → a hit (`attempted: true`, drains the paired target) or a miss (no
  target file/process found that round); `"run complete"` → stand down.
- `chaos-5-attacker`: `"attack round …"` → landed (T1/T3/T4/T5, per
  [01](01-sandbox.md)'s attack techniques) or blocked (non-fast-forward
  push rejected); `"run complete"` → stand down.
- Friendly roles: `"push (round …"` → push landed or was rejected and is
  retrying; `"key rotate …"` → rotation succeeded or was refused that
  round; `"final integrity self-check"` (operator only, see [01](
  01-sandbox.md)) → a `SCAN` event carrying the blobs-checked and
  findings counts, which is what drives the data-recovery gauge in replay
  mode; `"run complete"` → stand down; anything tagged `kind: 'error'` in
  the report → a warning event, never silently dropped.
- Anything else recognized-role but unmatched falls through to a generic
  neutral log line (`(raw.kind || 'log').toUpperCase()` as the tag) rather
  than being dropped — a message shape this spec's authors didn't
  anticipate still shows up in the log, just without special styling.

A line whose `role` isn't one of the six known ids (there shouldn't be any,
since [01](01-sandbox.md)'s cast is fixed) is filtered out before
classification, not passed through misrendered.

## Playback model

`state.events` is a flat, time-ordered array; `state.index` is the replay
cursor. Playing advances the cursor on a timer (`340ms / speed`, floor
`40ms`, speeds 1×/3×/8×); scrubbing jumps directly. Scrubbing *backward*
rebuilds all combatant/gauge state from scratch and fast-forwards to the
target index — replay state is cheap enough at this event scale (tens to
low hundreds of events per run) that this beats maintaining an undo log.
Reaching the last event always calls `resolveMatch()` exactly once
(`state.resolved` guards re-entry) and pauses.

## Resolution banner

Three outcomes, not two — this was corrected during design specifically
because a plain held/violated binary would misrepresent an incomplete
audit (the common case for a `report.jsonl`-only replay) as if it were a
clean pass:

- **`INVARIANT VIOLATED — REVIEW FINDINGS`** — at least one gauge reads
  `breach`.
- **`ALL THREE INVARIANTS HELD`** — all three gauges read `secure`.
- **`MATCH COMPLETE — AUDIT INCOMPLETE`** — neither of the above (typically
  a replay-mode match where only the data-recovery gauge could be
  populated).

## Visual design

Single deliberate world — a submarine/spacecraft damage-control board —
not adapted to the host page's light/dark theme, the same way a physical
control panel doesn't repaint itself for daytime (see the
`artifact-design` skill's "single deliberate visual world" exception for
game-shaped pages). Every color is still declared as an explicit CSS
custom property rather than left to inherit, so the page holds its own
look regardless of host. `prefers-reduced-motion` collapses all animation
durations to near-zero. No external JS dependency — Google Fonts
(Michroma for display headings, IBM Plex Sans/Mono for body/data) is the
only external load, matching the CDN allowlist a published Artifact
version of this page would need to respect anyway.

## Relationship to `chaos/README.md` and [01](01-sandbox.md)

`chaos/README.md`'s "Watching it happen: the match viewer" section is the
user-facing how-to (where to get `report.jsonl` out of the Docker volume,
how to open the file). This spec is the *design* record — why it has two
input modes, why the demo is unmistakably synthetic, why the banner has
three outcomes and not two, why the roster bar is cosmetic. [01](
01-sandbox.md)'s "Verifying the invariants" section remains the source of
truth for what each invariant means and how it's actually checked; this
spec only covers how that result gets rendered.

## Open questions

- **Live streaming.** Tailing `report.jsonl` out of a running container
  (e.g. via a small local relay script) instead of loading a finished
  file, so a match can be watched as it happens rather than replayed
  afterward. Not built — deliberately out of scope per "Non-goals" above,
  flagged here as the natural next step once a real run exists to
  validate the replay path against first.
- **Multi-run comparison.** Loading two `report.jsonl`/`verifier-result.json`
  pairs side by side (e.g. before/after a fix) has no supporting UI today.
