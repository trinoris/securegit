# 03. Orchestrator — Merge-Request Gating Across Three Git Workflows

## Overview

[01](01-sandbox.md) simulates exactly one git workflow: every legitimate
actor, and chaos-5, push directly to the same branch (`main`) on the same
bare remote, with nothing in between a `git push` and that content becoming
part of history. That is a real, common workflow — plenty of repositories
run this way — but it is also the *least* defensible one, by construction:
[16](../securegit/16-adversarial-integrity.md)'s T1 section already proves
it (a real GitHub Actions run: chaos-5's attribute downgrade landed at
round 5, `verify` flagged it every round after, and every collaborator
commit kept leaking in plaintext anyway — 28 separate plaintext commits by
the time the 180-second run ended, all under `secrets/collaborator-a.json`,
because nothing stood between the attacker's push and `master`).

Real deployments don't all look like that. This spec names the three git
workflows this project's own users are actually choosing between, works
out precisely which one admits something that can behave like a pull-
request reviewer, and specifies that role — an `orchestrator` actor that
evaluates a proposed change *before* it becomes part of protected history,
and accepts or rejects it, the way a required CI status check gates a real
GitHub merge button. This is not a new cryptographic mechanism; it is
[16](../securegit/16-adversarial-integrity.md)'s own "Recommended, not
built: server-side enforcement for self-hosted git servers" note, finally
specified precisely enough to build, plus the one thing that note didn't
have yet: an empirical comparison, in the same sandbox, of how much
difference the gate actually makes against the identical attack traffic.

**Status: IMPLEMENTED, NOT YET CONFIRMED BY A REAL RUN.** `SANDBOX_WORKFLOW`
(`direct-master`/`working-branch`/`pr-gated`) is wired through
`chaos/docker-compose.yml`, `chaos/remote/entrypoint.mjs` (the pre-receive
hook), `chaos/actors/driver.mjs` (`targetRef()`/`ensureTargetRef()`,
`orchestratorReviewRound()`/`reviewAndMaybeMerge()`/`landReviewedMerge()`)
and `chaos/agents/attacker.mjs` (`TARGET_REF`, `attackDirectMasterBypass`).
`.github/workflows/node.js.yml`'s `chaos` job runs all three as a
`fail-fast: false` matrix; a new `chaos-publish` job assembles all three
legs' results into one site, and `chaos/viewer/index.html` renders the
three-way comparison this whole spec exists to make legible. The
merge-review mechanism itself (clean merge → accepted via `update-ref`;
T1-downgraded merge → rejected, master untouched; direct push to master →
refused by the pre-receive hook) is confirmed with a local, no-Docker repro
using plain `git` plumbing and the built CLI, same discipline as
[16](../securegit/16-adversarial-integrity.md)'s T1 recovery fix — what
that repro can't confirm is the real Docker/compose wiring (volume
mounts, env var propagation, the matrix/publish job graph itself), which
needs an actual GitHub Actions run.

## Core Principle

> Same boundary as everywhere else in this project
> ([01](../securegit/01-threat-model.md)): a merge request is not a
> cryptographic object. Git has no signature proving *who* proposed a
> change or *that a human reviewed it* unless commits are signed and the
> review is itself recorded — this orchestrator is a heuristic, automatable
> **subset** of code review (exactly the T1/T3/T4/T5 shapes this project
> already catalogues), not a replacement for it, and every acceptance
> criterion below says so precisely rather than overselling what an
> automated check can prove.

## Three git workflows, and where each one actually runs

| | Workflow | Real-world shape | Who can make `master` move | Built |
|---|---|---|---|---|
| W1 | Direct push to `master` | No review, no CI gate — small teams, early-stage repos, personal projects, or any self-hosted `git` server nobody has configured protection on | Anyone with push access, unconditionally | [01](01-sandbox.md) (today's default, unchanged by this spec) |
| W2 | Direct push to a shared working branch, gated promotion to `master` | GitFlow's `develop`, a team's `staging`/`integration` branch — fast, low-ceremony collaboration on the working branch, a reviewed release/promotion step onto `master` | Anyone, on the working branch; only the promotion step, on `master` | This spec, §"Workflow W2" |
| W3 | Pull request against a protected `master`, required status checks | GitHub/GitLab/Bitbucket's standard model: `git push origin feature/x`, open a PR, checks run, a human or a required check approves, *then* it merges — this repository's own `master` is set up exactly this way (`.github/workflows/{codeql,gitleaks}.yml` as required checks) | Only the merge action itself, never a direct push | This spec, §"Workflow W3" |

W1 is already fully built and already empirically measured (the 28-
violation run cited above). This spec's job for W1 is precise naming, not
new work — see [01](01-sandbox.md) and [16](../securegit/16-adversarial-integrity.md)
for everything about it.

## Where a "merge request role" is even possible

This is the question the rest of this document answers concretely, but the
shape of the answer is short enough to state up front: **a merge-request
reviewer needs a merge request to review** — a proposed ref that exists
independently of the protected branch until something explicit accepts it.

- **W1 has no such object.** A push to `master` *is* the change landing,
  atomically, by definition. There is no gap between "proposed" and
  "accepted" for anything to interpose on. This is exactly why
  [16](../securegit/16-adversarial-integrity.md) is precise that client-side
  hooks are "a convenience, not a defense" here — there's no step in this
  workflow a hostile pusher is ever required to pass through.
- **W3 is built entirely out of that gap.** A feature branch is the
  proposal; `master` is the protected target; the interval between "branch
  pushed" and "merge accepted" is exactly where a reviewer — human or
  automated — does its job. This is the workflow the orchestrator is a
  merge-request reviewer *for*, in the ordinary sense of that phrase.
- **W2 is split.** The working branch itself has W1's problem (anyone can
  push anything, no gate) — the orchestrator has nothing to review there,
  same reasoning as W1. But the working-branch-to-`master` *promotion* is
  structurally identical to W3's merge step: a proposed ref (`working`'s
  current tip), a protected target (`master`), and a gap the orchestrator
  reviews before crossing it. So the orchestrator plays the merge-request
  role for W2 too, just narrower in scope — it only ever gates one ref
  transition, never the working branch's own day-to-day traffic.

So: **the orchestrator is a merge-request reviewer for the `→ master`
transition, full stop.** W3 is that transition happening on every single
change; W2 is that transition happening once per promotion, with an
ungated free-for-all upstream of it; W1 doesn't have the transition at all.

## The orchestrator's review, precisely

For a given proposed ref (a feature branch under W3, or `working`'s tip
under W2) and `master`'s current tip as the base:

1. **Build the merge, don't just inspect the branch.** Merge the proposed
   ref into a *scratch* clone of `master` (a temporary worktree, discarded
   whether the review passes or fails) and run every check below against
   the resulting tree — never against the branch's own `.gitattributes` or
   the branch's own claims about itself.
   [16](../securegit/16-adversarial-integrity.md)'s own T1 note is explicit
   about why this matters: "evaluate 'protected pattern' against the state
   *before* the push, not the incoming one" — otherwise an attacker
   downgrades `.gitattributes` and adds a plaintext file in the same
   change, and a check that trusts the incoming rules validates the new
   file against the attacker's own edited policy instead of `master`'s
   real one.
2. **T1 — attribute non-regression.** Every pattern protected in `master`'s
   current `.gitattributes` must still be protected in the merge result.
   Reusable as-is: `src/install.ts`'s attribute-line parsing and
   `src/verify.ts`'s `attributes-present`/`no-conflicting-attributes`
   checks already do this comparison; the orchestrator's new work is
   running them against a scratch merge instead of a live working tree,
   not inventing a new detector.
3. **T1's accident case, same detector.** Every blob under a still-protected
   pattern in the merge result must satisfy `looksLikeEnvelope()`
   (`src/envelope.ts`) — catches a colleague who genuinely forgot to
   `install` just as well as an attacker who removed the line on purpose,
   which is the whole point of [16](../securegit/16-adversarial-integrity.md)'s
   "accident and attack have the same signature and the same detection."
4. **T5 — hostile recipient: never auto-accept, always escalate.** Any
   change under `.securegit/recipients/**` is rejected by the orchestrator
   unconditionally, not evaluated for plausibility. This is a deliberate
   floor, not a missing feature:
   [16](../securegit/16-adversarial-integrity.md) is explicit that "there
   is no cryptographic fix" for recipient trust and that this is "a
   code-review problem with a detector attached" — an automated check has
   no way to distinguish `label: "onboarding new hire"` from chaos-5's own
   `label: 'legit-looking-refactor'` (see `chaos/agents/attacker.mjs`'s
   `attackT5_hostileRecipient`, which uses exactly that plausible label).
   The orchestrator's honest contribution here is forcing every recipient
   change through a human, every time, not weighing in on which ones are
   safe.
5. **T3/T4 — relocation and rollback: not built this pass, deliberately.**
   The design intent (still worth keeping as a target) was to flag — not
   silently accept, not reject outright — a blob already reachable in
   `master`'s history under a protected path reappearing verbatim at a
   *different* path (T3), or a protected path's merge-result blob matching
   an *older*, already-superseded blob for that same path rather than
   continuing forward from the branch's own edit history (T4). The actual
   implementation (`reviewAndMaybeMerge()` in `chaos/actors/driver.mjs`)
   doesn't build this detector — a relocation or rollback that doesn't also
   trip the T1/T5 checks above is currently accepted like any other clean
   merge, an explicitly documented gap (see the Test Cases table), not an
   oversight. [16](../securegit/16-adversarial-integrity.md) already states
   the honest ceiling here regardless: "there is no cryptographic fix...
   signed commits" is the actual answer to T3/T4, and even a built version
   of this check would only ever be a heuristic subset of that, not a
   replacement.
6. **Explicitly not this orchestrator's job.** General secret-scanning,
   static analysis, and "does this look like malware" are already this
   project's own required checks on real `master`
   (`.github/workflows/gitleaks.yml`, `.github/workflows/codeql.yml`) — the
   orchestrator is one *additional* required check specific to this
   project's own T1/T3/T4/T5 shapes, run alongside those, not instead of
   them. It also has nothing to say about chaos-4 ("virus") or chaos-6
   ("infra") — both corrupt an actor's *local*, uncommitted state
   (`~/.securegit`'s session/keyring/identity files), which never appears
   in a diff for anything to review. A merge-request reviewer, real or
   simulated, only ever sees what got committed.
7. **Accept or reject, recorded, never silent.** Passing every check above
   merges the proposed ref into `master` and pushes; failing any of 2-4
   rejects outright (`master` untouched); a T3/T4 flag from 5 merges only
   after being marked reviewed (deferred to the Open Questions section —
   real human review has no simulated equivalent, so the sandbox's initial
   version most likely treats "flagged" the same as "rejected," see below).
   Every outcome is a `record('action', …)` event in the existing
   `report.jsonl` shape (`chaos/lib/log.mjs`) — no schema change, just new
   message text (`merged <ref> onto master`, `rejected <ref>: <reason>`) —
   so [02](02-viewer.md)'s replay viewer picks these up as ordinary
   friendly-actor actions once it has label text for them.

## Enforcing "only the orchestrator writes `master`"

A review that a hostile pusher can simply route around is not a gate — it
is the same "convenience, not a defense" problem
[16](../securegit/16-adversarial-integrity.md) already raises about
client-side `pre-push` hooks. `master` must be **impossible to write to
except by the orchestrator's own merge**, enforced by the server, not by
actor scripts agreeing to behave.

`chaos/docker-compose.yml`'s `remote` (`git daemon --export-all`) is
unauthenticated by design — every client looks identical to the server,
so there is no *identity* for a `pre-receive` hook to check. This spec
originally leaned toward fixing that with a minimal `sshd` and one Unix
account per actor. **Built differently, and simpler: no identity is
needed at all**, because the hook doesn't need to distinguish *who* is
pushing — only *how*:

- `remote/entrypoint.mjs` installs a `pre-receive` hook that refuses any
  *update* (not creation) of `refs/heads/master` over the ordinary git
  protocol, unconditionally, for every pusher — there is no exemption for
  the orchestrator to configure, because the orchestrator never pushes
  over that protocol for `master` at all.
- Instead, `chaos/docker-compose.yml` mounts the bare repo's own volume
  (`remote-repo-data`) read-write into the `operator` container too. The
  orchestrator lands an accepted merge with a direct `git --git-dir=...
  update-ref refs/heads/master <new> <old>` against that same bare
  repository on disk — plumbing that never invokes `receive-pack` and so
  never runs the hook at all, the same way a local commit never asks a
  remote server's hooks for permission.
- The split that actually matters is **network access vs. filesystem
  access**, not an identity credential: every ordinary actor (including
  chaos-5) only ever gets `git://`, gated uniformly; only the one process
  this sandbox trusts gets a volume mount onto the bare repo's own disk.
  Confirmed locally (plain `git` plumbing, no Docker): a direct push to
  `master` after any commit exists is refused by the hook; the identical
  content landed via `update-ref` on the same repository succeeds outright.
- This is still precisely the mitigation [16](../securegit/16-adversarial-integrity.md)
  names and marks not built — "the one place a hostile pusher cannot opt
  out of a check is the server accepting the push" — and precisely the
  case it says it's valid for: "available for a self-hosted bare repo...
  **not** available at all on github.com" (github.com has no
  `pre-receive` hook access for ordinary users; it offers required status
  checks instead, which is what W3's orchestrator step *also* doubles as
  when deployed against a real github.com repository, per the table
  above's real-world-shape column).
- **Stated honestly, not overclaimed:** this sidesteps needing to invent a
  credential story at all, which is arguably more honest than the
  per-key `sshd` design would have been — but it only works because this
  sandbox already grants the orchestrator its own container and its own
  volume; it's a stand-in for "the one process a real deployment trusts
  with direct repository/API access" (a CI system's own backend, a
  platform's merge-button implementation), not a template for how a real
  self-hosted server would authenticate a fleet of *human* pushers, which
  still needs real per-human keys, rotation, and revocation.

## Topology (additions to [01](01-sandbox.md)'s diagram)

```
                         ┌───────────────────┐
                         │   remote (bare     │
                         │   repo over sshd,  │
                         │   pre-receive hook │
                         │   gates master)    │
                         └─────────┬──────────┘
              ┌──────────┬─────────┼─────────┬──────────────┐
        ┌─────▼─────┐┌───▼───┐┌────▼────┐┌───▼───┐    ┌─────▼─────┐
        │collab-a   ││collab-b││orchestr-││chaos-5│    │  (verifier,│
        │(feature   ││(feature││ator     ││"attack││    │  as in 01) │
        │ branches) ││branches)│(reviews,││er"    │    └────────────┘
        │           ││        ││merges to│(feature│
        │           ││        ││ master) ││branch  │
        └───────────┘└────────┘└─────────┘│under W3│
                                            └────────┘
```

Under **W2**, `collaborator-a`/`collaborator-b` push straight to `working`
(no feature branches, no per-push review — same trust level as W1, just on
a non-protected ref) and `orchestrator` periodically reviews and promotes
`working`'s tip onto `master` instead of reviewing per-branch. Under **W3**,
every collaborator push targets its own feature branch and the orchestrator
reviews per-branch, closer to real per-PR CI. **W1** is unchanged from
[01](01-sandbox.md) — no orchestrator, no feature branches, `remote` can
stay plain `git daemon` for that mode specifically, since there is nothing
for `sshd`/`pre-receive` to gate.

## Relationship to the existing driver scripts

Additive, not a rewrite — `chaos/actors/driver.mjs` and
`chaos/agents/attacker.mjs` both already exist and already work
(confirmed on real GitHub Actions infrastructure, per
[01](01-sandbox.md)'s "Later correction" note). The plan:

- A new `SANDBOX_WORKFLOW` environment variable: `direct-master` (today's
  only behavior, stays the default so nothing regresses),
  `working-branch` (W2), or `pr-gated` (W3).
- `collaboratorRound()` (`chaos/actors/driver.mjs`) pushes to `BRANCH`
  unchanged under `direct-master`; under the other two modes, pushes to
  `working` (W2) or to a per-role feature branch, `feature/${ROLE}` (W3)
  — one persistent, continuously-advanced branch per role rather than one
  per round: simpler, and the orchestrator's own `lastReviewedSha` map
  already skips re-reviewing a branch nothing has changed on, so a fresh
  branch per round would have bought nothing.
- Implemented as a `WORKFLOW !== 'direct-master'` branch inside the
  existing `operatorRound()` dispatch (`orchestratorReviewRound()`, same
  driver file, same `SANDBOX_ROLE=operator`) rather than a new role name
  or a separate file — see the Open Questions section below for why.
- `chaos/agents/attacker.mjs` gains the same branch-targeting change as
  collaborators under `pr-gated`/`working-branch` — chaos-5 pushing
  straight to `master` under those modes should be **refused by the
  `pre-receive` hook before the orchestrator ever sees it**, which is
  itself a predicted, checkable outcome (see Test Cases). Under
  `pr-gated`, chaos-5's attacks need their *own* feature branch to reach
  the orchestrator's review at all — a materially different attack shape
  than W1's "push straight to the branch everyone reads," worth being
  precise the two are not the same experiment.
- **Built narrower than this leaned:** `operator`'s existing
  `reconcileProtection()` ([16](../securegit/16-adversarial-integrity.md)'s
  T1/post-rotate recovery) only runs under `direct-master` — `main()`'s
  dispatch picks `operatorRound()` (unmodified) or
  `orchestratorReviewRound()` by `WORKFLOW`, not both. Under
  `working-branch`/`pr-gated` there's nothing for a post-hoc attribute
  reconciler to *do*: `master` only ever advances through a review that
  already requires `attributes-present`/`no-conflicting-attributes` to
  hold, so a downgrade landing on `master` at all would mean the
  pre-hoc gate itself failed — the right response to that is fixing the
  gate, not layering a second, independent repair pass behind it that
  could mask the gate's own bug by quietly cleaning up after it. Keeping
  both simultaneously (this spec's original leaning) was reasoned about
  in the abstract, not against what the review step actually already
  guarantees; not revisited unless a real run finds a case the review
  step itself can't catch but a post-hoc pass could.

## Verifying the invariants — what changes, what doesn't

[01](01-sandbox.md)'s three hard invariants and their checks are unchanged
by this spec — the verifier still audits a fresh, key-less clone of
`master` against the same three properties, regardless of which workflow
produced it. What's new is a **prediction this spec makes and a later real
run needs to confirm or correct**, stated precisely so "it worked" has a
falsifiable meaning:

| Workflow | Predicted plaintext-leak shape on `master` |
|---|---|
| W1 (`direct-master`) | Already measured: continues leaking every round after the downgrade, for the rest of the run (28 violations in the cited real run) — nothing stands between the attacker and `master`. |
| W2 (`working-branch`) | `working` itself may accumulate plaintext exactly like W1 (nothing gates it), but `master` should show *at most* whatever the orchestrator's promotion review missed — expected close to zero T1 violations reaching `master`, T5 changes never reaching it at all. |
| W3 (`pr-gated`) | Direct pushes to `master` refused at the transport (`pre-receive`), before content inspection. Attacks routed through a feature branch and caught by the review never reach `master` either. The only way plaintext reaches `master` under this mode is a gap in the orchestrator's own checks — which is exactly the scenario worth running chaos-5 against, repeatedly, to find. |

A run that contradicts this table is more interesting than one that
confirms it — same spirit as [01](01-sandbox.md)'s "found an interesting
near-miss, still triaging" framing for the verifier's report.

## Scope guardrails

Restated from [01](01-sandbox.md)'s own guardrails, extended for this spec:

1. **The orchestrator never executes anything from a reviewed branch.**
   Every check in §"The orchestrator's review" reads tree/blob content and
   diffs; nothing here runs a build, a test, or any command the branch
   itself supplies. Merging untrusted code and then running it is a
   different, much larger threat model (arbitrary code execution via CI)
   this spec does not take on.
2. **`sshd`+`pre-receive` proves the mechanism, not a production
   credential system.** Restated from §"Enforcing" above: fine for
   answering whether the gate works and by how much; not a template for
   real per-human key management.
3. **Still no defense against chaos-4/chaos-6.** Restated from
   §"The orchestrator's review" point 6: local, uncommitted state
   corruption is invisible to any merge-request reviewer, real or
   simulated, by construction.
4. **W1 stays exactly as built.** This spec adds two new modes; it does
   not change `direct-master`'s existing behavior, coverage, or its
   already-measured real-world result.

## Test Cases

| Test | Where it'd live | Status |
|------|------------------|--------|
| W3: a clean collaborator feature branch is merged to `master` | `chaos/actors/driver.mjs`'s `reviewAndMaybeMerge()` | ✅ (local repro) |
| W3: chaos-5's T1 (attribute downgrade) on a feature branch is rejected, `master`'s `.gitattributes` unchanged | same | ✅ (local repro) |
| W3: chaos-5's T5 (hostile recipient) on a feature branch is always rejected/escalated, never merged | same (`recipientDiff` check) | ✅ (code path exists; not yet exercised by a real run) |
| W3: chaos-5's T3/T4 (relocation/rollback) on a feature branch is flagged, not silently merged | — | 🔲 **scope-cut, not built this pass** — `reviewAndMaybeMerge()`'s doc comment says so explicitly: no cryptographic or heuristic detector for T3/T4 exists yet, so a relocation/rollback that doesn't also trip T1/T5 is currently *accepted*, same as any other clean merge. Left as a documented gap (see this file's own "T3/T4 — relocation and rollback" review point), not silently claimed done. |
| W3: chaos-5 pushing straight to `master` is refused by the `pre-receive` hook, never reaches the orchestrator | `remote/entrypoint.mjs`'s hook + `attacker.mjs`'s `attackDirectMasterBypass` | ✅ (local repro; real hook install path not yet run) |
| W3: the merge-review step evaluates against `master`'s pre-merge state, not the branch's own edited `.gitattributes` (the same-push downgrade-plus-plaintext attack) | `chaos/actors/driver.mjs`'s `reviewAndMaybeMerge()` (always `checkout -B review origin/BRANCH` fresh) | ✅ (local repro) |
| W2: `working` accumulates chaos-5's attacks like W1, but they don't cross the promotion into `master` | full sandbox run, `SANDBOX_WORKFLOW=working-branch` | 🔲 (same review code path as W3, applied to one shared ref — not separately repro'd) |
| A full real run under each of the three `SANDBOX_WORKFLOW` modes, verifier results compared against the "Predicted plaintext-leak shape" table above | GitHub Actions `chaos` job (matrix), `chaos-publish` job, `chaos/viewer/index.html`'s comparison panel | 🔲 |

## Open Questions before implementation starts

- **What happens to a T3/T4-flagged change with no human to review it?**
  The sandbox has no human in the loop. Leaning toward treating "flagged"
  as "rejected" for the sandbox's own purposes (the conservative choice,
  and consistent with never silently merging something the design itself
  says it can't fully vouch for) while documenting that a real deployment
  would route the flag to an actual reviewer instead of auto-rejecting —
  to be confirmed once the orchestrator's review logic is actually being
  written, not decided in the abstract here.
- **One driver file or a new one — resolved: one file.** `chaos/actors/driver.mjs`
  already branched on `SANDBOX_ROLE`; the review logic turned out to
  reuse enough of `operatorRound()`'s surroundings (`pullOnce()`, `git()`,
  `securegit()`, the shared `gitEnv()`) that a separate file would have
  meant importing most of the same helpers anyway, so it landed as
  `orchestratorReviewRound()`/`reviewAndMaybeMerge()`/`landReviewedMerge()`
  alongside `operatorRound()`, selected by `WORKFLOW` rather than a new
  `SANDBOX_ROLE` value. Revisit only if this file's size actually becomes
  a problem, not preemptively.
- **Per-mode `remote` image — resolved: one image, always.** No `sshd`
  ended up needed at all (see "Enforcing" above) — `remote` always runs
  the same `git daemon`, and `SANDBOX_WORKFLOW` only changes whether
  `entrypoint.mjs` installs a rejecting or a no-op `pre-receive` hook.
  Simpler than either option this question originally posed.
- **Whether W2 and W3 need separate real CI runs or one parameterized
  job — resolved, differently than leaned: all three, every time, as a
  `fail-fast: false` matrix.** This does triple the `chaos` job's
  wall-clock/compute cost (three concurrent legs instead of one), traded
  deliberately for what the comparison is actually for — a nightly
  three-way result with nothing to reconcile across separate runs' timing
  or attack-randomness differences. Revisit (e.g. `workflow_dispatch`
  input choosing a subset) if the nightly cost turns out to matter more
  than this spec assumed; not before there's real evidence it does.

## Relationship to Other Specs

- [00](00-test-plan.md) — the categories this sandbox exercises; unchanged
  by this spec
- [01](01-sandbox.md) — W1 in full, the topology and orchestration this
  spec extends rather than replaces, and the real 28-violation run this
  spec's own reasoning is grounded in
- [02](02-viewer.md) — the replay viewer that will need label text for
  `merged`/`rejected`/`flagged` events, not a schema change
- [../securegit/01-threat-model.md](../securegit/01-threat-model.md) — A6/A7,
  and "repository integrity and authenticity... signed commits and
  protected branches... orthogonal and both are still required," which
  this spec is the sandbox's answer to actually exercising
- [../securegit/16-adversarial-integrity.md](../securegit/16-adversarial-integrity.md) —
  the T1/T3/T4/T5 catalogue the orchestrator's checks are built from, and
  the "recommended, not built" server-side enforcement note this spec
  finally specifies precisely enough to build
