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

**Status: IMPLEMENTED AND CONFIRMED.** Three real GitHub Actions runs
(33955186271 → 33955584166 → 33955942857 → 33956353815, each fixing a real
bug the previous one found) converged on a clean, repeatable result:
`pr-gated` reaches `hardInvariantsHeld: true` — zero plaintext violations,
zero hostile recipients, zero data loss — while `direct-master` and
`working-branch` both consistently show real violations. See "Predicted
plaintext-leak shape" below for the corrected mechanism (branch isolation,
not just post-hoc rejection) and the Test Cases table for exactly what
each bug was. `SANDBOX_WORKFLOW`
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
[16](../securegit/16-adversarial-integrity.md)'s T1 recovery fix.

**First real run (33955186271) found a real bug the repro's own fetch
step had silently papered over.** `orchestratorReviewRound()`'s first cut
learned a candidate branch's sha via `git ls-remote` alone — which never
transfers the commit *object*, only the ref pointer — so every real merge
attempt after a branch's first (still-at-bootstrap) review failed with
git's own "not something we can merge" (an unknown-object error, easily
misread as an ordinary merge conflict, since both land in the same
`merge.code !== 0` branch). Net effect: `pr-gated` and `working-branch`
both showed `zeroDataLoss: false` (every collaborator commit "missing"
from the operator's own `git log --all`, because their branches were
never actually fetched) even though `noPlaintextLeaked` still correctly
came back `true` for `pr-gated` — master simply never advanced past its
initial clean state, which trivially has nothing to leak. The local repro
never caught this because it always fetched the branch by name before
merging by hand; the real driver code didn't do the same until this was
found. Fixed by having `orchestratorReviewRound()` `git fetch origin
<ref>` (not `ls-remote`) before ever attempting the merge.

**Second real run (33955584166) — the actual comparison landed clean**
(`pr-gated`: all three invariants held; `direct-master`/`working-branch`:
real violations, exactly the target claim) **but exposed two more, smaller
bugs.** `chaos-publish`'s site assembly assumed each matrix leg's
downloaded artifact was flat; `actions/upload-artifact` actually kept a
`site/` prefix (the upload step lists `site/report.jsonl` alongside a
*sibling* `verifier.log`, so the computed common ancestor is the workspace
root, not `site/`) — every mode's comparison-panel subfolder came back 404
until the copy path was corrected. Separately, `working-branch` showed
`zeroDataLoss: false` by one or two commits even with zero decrypt
failures — a collaborator's very last push landing after the
orchestrator's last review round of the run, past the point anything would
fetch that branch's tip again before `finalIntegritySelfCheck()`'s
`git log --all`. Fixed by fetching every branch (`git fetch origin`, no
ref argument) immediately before that check, not just `BRANCH`.

**Third real run (33955942857) confirmed the site fix, re-surfaced the
same data-loss race** (this time on `pr-gated`, 2 commits) **since the
fetch-every-branch fix hadn't landed yet — fourth run (33956353815)
confirmed it resolved:** `pr-gated` reached `hardInvariantsHeld: true`
outright, all three invariants clean.

**Since then: commit signing (✅ both halves built).**
[08-multi-recipient.md](../securegit/08-multi-recipient.md)'s "Commit
signing" (`securegit identity init`'s detect-or-generate signing key,
`key add-recipient --signing-key`, and `verify`'s
`commit-signed-by-recipient` check on `HEAD`) and §"The orchestrator's
review, precisely" point 5 (`driver.mjs`'s `allCommitsSignedByRecipient()`
— every commit unique to the proposed ref, not just its tip, checked
against `master`'s own recipient list before landing) are both
implemented, found to subsume the T3/T4 gap this document originally
scoped out ("not built this pass, deliberately") once it became clear the
identity question is simpler and more general than trying to detect each
content shape individually.

Confirmed by direct local plumbing test (no Docker): a real recipient
file with a registered SSH signing key, an unsigned commit (`%GF` empty,
correctly rejected), a commit signed by that registered key (`%GF`
matches `key list-recipients --json`'s `signingFingerprint`, correctly
accepted), and a commit signed by an unregistered key (`%GF` present but
absent from the registered set, correctly rejected) — the same three
shapes point 5 exists to catch.

**Honestly scoped, not yet exercised by a real chaos run:** the sandbox's
own actors (`bootstrapAsCollaboratorA`/`bootstrapAsFollower`) share one
keyring copied over `SHARED_DIR` rather than registering each other as
recipients at all — so today, every real Docker chaos run has 0
recipients, which is this check's own designed no-op tier
(`commit-signed-by-recipient` and `allCommitsSignedByRecipient()` both
treat 0-1 recipients as "nobody to impersonate," a silent pass, not a
failure). The plumbing is real and locally confirmed; making a live chaos
run actually exercise a rejection needs a separate, larger change —
registering collaborator-a/collaborator-b as signing recipients at
bootstrap and deliberately leaving chaos-5 unregistered — not done here.

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
4. **T5 — hostile recipient: never auto-accept, always escalate — and,
   once commit signing exists, rejected outright before it even reaches
   that escalation.** Any change under `.securegit/recipients/**` is
   rejected by the orchestrator unconditionally, not evaluated for
   plausibility. This is a deliberate floor, not a missing feature:
   [16](../securegit/16-adversarial-integrity.md) is explicit that "there
   is no cryptographic fix" for recipient trust and that this is "a
   code-review problem with a detector attached" — an automated check has
   no way to distinguish `label: "onboarding new hire"` from chaos-5's own
   `label: 'legit-looking-refactor'` (see `chaos/agents/attacker.mjs`'s
   `attackT5_hostileRecipient`, which uses exactly that plausible label).
   Point 5 below adds a check that catches this *specific* attacker's
   attempt before the escalation logic even runs (chaos-5 was never a
   recipient, so it can't sign at all) — real value, but it doesn't retire
   this floor: a signature only proves *who* committed something, never
   *whether* the recipient they're legitimately adding should be trusted,
   which is still exactly the human question this point exists to force.
5. **Commit signing — one general check, not a T3/T4-specific detector
   (✅ both halves — [08-multi-recipient.md](../securegit/08-multi-recipient.md)'s
   "Commit signing" and this section — see the "Since then" note above for
   what's built vs. what a real chaos run has actually exercised).** Every commit unique to the
   proposed ref (`git log origin/master..<sha>`) must be signed, and by a
   fingerprint already present in `master`'s own `.securegit/recipients/`
   — reject the whole merge otherwise. This was originally scoped as "not
   built this pass, deliberately" specifically for T3/T4 (flag a
   relocated/rolled-back blob) — reconsidered once it became clear the
   *identity* question is simpler and more general than the *content*
   question: an attacker who was never added as a recipient can't produce
   a valid signature under any registered key, so this one check rejects
   T1/T3/T4/T5 alike, and anything else an attacker without a registered
   identity might try, without needing to recognize the attack shape at
   all. [16](../securegit/16-adversarial-integrity.md)'s own ceiling
   still holds precisely: "there is no cryptographic fix" for the
   *content itself* — a relocated blob is still genuinely valid
   ciphertext — this check works on the *commit*, not the blob, which is
   a different, narrower, and actually closeable question.
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
   merges the proposed ref into `master` and pushes; failing any of 2–5
   rejects outright, `master` untouched — no separate "flagged" state:
   point 5's reconsideration (a hard identity check, not a content
   heuristic) means there's no longer a middle "looks suspicious, ask a
   human" outcome this sandbox would need to simulate without a human in
   the loop, which the original T3/T4 design (see point 5's own history)
   would have needed. Every outcome is a `record('action', …)` event in the existing
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

| Workflow | Predicted plaintext-leak shape |
|---|---|
| W1 (`direct-master`) | Already measured: continues leaking every round after the downgrade, for the rest of the run (28 violations in the cited real run) — nothing stands between the attacker and `master`. |
| W2 (`working-branch`) | `working` itself may accumulate plaintext exactly like W1 (nothing gates it), and — see the correction below — that alone is already a real leak, not a quarantined staging area; the promotion review only ever stops it from *also* being blessed as `master`'s own history. |
| W3 (`pr-gated`) | Direct pushes to `master` refused at the transport (`pre-receive`), before content inspection. Attacks routed through a feature branch and caught by the review never reach `master` either. |

**Confirmed by three real runs (33955186271 fixed forward through
33956353815) — `pr-gated` reached `hardInvariantsHeld: true`, 0 violations,
0 hostile recipients, twice out of three; `direct-master` and
`working-branch` never once did.** But the *mechanism* for W3's result
needed correcting once the numbers were actually looked at, not just
their pass/fail color:

**Correction: `verify.mjs`'s plaintext check walks `git rev-list --all`
— every branch reachable in the clone, not `master` alone** — because
[01](../securegit/01-threat-model.md)'s own invariant is "no plaintext
ever crossed the boundary... everywhere in history", and a feature/
working branch sitting on the shared remote is exactly as visible to
anyone with ordinary read access as `master` is; nothing about a branch
name makes git access-control it separately. This was invisible under W1
(only `main` ever existed, so "`--all`" and "`main`" were the same set)
and is why a run that contradicts the table above is more interesting
than one that confirms it — same spirit as [01](01-sandbox.md)'s "found
an interesting near-miss, still triaging" framing. It surfaced a real,
structural difference between W2 and W3 the original table's "master
should show at most..." framing didn't capture:

- **W3 achieves zero not merely because the gate rejects bad merges, but
  because each role's own feature branch is *isolated* from every other
  role's.** T1 downgrades `.gitattributes` on `feature/chaos-5-attacker`
  — a file collaborators never read, since each of their own branches has
  its own independent copy. A collaborator's next edit on their *own*
  branch is completely unaffected; there is no shared state for the
  downgrade to poison. This is a stronger property than "reviewed before
  landing" — it's that the attack has no victim to reach in the first
  place.
- **W2 has no such isolation — `working` is shared, so a downgrade
  landing there *does* poison every collaborator's next edit on it**,
  producing a real plaintext blob on the one branch everyone (including
  chaos-5) reads and writes. The promotion review still does its job —
  none of that ever gets blessed as `master`'s own history — but the leak
  already happened the moment it was pushed, on a branch anyone with
  ordinary read access to the remote could already see. Confirmed exactly
  this shape in the cited runs: `working-branch` legs consistently showed
  real violations while their own `merged working onto master` events
  stayed few and early (before the first T1/T5 landed), with every later
  promotion attempt correctly rejected.

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
| W3: a clean collaborator feature branch is merged to `master` | `chaos/actors/driver.mjs`'s `reviewAndMaybeMerge()` | ✅ (local repro + real runs, e.g. 33956353815: `pr-gated` merged legitimate branches every run) |
| W3: chaos-5's T1 (attribute downgrade) on a feature branch is rejected, `master`'s `.gitattributes` unchanged | same | ✅ (local repro + real runs) |
| W3: chaos-5's T5 (hostile recipient) on a feature branch is always rejected/escalated, never merged | same (`recipientDiff` check) | ✅ (real runs: `pr-gated`'s `hostileRecipients` count was 0 in every run) |
| W3: chaos-5's T3/T4 (relocation/rollback) on a feature branch is rejected via the commit-signing check (§5), not silently merged | `chaos/actors/driver.mjs`'s `allCommitsSignedByRecipient()` | ✅ built (chaos-5 is never a recipient, so any commit it produces fails the check regardless of content) — **not yet exercised by a real chaos run**: the sandbox's actors share one keyring rather than registering each other as signing recipients, so every live run still has 0 recipients, the check's own no-op tier. Registering collaborator-a/b at bootstrap (chaos-5 deliberately excluded) is the follow-up that would make a real run actually exercise a rejection. |
| Commit signing: an unsigned commit, or one signed by a non-recipient, is rejected by the orchestrator regardless of what it changes | `chaos/actors/driver.mjs`'s `allCommitsSignedByRecipient()` | ✅ built, confirmed by direct local plumbing test (real `ssh-keygen`/`git -S`/`%GF`, no Docker) — not yet exercised by a live chaos run, see the row above |
| Commit signing: a legitimate collaborator's properly-signed commit is unaffected, accepted as before | `chaos/actors/driver.mjs`'s `allCommitsSignedByRecipient()` | ✅ built, confirmed by the same local plumbing test — not yet exercised by a live chaos run |
| W3: chaos-5 pushing straight to `master` is refused by the `pre-receive` hook, never reaches the orchestrator | `remote/entrypoint.mjs`'s hook + `attacker.mjs`'s `attackDirectMasterBypass` | ✅ (local repro + real runs: every `direct-master-bypass` attempt logged `rejected: true`) |
| W3: the merge-review step evaluates against `master`'s pre-merge state, not the branch's own edited `.gitattributes` (the same-push downgrade-plus-plaintext attack) | `chaos/actors/driver.mjs`'s `reviewAndMaybeMerge()` (always `checkout -B review origin/BRANCH` fresh) | ✅ (local repro) |
| W2: `working` accumulates chaos-5's attacks like W1 — confirmed, and worse than originally predicted: a shared branch is *not* a quarantined staging area, since anyone with ordinary read access to the remote can already see it (see the corrected mechanism above) | full sandbox runs, `SANDBOX_WORKFLOW=working-branch` | ✅ real violations every run; promotion-to-`master` review itself also confirmed working (rejects resumed correctly once a hostile recipient landed on `working`) |
| A full real run under each of the three `SANDBOX_WORKFLOW` modes, verifier results compared against the "Predicted plaintext-leak shape" table above | GitHub Actions `chaos` job (matrix), `chaos-publish` job, `chaos/viewer/index.html`'s comparison panel | ✅ four real runs, three real bugs found and fixed along the way |

## Open Questions before implementation starts

- **What happens to a T3/T4-flagged change with no human to review it? —
  resolved by reframing, not by answering.** This question assumed T3/T4
  needed a *content* heuristic with an uncertain, "looks suspicious"
  middle state. Once the check became identity-based (point 5: is this
  commit signed by an already-known recipient) there's no middle state
  to route anywhere — it's the same hard accept/reject as every other
  check. The genuinely open question underneath this one is now about
  *signing itself*, not about what to do with an uncertain verdict: how
  does a repository handle a legitimate collaborator who hasn't set up a
  signing key yet (see [08-multi-recipient.md](../securegit/08-multi-recipient.md)'s
  "two cases this rule must not silently break")? Answered for the general
  case (the no-op tiers), still open for this sandbox specifically: the
  check itself is built (`allCommitsSignedByRecipient()`), but
  `bootstrapAsCollaboratorA`/`bootstrapAsFollower` still share one keyring
  rather than registering each other as recipients at all, so a real
  chaos run's recipient count is always 0 today — the check's own no-op
  tier, not a gap in the check. The remaining work is exactly the wiring
  this bullet originally anticipated: every legitimate actor's container
  generates a signing key at bootstrap and registers itself as a
  recipient (same shared-volume mechanism the keyring already uses),
  chaos-5 deliberately excluded — not done here.
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
  `merged`/`rejected` events, not a schema change
- [../securegit/01-threat-model.md](../securegit/01-threat-model.md) — A6/A7,
  and "repository integrity and authenticity... signed commits and
  protected branches... orthogonal and both are still required," which
  this spec is the sandbox's answer to actually exercising
- [../securegit/16-adversarial-integrity.md](../securegit/16-adversarial-integrity.md) —
  the T1/T3/T4/T5 catalogue the orchestrator's checks are built from, and
  the "recommended, not built" server-side enforcement note this spec
  finally specifies precisely enough to build
- [../securegit/08-multi-recipient.md](../securegit/08-multi-recipient.md) —
  "Commit signing," the identity keypair and recipient-file field this
  spec's point 5 depends on — now built, both there and here
- [../securegit/13-verify.md](../securegit/13-verify.md) — `verify`'s own,
  narrower (`HEAD`-only) half of the same signature check
