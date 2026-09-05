# Evidence contract

MergeGrounds evidence is a machine-readable receipt, not a proof by itself. Its value depends on where the runner executed, which commit and policy were used, and whether a trusted system retains or signs the result.

Keep claims, advisory output, evidence, and decisions distinct. Model confidence, explanation, chain-of-thought, self-review, provider claims, benchmark scores, and dashboard labels are not evidence and cannot satisfy a gate. The portable runner's receipt is not itself an independent admission decision.

## Required properties

Every admission run must identify:

- schema version and unique run ID;
- UTC start and finish timestamps;
- tested Git commit and, when available, Git tree;
- protected-base pre-implementation design, acceptance-oracle, and invariant-record digests;
- profile, risk tier, detected adapters, policy hash, and resolved tool identities; a version is included only when supplied by trusted provisioning or a typed tool report;
- every stage and command result, including timeout and exit status;
- declared thresholds and parsed observed metrics;
- required report/artifact path, size, and SHA-256 digest;
- removed sensitive environment variable names, never their values;
- final status derived fail-closed from all required controls.

An absent Git commit, dirty tree, empty report, unparsable metric, missing artifact, or stage reported only as “skipped” must be called out. A release policy may reject all such states.

The local normalizer accepts an `allow` record only when its canonical UTC finish time is no more than five minutes in the future and no more than one hour old at validation. Its elapsed time must not exceed the smaller of 24 hours and `execution.timeout_seconds × exact expected command-result count + 15 minutes` of bounded non-command overhead. A stale, future-dated, reversed, or overlong record becomes a deny receipt. The UUIDv4 evidence ID and ambient GitHub run/attempt fields aid correlation, but the portable local normalizer does not prove their global uniqueness or bind them to an authenticated platform execution. The external verifier must bind run and attempt identity, reject replays/conflicting verdicts, and retain the accepted digest in append-only storage.

MergeGrounds's local `tool_versions` field deliberately performs no candidate-declared `--version` execution during discovery. For non-Python tools it records the resolved executable plus `version-not-executed`; this proves presence, not version. Pin versions in a trusted runner image/lock and bind the observed version through the stage's typed report or external producer evidence. The current verifier's own Python version may be recorded because that interpreter is already executing the gate.

## Conditional AI-product evidence

When the shipped product uses AI/ML and policy materializes `MG-AI-001` through `MG-AI-008`, each result also identifies every applicable model/provider revision, inference/prompt configuration, corpus/index/retrieval/context component, evaluation/training dataset and expected case set, oracle/judge, base/candidate model, tool/capability/sandbox/egress policy, provider-policy record, and runtime promotion subject.

AI metric reports must include exact expected and actual case/slice identities; numerator and denominator; invalid, skipped, duplicate, unexpected, and retried cases; critical-slice outcomes; baseline conditions; thresholds; input/component digests; and privacy classification. Zero cases, hidden invalid cases, missing expected scope, NaN/infinity, an unrecomputable aggregate, or a passed aggregate masking a failed critical slice invalidates the result.

Typed payloads and per-control requirements are defined in [`ai-product-assurance.md`](ai-product-assurance.md) and [`../../../docs/assurance-evidence.md`](../../../docs/assurance-evidence.md). A local Boolean or repository file cannot prove provider contract terms, provider-internal retention/deletion, human identity/independence, or that a holdout remained private. Those fields reference fresh signed records from separately administered authorities; without them the control is `not_evaluated`.

Do not collect chain-of-thought. Store minimal structured measurements, case/source IDs and digests, redacted tool metadata, and authority references instead of raw prompts, retrieved contexts, embeddings, outputs, credentials, or customer data unless a separately approved evidence purpose and retention policy requires the content.

## Status vocabulary

- `pass`: the control ran, produced valid evidence, and met policy.
- `fail`: execution or policy failed, including timeout.
- `not_evaluated`: a prerequisite, scope, parser, producer, or external verification is unavailable; this is not success.
- `waived`: a rule-specific, valid exception authorizes the exact non-pass state while preserving the underlying result.

UI or transport layers may display `passed`, `failed`, `not_applicable`, `externally_unverified`, or `blocked`, but the decision record maps them to the four normative states above. `not_applicable`, `externally_unverified`, and `blocked` map to `not_evaluated` until trusted policy materialization proves omission or a valid exception yields `waived`. Do not use `skipped` as an admission-success state.

`mergegrounds.py` implements only `pass`, `fail`, and `not_evaluated`; it never consumes repository exception records or emits `waived`. That fourth state is reserved for a protected external verifier that can authenticate the exact subject/finding/evidence tuple, signatures, revocations, action/environment, budget, and append-only use ledger. Local exception checks are structural registry linting only, and a local exception never changes a gate decision.

## Metric integrity

The runner must parse known report formats; exit code alone is insufficient unless the tool's pinned configuration demonstrably enforces the same threshold. Reject NaN, infinity, negative values, values above 100, missing denominators, unknown status values, empty mutation sets, and replayed reports. The portable runner removes pre-existing configured untracked metric files before each metric stage and requires the stage to recreate them; tracked report targets and unsafe paths are denied.

Record both numerator/denominator and percentage when the format exposes them. Mutation score must state how killed, survived, timed-out, no-coverage, ignored, and invalid mutants are treated. Timeouts are never counted as safe by default.

For `MG-QLT-008`, record the selected adapter/tool identity, expected and analyzed changed-code scope, baseline and candidate values, and individual deltas for complexity, duplication, dead/unreachable code, suppressions, and explicit refactor debt. An opaque maintainability score, missing baseline, unsupported changed file, or aggregate that masks a regressed enforced dimension is not sufficient evidence.

## Storage and trust

For pull requests, upload reports from an unprivileged runner with a short retention period. For releases, a trusted workflow should retrieve evidence by immutable run/artifact identity, verify commit and hashes, create the SBOM/provenance, and sign or attest without executing pull-request code.

Do not commit ordinary run evidence. The repository keeps only `.mergegrounds/evidence/.gitkeep`. Evidence may contain project paths and dependency names; apply the repository's data-retention policy and never include command output that may contain secrets.

## Control-plane lock

`.mergegrounds/control-plane.lock.json` schema 2 binds the SHA-256 and committed Git executable mode of each repository-owned control file. `seal --write` refuses dirty, untracked, staged-only, or otherwise HEAD-divergent critical controls: commit the reviewed controls first, generate the lock, then commit the lock separately. Verification requires the declared seal commit to remain an ancestor of the current HEAD, reproduces every record from that immutable tree, and separately compares current HEAD, index, and worktree content/modes. It rejects content drift, filesystem or index-only `chmod` drift, unexpected/missing control files, dishonest commit provenance, and legacy content-only lock entries. Because a pull request can still propose reviewed changes to both code and policy over multiple commits, the lock is not an independent trust anchor. High-assurance enforcement must compare against a trusted external workflow or approved base-branch policy.
