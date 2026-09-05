# Admission control model

Use this reference whenever evaluating, planning, reviewing, or admitting a code change. It is stack-neutral and normative for the strict profile.

## Core rule

Treat every contribution as untrusted regardless of whether its author is a human, AI, generator, vendor, or bot. Known AI assistance is metadata for analysis and never a reason to reduce controls.

Keep claims, advisory output, evidence, and decisions distinct. A model's confidence, explanation, chain-of-thought, self-review, or benchmark reputation has no admission authority. Only typed evidence from a policy-authorized producer may satisfy its exact materialized control, and only the independent verifier may issue an admission or release decision.

Do not claim that code is “safe” merely because tools pass. Report the precise assurance statement:

> The exact revision is admissible under policy `<digest>` at risk tier `<R0–R4>` because all materialized controls have authentic, complete, fresh evidence; the final diff has the required independent approvals; and no hard prohibition applies.

If that statement cannot be completed from evidence, deny admission.

Normative words `MUST`, `MUST NOT`, `SHOULD`, and `MAY` carry their RFC 2119 meanings.

## 1. Required inputs

Before classification, obtain:

- canonical repository, protected target ref, base commit, candidate commit, and tree/diff digests;
- behavior/acceptance criteria and affected components;
- file/path and semantic diff, including renames, deletions, modes, symlinks, submodules, binaries, and generated output;
- AI/generator disclosure when known, generator source, and reproducibility command;
- external interfaces, trust boundaries, privilege changes, and untrusted input paths;
- data classifications, retention/privacy impact, and tenant boundaries;
- when AI/ML is shipped in the product: model/provider identities, prompts/templates, inference settings, retrieval corpora/indexes, embedding/reranking components, evaluation/training datasets, agent tools, capability boundaries, and production monitoring;
- dependency/toolchain/lockfile changes and package origins;
- infrastructure, CI, policy, ownership, signing, and release-path changes;
- database/state migration, compatibility, rollback/roll-forward, and blast radius;
- tests, threat-model delta, rollout/observability, and evidence references.

Contradictory, missing, or unverifiable input is not neutral: select the higher plausible tier and require completion before admission.

## 2. Risk classification

Risk is determined by deterministic escalation triggers. **The highest matching tier wins.** Do not average dimensions into a lower score. Machine-derived diff facts override an author's lower declaration. A downgrade requires a separate signed classification rationale and independent approver.

Legacy four-label configurations map as follows: `low` = R1, `moderate` = R2, `high` = R3, and `critical` = R4. R0 is reserved for proven inert changes. Store the canonical R-tier in evidence even when a UI also displays the legacy label.

### R0 — inert change

All of these must be true:

- no executable/runtime/build/test/policy behavior can change;
- no security guidance, user trust decision, legal promise, API contract, or operational procedure changes materially;
- no dependency, lockfile, generated executable, binary, symlink, submodule, workflow, or configuration change;
- impact is limited to prose, comments, safe static assets, or mechanically verified formatting.

Examples: typo correction, explanatory docs, non-functional comment. Documentation containing commands, security claims, or operator instructions may be R1 or higher.

### R1 — bounded low-risk behavior

All of these must be true:

- localized, reversible behavior with no new trust boundary or privilege;
- no authentication, authorization, cryptography, secrets, payments, tenant isolation, privacy-sensitive data, parser/deserializer, network exposure, infrastructure, release, or policy change;
- dependency graph and persistent data schema are unchanged;
- blast radius is one non-critical component and rollback is routine.

Examples: internal leaf logic, low-impact UI behavior, test additions that do not change enforcement.

### R2 — material application change

Use R2 when any of these applies and no R3/R4 trigger applies:

- new or changed API/interface, untrusted input, outbound network call, file handling, cache, concurrency, or background job;
- dependency addition/update, lockfile resolution, container base change, or supported toolchain update;
- internal/confidential data flow, logging/telemetry change, or reversible schema migration;
- meaningful performance/cost/availability impact or multi-component blast radius;
- product model/revision, inference parameter, prompt/template, embedding, chunking, retrieval/reranking logic, corpus ingestion, output validator, AI telemetry, or non-sensitive AI evaluation-data change;
- public UI that affects a trust decision, form/input handling, session-adjacent behavior, or business rules;
- material test harness, code generator, or build behavior change outside protected control-plane files.

### R3 — high-risk or security-sensitive change

Any one trigger selects R3 unless R4 applies:

- authentication, authorization, identity, session, token, permission, tenant isolation, admin surface, or privilege boundary;
- cryptography, key handling, secret management, signature/provenance verification, update mechanism, or security logging;
- regulated/restricted/customer data, privacy boundary, payments, safety/financial decision, or destructive data operation;
- external model use with customer/restricted data; tenant- or authorization-sensitive retrieval; fine-tuning/training; model-driven tools; provider data-handling changes; or AI behavior used for a high-impact decision;
- parser/deserializer/template/interpreter/compiler behavior on untrusted input; upload/archive extraction; command/query construction;
- internet-exposed service, sandbox boundary, native/unsafe memory, kernel/device access, or high-impact resource control;
- irreversible or large-scale state/data migration; cross-region/disaster recovery behavior;
- production infrastructure, deployment permissions, network perimeter, runtime policy, or critical availability path;
- new dependency with install scripts/native code, immature origin, broad privilege, or critical runtime role;
- security fix whose details expose an actively exploitable condition.

### R4 — control-plane or exceptional critical change

Any one trigger selects R4:

- CI workflows, branch/ruleset protection, merge controller, gate policy, risk classifier, exception budget, baseline/suppression rules, owners, audit/evidence schemas, trusted identities, runner/builder images, signing, artifact promotion, or release authorization;
- AI applicability rules, release thresholds, trusted evaluator identities, private-holdout or production-evaluation registry, approved-provider registry, model-promotion/revocation authority, capability broker, sandbox/egress policy, or safety-critical/organization-wide model promotion;
- recovery/admin paths, root of trust, policy engine/verifier, credential broker, or system-wide security library;
- change can silently authorize arbitrary future code/artifacts or defeat both contours;
- blast radius is organization-wide, safety-critical, or cannot be bounded/recovered using tested controls;
- unsigned/unreproducible executable or binary is proposed for a trusted/runtime path;
- requested ordinary exception would bypass a non-waivable control.

R4 is not automatic permission to merge. It invokes the most stringent design, verification, and approval track; hard prohibitions still deny.

## 3. Hard prohibitions

The strict profile MUST deny and offers no ordinary exception for:

- a live credential, private key, authentication token, or customer secret in source/history/artifacts;
- known malicious/backdoored dependency or artifact, or confirmed unauthorized data-exfiltration behavior;
- evidence/signature forgery, subject mismatch, hidden result truncation, or candidate-controlled attestation signing;
- candidate selection/modification of the active policy used to judge itself;
- direct/force push or an update to protected state without the merge controller and exact decision attestation;
- untrusted candidate code executing with production, signing, control-plane, or protected-repository write credentials;
- missing required independent human authorization, including two-human break-glass activation;
- release/deployment by mutable name when digest verification fails or provenance does not reach admitted source;
- known reachable critical/high vulnerability in introduced or materially changed code/dependency;
- an irreversible destructive operation without independently tested recovery or safe roll-forward;
- an unknown executable/binary, unreviewable obfuscation, or generated security-critical code without trusted reproducible source;
- deletion/disablement of tests, scans, owners, audit, or protection without an approved R4 control-plane change;
- an AI product sending data under an absent, expired, mismatched, or unverifiable required provider authorization; or a model-driven action bypassing its capability broker, sandbox, egress policy, or required effect-bound confirmation.

A proven false positive is adjudication, not a waiver. Preserve the original finding plus signed technical proof and corrected normalized state.

## 4. Mandatory baseline gates

The policy materializes applicable controls from the repository/stack manifest. Every protected change MUST receive evidence for this baseline:

### Change integrity

| ID | Required outcome |
|---|---|
| `MG-META-001` | complete change manifest, acceptance criteria, AI/generator disclosure when known |
| `MG-META-002` | machine-assisted risk classification with all escalation reasons |
| `MG-META-003` | a protected-base-resident pre-implementation design record predates the candidate and defines the independently reviewable acceptance oracle, system invariants, boundaries, and failure behavior; the candidate cannot establish or rewrite the specification used to accept itself |
| `MG-SRC-001` | immutable base/candidate/tree/diff identity; safe path canonicalization |
| `MG-SRC-002` | no unexplained binary, submodule, symlink, case collision, bidi/confusable, minified, or generated material |
| `MG-SRC-003` | protected ownership exists for every changed path; diff is within cognitive budget |
| `MG-CTL-001` | candidate cannot alter/select the policy, producer, or result used for its own decision |

### Contour A — correctness and quality

| ID | Required outcome |
|---|---|
| `MG-QLT-001` | deterministic formatting and strict lint; zero new warnings, suppressions, or debt |
| `MG-QLT-002` | compile/build/type/schema validation with warnings treated as errors |
| `MG-QLT-003` | tests derived from acceptance criteria; unit plus relevant integration/contract tests pass |
| `MG-QLT-004` | changed-code branch/condition coverage meets policy and total coverage does not regress |
| `MG-QLT-005` | deleted/changed tests and snapshots are justified; no assertion weakening or skipped/focused tests |
| `MG-QLT-006` | error paths, resource cleanup, bounds, cancellation/timeouts, and deterministic behavior are checked where applicable |
| `MG-QLT-007` | mutation testing for changed executable code meets the configured score/coverage floors with no critical surviving mutant; scope and semantics follow [`mutation-testing.md`](mutation-testing.md) |
| `MG-QLT-008` | adapter-native maintainability evidence covers the changed-code delta for complexity, duplication, dead/unreachable code, suppressions, and explicit refactor debt; missing scope or an unexplained policy regression denies |

### Contour B — security and supply chain

| ID | Required outcome |
|---|---|
| `MG-SEC-001` | diff and relevant tree/history contain no introduced secrets or sensitive material |
| `MG-SEC-002` | SAST and dangerous-pattern analysis cover every changed executable/configuration language |
| `MG-SEC-003` | dependency/lock/toolchain diff is intentional, pinned, from approved origin, and free of prohibited vulnerability/malware/license risk |
| `MG-SEC-004` | relevant IaC, container, permissions, endpoints, and configuration are scanned with secure defaults |
| `MG-SEC-005` | security tests cover changed trust boundaries, input validation, authorization, and abuse cases |
| `MG-SUP-001` | evidence producer, workflow, tool, runner, scope, policy, subject, freshness, and completeness verify |
| `MG-SUP-002` | SBOM/provenance inputs are complete for releasable changes; artifact chain is verified at release |

### Review and operation

| ID | Required outcome |
|---|---|
| `MG-REV-001` | tier-specific independent reviewer quorum approves the exact final diff |
| `MG-REV-002` | an independent human performs a recorded challenge and can explain back intent, invariants, acceptance oracle, failure/abuse paths, and rollback from the source/evidence; AI, model self-review, or an AI-authored summary cannot occupy a human seat |
| `MG-OPS-001` | impact, observability, safe rollout, rollback/roll-forward, and recovery are proportionate to the tier |
| `MG-EXC-001` | every non-pass state has a valid rule-specific waiver; budget/TTL/use constraints verify |

If a control does not apply, the policy must omit it deterministically during gate materialization and record the applicability rationale. A scanner returning “not applicable” or scanning zero expected files is `not_evaluated`, not `pass`.

### Conditional AI-product assurance

These controls are materialized only when AI/ML is part of the shipped product. AI-assisted authorship alone remains covered by the universal baseline. Applicability, detailed requirements, authority domains, and evidence semantics are defined in [`ai-product-assurance.md`](ai-product-assurance.md).

| ID | Required outcome |
|---|---|
| `MG-AI-001` | complete applicability declaration and immutable identity for every decision-relevant model, prompt, data, retrieval, tool, and policy component |
| `MG-AI-002` | executable product-specific evaluation with complete expected scope, contamination analysis, equivalent baseline comparison, critical-slice gates, and governed production evaluation |
| `MG-AI-003` | retrieval relevance, pre-context authorization, freshness, source/span grounding, injection resistance, and correct no-support behavior |
| `MG-AI-004` | context completeness across position, paraphrase, multi-fact, distraction, conflict, and overflow/truncation cases |
| `MG-AI-005` | exact base/candidate identity, target and broad regression comparison, staged promotion, and tested immutable rollback for training/fine-tuning |
| `MG-AI-006` | externally governed provider approval covering purpose, data classes, training use, retention, location, access, deletion, subprocessors, and incident duties |
| `MG-AI-007` | independently authorized agent tools, no ambient credentials, sandbox and deny-by-default egress, effect-bound confirmation, resource limits, and audit |
| `MG-AI-008` | production drift monitoring bound to deployed identities with canary, stop, quarantine, revocation, and recovery behavior |

## 5. Tier additions

The baseline is cumulative.

| Tier | Additional automated/dynamic evidence | Human approval | Required engineering artifact |
|---|---|---|---|
| R0 | render/link/schema/spelling validation appropriate to artifact | one independent owner | concise intent |
| R1 | focused unit + integration and mutation tests; changed-path performance sanity | one independent domain owner | acceptance criteria and rollback note |
| R2 | cross-component contract tests; dependency/API compatibility; property tests; performance/resource budgets; preview/staging test | domain owner + relevant specialist, two humans total | threat-model delta, rollout/rollback plan |
| R3 | independent negative/abuse tests; fuzzing; mutation testing; concurrency/data invariants; DAST where exposed; migration/restore rehearsal; artifact-level scan | domain owner + security owner + affected specialist | reviewed threat model, operational runbook, staged rollout and recovery evidence |
| R4 | old-policy evaluation; policy/verifier negative conformance suite; independent assessment; root-of-trust/recovery exercise; staged control rollout | domain + security + platform owners, all different; add executive risk owner when policy requires | approved design/decision record, explicit trust-boundary proof, rollback/revocation rehearsal |

For R3/R4, at least one abuse/negative test MUST be designed independently of the change author/AI operator. For security-critical algorithms, policy SHOULD require an approved library or independently reviewed reference/specification and MAY require formal verification.

## 6. Conditional gate map

Apply every matching row in addition to the tier profile.

| Change signal | Required controls |
|---|---|
| New/changed dependency | lock consistency; origin/publisher review; transitive diff; vulnerability, malware, license checks; SBOM delta; install-script review; maintenance/abandonment risk |
| API/schema/protocol | compatibility and consumer contract tests; authz matrix; rate/size/time limits; version/rollback behavior; schema fuzzing |
| UI/browser | output encoding; DOM/client security; accessibility; CSP/security headers where applicable; visual/interaction regression; untrusted URL/input handling |
| Authentication/session/token | explicit state machine; brute force/replay/fixation tests; secure storage/rotation/revocation; cross-tenant authorization matrix; security-owner review |
| Cryptography/signatures | approved primitive/library; key lifecycle; algorithm negotiation/downgrade tests; test vectors; independent specialist review |
| Database/migration | forward/backward compatibility; dry run on representative data; invariants; backup restore or safe roll-forward; lock/load analysis; privacy review |
| Files/archive/media/parser | size/type/path limits; traversal/symlink/bomb tests; malformed corpus/fuzzing; isolated processing; cleanup/quota behavior |
| Outbound network/webhook | destination allowlist; SSRF/DNS/rebinding tests; TLS/auth; timeout/retry/idempotency; sensitive-data egress review |
| Concurrency/async/cache | race/property tests; ordering/idempotency; eviction/poisoning; cancellation; retry storm and stale-data behavior |
| Infrastructure/IaC/container | least privilege; public exposure; encryption; immutable image digest; non-root/read-only runtime; policy scan; plan/change review; drift detection |
| CI/control-plane build/release generator | R4; trusted-base execution; pin every external action/tool; untrusted PR credential test; reproducibility; cache isolation; negative policy tests |
| Application code generator/output | at least R2; review generator source/config; reproducible clean generation; semantic output diff; no hand-edited generated security-critical code |
| Observability/logging | no secret/PII leakage; tamper resistance; security event coverage; bounded cardinality/volume; retention/access policy |
| AI model inference | `MG-AI-001`, `MG-AI-002`, `MG-AI-008`; add `MG-AI-006` for an external provider; output validation; bounded latency/token/cost behavior; safe fallback |
| Retrieval/RAG or long context | `MG-AI-001`–`MG-AI-004`, `MG-AI-008`; add `MG-AI-006` for an external provider; corpus/data authorization and provenance; grounding/abstention; context omission and overflow tests |
| Training or fine-tuning | `MG-AI-001`, `MG-AI-002`, `MG-AI-005`, `MG-AI-008`; add `MG-AI-006` for externally operated training/inference; data rights/purpose; broad pre/post regression; staged promotion and rollback |
| Model-driven agent/tool use | `MG-AI-001`, `MG-AI-002`, `MG-AI-007`, `MG-AI-008`; add `MG-AI-006` for an external provider; prompt-injection tests; independent capability broker; sandbox/egress; exact-action confirmation; resource/cost limits |

Unsupported input is not exempt. Use an approved equivalent control or perform documented independent assessment that produces the required typed evidence.

## 7. Two-contour independence

Both contours MUST:

- use policy/workflow definitions obtained from a trusted location, not the candidate branch;
- run candidate code as hostile input in clean, resource-limited isolation;
- emit signed structured evidence with exact subject and scope;
- fail on timeout, parse loss, missing files, unsupported content, or stale inputs.

They MUST use distinct service identities, credentials, policy ownership, and signing authorization. Prefer separate runner pools/isolation domains and administrators. One ordinary maintainer or repository PR MUST NOT be able to alter both contours or fabricate either signature.

Contour A cannot waive a contour B finding because tests pass. Contour B cannot establish functional correctness because a scan is clean.

## 8. Human review rules

- Approvals are bound to base/candidate/diff digests and occur after the last substantive change.
- Author, AI operator, material co-author, and gate service do not count as independent reviewers.
- One person may satisfy only one required role for R2–R4.
- Reviewers inspect source, relevant context, tests, findings, and operational plan; AI summaries, confidence, chain-of-thought, and model self-review are untrusted claims or navigation aids, not evidence.
- For `MG-REV-002`, the independent human records a concrete challenge and explains the implementation back against the protected-base design, acceptance oracle, invariants, failure/abuse paths, and rollback. Repeating an author or AI summary does not satisfy explain-back.
- Changes above the cognitive budget in `docs/governance-and-metrics.md` are split, not rubber-stamped.
- Any changed control, dependency, public interface, trust boundary, privilege, data flow, or migration is called out explicitly.
- Stale, dismissed, ambiguous, delegated-to-bot, or conflict-affected approval is invalid.

## 9. Evidence decision order

Evaluate in this order; later steps cannot override an earlier denial:

1. Canonicalize and bind exact source/artifact subjects.
2. Load signed active policy from the trusted control plane.
3. Detect hard prohibitions and control-plane tampering.
4. Classify risk and materialize every required control/reviewer.
5. Verify signatures, producer authorization, scope/completeness, policy/subject binding, and freshness.
6. Apply findings/threshold rules from both contours.
7. Validate rule-specific exceptions and weighted budget.
8. Validate reviewer roles, independence, and freshness.
9. Emit signed `allow` or `deny` with all evidence and exception digests.
10. Recheck candidate, base, invalidations, and exception state atomically at merge/release.

Allowed evidence states are `pass`, `fail`, `not_evaluated`, and `waived`. Only `pass` satisfies a required gate unless the rule is waivable and a valid exception produces `waived`.

## 10. Strict debt rules

- Greenfield: zero warnings, suppressions, skipped tests, unresolved enforced findings, and baseline debt.
- Existing repository: immutable enumerated baseline may exist only in a fixed-term migration state. New/changed code meets the target policy and total debt never increases.
- A baseline is not a wildcard. Findings use stable fingerprints, exact scope, owner, and remediation deadline.
- A changed line/module adopts the current rule where technically possible; touching debt cannot reset its age.
- Broad path/tool/severity suppressions are prohibited. Rule tuning is an R4 policy change with negative tests.

## 11. Required evaluation output

When applying this model, produce a decision record containing:

1. exact subject and policy identity, including the protected-base design/oracle digest;
2. risk tier plus every trigger and unresolved uncertainty;
3. required gate/reviewer matrix;
4. evidence status per control (`pass`, `fail`, `not_evaluated`, `waived`), producer, freshness, and link/digest;
5. hard blockers and normalized findings;
6. exception IDs, scope, owner, expiry, uses, and budget impact;
7. reviewer identities/roles, final-diff binding, and `MG-REV-002` challenge/explain-back record;
8. admission/release outcome and precise remediation for each denial;
9. post-merge monitoring, rollout, and revocation conditions.

Never recommend “merge now and test later” for a required admission control. Deep scheduled checks add detection; they do not replace evidence required before admission.
