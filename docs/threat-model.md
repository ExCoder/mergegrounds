# Threat model

Status: normative security analysis

Method: asset/boundary analysis with abuse cases; STRIDE and software-supply-chain threats are used as completeness prompts

Review cadence: on every control-plane change, new trust boundary, material incident, and at least annually

## 1. Security objectives

MergeGrounds must prevent or make evident:

- unauthorized or insufficiently reviewed code entering a protected ref;
- a candidate changing the controls used to approve itself;
- malicious, vulnerable, low-quality, or policy-violating code being accepted through incomplete or forged evidence;
- release of an artifact that does not correspond to the reviewed source and trusted build;
- silent bypass, stale approvals, broad exceptions, and unaudited emergency actions;
- exfiltration of source, prompts, credentials, customer data, or signing material during AI-assisted authoring and evaluation;
- promotion or continued operation of an AI-product configuration whose retrieval, context, evaluation, provider, tool, or runtime controls are incomplete, stale, mismatched, or outside authorized bounds.

Availability is important but subordinate to admission integrity. A failed control plane stops admission and release rather than reducing required assurance.

## 2. Protected assets

| Asset | Required property |
|---|---|
| Protected refs and source history | authorized, append-only history; no unreviewed state transitions |
| Admission/release policy | integrity, versioning, independent approval, rollback safety |
| Reviewer and service identities | strong authentication, least privilege, attributable actions |
| CI runners and builder images | isolation, integrity, ephemeral state, known configuration |
| Secrets and signing keys | confidentiality, non-exportability where practical, scoped use |
| Evidence and audit records | authenticity, subject binding, completeness, immutability, retention |
| Dependencies and toolchains | identity, integrity, approved origin, pinned resolution |
| Build artifacts and SBOMs | digest integrity, provenance, correspondence to admitted source |
| Security findings and exception records | confidentiality where necessary, integrity, expiry, ownership |
| Product/customer data | confidentiality, integrity, purpose limitation; never used as model context without authorization |
| AI component manifest | complete, immutable identity of deployed model, prompts, inference parameters, retrieval pipeline, corpus, tools, and policies |
| Evaluation and training assets | integrity, provenance, expected-case completeness, access separation, confidentiality, purpose and subject binding |
| Retrieval corpus/index | source provenance, freshness, authorization/tenant isolation, deletion propagation, resistance to poisoning |
| Provider approval records | authentic external authority for purpose, data classes, training use, retention, location, access, deletion, and incident duties |
| Agent capabilities and runtime | least privilege, independent authorization, containment, bounded egress/resources, attributable effects, revocation |

## 3. Adversaries and failure sources

- a malicious external contributor or compromised contributor account;
- a well-intentioned author accepting plausible but unsafe AI output;
- a compromised, poisoned, or manipulated model, agent tool, skill, MCP server, IDE extension, or retrieved context source;
- a malicious dependency maintainer, package registry, mirror, or typosquatted package;
- candidate code intentionally attacking CI, test runners, caches, parsers, or scanners;
- a compromised CI runner, build service, artifact registry, or evidence producer;
- a negligent or malicious reviewer, repository administrator, security operator, or insider collusion;
- leaked tokens, signing credentials, recovery keys, or stale service identities;
- configuration drift, parser ambiguity, race conditions, nondeterminism, and ordinary engineering error.

The model assumes an attacker can fully control candidate source, tests, build scripts, filenames, commit messages, PR descriptions, issue text, dependency metadata, and any data retrieved into an AI context. It does not assume AI origin labels are truthful.

## 4. Trust assumptions

The assurance claim depends on these assumptions:

1. Protected-ref enforcement and identity authentication work as configured.
2. At least one administration path for each independent contour is not controlled by the same actor or credential.
3. Cryptographic primitives, signature verification, and digest implementations are sound.
4. Trusted runner and builder images are produced through a separately secured process.
5. Human reviewers act independently and have enough context and competence for their assigned role.
6. The organization can revoke identities, producers, artifacts, and decisions after compromise.
7. External data/privacy/legal authorities can establish provider obligations and holdout governance that repository-local files cannot prove.

When an assumption is untrue or cannot be demonstrated, affected admission/release decisions are untrusted and must be suspended or quarantined.

## 5. Primary attack surfaces

- authoring agents, prompts, retrieved content, and tool calls;
- product model endpoints, routers/fallbacks, prompts, output validators, training/fine-tuning pipelines, and model registries;
- corpus ingestion, ACL filters, embeddings, indexes, retrievers/rerankers, context assembly, and citation resolution;
- evaluation datasets, private holdouts, benchmark imports, judge models, production sampling, and promotion thresholds;
- capability brokers, agent sandboxes, egress proxies, confirmation interfaces, provider APIs, and AI telemetry;
- source-control APIs, webhooks, branch/ruleset configuration, and merge queues;
- diff parsers, path classification, generated files, Unicode handling, and archive extraction;
- CI workflow definitions, third-party actions/plugins, runner images, caches, and artifacts;
- compilers, package managers, test frameworks, scanners, and their configuration;
- policy distribution, evidence ingestion, signature verification, and exception lookup;
- build services, dependency mirrors, artifact registries, promotion, and deployment APIs;
- reviewer interfaces, approval dismissal behavior, administrator and recovery paths.

## 6. Threat register

`P` = prevent, `D` = detect, `R` = respond/recover. Controls are mandatory unless the referenced risk tier explicitly adds a stronger requirement.

| ID | Threat / abuse case | Principal controls | Verification / response | Residual risk |
|---|---|---|---|---|
| T-01 | AI hallucinates insecure API use, missing authorization, unsafe defaults, or subtle logic errors | strict compile/type/lint; tests from requirements; property/contract tests; independent review; tiered security verification | contour A+B evidence; changed-code review; escaped-defect monitoring | correlated blind spots in tools and reviewers |
| T-02 | Prompt injection in repository, issue, dependency docs, or retrieved web content directs an agent to leak data or weaken controls | treat content as data; tool allowlists; no production credentials; network deny-by-default; policy outside candidate; human approval | tool-call audit; egress logs; secret scans; incident revocation | authorized tools may still be abused through semantic manipulation |
| T-03 | Agent invents or selects a malicious/typosquatted dependency | dependency allowlist; exact lock; publisher/origin validation; approved mirror; age/reputation rule; SBOM; malware/vulnerability/license scans | dependency-diff evidence; mirror/audit logs; quarantine package/artifacts | legitimate publisher or registry compromise |
| T-04 | Candidate adds tests that only assert its own incorrect behavior or deletes/weakens tests | `MG-META-003`; protected-base design and independent acceptance oracle/invariants; mutation and property tests; coverage non-regression; reviewer ownership | bind design/oracle digest; mutation score and changed coverage; compare test intent to acceptance criteria | incomplete specification and shared assumptions |
| T-05 | Candidate modifies CI, policy, owners, baselines, suppressions, or scanner config to approve itself | R4 classification; old trusted policy evaluates change; separate control PR; security + platform approval; negative policy tests | control-plane attestation; config-diff alert; staged rollout | colluding privileged administrators |
| T-06 | Malicious build/test code escapes the runner, steals tokens, poisons caches, or attacks sibling jobs | ephemeral isolated runners; no write/sign/prod credentials; resource limits; no host socket/metadata; restricted network; untrusted caches | runtime telemetry; runner destruction; token revocation; producer quarantine | zero-day in isolation platform |
| T-07 | Attacker forges, replays, swaps, or truncates gate evidence | signed typed attestations; exact subject/policy binding; nonce/invocation ID; append-only store; independent verifier; deny missing evidence | signature and graph verification; replay detection; revoke producer | signing identity or verifier compromise |
| T-08 | A passing result is reused after source, base, policy, toolchain, or vulnerability intelligence changes | include all digests; freshness windows; merge-queue rerun; invalidation events; final atomic recheck | verifier rejects stale graph; admission metrics | undiscovered material input omitted from provenance |
| T-09 | Reviewer rubber-stamps an AI summary, reviews an earlier diff, or is the effective author | `MG-REV-002`; source-first independent challenge and human explain-back; approval after final commit; stale approval dismissal; role/identity separation; diff-size caps | approval attestation with subject, role, challenge, and protected-base design/oracle binding; review sampling | human collusion, fatigue, or domain gaps |
| T-10 | Direct push, administrator bypass, force push, or alternate bot bypasses admission | merge controller is only writer; rules apply to admins; branch deletion/force-push disabled; identity inventory; audit alerts | reconcile protected-ref history to allow decisions; quarantine unmatched commits | source-control control-plane compromise |
| T-11 | Malicious logic is hidden in generated/binary/minified code, homoglyphs, bidi controls, or oversized diffs | deny unknown binaries; reproducible generation; source maps; Unicode/confusable scan; normalized paths; diff budgets; split change | artifact/source comparison; rendered diff; binary provenance | malicious compiler or visually deceptive format not recognized |
| T-12 | Secret, personal data, proprietary code, or prompt content leaks to model/provider/logs | data classification; approved model/provider policy; context minimization; pre-send secret/PII filters; no raw prompt retention; egress controls | DLP alerts; audit metadata; credential rotation; breach process | semantic sensitive data not detected by classifiers |
| T-13 | Vulnerable transitive dependency or compromised toolchain enters after a clean source review | immutable lock; complete SBOM; resolved input provenance; vulnerability/malware scan at PR and release; continuous monitoring | signed SBOM/provenance; artifact revocation and rebuild | unknown vulnerability or trusted upstream compromise |
| T-14 | Artifact is rebuilt or replaced after review; deployment resolves a mutable tag | build once; immutable digest; trusted builder; signature/provenance; registry immutability; deploy by digest | release verifier; admission-to-artifact graph; registry audit | compromised trusted builder or signing service |
| T-15 | Scanner is configured to skip paths, returns partial results, times out, or reports success despite parse errors | expected-file manifest; completeness counters; explicit `not_evaluated`; timeout=deny; scanner self-tests; schema validation | contour verifies scope/exit semantics; canary vulnerabilities | shared parser bug or unsupported language construct |
| T-16 | False-positive pressure causes broad suppressions or permanent waivers | exact rule/path/subject scope; TTL/use limit; compensating control; independent approver; weighted budget; renewal cap | exception audit; expiry denial; recurring-rule review | organizational willingness to accept chronic debt |
| T-17 | Break-glass becomes a routine release lane | incident-only eligibility; two-person activation; minimal non-waivable gates; short TTL; one use; degraded-assurance state; mandatory retrospective | alert security leadership; block next release until revalidation | severe incident pressure and privileged collusion |
| T-18 | Fork PR gains access to secrets or privileged workflow context | untrusted-fork execution with no secrets/write token; trusted post-review stage fetches by digest; never execute fork-controlled workflow with privilege | permission assertions; credential canaries; workflow audit | CI provider vulnerability |
| T-19 | Cache/artifact poisoning makes a clean revision consume attacker-controlled output | content-addressed cache; producer identity; read-only untrusted cache; clean rebuild for release; provenance links | digest mismatch denial; cache purge; compare clean build | omitted or nondeterministic build input |
| T-20 | Path tricks bypass owners/classifier (`..`, case folding, symlinks, renamed files, submodules) | canonical path parser; repository-aware rename handling; symlink/submodule policy; case-collision and archive checks; highest-trigger classification | adversarial classifier tests; tree walk independent of diff labels | platform-specific filesystem ambiguity |
| T-21 | Model-generated denial-of-service or cost-amplification code passes functional tests | performance/resource budgets; load tests; algorithmic complexity review; runtime quotas; cost anomaly detection | tiered performance evidence; rollback/circuit breaker | data-dependent pathological behavior |
| T-22 | Data migration corrupts or irreversibly exposes data | R3/R4 classification; forward/backward compatibility; backup/restore test; shadow/dry run; invariants; staged rollout; rollback/roll-forward plan | migration rehearsal attestation; data-quality monitors | latent semantic corruption discovered after TTL |
| T-23 | Multiple individually safe changes interact unsafely in merge order | merge queue on prospective base; integration/contract tests; serialized admission decision | invalidate on base change; post-merge canary | environment-only and emergent interactions |
| T-24 | Insider manipulates risk classification to avoid stronger gates | diff-derived triggers; highest tier wins; downgrade requires signed rationale and independent classification approver | compare manifest to diff; classification audit samples | collusion among classifiers and approvers |
| T-25 | Findings are hidden by log truncation, format incompatibility, or excessive output | structured results; finding counts and hashes; bounded logs with retained full artifact; schema/version negotiation; fail on parse loss | evidence completeness check; ingestion alarms | tool silently fails to detect issue |
| T-26 | Dependency or source license creates legal/distribution risk | license allow/deny policy; notices; source-offer obligations; legal owner for exceptions | SBOM license evidence; release denial | ambiguous or incorrectly declared upstream license |
| T-27 | AI-origin declaration is omitted or falsified | apply same controls to all code; record known provenance; diff heuristics only for escalation, never reduced scrutiny | audit declarations; compare agent/session metadata when available | undetectable copy/paste; no security dependency on label |
| T-28 | Security remediation reveals exploitable details through public logs or prompts | private finding channel; redacted evidence; least-privilege access; embargo workflow; hashes in public attestations | access audit and redaction tests | side-channel inference from changed code |
| T-29 | RAG returns irrelevant, similar-but-wrong, stale, poisoned, deleted, or unauthorized cross-tenant content and the answer presents it as grounded | `MG-AI-001`, `MG-AI-003`; authorization before context; immutable corpus/index identity; independent relevance judgments; source/span citations; abstention; injection tests | per-slice retrieval/grounding evidence; ACL canaries; ingestion/deletion reconciliation; revoke corpus/index | unseen semantic confusion; authorized source contains false or malicious content |
| T-30 | Long context omits or distorts required facts because of position, paraphrase, distraction, multi-fact load, summarization, or truncation | `MG-AI-004`; ordered context manifest; explicit token/truncation budget; position/paraphrase/multi-fact/overflow suites; element-level oracles | omission and position-slice evidence; reconstruct assembled context by digest; fail safely on missing inputs | emergent failures outside evaluated distributions |
| T-31 | Public benchmark contamination, non-executable cases, hidden skips, judge bias, or aggregate metrics produce a false quality claim | `MG-AI-002`; protected expected-case manifest; private/time-split holdout; overlap analysis; exact case accounting; critical slice gates; baseline-equivalent execution | reject missing/duplicate/invalid cases and identity mismatch; calibrate judge; production shadow/canary; refresh holdout | overlap detectors cannot prove absence; private set may still be biased |
| T-32 | Fine-tuning improves the target metric while degrading unrelated capabilities, authorization, privacy, refusal, safety, latency, or cost | `MG-AI-002`, `MG-AI-005`; exact base/data/recipe identity; broad pre/post regression; incident canaries; staged promotion; immutable rollback | compare base, production, and candidate on all protected slices; stop promotion on any prohibited regression; rollback rehearsal | rare or delayed behavior shift; base-provider drift |
| T-33 | Provider trains on, retains, transfers, exposes, or fails to delete data contrary to product policy or contractual expectation | `MG-AI-006`; external approved-provider registry; purpose/data minimization; runtime-setting verification; retention/location/subprocessor/human-access/deletion terms; revocation | signed external provider-policy attestation; configuration reconciliation; synthetic lifecycle probes; privacy/legal review; incident response | repository cannot observe or prove provider-internal behavior |
| T-34 | Prompt injection or model error abuses an authorized tool, ambient credential, filesystem, network path, redirect, DNS, or covert channel to create unauthorized effects or exfiltrate data | `MG-AI-007`; independent capability broker; no ambient credentials; closed tool schemas; ephemeral sandbox; deny-by-default brokered egress; exact-effect confirmation; resource caps | adversarial tool/egress fixtures; authorization and redacted audit trail; immediate capability revocation; sandbox destruction | isolation zero-days and semantic/covert abuse of permitted destinations |
| T-35 | Model, provider, input distribution, corpus, evaluator, or policy drifts after admission while stale evaluation remains green | `MG-AI-008`; deployed-component identity; governed telemetry; canary/shadow evaluation; freshness/invalidation; stop, quarantine, rollback, revocation | drift and policy reconciliation; alert-to-stop exercises; re-evaluate on trusted inputs before re-promotion | sparse samples, delayed labels, and undetected distribution shift |
| T-36 | Candidate adds `scripts/json.py`, another sibling module, bytecode, or native extension that executes while a policy or credentialed operator helper imports the standard library, before repository validation starts | invoke every repository Python control and inline helper with isolated mode (`python3 -I`); protect the complete `/scripts/` tree; classify and seal executable control sources; trusted-base verifier uses a pinned interpreter/image | import-shadow negative probe; control-tree diff and digest; deny unexpected executable files | compromised interpreter/runtime image or an omitted non-Python interpreter startup hook |
| T-37 | Candidate hides authority in a local Action/reusable workflow, selects a mutable container/service image, launders PR text through a job output, or uses a PR-controlled expression to skip a job/step or select a runner, shell, or working directory; implicit `github.token`, conditional omission, or a privileged/self-hosted target bypasses visible `run`/`env` checks | reject candidate-local `uses:`, non-digest OCI images, PR-controlled job outputs, conditions, and execution fields in candidate-evaluated admission workflows; external trusted-base recursive workflow policy; Actions allowlist; secretless ephemeral runner; required aggregate checks treat skipped dependencies as denial | adversarial workflow parser fixtures; external policy result; runner and token inventory | future GitHub syntax/context changes, indirect dataflow, or parser differentials require policy updates |
| T-38 | Caller-controlled Git environment/configuration, replacement refs/objects, import paths, executable-bit drift, or a hostile evidence symlink changes what the bootstrapper or judge reads/writes while the displayed subject still looks valid | isolated Python; scrub all inherited `GIT_*`; disable replacement objects and external/global configuration; require exact Git top-level and `100644` control blobs; no-follow descriptor reads; ignored/untracked atomic decision output; content/mode control lock | environment/redirection, tree-replacement, import-shadow, symlink/FIFO, and mode-drift negative probes; exact commit/tree/config/report digests | local candidate execution still shares a mutable runner/workspace in the portable profile; maximum assurance requires an external verifier and isolated read-only subject mount |

## 7. AI-specific abuse tree

### 7.1 AI-assisted development

An unsafe AI-assisted change reaches production if an attacker or failure source can achieve all four stages:

1. **Influence generation**
   - poison instructions/context/tools, exploit prompt injection, or induce hallucinated code;
2. **Hide the unsafe behavior**
   - overwhelm the diff, manipulate tests, use obfuscation, or add plausible but malicious dependencies;
3. **Defeat admission**
   - weaken policy, forge evidence, exploit runner privileges, obtain invalid review, or consume an exception;
4. **Break source-to-release binding**
   - replace/rebuild the artifact, exploit mutable tags, or deploy outside the verified path.

The architecture places an independent control at every stage. AI sandboxing alone is insufficient; even benign generation can produce unsafe code. Conversely, scanning alone is insufficient if evidence or artifact identity can be substituted.

### 7.2 AI-product runtime

Unsafe model behavior reaches users if a failure source can:

1. introduce a bad or unauthorized model, prompt, corpus item, index, tuning record, provider setting, or tool policy;
2. evade a product-specific oracle through contamination, missing cases, context/retrieval blind spots, judge bias, or aggregate masking;
3. cross a data or capability boundary through retrieval, provider processing, an ambient credential, a permissive tool, or egress;
4. survive promotion through stale/mismatched evidence and then escape runtime drift detection, canary stop, rollback, or revocation.

The controls in [`../skills/mergegrounds/references/ai-product-assurance.md`](../skills/mergegrounds/references/ai-product-assurance.md) place separately authorized prevention, evaluation, decision, and recovery measures at these stages. A provider claim, model self-review, confidence score, chain-of-thought, or repository-local assertion is not evidence of the corresponding control.

## 8. Non-waivable threat controls

The following may not be bypassed by an ordinary exception or break-glass activation:

- prevention of direct/anonymous writes to protected refs;
- exact revision/artifact subject binding and signature verification;
- immutable audit record of the actual decision, waivers, and actors;
- secret detection for introduced material and prohibition on committing live credentials;
- two-human authorization for break-glass;
- isolation of untrusted code from production/signing/control-plane credentials;
- denial of known malicious dependencies/artifacts and evidence tampering;
- protected policy selection: a candidate cannot approve itself;
- ability to identify and revoke the released artifact by digest;
- where an AI-product control is materialized: pre-context data/tenant authorization, prohibition on ambient agent credentials, and independent authorization of consequential tool effects.

If any of these controls is unavailable, protected admission and release stop.

## 9. Residual-risk treatment

Residual risk is handled in this order:

1. remove the unsafe capability or reduce the change scope;
2. add prevention and independently generated verification;
3. restrict blast radius with sandboxing, least privilege, staged rollout, and runtime controls;
4. add detection, rollback, and incident response;
5. accept only the remaining, explicitly described risk through the exception process.

“The tests passed,” “the model is trusted,” and “a reviewer looked at it” are not sufficient residual-risk statements. A valid statement names the failure mode, affected asset, maximum impact, likelihood basis, compensating control, detection signal, recovery action, owner, and expiry.

## 10. Validation exercises

At least quarterly, and after material control changes, the platform team executes safe adversarial tests in a non-production repository:

- a candidate attempts to alter its required checks and owners;
- a candidate adds a local Action, mutable job/service image, PR-controlled execution field, or job-output laundering path;
- a fork workflow attempts to read a secret or obtain a write token;
- evidence is replayed for another commit and for an expired policy;
- inherited Git redirection, commit/tree replacement, an import-shadow module, executable control data, and an evidence symlink/FIFO attempt to redirect or reinterpret the judge;
- a test job attempts network, metadata service, host socket, and cache-write access;
- a dependency uses a confusable name or mutable/unpinned reference;
- a diff contains bidi controls, case-colliding paths, symlink escapes, and an unsigned binary;
- a required scanner times out, emits malformed output, and scans zero files;
- an approval predating the final commit is presented;
- a candidate attempts to introduce or rewrite its own design/acceptance oracle, and an AI/self-review attempts to occupy the independent challenge/explain-back seat;
- an expired/over-budget exception and reused break-glass token are presented;
- a registry tag is moved while the artifact digest differs;
- retrieval is fed relevant, similar-but-wrong, stale, instruction-bearing, deleted, and cross-tenant sources; only the authorized grounded/abstaining cases may pass;
- required context facts are moved across beginning/middle/end, paraphrased, multiplied, distracted, conflicted, and truncated; missing required elements must deny;
- an evaluation report omits/duplicates/skips expected cases, hides a failed critical slice in an aggregate, reuses a contaminated fixture, or changes its judge/baseline subject;
- a fine-tuned model improves its target case but regresses a protected unrelated, safety, privacy, authorization, latency, or cost slice;
- provider authorization is absent, expired, or mismatched to data class/purpose/region, and a local configuration falsely claims compliance;
- an agent attempts permission expansion, metadata/private/IPv6/DNS-rebinding/redirect egress, raw sockets, filesystem escape, unapproved tools, missing confirmation, and budget exhaustion;
- deployed model/corpus/provider/evaluator identity drifts and the canary-stop, quarantine, rollback, and re-evaluation path is exercised.

Every exercise must produce an explicit denial and immutable evidence. Failure is a control-plane incident: stop affected admissions, assess previously accepted revisions, repair the control, and repeat the exercise.

## 11. Review triggers

This threat model must be revised when any of the following changes:

- model/provider, agent permissions, retrieval sources, or developer tooling;
- source-control provider, CI/build system, runner isolation, artifact registry, or signing method;
- trust boundary, privileged identity, approval role, risk trigger, waiver policy, or evidence schema;
- supported stack introduces a new executable artifact, package manager, or deployment path;
- incident, near miss, bypass attempt, repeated false positive, or new supply-chain technique exposes a missing scenario.

Each revision is an R4 control-plane change and must record which threats, assumptions, and validation exercises changed.
