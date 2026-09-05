# Conditional AI-product assurance

Status: normative when the shipped product invokes, trains, retrieves for, or delegates actions to an AI/ML model

This reference extends the universal software-admission controls in [`control-model.md`](control-model.md). It does not apply merely because a developer used an AI assistant: AI-assisted source remains subject to the universal controls regardless of product architecture. The controls below are materialized when the product contains model inference, retrieval-augmented generation, long-context behavior, fine-tuning, model-driven tools, or an external model provider.

No finite evaluation establishes that an AI system is generally safe, correct, uncontaminated, or aligned. Conformance means only that the exact product revision and identified AI configuration met the materialized policy on the recorded evaluation scope and that required runtime controls remain active.

Normative words `MUST`, `MUST NOT`, `SHOULD`, and `MAY` carry their RFC 2119 meanings.

## 1. Information classes and decision authority

Keep these classes distinct in schemas, interfaces, and reviews:

| Class | Meaning | Admission authority |
|---|---|---|
| **Claim** | an assertion from an author, model, provider, benchmark publisher, or tool that has not been independently verified | none |
| **Advisory** | navigation, triage, explanation, score, model self-review, or heuristic that may guide work | none; it cannot satisfy a required control |
| **Evidence** | a typed result from a policy-authorized producer, bound to exact subjects and inputs, with validated scope, completeness, freshness, and provenance | satisfies only the control and scope for which the producer is authorized |
| **Decision** | an `allow` or `deny` produced by the independent verifier after materializing policy and validating all evidence, authorities, and hard prohibitions | merge/release authority only when the decision is authentic and current |

A model's confidence, explanation, chain-of-thought, self-critique, or assertion that it checked its work is a claim or advisory output, not evidence. Do not request or retain hidden reasoning as a control artifact. Observable outputs, tool calls, independently defined oracles, and typed measurements may become evidence only after a trusted producer validates and binds them. An LLM-as-judge result remains a fallible measurement: policy MUST identify and calibrate that judge, and it MUST NOT be the sole oracle for a critical safety, authorization, privacy, or factuality requirement.

## 2. Applicability and risk floors

The change manifest MUST declare whether the shipped product uses AI/ML and enumerate model/provider endpoints, prompts and templates, retrieval corpora and indexes, embedding/reranking components, evaluation and training datasets, fine-tuning pipelines, agent tools, capability brokers, data classifications, and network destinations. Diff/dependency heuristics MAY detect an omitted declaration and escalate it; they MUST NOT be treated as proof that an undeclared product has no AI behavior.

A trusted policy materializer, not candidate code, determines applicability. If applicability cannot be established, the relevant controls are `not_evaluated`, not omitted or passed. A protected external registry is required wherever the fact cannot be proven from repository state.

Minimum tiers are cumulative:

- **R2 minimum:** change to product model/revision, inference parameters, prompt/template, embedding, chunking, retrieval/reranking logic, corpus ingestion, output validator, AI-facing telemetry, or non-sensitive evaluation data.
- **R3 minimum:** customer/restricted data enters a model or retrieval system; retrieval enforces tenant/authorization boundaries; fine-tuning or training changes; an agent can invoke tools; provider data handling changes; AI affects a financial, safety, identity, eligibility, destructive, or similarly high-impact decision.
- **R4:** change to AI applicability rules, release thresholds, evidence schema/verifier, trusted evaluator identities, private holdout or production-evaluation registry, approved-provider registry, model-promotion/revocation authority, capability broker, sandbox/egress policy, or another control that can silently authorize future AI behavior. A safety-critical or organization-wide model promotion is also R4.

The highest ordinary or AI-specific trigger wins. A local declaration of `not_applicable` cannot lower a tier or prove absence.

## 3. Control catalogue and authority domains

| ID | Required outcome | Accountable authority domains |
|---|---|---|
| `MG-AI-001` | AI applicability and every decision-relevant model, data, prompt, retrieval, tool, and policy component are completely inventoried and immutably identified | `domain`, `security` |
| `MG-AI-002` | product-specific evaluation is executable, scope-complete, contamination-aware, baseline-comparative, slice-gated, and connected to governed production evaluation | `assurance`, `domain`, `release` |
| `MG-AI-003` | retrieval is relevant, authorization-preserving, freshness-bounded, provenance-bound, injection-resilient, and able to abstain when support is absent | `data`, `security`, `domain` |
| `MG-AI-004` | context assembly and model behavior remain complete across position, paraphrase, multi-fact, distraction, conflict, and overflow cases | `assurance`, `domain` |
| `MG-AI-005` | a trained/fine-tuned candidate is compared with its exact base and production baseline across target and broad regression suites and has a verified rollback path | `platform`, `assurance`, `security`, `release` |
| `MG-AI-006` | provider use conforms to an externally governed approval covering purpose, data, training use, retention, location, access, deletion, and incident duties | `data`, `privacy`, `legal`, `security` |
| `MG-AI-007` | model-driven tools execute through independent authorization, sandbox, egress, confirmation, and resource controls without exposing ambient credentials | `platform`, `security`, `domain` |
| `MG-AI-008` | released AI behavior is monitored for quality, safety, security, cost, and distribution drift with canary, rollback, quarantine, and revocation capability | `operations`, `domain`, `security`, `release` |

Authority-domain labels are policy identifiers, not claims about people. Human identity, qualification, independence, quorum, and current role membership MUST be verified by the protected identity/approval system. A repository file cannot establish them.

For machine finding/exception routing, use this exact control-domain classification:

| Control | Allowed machine authority domains |
|---|---|
| `MG-AI-001` | `governance`, `privacy`, `security` |
| `MG-AI-002` | `governance`, `quality`, `reliability` |
| `MG-AI-003` | `privacy`, `quality`, `security` |
| `MG-AI-004` | `quality`, `reliability` |
| `MG-AI-005` | `quality`, `reliability`, `security`, `supply-chain` |
| `MG-AI-006` | `privacy`, `security`, `supply-chain` |
| `MG-AI-007` | `privacy`, `reliability`, `security` |
| `MG-AI-008` | `governance`, `reliability`, `security` |

This classification selects the relevant exception/finding authority family; it does not mean that choosing one machine domain satisfies all accountable approvals in the preceding table. In particular, `MG-AI-006` still requires the independently verified data/privacy/legal/provider authority record described below. Reusing the software-license domain as a proxy for provider-contract authority is prohibited.

## 4. `MG-AI-001` — applicability and immutable identity

The manifest and evidence graph MUST bind, when applicable:

- provider, endpoint, model ID and immutable revision/digest or a provider-signed snapshot identity;
- inference runtime and parameters that can affect behavior, including system/developer prompt and template digests;
- safety filters, output validators, routing/fallback policy, and feature-flag digests;
- corpus snapshot, ingest policy, ACL policy, embedding model, chunker, index build, retriever, reranker, and context-builder digests;
- evaluation manifest, expected case-set digest, holdout class, oracle versions, and production baseline identity;
- base model, tokenizer, tuning dataset, recipe/code, seed policy, and tuned artifact identity;
- tool catalogue, capability/confirmation policy, sandbox image/profile, egress policy, and resource-budget digests;
- externally verified provider-policy and model-promotion records.

Mutable aliases such as `latest`, marketing model names, endpoint URLs, feature names, or dashboard labels are descriptive only. If a provider does not expose an immutable model identity, policy MUST define an approved snapshot attestation and shorter freshness window; otherwise the corresponding behavior comparison is `not_evaluated`.

## 5. `MG-AI-002` — evaluation integrity

Public benchmarks and vendor scores are advisory. Release evidence MUST come from executable, product-specific evaluations with independently defined expected behavior. At minimum:

1. A protected case manifest enumerates expected case IDs, critical slices, oracle type, applicability, and dataset digest. Missing, duplicate, unexpected, skipped, invalid, or silently retried cases invalidate completeness.
2. The evaluator records numerator, denominator, invalid count, per-slice results, uncertainty/confidence method where meaningful, seeds, retries, parameters, latency, cost, and exact candidate/baseline identities. NaN, infinity, zero denominators, or an aggregate that hides a failed critical slice is invalid.
3. Candidate and current production baseline run under equivalent prompts, tools, data snapshot, runtime, parameters, and resource budgets unless each difference is explicitly bound and approved.
4. Critical authorization, tenant-isolation, privacy, safety, and prohibited-action slices permit no regression. Other thresholds and statistical margins are product/risk-specific and live in protected policy; this reference does not invent universal quality numbers.
5. Dataset provenance and known overlap with training, tuning, prompt examples, public benchmarks, prior outputs, and development logs are assessed using exact and appropriate near/semantic checks. A detector can establish discovered overlap, not prove absence of contamination; ambiguity is recorded and may require a fresh holdout.
6. Private/time-split holdouts are stored and sampled outside candidate and model-developer control with access logging. Repository fixtures cannot prove that a holdout was private.
7. Offline evidence is supplemented by governed shadow, canary, or sampled production evaluation appropriate to impact. Customer content MUST NOT be copied into CI or general evidence without authorized purpose, minimization or de-identification, access control, and retention.

An evaluator based on another model MUST record its model/prompt/configuration identity, calibration suite, disagreement/escalation path, and known limitations. Deterministic or independently reviewed human oracles are required for critical requirements that a judge model cannot reliably establish.

## 6. `MG-AI-003` — retrieval and grounding

Retrieval MUST be tested independently from generation. Evidence MUST bind the query set, relevance judgments, corpus and ACL snapshots, embedding/chunk/index/retriever/reranker configuration, `k`, filters, and freshness policy.

The suite MUST include:

- relevant documents expressed with and without query vocabulary;
- plausible, topically similar, but incorrect documents;
- no-support, stale, superseded, conflicting, poisoned/instruction-bearing, malformed, and duplicate content;
- cross-user, cross-tenant, restricted-classification, deleted, and revoked-source cases;
- ranking changes, empty indexes, partial ingestion, and dependency/provider failure.

Policy selects metrics appropriate to the product, normally including recall at `k` and a ranking measure such as nDCG or MRR, plus unsupported-claim rate, correct abstention, stale-source rate, and authorization violations. Relevance metrics MUST report per-slice numerators and denominators. Retrieval similarity or a citation-shaped string is not proof of relevance or grounding.

Authorization and data-classification filtering MUST occur before content enters model context. Generated citations MUST resolve to the exact retrieved source version and supporting span; a citation to an unrelated or merely similar source fails grounding. Retrieved instructions remain untrusted data and cannot modify system policy, tool authority, or evidence rules.

## 7. `MG-AI-004` — long-context completeness

Advertised context-window size is a capacity claim, not evidence of reliable recall or reasoning. Context evidence MUST bind the ordered context manifest, tokenization/runtime version, actual token counts, reserved-output budget, truncation/summarization decisions, and every included or omitted source digest.

The evaluation suite MUST vary:

- required facts at the beginning, middle, and end;
- paraphrases, aliases, and vocabulary with low lexical overlap;
- independently required facts and multi-hop combinations of increasing cardinality;
- irrelevant distractors, near-duplicate sources, conflicting evidence, and adversarial instructions;
- exact-boundary and overflow behavior, including deterministic truncation and explicit omission.

Oracles MUST enumerate required answer elements and distinguish omission from incorrect assertion. Aggregate answer quality cannot conceal a failed position, multi-fact, authorization, or critical completeness slice. If required input was not assembled, was truncated without policy authorization, or cannot be reconstructed by digest, the control is `not_evaluated` or `fail`, never pass.

## 8. `MG-AI-005` — training and fine-tuning regression

Training/fine-tuning evidence MUST bind the exact base model and tokenizer, dataset and filtering/deduplication manifests, recipe/code, hyperparameters, randomness policy, compute/runtime image, checkpoints, and candidate artifact. Data licensing, consent, purpose, deletion, and poisoning controls remain separately enforceable.

The candidate MUST be compared with both its exact base and current production model across:

- the targeted capability and its boundary/error cases;
- unrelated retained capabilities representative of production use;
- authorization, privacy, safety/refusal, prompt-injection, tool-use, factuality/grounding, multilingual/accessibility, latency, resource, and cost slices as applicable;
- every previously escaped defect, incident case, and protected regression canary.

A target improvement cannot offset a prohibited or critical regression. Changing a base model, tokenizer, dataset, recipe, evaluator, inference stack, or safety layer invalidates prior comparison evidence. Promotion MUST be staged and reversible by immutable identity, and rollback MUST be exercised against a representative production path before release authorization.

## 9. `MG-AI-006` — provider data governance

Before sending production or evaluation data to an external provider, a protected external registry MUST authorize the exact provider/service/model purpose and data classes. Its signed attestation MUST cover, as applicable:

- permitted purposes and prohibited secondary use or training;
- collection and context minimization, encryption, isolation, logging, human access, and support access;
- retention duration, deletion behavior and verification, backup treatment, and account closure;
- processing/residency locations, transfers, subprocessors, and material-change notification;
- contract/DPA status, incident notification, audit evidence, and revocation owner;
- runtime account/endpoint settings that implement the approved terms.

Local configuration can show intent and runtime settings; it cannot prove provider contract terms, actual retention/deletion, subprocessors, residency, or human access. Those facts require provider/contract artifacts and an authorized data/privacy/legal decision outside candidate control. A missing, expired, mismatched, or unverifiable provider attestation is `not_evaluated` and denies use of affected data.

Evidence stores and telemetry SHOULD retain minimal structured metadata and digests rather than raw prompts, contexts, outputs, embeddings, or reasoning. Synthetic lifecycle probes MAY verify observable deletion/configuration behavior but MUST NOT be described as proof of provider-internal deletion.

## 10. `MG-AI-007` — agent authorization, sandbox, and egress

The model is a planner, not an authorization principal. All tools MUST execute through a separately controlled capability broker that validates the authenticated user/service, current subject, tool, exact arguments, resource, data class, purpose, and policy. The model MUST NOT receive ambient credentials; the broker issues narrow, short-lived, per-action capabilities after authorization.

Runtime containment MUST:

- use an ephemeral, least-privilege sandbox with explicit filesystem roots and no host/container/daemon sockets, metadata service, sibling workload, or persistent secret access;
- deny network by default and broker approved egress by destination identity, resolved public IP ranges, port, protocol, method, redirect chain, and data class;
- revalidate DNS and every redirect, and deny loopback, link-local, private, metadata, alternate-encoding, raw-socket, and unbrokered proxy paths for IPv4 and IPv6;
- validate tool names and arguments against closed schemas; reject unknown tools/fields and prevent retrieved content from expanding authority;
- require a fresh human confirmation bound to the exact effect for external communication/publication, destructive actions, purchases/payments, deployment, permission changes, sensitive-data disclosure, or other policy-designated consequences;
- cap calls, recursion/delegation, wall time, CPU, memory, storage, output, tokens, and monetary cost, with deterministic stop behavior;
- record redacted, tamper-evident request/authorization/tool/result metadata and make revocation immediate.

An allowlisted destination can still be a covert or semantic exfiltration channel. Destination allowlisting is therefore insufficient without data-class/purpose checks, bounded payloads, monitoring, and residual-risk treatment. Sandbox tests demonstrate resistance to enumerated escapes; they do not prove the absence of isolation or provider vulnerabilities.

## 11. `MG-AI-008` — runtime drift and recovery

Release authorization MUST define an owner, staged rollout, canary/shadow population, monitored critical slices, service and cost budgets, alert thresholds, automatic/manual stop conditions, and immutable rollback target. Monitoring MUST distinguish at least model/config drift, input/distribution drift, retrieval/corpus freshness, evaluator drift, safety/security events, unauthorized tool/egress attempts, provider-policy changes, and quality/latency/cost regressions.

Telemetry is detection evidence, not retroactive admission proof. Production evaluation MUST use governed sampling, access, minimization, retention, and human-review rules. Alerts bind to model, prompt, retrieval, tool-policy, provider-policy, and release identities so that an affected decision can be scoped.

On a critical violation, unknown provider/model revision, revoked corpus/source, compromised evaluator, policy mismatch, or unexplained material drift, the system MUST stop or reduce affected capability according to policy, revoke promotion, quarantine dependent evidence/decisions, and roll back or fail safely. Recovery includes re-evaluation on trusted inputs before promotion resumes.

## 12. Evidence and failure semantics

AI evidence follows [`evidence.md`](evidence.md) and [`../../../docs/assurance-evidence.md`](../../../docs/assurance-evidence.md). Each result MUST state the control ID, expected and actual cases/slices, component/input identities, policy thresholds, normalized metrics, completeness, producer authority, subject, freshness, and privacy classification.

The following invalidate a required AI result:

- mutable, unknown, or unresolved all-zero model/data/configuration identity or digest;
- zero cases, missing expected cases/slices, invalid/skipped cases hidden from the denominator, or an unsupported parser/schema;
- NaN/infinite/out-of-range metrics, unbound aggregate values, or a passed aggregate with a failed critical slice;
- stale/replayed reports or a mismatch among source, model, prompt, corpus, dataset, provider, tool, sandbox, or policy subjects;
- discovered prohibited overlap/contamination, authorization leakage, provider-policy mismatch, sandbox/egress violation, or prohibited broad regression;
- an advisory, self-review, confidence value, dashboard label, or unsigned local assertion presented as evidence;
- unavailable external authority represented locally as verified.

Missing evidence is `not_evaluated` and denies the materialized gate. Scheduled or production monitoring can revoke eligibility and trigger response, but it cannot replace release-blocking evidence required before admission or promotion.

### Executable schema-v2 bindings

`scripts/ai_assurance.py` implements a closed schema for the repository-local portion of these controls. Schema v2 is intentionally incompatible with v1:

- the invocation root MUST equal the exact Git top-level; Git environment indirection, replacement objects, caller indexes/object stores, and external Git config injection are suppressed; the applicability config and every referenced protected policy MUST be non-executable `100644` blobs in one immutable `HEAD` tree and byte-identical to the worktree copies; the mutable report MUST instead be an ignored, untracked, non-executable evidence output;
- each policy case binds an input digest, independently defined expectation digest, and an `exact` or `minimum` sample requirement; each report case binds the resulting observation digest and actual sample count;
- every slice and metric names its exact case membership, exact observed sample total, and a canonical observation-set digest; normalized rates and thresholds remain in `0..1`, the numerator cannot exceed the denominator, and the denominator MUST equal that bound sample total, so an unrelated `1/1` cannot satisfy a five-case or larger policy scope;
- authoritative producers are closed `{class, id}` pairs rather than independent class/ID allowlists; an authorized ID cannot be relabeled into a different authority class;
- a successful machine decision emits the source commit/tree, config digest, expected-case-set digest, and report digest so an external verifier can authenticate and bind the decision artifact;
- CI writes that decision only through `evaluate --output .mergegrounds/evidence/ai-decision.json`; the engine requires an ignored/untracked target and atomically replaces a no-follow temporary file, preventing a pre-existing evidence symlink from redirecting shell output into Git or control data;
- when `fine_tuning` applies, protected comparison policies for both the exact base model and current production baseline are mandatory. Candidate and baseline runs bind the same per-case inputs, expectations, and sample counts; candidate/baseline report and computed result digests are distinct and canonically bound to comparison kind, baseline identity, and input manifest; cross-kind baseline payload reuse is denied; every protected metric supplies an arithmetically checked delta and direction-aware maximum regression.

The local engine recomputes canonical manifests and result digests, but it cannot authenticate the producer by itself. The admission check remains non-authoritative until a protected external verifier authenticates the producer attestation and the decision subject.
