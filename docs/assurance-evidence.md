# Assurance and evidence model

Status: normative

Purpose: make every admission and release decision independently reproducible and auditable

## 1. Evidence, not dashboard state

A green CI badge is mutable presentation state. MergeGrounds accepts only structured evidence that is:

- produced by a policy-trusted identity in an approved isolation class;
- signed after collection outside the untrusted candidate process;
- bound to the exact source and artifact digests it evaluates;
- explicit about scope, inputs, tool/policy versions, result, and completeness;
- retained independently from transient CI logs and branches;
- verifiable without trusting the author or the repository working tree.

Evidence demonstrates execution and result of a control; it does not prove that the control is perfect. Independent contours and human review reduce correlated failure.

The evidence graph distinguishes four information classes: an unverified **claim**, a non-authoritative **advisory**, typed and independently verifiable **evidence**, and the verifier's signed **decision**. A model/provider assertion, confidence, chain-of-thought, self-review, public benchmark, or dashboard label is a claim or advisory output. It does not become evidence by being placed in JSON, signed by the claimant, or repeated by another model.

## 2. Evidence graph

An admission decision is the root of a directed, content-addressed graph:

```text
admission-decision
├── protected-base design and acceptance-oracle reference
├── change-classification
├── contour-a-summary
│   ├── build-and-typecheck
│   ├── lint-and-policy
│   ├── test-results
│   ├── coverage
│   └── tier-conditional quality evidence
├── contour-b-summary
│   ├── secret-and-source scans
│   ├── dependency / license / malware results
│   ├── SAST / IaC / container results
│   ├── SBOM assertion
│   └── tier-conditional adversarial evidence
├── human-review attestations
├── when AI is shipped: conditional AI-product evidence
│   ├── component/applicability manifest
│   ├── product/retrieval/context evaluation results
│   ├── training/fine-tuning comparison
│   ├── external provider-policy attestation
│   ├── agent authorization/sandbox/egress attestation
│   └── runtime promotion/monitoring decision
└── zero or more exception records

release-decision
├── admission-decision
├── build provenance
├── artifact scan and SBOM
├── signature / registry identity
└── environment-specific authorization
```

Every edge names the digest of the child record. Missing children, duplicate/conflicting identities, cycles, or an untrusted producer invalidate the graph.

## 3. Common evidence envelope

Implementations may encode attestations with in-toto/DSSE or an equivalent signed envelope. The semantic minimum is:

| Field | Required meaning |
|---|---|
| `schema` | immutable type URI and semantic version |
| `information_class` | `evidence`; claims/advisories use separate non-authoritative schemas and decisions use a decision schema |
| `evidence_id` | globally unique invocation/result identifier |
| `subject` | repository identity, commit SHA, tree digest, base SHA; artifact name and digest when applicable |
| `change` | proposal ID, canonical diff digest, risk tier, classifier/policy inputs |
| `control` | stable rule/control ID, contour, profile, expected scope |
| `producer` | service identity, tool name/version/digest, runner image digest, isolation class, workflow/build definition digest |
| `invocation` | start/end time, invocation ID, external parameters, resolved input digests, retry/attempt |
| `scope` | files/components/artifacts examined, exclusions, expected and actual counts |
| `result` | one of the states below, normalized findings, thresholds, completeness |
| `policy` | policy bundle digest/version and applicable rule parameters |
| `references` | content digests for structured reports, logs, SBOM, provenance, reviews, exceptions, prior decisions |
| `validity` | issued time, expiry/freshness class, invalidation events |
| `privacy` | classification/redaction marker; no secrets or unnecessary raw prompts |
| `signature` | signer identity, mechanism, signature, certificate/transparency metadata as applicable |

For `MG-SEC-002`, a candidate-workspace SARIF file, its hash, and a downstream structural parse remain a claim rather than authoritative evidence. The trusted producer MUST independently rerun every applicable project SAST tool against the exact subject on a read-only/content-addressed source mount, with report outputs unavailable to candidate processes. Its signed envelope binds a trusted-Git expected changed-file/language manifest, report-native analyzed-path identities, tool/query/runtime/policy identities, expected and observed scope, findings and baseline disposition, artifact identity/digest, and subject. Missing/unsupported required scope, a candidate-produced sole report, a finding, or a prohibited baseline state becomes `not_evaluated` or `fail`.

Abridged illustrative payload (the production envelope also includes every required field listed above):

```json
{
  "schema": "https://example.invalid/mergegrounds/evidence/v1",
  "information_class": "evidence",
  "evidence_id": "urn:uuid:1db6c5de-3629-4a30-872c-e2e6c6d61018",
  "subject": {
    "repository": "scm.example/team/service",
    "commit": "8f179ab47b54d1aa09e8a852c89d95ab8d7fb04f",
    "tree_sha256": "03ae66b0c590bb85dd38f4c1cf284a674672359d91f55f2df9c17f8b1a1d8e1c",
    "base_commit": "6f84d8b5fe5046ea61e10b0137d31b60c8fae231"
  },
  "control": {
    "id": "MG-SEC-SECRETS-001",
    "contour": "security",
    "profile": "pull-request"
  },
  "producer": {
    "identity": "spiffe://mergegrounds.example/contour-b/secret-scan",
    "tool": "approved-secret-scanner",
    "tool_version": "4.2.1",
    "tool_digest": "sha256:bb38885113eca28fec9ae464b3c8b67216b081b4d34d56424f15f8752fddf629",
    "runner_image": "sha256:267c26b7379b32d84ced1192a720d684f79b69925f1ca103e48cb27fc36d2f5d",
    "isolation_class": "untrusted-source-ephemeral"
  },
  "result": {
    "state": "pass",
    "findings": 0,
    "examined_files": 147,
    "expected_files": 147,
    "complete": true
  },
  "policy": {
    "version": "2026.09.1",
    "digest": "sha256:209fc4f592a150da7f35c74dd1200514f4d633e6471f3865961533fccd08e3d2"
  },
  "validity": {
    "issued_at": "2026-09-05T10:02:14Z",
    "expires_at": "2026-09-06T10:02:14Z"
  }
}
```

The example uses a reserved domain and illustrative digests; deployments define their own schema URI and trust roots.

## 4. Result-state semantics

Only four normalized states are allowed:

- `pass`: the complete declared scope was evaluated and satisfied the rule;
- `fail`: the scope was evaluated and at least one enforced condition failed;
- `not_evaluated`: the control did not produce a valid complete determination, including skip, timeout, crash, unsupported input, parse loss, or missing expected files;
- `waived`: a valid exception authorizes this specific non-pass state for this exact scope and subject.

Rules:

1. A required control is satisfied only by `pass`, or by `waived` when that control is explicitly waivable and every exception constraint validates.
2. `not_evaluated` is never equivalent to zero findings.
3. A tool exit code alone is insufficient; the collector validates structured output, scope counts, and completeness.
4. Severity is normalized without discarding the vendor-native value and finding fingerprint.
5. Suppressed findings remain in evidence with suppression identity and rationale.
6. Retries are separate invocations. A pass after a fail is accepted only when the graph explains the changed code, policy, tool, or adjudication.

Repository runners may expose a richer operational vocabulary. Normalize it before a security decision:

| Runner state | Decision state |
|---|---|
| `passed` | `pass` only after scope/completeness verification |
| `failed` | `fail` |
| `blocked` | `not_evaluated` |
| `externally_unverified` | `not_evaluated` |
| `not_applicable` | no gate is materialized only when trusted policy independently proves non-applicability; otherwise `not_evaluated` |
| valid exception over a waivable non-pass result | `waived` |

This mapping keeps diagnostic detail without allowing “not applicable” or “external setting not checked” to satisfy an admission requirement.

## 5. Subject and input binding

Source admission evidence binds at least:

- canonical repository identity;
- candidate commit and tree digest;
- base commit and canonical diff digest;
- protected-base pre-implementation design, acceptance-oracle, and invariant-record digests;
- submodule, large-file, generated-source, and relevant toolchain input digests;
- active policy digest and trusted workflow definition digest.

Release evidence additionally binds:

- artifact digest and media type;
- admitted source decision digest;
- builder identity and build definition;
- all resolved build inputs or an approved completeness statement;
- SBOM and artifact-scan report digests.

Branch names, PR numbers, filenames, tags, URLs, and mutable package versions may be descriptive fields but are never sufficient subject identifiers.

## 6. Conditional AI-product evidence contracts

These evidence types are required only when the corresponding controls in [`../skills/mergegrounds/references/ai-product-assurance.md`](../skills/mergegrounds/references/ai-product-assurance.md) are materialized. They extend, rather than replace, the common envelope.

### 6.1 Common AI subject

Every AI-product result MUST bind all behavior-affecting inputs applicable to its scope:

- provider, endpoint, model ID, immutable revision/digest or approved provider snapshot attestation;
- inference runtime, parameters, model router/fallback, prompt/template, safety layer, and output-validator digests;
- corpus and ACL snapshots, embedding model, chunker, index build, retriever, reranker, context builder, and freshness policy digests;
- evaluation/training case manifest, expected-case digest, dataset provenance/digest, oracle and judge identities, holdout class, and access-policy digest;
- exact base, production, and candidate model/configuration identities;
- tool catalogue, capability/confirmation policy, sandbox image/profile, egress policy, and resource-budget digests;
- provider-policy, promotion-policy, production-sampling-policy, and active AI-policy digests.

Fields that do not apply are omitted by trusted policy materialization with a typed rationale; producers do not write `not_applicable` as a passing value. A mutable alias or unknown revision cannot satisfy an immutable identity field. When a provider cannot expose an immutable model digest/revision, evidence references an approved external snapshot attestation and its freshness limit or remains `not_evaluated`.

### 6.2 Typed contracts

| Evidence type / controls | Additional required payload | Invalid or non-pass conditions |
|---|---|---|
| `ai-component-manifest/v1` — `MG-AI-001` | declared capabilities; every common-AI component identity; data classifications/purposes; trust-boundary and authority references; expected control set; explicit unresolved/unknown fields | undeclared detected capability, incomplete inventory, mutable/unknown identity, contradictory data/purpose, candidate-selected applicability or authority |
| `ai-evaluation/v1` — `MG-AI-002` | expected and actual case IDs/digests; case count; critical slice IDs; per-case and per-slice numerator/denominator/result; invalid/skipped/duplicate/unexpected counts; baseline/candidate results under bound conditions; thresholds/margins; retries/seeds; latency/token/cost; oracle/judge calibration; dataset provenance and exact/near/semantic overlap method/results; production shadow/canary reference | zero denominator, missing/extra/duplicate/hidden-invalid case, NaN/infinity, failed critical slice hidden by aggregate, candidate/baseline mismatch, prohibited known overlap, uncalibrated sole judge for a critical rule, private/production status asserted only by candidate |
| `ai-retrieval-evaluation/v1` — `MG-AI-003` | query/relevance-set digest; `k`; retrieval/ranking counts and metrics; source/version/span citations; ACL decision and identity/tenant/data-class inputs; freshness/deletion state; unsupported-claim, abstention, stale-source and authorization-violation counts | missing relevance judgment, unauthorized content enters context, citation does not support the claim, expected deletion/revocation absent, similar-but-wrong/no-support critical case passes, partial index/case scope hidden |
| `ai-context-evaluation/v1` — `MG-AI-004` | ordered assembled-context manifest; tokenizer/runtime; actual/reserved token counts; included/omitted source digests; truncation/summarization decisions; required answer elements; results by position, paraphrase, fact cardinality, distraction, conflict, and overflow slice | unreconstructable context, unexplained omitted/truncated input, required element absent, critical position/multi-fact/overflow slice masked by aggregate |
| `ai-training-comparison/v1` — `MG-AI-005` | base/production/candidate identities; tokenizer; training/tuning data and filtering/dedup manifests; recipe/code/runtime/hyperparameters/randomness; target and retained-capability slices; safety/privacy/auth/tool/latency/cost comparisons; promotion and exercised rollback references | input identity mismatch, incomplete broad suite, prohibited/critical regression despite target improvement, prior evidence reused after material input change, rollback target mutable or unexercised |
| `ai-provider-policy/v1` — `MG-AI-006` | external authority and registry identity; provider/service/model/purpose/account/endpoint; allowed data classes; training/secondary-use terms; retention/deletion/backup; locations/transfers/subprocessors; human/support access; contract/DPA and incident terms; runtime-setting reconciliation; issue/expiry/revocation | repository/candidate is sole producer, missing authority, scope/purpose/data mismatch, expired/revoked record, unverified runtime setting, local or synthetic test represented as proof of provider-internal conduct |
| `ai-agent-controls/v1` — `MG-AI-007` | authenticated actor/subject; tool and closed argument schema; authorization/capability and confirmation records; sandbox image/profile; filesystem/process/resource limits; egress destination/IP/redirect/protocol/method/data/purpose decision; redacted tool result/audit; adversarial fixture scope | ambient credential, missing/mismatched authorization or confirmation, unknown tool/field, unbrokered network/socket/path, metadata/private/link-local/loopback route, redirect/DNS rebinding, filesystem escape, budget overrun without deterministic stop, raw secret in evidence |
| `ai-runtime-assurance/v1` — `MG-AI-008` | deployed identities; rollout/canary cohort; production-sampling authority; monitored slice/metric definitions; observation window/counts; drift inputs/results; alerts and stop thresholds; rollback/quarantine/revocation target and exercise; provider/corpus/evaluator reconciliation | unknown/drifted subject, incomplete window/sample represented as pass, breached critical stop condition, stale provider/corpus/evaluator policy, ungoverned customer sample, rollback/revocation cannot be executed |

### 6.3 Evaluation case integrity

Case-level results are content-addressed and reconcile exactly to a protected expected-case manifest. Evidence records expected, attempted, completed, valid, invalid, skipped, duplicate, and unexpected counts. Percentages include their numerator and denominator; retries remain distinct attempts. The verifier rejects an aggregate that cannot be recomputed or that conceals a failed required slice.

Contamination evidence records dataset lineage and the exact/near/semantic methods, versions, comparison corpora, coverage, and discovered overlaps. It can establish a detected overlap; it MUST NOT claim that no undiscovered contamination exists. `private_holdout=true` in repository data is a claim, not proof: the decision consumes a separately administered holdout-registry attestation and access record.

### 6.4 External and human authority

Provider contracts, actual provider retention/deletion, processing location, subprocessor status, private-holdout secrecy, and human identity/qualification/independence cannot be established by candidate code or repository-local evidence. The graph references signed records from the policy-authorized data, privacy, legal, identity, assurance, or control-plane service. Missing or unverifiable authority maps to `not_evaluated`.

## 7. Producer trust

The policy maps evidence types to allowed producer identities and isolation requirements. Trust is narrow: authorization to produce unit-test evidence does not authorize a source-provenance or security-review attestation.

A trusted producer must have:

- a reviewed, versioned build/workflow definition outside candidate control;
- an ephemeral or equivalently clean environment appropriate to hostile source;
- least-privilege, short-lived credentials;
- a pinned runner/tool image with a traceable update process;
- a signing path inaccessible to candidate processes;
- monitored identity use and a revocation mechanism;
- conformance tests for success, detection, malformed output, timeout, and partial-scope behavior.

Self-hosted producers are not trusted merely because they are internal. Their administrators, host isolation, update path, and signing boundary are part of the trusted computing base and must be assessed.

## 8. Freshness and invalidation

Evidence is valid only while all bound inputs and policy freshness conditions remain unchanged. The following invalidate an admission decision:

- candidate, base, submodule, lockfile, generated artifact, or tree digest changes;
- active policy, classifier, workflow, trusted producer set, or required tool version changes materially;
- an approval becomes stale, is dismissed, or its identity/role is revoked;
- an exception expires, exhausts uses, exceeds budget, or is revoked;
- vulnerability/malware/license intelligence exceeds its freshness limit;
- a referenced producer, runner image, dependency, or signing identity is compromised;
- merge-queue ordering changes integration inputs;
- an applicable model/provider revision, inference parameter, prompt/template, corpus/index, embedding/retrieval/context component, evaluator/dataset/holdout, fine-tuning input, tool/capability/sandbox/egress policy, runtime sampling policy, or provider authorization changes.

Default maximum age recommendations, unless a stricter product policy applies:

| Evidence | Maximum age at decision |
|---|---:|
| source/diff deterministic checks | exact revision; 7 days |
| dependency vulnerability/malware intelligence | 24 hours |
| independent human approval | exact final diff; 7 days |
| merge-queue integration result | exact prospective base; 4 hours |
| release artifact scan and decision | exact artifact; 24 hours |
| break-glass authorization | 60 minutes and one use |

Age never rescues evidence whose subject or inputs differ.

## 9. Human-review evidence

A review attestation records:

- reviewer identity, authenticated role, and applicable ownership domain;
- candidate/base/diff digests actually reviewed;
- review mode (`domain`, `security`, `platform`, `data`, `privacy`, `legal`, `assurance`, `operations`, or `release`);
- checklist/control version and explicit decision;
- timestamp and whether the reviewer had authored, generated, operated, or materially edited the change;
- disclosed conflict of interest and independence decision;
- linked findings and their resolution digests;
- for `MG-REV-002`, the independently raised challenge, protected-base design/oracle digest, and the human reviewer's explain-back of intent, invariants, failure/abuse paths, and rollback.

An approval is invalid after any substantive code, test, dependency, manifest, generated artifact, or policy-relevant change. Policy may treat typo-only or metadata-only changes as non-substantive only through a deterministic classifier; ambiguity dismisses the approval.

Reviewers approve source and evidence, not an AI-generated summary. The summary can guide navigation but is untrusted commentary.

Model confidence, explanation, chain-of-thought, self-review, or simulated persona cannot constitute reviewer identity, independence, qualification, or approval. Those properties are verified against the protected human identity and role authority.

## 10. Admission verification algorithm

The verifier executes in a deterministic order:

1. Canonicalize the candidate, base, tree, and diff subjects from source control.
2. Load a signed active policy by digest from the trusted control plane.
3. Verify classification evidence; recompute machine-observable escalation triggers; choose the highest tier.
4. Materialize the complete required gate and reviewer set for that tier.
5. Fetch referenced evidence by digest from append-only storage.
6. Verify envelope signatures, certificate/identity constraints, schema versions, and producer authorization.
7. Verify exact subject, policy, workflow, scope completeness, freshness, and invalidation events.
8. Apply deny rules. A non-waivable fail, missing control, ambiguous state, or prohibited change immediately denies.
9. Validate each exception against rule, subject, path, owner, approver, TTL, use count, compensating controls, and budget.
10. Validate reviewer quorum, roles, independence, and approval freshness.
11. Emit and sign `allow` or `deny`, including policy digest and every consumed evidence/exception digest.
12. Reperform subject, base, invalidation, and exception checks atomically at merge.

Implementations must test the verifier with negative fixtures. An unknown evidence type, schema field critical to interpretation, signature algorithm, or policy rule fails closed.

## 11. Release verification

The release verifier proves the chain:

```text
deployed digest
  = signed registry artifact digest
  = trusted-builder output digest
  -> build provenance subject
  -> admitted source revision
  -> valid admission decision and evidence graph
```

It additionally confirms the SBOM belongs to the same artifact, required artifact scans pass, environment policy permits the artifact, and no revocation/quarantine record exists. Rebuilding a semantically identical version produces a different subject and requires a new release decision.

Where practical, use SLSA provenance and an in-toto-compatible envelope. Generate source and build attestations in trusted services, and validate identity plus expected build parameters—not only signature cryptographic validity.

## 12. Storage, retention, and privacy

- Store attestations and their referenced structured reports in content-addressed, append-only storage with versioning and deletion controls.
- Retain admission evidence for at least the support lifetime of derived releases plus one year; retain release provenance/SBOMs for the product support lifetime plus any legal or regulatory period.
- Keep audit clocks synchronized and record source timestamps plus ingestion timestamps.
- Back up trust roots, policy versions, revocation records, and evidence indices separately; test restoration.
- Never store credentials, live secret values, unnecessary source snapshots, customer data, or raw prompts in general evidence.
- Do not collect or retain chain-of-thought. AI-product evidence normally stores component/input digests, case IDs, normalized measurements, redacted tool metadata, and privacy classification rather than raw prompts, retrieved context, embeddings, outputs, or customer samples.
- Store finding details in an access-controlled system and place a digest plus minimal classification in the attestation when disclosure would aid exploitation.
- Redaction creates a new signed view; it must not alter the retained original or hide decision-relevant counts/state.

## 13. Revocation and reconstruction

Trust can change after merge. The control plane supports signed revocation for producer identities, signer certificates, policy versions, evidence records, admission decisions, and artifacts.

On suspected compromise:

1. revoke the producer/identity and stop affected admissions/releases;
2. query the evidence graph for every dependent revision and artifact;
3. mark them `quarantined` until re-evaluated by trusted producers;
4. rebuild and rescan from admitted source where artifact trust is affected;
5. publish corrected decisions or artifact revocations without deleting original history;
6. update the threat model and add a regression exercise.

Reconstruction succeeds only if a third party can retrieve the retained policy, evidence graph, trust roots/revocations, source subject, and artifact digest and obtain the same decision.

## 14. Conformance criteria

An implementation conforms to this evidence model only if it can demonstrate:

- 100% of protected-ref updates map to a valid admission decision for the exact state transition;
- 100% of releases map by digest to trusted build provenance and an admitted source revision;
- missing, stale, tampered, partial, and replayed evidence is denied in tests;
- candidate code cannot access evidence-signing credentials;
- exceptions and break-glass actions appear as explicit non-pass states in the decision graph;
- producer compromise can be scoped and affected artifacts can be revoked;
- an auditor can reconstruct sampled decisions without relying on mutable CI UI state;
- when AI-product controls apply, the auditor can reconstruct the exact evaluated/deployed component set, expected/actual case and slice scope, external provider/holdout authority references, agent sandbox/egress policy, and promotion/rollback state without treating a model/provider/repository claim as evidence.
