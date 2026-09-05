# Exceptions, risk budget, and break-glass

Use this reference only after a required control has a concrete non-pass result. Exceptions are controlled, visible risk debt—not a way to make a failing result green.

Implementation boundary: the bundled `mergegrounds.py` validates only the shape, dates, roles, quorum, counters, and local budget of registry entries. It deliberately never applies an exception, decrements a use, or emits `waived`. Consumption requires the separately administered, signature-verifying, context-aware verifier and append-only ledger defined here. Until that system exists, every underlying local non-pass remains a denial.

## 1. Principles

1. **Fix first.** Narrow the change, repair the code/control, replace the dependency, or supply an approved equivalent verification before seeking a waiver.
2. **One rule, one scope.** An exception authorizes one stable control ID for an exact subject and affected object. It never waives an entire job, profile, severity, directory, or repository.
3. **Non-pass remains visible.** The underlying result stays `fail` or `not_evaluated`; the decision graph records `waived` only through the signed exception edge.
4. **Short lived and single purpose.** Every record has issue/expiry times, maximum uses, allowed actions/environments, and a remediation deadline.
5. **Named human accountability.** A human owner operates compensating controls and removes the debt. A different authorized human approves the residual risk.
6. **Budgeted.** Active exceptions consume weighted repository and team budget. Exhausted budget denies new exceptions and admissions depending on them.
7. **No silent renewal.** Renewal is a new decision with current evidence, increased scrutiny, and additional budget cost.
8. **No exception to evidence integrity.** Missing identity, tampered evidence, wrong subject, or unavailable audit is a stop condition.

## 2. What is not an exception

- **Proven false positive:** a signed adjudication demonstrates the rule does not apply to the exact finding and tool/source versions. Preserve the original finding and proof. Re-evaluate when code, rule, or tool changes.
- **Alternative control:** policy already permits another evidence type with equivalent outcome and trusted producer. Use that control normally.
- **Baseline debt:** the findings themselves are not gate-level exceptions and cannot yield `waived` for new/changed code. A fixed-term authorization to operate the repository in `migration` state uses class `XM`; its inventory still needs exact fingerprints, owners, and deadlines.
- **Risk acceptance outside admission:** a business decision that lacks a machine-verifiable exception record does not authorize merge or release.
- **CI rerun:** retries are new evidence invocations, not waivers. Rerun-to-green without explained input/environment change is prohibited.

## 3. Non-waivable controls

Neither an ordinary exception nor break-glass may bypass:

- exact source/artifact subject binding and cryptographic verification;
- immutable recording of the real decision, actors, failures, and waivers;
- prevention of direct/anonymous protected-ref writes;
- trusted policy selection outside candidate control;
- introduced live-secret detection and prohibition on committing live credentials;
- denial of known malware/backdoors and confirmed unauthorized exfiltration;
- isolation of hostile candidate code from production, signing, control-plane, and protected-write credentials;
- required human authorization, including two-human break-glass activation;
- artifact digest/provenance correspondence to the reviewed source;
- ability to revoke/quarantine the affected artifact;
- denial of known reachable critical/high vulnerabilities in introduced or materially changed code;
- tested recovery or safe roll-forward for irreversible destructive operations.

When one of these blocks urgent work, change the implementation or restore the control. Do not issue an exception.

## 4. Exception classes

| Class | Permitted use | Default maximum admission TTL | Default remediation deadline | Base weight |
|---|---|---:|---:|---:|
| `XQ` quality/tooling | non-security lint, documentation, non-material coverage edge, bounded tool defect | 14 days | 30 days | 1 |
| `XR` reliability/operations | bounded performance, availability, compatibility, or operational control with tested compensation | 7 days | 14 days | 2 |
| `XS` security/privacy/supply | medium-or-lower residual security/privacy/license risk with strong compensating control; never a hard prohibition | 72 hours | 7 days | 4 |
| `XM` migration-state authorization | temporary operation with enumerated legacy findings existing before enforcement; never waives a changed-code gate | 30 days | 30 days | 3 per homogeneous finding group |

Product policy MAY shorten these limits and MAY prohibit a class. Longer limits require a separate R4 governance decision made before, and independently from, the benefiting change.

An `XM` group contains no more than 10 exact fingerprints sharing the same control, root cause, owner, and remediation. It authorizes only the declared `migration` state; it is not consumed as a waiver in an ordinary admission decision.

`admission TTL` is the period in which the exception may be consumed by a merge/release decision. `remediation deadline` is the latest time the accepted debt may remain unresolved after consumption. On deadline breach, the repository becomes `degraded`, routine releases stop, and the owner must remediate or quarantine affected artifacts.

## 5. Weighted exception budget

Compute points when an exception is issued:

```text
points = base_class_weight × risk_tier_multiplier × blast_radius_multiplier

risk_tier_multiplier:
  R0=1, R1=1, R2=2, R3=4, R4=8

blast_radius_multiplier:
  component=1, service/team=2, multi-service/customer=3, organization/critical=4
```

Default strict-profile caps:

- per change: 8 points;
- per repository: 12 active points;
- per owning team across repositories: 24 active points;
- any `XS`: at most one active per repository;
- R4: ordinary exceptions are prohibited independently of the points calculation; redesign the change or use an eligible, incident-scoped break-glass action.

Caps apply at issue time, admission time, release time, and renewal. Points remain active until remediation evidence closes the exception, even if the admission TTL has expired. A waiver cannot be split into multiple records to evade the cap; records sharing root cause or affected behavior are aggregated.

Budget cannot be increased, reclassified, or reset in the change that needs it. Reaching 60% sends an owner warning; 80% requires security leadership review; 100% denies new waiver-dependent admissions. Expired unresolved debt continues consuming points with a 2× overdue multiplier.

## 6. Required exception record

An exception is invalid unless a signed, protected record contains all fields:

```yaml
schema: mergegrounds/exception/v1
exception_id: EXC-2026-0042
class: XS
control_id: MG-SEC-003
control_domain: security
underlying_evidence_digest: sha256:85f4f121f2e1f7b2dab42c5229e7c9f5829c579b0d030b57661ec25252a88089
subject:
  repository: scm.example/team/service
  candidate_commit: 8f179ab47b54d1aa09e8a852c89d95ab8d7fb04f
  base_commit: 6f84d8b5fe5046ea61e10b0137d31b60c8fae231
  diff_digest: sha256:d461a5673a37e1015f7c586e51aab5c3cebb84767bf3493c9657cb0f04f9d9a3
affected_object:
  finding_fingerprint: vuln:pkg:example/library@2.4.1:CVE-2099-12345
  paths: [lockfile.example]
risk_tier: R2
blast_radius: component
reason: Temporary upstream compatibility constraint; fixed version fails the documented protocol contract.
residual_risk: Authenticated internal request can trigger bounded component degradation; no confidentiality or integrity impact is known.
compensating_controls:
  - Egress and caller allowlist limits access to the affected endpoint.
  - Runtime rule alerts and blocks the published exploit precondition.
  - Canary rollback is verified for the exact artifact.
validation_evidence:
  - sha256:f3e12a6a67423f0a41ea028df9041931679d6577c812b196f9a899f5c1b89e04
owner:
  identity: user:service-owner@example.invalid
  role: service-owner
approver:
  identity: user:security-owner@example.invalid
  role: security-owner
issued_at: 2026-09-05T10:00:00Z
expires_at: 2026-09-08T10:00:00Z
must_fix_by: 2026-09-12T10:00:00Z
allowed_actions: [merge, one_release]
allowed_environments: [staging, production]
max_uses: 2
uses: 0
points: 8
remediation_issue: SEC-1842
remediation_change: planned
renewals: 0
```

The example is illustrative. Real records use canonical identities, evidence digests, scopes, and approved controlled vocabulary.

The portable registry precheck accepts only explicit human identities in the form `user:<issuer-specific-id>` with no whitespace, exact lowercase hexadecimal commit/digest values, repository-relative exact affected paths (no globs or traversal), and lowercase action/environment tokens. Every record also declares a structural `control_domain`: one of `governance`, `quality`, `coverage`, `reliability`, `security`, `privacy`, `supply-chain`, or `license`. The control ID must exist in the reviewed control-to-domain map; unknown controls and mismatched domains fail closed. In particular, `MG-QLT-004` is `coverage`, while `MG-SEC-003` permits `security`, `supply-chain`, or `license` according to the exact finding. The protected verifier must additionally resolve each identity against its current issuer and authorization source; a syntactically valid identity is not proof that the human or role exists.

The record MUST also state:

- why remediation or an approved equivalent control is not currently possible;
- maximum credible impact and likelihood basis;
- exact detection signal, monitor owner, containment, and rollback action;
- dependency on any external fix and the version/date trigger;
- who is paged if compensation fails;
- whether public disclosure or legal/privacy review is required.

Free-form “accepted risk,” “false positive,” “tests pass,” or “deadline” is insufficient.

## 7. Approval authority

| Exception | Minimum approvers, excluding owner/author/AI operator |
|---|---|
| `XQ` R0–R1 | domain owner |
| `XQ` R2 or `XR` R1–R2 | domain owner + relevant specialist |
| `XQ` or `XR` R3 | domain owner + security owner + operations/release owner |
| `XS` any permitted tier | security owner + domain/data/privacy owner as applicable |
| `XM` | domain owner + security owner + platform owner |

One human fills one approval seat. R3 exceptions require at least three different humans. An `XS` waiver for customer/regulated data also requires the data/privacy authority. Legal/license exceptions require the designated legal owner.

Authority is selected from the structural control domain, not free-form prose. An R2 `coverage` exception requires a distinct `quality-owner` or `testing-owner` specialist in addition to the domain owner; unrelated legal, data, or privacy roles cannot fill that seat. A `license` exception retains the baseline XS security/contextual seats and additionally requires a distinct `legal-owner`.

Approvers review the exact candidate, underlying evidence, residual risk, compensating-control evidence, budget computation, TTL, and remediation plan. Approval before a substantive change is stale.

## 8. Lifecycle

1. **Detect:** a required control emits `fail` or `not_evaluated` with exact scope.
2. **Attempt remediation:** owner records attempted safe alternatives and why they cannot meet incident/business constraints.
3. **Request:** create the complete exception record in the protected exception system; never place approval solely in PR prose.
4. **Validate:** policy checks waivability, hard prohibitions, subject, class, points, caps, TTL, use count, and conflicts.
5. **Approve:** required independent humans sign after reviewing final evidence.
6. **Consume:** verifier records one allowed action/use in the append-only ledger and emits `waived`, not `pass`.
7. **Monitor:** owner proves compensating controls remain healthy until remediation closes the debt.
8. **Remediate:** a normal fully gated change removes the condition; relevant scans rerun.
9. **Close:** independent verifier links remediation evidence, stops point accrual, and records affected releases.
10. **Learn:** repeated control/tool/root-cause patterns become a controlled policy/tool improvement, never a broad suppression.

For `XM`, step 6 records/renews only the repository's `migration` state. It cannot produce `waived` for a candidate control; new and changed code still satisfies the target policy.

Expiry, budget exhaustion, scope mismatch, identity revocation, compensation failure, new exploitability, higher severity, or code/policy changes immediately invalidate future consumption.

## 9. Renewal

Renewal is allowed at most once for `XQ`, `XR`, or `XM`; `XS` is not renewable in the strict profile. A renewal:

- is a new exception ID and signatures, not an edited expiry;
- requires current evidence and an unchanged exact affected object;
- documents progress, missed assumptions, and why the original deadline failed;
- has no longer than half the original maximum TTL/deadline;
- consumes new points while overdue original points remain active;
- requires one approval level above the original authority.

If remediation still cannot complete, stop affected releases, remove the feature/dependency, or enter a separately governed migration/risk program. Rolling waivers are prohibited.

## 10. Break-glass eligibility

Break-glass is a separate incident mechanism. It may be activated only when delay is expected to increase active harm to confidentiality, integrity, availability, safety, or legal obligations, and the action restores or contains service/security.

Eligible examples:

- contain an actively exploited vulnerability;
- revoke a compromised credential/artifact or block ongoing exfiltration;
- restore a critical service during a declared incident when normal gates are unavailable or too slow;
- apply a narrowly scoped legal/safety stop required immediately.

Ineligible reasons:

- release deadline, feature launch, convenience, reviewer absence, flaky/noisy tooling, cost saving, or ordinary CI outage;
- bypassing a hard prohibition;
- shipping known unsafe behavior because remediation is difficult;
- pre-authorizing a class of future emergencies.

## 11. Break-glass controls

Activation MUST have:

- a declared incident ID and severity;
- exact repository, candidate/base/diff and artifact digests;
- one narrowly described action and environment;
- two different strongly authenticated humans: incident commander plus security or platform owner;
- a maximum 60-minute authorization window and one use;
- a tested rollback/containment action and named executor;
- immediate immutable audit event and paging to security/platform leadership;
- explicit list of incomplete/failed waivable gates; no result is relabeled `pass`.

The minimum emergency gate cannot be bypassed:

1. exact subject/diff/artifact and trusted-policy binding;
2. live-secret and known-malware/backdoor denial;
3. hostile-code isolation from privileged credentials;
4. targeted build/syntax plus tests for the incident fix and rollback path;
5. human inspection of the final diff by both activators;
6. immutable artifact digest/signature/provenance and deploy-by-digest;
7. audit/evidence emission and revocation capability.

Prefer an immutable emergency artifact from a dedicated incident ref while leaving the canonical protected ref unchanged until normal admission completes. If organizational policy permits an emergency protected-ref update, it must still use the merge controller and a signed `emergency_allow` decision; the repository immediately becomes `degraded` and cannot perform routine releases.

Break-glass credentials are dormant, separately stored, short-lived, least-privilege, and tested without exercising production mutation. They are never embedded in CI or available to candidate jobs.

## 12. After break-glass

Immediately after the action:

1. verify containment/service health and preserve all evidence;
2. revoke the one-use authorization and any temporary credentials;
3. freeze unrelated routine releases while assurance is degraded;
4. run the complete normal R3/R4 gate set on the exact source/artifact within 24 hours;
5. revert/roll forward or quarantine immediately if full validation fails;
6. merge the incident change through the normal path if an emergency ref/artifact was used;
7. complete preliminary human review within 24 hours and a blameless retrospective/remediation plan within 72 hours;
8. test the failed/unavailable controls and update threat/conformance fixtures;
9. return to `enforced` only through a signed recovery decision referencing full evidence.

Every activation is reviewed by independent assurance, included in metrics, and reported regardless of success. Repeated break-glass use for the same failure mode is a control-plane incident and blocks further activation for that reason until governance approves remediation.

## 13. Verifier checks

Before accepting `waived` or `emergency_allow`, the verifier MUST confirm:

- record schema and all signatures validate against current authorized roles;
- subject, affected object, control ID, underlying evidence digest, action, and environment match exactly;
- control is waivable and no hard prohibition is present;
- issue time precedes approval/consumption; expiry and remediation deadline have not passed;
- owner/approvers are different, active, and independent of authorship/AI operation as required;
- compensating-control evidence is current and its producer trusted;
- points are correctly computed and all caps remain below denial threshold;
- use count and renewal constraints allow the requested action;
- no revocation, compensation failure, new exploit, severity increase, or repository quarantine exists;
- the final decision lists the exception and underlying non-pass result.

Any ambiguity, missing field, clock inconsistency, or backend unavailability denies the action.
