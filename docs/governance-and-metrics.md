# Governance, human review, and metrics

Status: normative governance baseline

Principle: automation supplies repeatable evidence; accountable humans own intent, residual risk, and operation of the control plane

## 1. Roles and accountability

| Role | Accountable for | Must not do alone |
|---|---|---|
| Change author / AI operator | intent, accurate manifest, small reviewable diff, oracle traceability, tests, explain-back, remediation | approve or independently challenge own change; select a lower tier; issue own exception |
| Domain owner | acceptance oracle, business invariants, behavior, architecture fit, operational impact, rollback | let the implementation or authoring model silently decide an ambiguous business rule; substitute for required security/platform approval outside their domain |
| Security owner | threat model, security policy, high-risk review, exception approval | author and solely approve a security-control change |
| Platform/control-plane owner | CI, runners, policy distribution, merge controller, evidence/signing services | use candidate policy to approve that policy; solely approve control-plane change |
| Data/privacy owner | data classification, migration/privacy impact, retention | approve unrelated implementation correctness |
| Release owner | artifact-to-source chain, rollout and recovery readiness | release an artifact lacking a valid digest-bound decision |
| Exception owner | compensating controls, expiry/remediation, operational monitoring | approve their own exception |
| Incident commander | emergency scope and coordination | silently bypass non-waivable controls or erase degraded-assurance state |
| Auditor / assurance reviewer | sample decisions, reconcile protected refs/releases, report control drift | mutate evidence under review |

Every protected path has a current human owner and backup. Orphaned ownership denies admission. Bots may produce evidence and route approvals but never occupy a required human role.

## 2. Separation of duties

The following pairs must be different authenticated humans or independently administered service identities:

- author/AI operator and required reviewer;
- author/AI operator and independent challenger;
- exception owner and exception approver;
- contour A producer and contour B producer;
- candidate code executor and evidence signer;
- ordinary repository maintainer and merge-controller identity;
- control-plane change author and both security/platform approvers;
- artifact builder and release-policy verifier.

For R3 and R4 changes, domain and security approvals must be from different humans. For R4 control-plane changes, the platform approver must also be different from both. One person holding multiple organizational titles does not satisfy multiple independent approvals for the same decision.

Small teams that cannot meet separation must use an external reviewer/service or classify the repository as not meeting the strict profile. “No other person was available” is not an exception.

## 3. Human review standard

Human review validates intent and attack paths that mechanical tools cannot reliably infer. A valid reviewer:

1. is identified through a protected organization identity with strong authentication;
2. is an owner or qualified delegate for the affected domain;
3. reviews the exact final diff, relevant surrounding code, manifest, tests, and gate evidence;
4. can explain the change without relying on the author/AI summary;
5. checks failure behavior, privilege/data flows, dependency intent, observability, rollback, and test independence;
6. records blocking findings explicitly and verifies their resolution;
7. approves after the last substantive commit and before the evidence freshness window closes;
8. declares material authorship, prompt operation, conflict, or prior design participation.

A reviewer does not accept model reasoning, confidence, self-critique, or a fluent AI summary as evidence. Review is grounded in the acceptance oracle, reviewed design, final source, independently observable results, and retained artifacts. Private chain-of-thought must not be requested or retained.

Review is refused when the diff exceeds the configured cognitive budget. The change must be split by coherent behavior; generated-file bulk is reviewed through source generator plus reproducibility evidence, not hidden from size accounting.

Suggested maximum review units, adjustable only downward by product policy:

| Tier | Human-authored logical changed lines per review unit | Generated material |
|---|---:|---|
| R0 | 800 | rendered/validated output allowed |
| R1 | 500 | reproducible and separately summarized |
| R2 | 300 | reproducible, source reviewed, artifact diff available |
| R3 | 200 | normally split; security-sensitive generated code prohibited |
| R4 | 120 | one control objective per change; generated executable policy prohibited |

These are stop thresholds, not productivity targets. Renames, deleted controls, lockfiles, and compressed/minified/binary artifacts receive specialized review and cannot be used to game line counts.

### 3.1 Design and acceptance-oracle review

For R2–R4, and for any material business rule, trust boundary, public interface, persistent data, dependency, migration, or operational-control change, design review precedes substantive implementation or generation. The record identifies the outcome and non-goals, accountable acceptance oracle, business/security invariants, data and privilege flows, alternatives, failure/abuse cases, observability, rollout/recovery, and independent test strategy.

Approval is bound to the design digest, base revision, reviewer identities, and time. Material design change invalidates it. A same-change or post-hoc design can improve documentation but does not prove that review preceded implementation; where an external verifier cannot establish chronology, report the control as externally unverified.

Tests produced by an authoring agent do not become independent merely because they are in a separate file. Expected behavior must trace to an approved specification, business-rule table, protocol/schema, test vector, independently prepared example, invariant, or explicit domain-owner decision. Unresolved material ambiguity blocks implementation.

### 3.2 Independent challenge and explain-back

For R2–R4, a challenger who did not author or materially steer the change attempts to falsify it. They receive the oracle, design, exact diff, relevant source, and gate evidence, but initially not the author's preferred diagnosis, conclusion, or confidence. The challenge covers counterexamples, violated invariants, test independence, privilege/data flows, failure behavior, concurrency/resources, migration/recovery, and simpler alternatives. Record supplied-input digests, identity and prior involvement, findings, dispositions, and resulting tests or design changes.

Continuing the authoring session, asking the same model to “check again,” rephrasing the question, or increasing reasoning length is correlated self-check and cannot satisfy independence. A clean-context agent or different model is useful defense in depth, but it never occupies a required human seat.

Before approval, the accountable human operator explains the final externally visible behavior, data/control flow, business and security invariants, failure modes, test oracle, deployment observation, and recovery path from the source and design. For R3/R4, a reviewer asks concrete counterfactual or failure questions. Pasted AI prose or inability to explain is a failed comprehension check. Explain-back evaluates whether the team can own and debug the change, not presentation style.

The full process is defined in [AI-assisted development assurance](ai-assisted-development.md). AI-enabled product behavior has additional controls in [AI product assurance](../skills/mergegrounds/references/ai-product-assurance.md).

## 4. Review quorum by risk

| Risk tier | Minimum human quorum | Additional review material |
|---|---|---|
| R0 | one domain/documentation owner | rendered output, link/schema validation as applicable |
| R1 | one independent domain owner | acceptance criteria, tests, operational impact |
| R2 | two independent humans: domain owner plus relevant specialist | threat-model delta, dependency/API/data impact, rollback |
| R3 | domain owner + security owner + affected specialist (platform/data/release) | abuse cases, property/fuzz/mutation evidence, staged rollout and recovery proof |
| R4 | domain owner + security owner + platform/control-plane owner; executive risk owner when product policy requires | approved design record, negative control tests, independent assessment, rehearsed recovery |

The highest affected tier determines quorum. An approval satisfies one role only. Policy may require more reviewers for regulated, safety-critical, cryptographic, identity, payment, tenant-isolation, or production-control surfaces.

## 5. Policy and control-plane governance

Policy is code with a larger blast radius than application code. Each control change must include:

- motivation and identified threat/control IDs;
- old-versus-new behavior for pass, fail, missing, stale, and malformed evidence;
- positive and negative conformance fixtures;
- migration and rollback plan;
- expected metric impact and alert changes;
- compatibility assessment for evidence producers and consumers;
- independent security and platform approvals.

The last trusted policy evaluates the proposal. Activation is signed, staged in observe mode on representative repositories, then enforced at a scheduled version boundary. An emergency policy rollback restores the last signed known-good bundle; it does not permit an unsigned hand edit.

Risk triggers, trusted identities, non-waivable rules, exception budgets, and branch/release protections cannot be weakened in the same change that benefits from the weakening.

## 6. Repository assurance states

The repository and each release have an explicit state:

- `enforced`: all required controls and reconciliation checks are operating;
- `degraded`: a break-glass action, producer compromise, material control outage, or overdue evidence issue is active;
- `quarantined`: protected history/artifact cannot be reconciled or a critical compromise affects its assurance chain;
- `migration`: approved fixed-term adoption baseline exists; target controls are not yet fully enforced.

Only `enforced` may perform routine release. `degraded` permits only incident-scoped actions and remediation. `quarantined` blocks promotion/deployment. State transitions are signed audit events with owner, reason, start, deadline, and exit evidence.

## 7. Exception governance

Exceptions are not informal approvals or CI reruns. They are typed, signed records governed by [`../skills/mergegrounds/references/exceptions.md`](../skills/mergegrounds/references/exceptions.md).

Governance rules:

- exception authority is separate from code authorship;
- each waiver consumes a weighted repository/team budget when issued and again if renewed;
- budgets are configured centrally and cannot be increased by the benefiting change;
- expiry and use count are enforced automatically at verification and merge time;
- recurring exceptions trigger root-cause remediation or rule tuning, not rolling renewal;
- non-waivable controls and hard prohibitions have no ordinary exception path;
- break-glass is incident response, not an expanded exception budget.

## 8. Metrics model

Metrics are decision-quality signals, not proof of safety. Report by risk tier, repository, team, control, stack, AI-origin declaration, and time window; normalize defect/finding counts by changed logical lines or change count. Do not rank individuals or reward raw merge volume, low finding counts, or AI-generated line counts.

### 8.1 Integrity and coverage

| Metric | Definition | Strict target / alert |
|---|---|---|
| Protected-ref reconciliation | protected updates with valid exact admission decision / all protected updates | 100%; any miss = critical incident |
| Release provenance coverage | released artifact digests with valid provenance to admitted source / all released digests | 100%; any miss blocks/recalls release |
| Required evidence completeness | decisions containing every required valid evidence node / all decisions | 100% |
| Trusted-producer coverage | evidence from currently trusted producers / required evidence | 100% |
| Stale/replay rejection | injected stale/replayed fixtures denied / all such fixtures | 100% in conformance tests |
| Owner coverage | protected paths with active primary and backup owner / protected paths | 100% |
| Unsigned or mutable dependency rate | unpinned/unverified resolved inputs / all resolved inputs | 0 in releases |

### 8.2 Security and quality outcomes

| Metric | Definition | Interpretation |
|---|---|---|
| Security escape rate | confirmed post-admission vulnerabilities attributable to changes / 1,000 admitted changes | primary lagging outcome; target critical/high = 0 |
| Defect escape rate | production defects attributable to changes / 1,000 admitted changes | trend by tier and control gaps |
| Change failure rate | deployments causing rollback, hotfix, incident, or degradation / deployments | guard against tests that do not reflect production |
| Detection lead | time from introduction to pre-merge detection | shorter is better; post-merge detections are separately reported |
| Recovery time | time from quarantine/incident to contained and verified state | track by impact tier |
| Changed-code coverage | covered changed branches / instrumentable changed branches | policy threshold; never trade assertion quality for percentage |
| Mutation adequacy | killed non-equivalent mutants / executed non-equivalent mutants | required for changed executable code; survivor classes drive tests and R3+ requires expanded scope |
| Fuzz/property effectiveness | unique valid failure conditions found and fixed, with corpus growth | coverage and recurrence matter more than run count |

### 8.3 Gate health

| Metric | Definition | Guardrail |
|---|---|---|
| Gate availability | valid determinations / required invocations | availability issue never converts to pass |
| Incomplete-scan denial rate | partial/zero-scope/malformed runs denied / all such runs | 100% |
| Confirmed precision | confirmed actionable findings / adjudicated findings | tune noisy rules without broad suppression |
| Regression catch rate | seeded/canary defects detected / seeded defects | 100% for mandatory canaries |
| Flake rate | materially identical reruns with conflicting results / reruns | investigate; repeated rerun-to-green is prohibited |
| Policy drift | repositories whose effective policy digest differs from assigned digest | 0 unless signed staged rollout |
| Intelligence freshness | age of advisory/malware/license data at decision | within policy window; otherwise deny |

### 8.4 Human review integrity

| Metric | Definition | Guardrail |
|---|---|---|
| Fresh approval rate | approvals bound to final substantive diff / required approvals | 100% |
| Independence rate | approvals satisfying identity/authorship separation / required approvals | 100% |
| Pre-implementation design coverage | applicable changes with digest-bound design approval preceding implementation / applicable changes | 100% for R2–R4; unverifiable chronology is reported separately, not counted |
| Oracle traceability | material acceptance criteria and test expectations linked to an accountable independent source / required criteria | 100%; implementation-derived expectations do not count |
| Independent challenge coverage | applicable changes with a valid clean-context challenge and resolved disposition / applicable changes | 100% for R2–R4 |
| Explain-back completion | applicable changes with reviewer-accepted human comprehension evidence / applicable changes | 100%; pasted AI summaries do not count |
| Review-unit compliance | changes within tier cognitive budget / changes | 100%; oversize is split, not waived routinely |
| Finding resolution integrity | reviewer findings resolved and reverified / blocking findings | 100% before admission |
| Review concentration | share of high-risk approvals by top reviewer(s) | alert for bottleneck/fatigue; no universal numeric target |
| Sampled review adequacy | assurance audits with no material review omission / sampled approvals | threshold defined by assurance owner; any critical miss triggers expansion |

### 8.5 Exception and emergency health

| Metric | Definition | Strict target / action |
|---|---|---|
| Weighted open exception budget | sum of active exception weights by team/repository | at or below configured cap; cap reached denies new waiver |
| Exception utilization | active weighted points / allowed points | alert at 60%; escalation at 80%; deny at 100% |
| Expired exception usage | admissions/releases using expired records | 0; any occurrence = critical control incident |
| Renewal rate | renewed exceptions / expired exceptions | downward trend; repeated same-rule renewal triggers remediation |
| Exception age | current time − issue time for active records | within class TTL; report p50/p95/max |
| Break-glass frequency | activations per rolling 90 days | target 0; every event reviewed |
| Break-glass closure | events fully revalidated/remediated within SLO / events | 100% |
| Degraded-state duration | time repository remains degraded | alert continuously; stop routine releases |

### 8.6 AI-assistance analysis

Known AI assistance is recorded to analyze controls, never to grant lower scrutiny.

Track:

- admitted, rejected, and remediated changes by declared assistance class and risk tier;
- security/defect escape rate normalized by tier and change size, compared with non-AI baseline;
- top categories of AI-associated findings and review corrections;
- dependency inventions/typosquat detections, test-gaming indicators, and oversized-generation denials;
- context/tool policy violations and attempted secret/data egress.

Do not infer safety from model brand, acceptance rate, or generation speed. Do not use metrics to punish honest AI-origin disclosure; that creates concealment incentives.

### 8.7 Delivery flow, rework, and comprehension

Generation speed is not delivery speed. Measure the whole path from an accepted problem or approved design to verified production behavior, with quality and safety outcomes attached.

| Metric | Definition | Interpretation / guardrail |
|---|---|---|
| Outcome lead time | elapsed time from accepted problem or approved design to verified production outcome | primary speed measure; also report queue, implementation, verification, and rollout segments |
| Time to review | ready-for-review to first substantive independent review, plus active review duration when measurable | expose review bottlenecks; a very short review is not automatically good |
| First-pass yield | changes admitted without substantive corrective revision after first independent review / review-ready changes | low yield reveals premature generation or weak design; never reward by discouraging findings |
| Revision/rework load | substantive corrective revisions, review cycles, and active corrective time before admission | stratify cause: requirements, design, AI implementation, tests, tooling, or review |
| Early-life corrective churn | code changed to correct or replace the admitted behavior within 7 and 30 days / original changed logical code | distinguish planned iteration/refactoring from defect-driven repair |
| Debug time | time from first reproducible failure or reviewer finding to verified resolution | report pre-merge and post-release separately; include time spent understanding generated code |
| Defect/security escape rate | attributable confirmed post-admission defects or vulnerabilities per normalized admitted-change cohort | pair with severity and time-to-detection; use the definitions in section 8.2 |
| Change failure rate | deployments causing rollback, hotfix, incident, or degraded state / deployments | quality guardrail for any claimed acceleration |
| MTTR / verified recovery time | detection or degraded-state start to containment and verified restoration | include time to identify the owning logic and validate recovery |
| Complexity delta | changed functions/modules newly above, remaining above, or removed from approved cognitive/cyclomatic ceilings | target no new breach and downward legacy trend; thresholds cannot rise in the benefiting change |
| Duplication delta | new, removed, and net duplicated blocks or normalized duplicated changed code | target no unapproved increase; exclude only reproducible generated/vendor material by reviewed policy |
| Refactoring/debt balance | maintainability debt retired versus introduced, with fingerprinted rule/category | feature volume must not hide declining refactoring or growing baseline debt |
| Comprehension coverage | applicable changes whose accountable human passed explain-back / applicable changes | 100%; audit quality with counterfactual questions, not self-attestation alone |
| Knowledge spread | critical changed areas that at least one qualified non-author reviewer can explain and operate / critical changed areas | prevents single operator/model dependency; do not turn into individual ranking |
| Total delivery cost | model/API spend + trusted compute/CI + human design/review/debug/rework + incident/recovery cost | compare delivered outcomes, not cheap generated tokens or lines |

Local MergeGrounds stage durations describe command execution only. They do not measure discovery, design, waiting, review, debugging, rollout, or recovery, and therefore cannot establish productivity by themselves. Lifecycle measures come from trusted source-control, review, CI, deployment, incident, and cost systems; author or model estimates remain separate qualitative data.

### 8.8 Comparison and decision rules

Compare AI-assisted and non-AI work only across comparable risk tier, stack, team, change type, dependency/migration profile, and size, or through a controlled pre/post design. Report medians and tail distributions with sample size and observation window; do not turn a small or selectively completed sample into a causal claim. Cases that failed, were abandoned, did not execute, or were rolled back remain in the denominator appropriate to the measure.

Perceived acceleration is a useful survey signal but is reported beside, never in place of, observed outcome lead time and rework. Missing telemetry yields `unknown`, not zero and not “faster.” Model/provider upgrades reset the comparison baseline when their behavior or economics changes materially.

Expand AI use only when outcome lead time or total cost improves without material deterioration in security/defect escapes, change failure rate, recovery time, rework, review integrity, complexity, duplication, comprehension, or knowledge spread. A regression creates a process-improvement experiment with an owner and deadline; it is not repaired by lowering a quality gate.

## 9. Operational objectives

At minimum, strict-profile deployments establish these objectives:

- protected-ref and release provenance coverage: 100%;
- unauthorized direct writes, expired-waiver admissions, and untraceable releases: 0;
- non-waivable critical/high findings at admission/release: 0;
- R2–R4 changes with accountable acceptance-oracle traceability, pre-implementation design review, independent challenge, and human explain-back: 100%;
- R3/R4 changes with complete required reviewer roles and threat-model delta: 100%;
- control-plane conformance exercises completed successfully each quarter and after material changes: 100%;
- break-glass post-event preliminary review within 24 hours, full revalidation within 24 hours, and durable remediation plan within 72 hours;
- compromised producer/artifact quarantine begins within the organization's critical-incident response objective.

Products add availability and recovery SLOs appropriate to their impact. They may be stricter, but not relax integrity objectives while claiming the strict profile.

## 10. Review cadence and actions

- **Per decision:** verifier evaluates thresholds and sends immutable result.
- **Daily:** reconcile protected refs, release digests, policy assignment, expired exceptions, and quarantines.
- **Weekly:** review gate outages/flakes, new baselines, exception budget, ownership gaps, vulnerability intelligence freshness, failed explain-backs, and unresolved challenge findings.
- **Monthly:** review delivery lead time, review/rework/debug load, escapes, change failures, recovery, maintainability, comprehension, and total cost by comparable cohort; tune rules through controlled policy changes.
- **Quarterly:** adversarial conformance exercises, reviewer-load/adequacy sampling, privileged identity review, exception root-cause review.
- **Annually and after incidents:** independent architecture, threat-model, trust-boundary, retention, and recovery review.

Threshold breach has a named action, not merely a dashboard color. Integrity breaches stop admission/release or quarantine affected artifacts. Quality trends create owned remediation with a deadline. A noisy gate is repaired or narrowly excepted; it is not silently made advisory.

## 11. Audit sampling

Independent assurance samples must include:

- every break-glass event and R4 change;
- all R3 changes with exceptions;
- a risk-weighted random sample of R0–R3 accepted and denied changes;
- changes with unusually short review, repeated reruns, large generated diffs, new dependencies, or classification downgrades;
- one end-to-end reconstruction from protected commit to deployed artifact per critical service each quarter.

Auditors verify evidence semantics and source behavior, not only checklist completion. Material failures expand the sample, trigger impact analysis across the evidence graph, and may revoke prior decisions.
