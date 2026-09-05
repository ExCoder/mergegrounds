# AI-assisted development assurance

Status: normative process baseline

Scope: software changes whose design or implementation is assisted by a model, coding agent, generator, or model-connected tool

## 1. Assurance is based on outcomes

Model output is a proposal, not evidence. A fluent explanation, visible reasoning trace, confidence score, self-critique, or a second answer from the same model/session does not establish correctness. Do not request, retain, or review private chain-of-thought. A concise rationale may help humans navigate a change, but it remains an untrusted claim.

Admission evidence must be independently observable: behavior against an acceptance oracle, test and mutation results, typed scanner reports, source and artifact digests, reviewer attestations, and production outcomes. Verification asks **what result was observed, against which oracle, on which exact subject, by which independent producer**. It does not ask whether the model sounded convincing.

Prompt tone is not a security, privacy, or quality control. Politeness, bluntness, or a request to remember/forget cannot substitute for provider governance. Treat conversation history, product “memory,” retrieved context, telemetry, retention, training use, and deletion as separate system/provider state: classify and minimize what is sent, keep secrets and customer data out by default, and verify the provider/account controls that actually govern it.

## 2. Keep two scopes separate

**AI-assisted development** uses AI to help create ordinary software. The generated change enters the same admission path as human-written code, with additional provenance, comprehension, and challenge controls. Model choice never lowers scrutiny.

**AI-enabled product behavior** puts a model, retrieval system, agent, or model tool in the shipped product. It additionally needs model/data/provider, evaluation, prompt-injection, retrieval, tool-authorization, output-validation, cost, and rollback controls. Follow [AI product assurance](../skills/mergegrounds/references/ai-product-assurance.md) in addition to this document. Passing the repository code gates alone does not validate stochastic product behavior.

Do not apply AI-product controls to a repository merely because a developer used an assistant. Conversely, do not treat an AI-enabled product as ordinary deterministic application code merely because its orchestration layer passed unit tests.

## 3. Design before generation

For R2–R4 work, and for any change to a trust boundary, business rule, persistent data, public interface, dependency, migration, or operational control, review the design before substantive implementation or code generation begins. R0/R1 work may use a proportionate inline design, but it still needs an explicit problem and acceptance oracle.

The reviewed design records:

- problem, intended user/business outcome, scope, and intentionally unchanged behavior;
- acceptance oracle and its accountable owner;
- business, security, privacy, data, availability, performance, and compatibility invariants;
- affected components and data/control flows, including trust boundaries and privileges;
- alternatives considered and why the selected design is preferred;
- failure modes, abuse cases, observability, rollout, rollback or roll-forward, and recovery;
- test strategy, including which oracle is independent from the implementation;
- unresolved assumptions and the decision that would invalidate the design.

Approval is bound to the design digest, base revision, reviewers, and time. A material design change invalidates the approval and returns the work to design review. Writing a design explanation after code exists can improve documentation, but it is not evidence that design was reviewed before implementation. Maximum-assurance deployments verify the chronology through a protected design record and signed approval outside candidate control.

## 4. Establish an acceptance oracle

Tests written by the same agent from its own implementation can faithfully confirm the wrong behavior. Before implementation, identify the source of truth against which the result will be judged. Depending on the change, the oracle may be an approved specification, business-rule table, protocol/schema, reference implementation, test vectors, independently prepared examples, production invariant, or accountable domain-owner decision.

An adequate oracle defines:

- positive behavior and boundary cases;
- prohibited behavior and negative/abuse cases;
- invariant relationships rather than only example outputs;
- error, timeout, cancellation, partial-failure, and recovery behavior;
- non-functional budgets where material;
- known ambiguity, ownership, version, and applicability limits.

The implementation author or authoring agent must not silently invent missing business rules. Ambiguity blocks implementation until the oracle owner resolves it or explicitly records a bounded assumption. A generated test is useful evidence only when its expected behavior is traceable to an oracle independent of the code under test.

## 5. Separate creation from challenge

Self-correction is not independent review. Rephrasing “are you sure?”, continuing the authoring session, increasing reasoning tokens, or asking the same agent to approve its own patch remains a correlated check and cannot fill a reviewer or challenger role.

For R2–R4, use an adversarial challenge after the first coherent implementation and before final approval. The challenger receives the acceptance oracle, reviewed design, exact source diff, relevant surrounding code, and gate evidence. Initially withhold the author's preferred diagnosis, confidence, and justificatory narrative so they do not anchor the review. Ask the challenger to falsify the change by finding:

- violated invariants, missing cases, and disagreement with the oracle;
- privilege, data-flow, trust-boundary, and dependency mistakes;
- tests that merely mirror implementation or cannot fail meaningfully;
- unsafe error handling, concurrency, resource, migration, or rollback behavior;
- simpler designs and counterexamples to key assumptions.

Record supplied-input digests, challenger identity and prior involvement, findings, dispositions, and resulting tests or design changes. A separate model or agent with clean context is useful defense in depth, especially when its prompt seeks disconfirmation, but it is still automation: it never occupies a required human approval seat. For R3/R4, at least one negative or abuse test must be designed independently from the change author/AI operator.

## 6. Require human explain-back

Before approving AI-assisted executable code, an accountable human operator must be able to explain it from the source and design, without relying on the model's summary. The explanation covers:

1. externally visible behavior and intentionally unchanged behavior;
2. principal data and control flow;
3. business and security invariants;
4. trust boundaries, privileges, dependencies, and sensitive data;
5. important failure modes and recovery behavior;
6. why the tests and mutation/negative checks can distinguish correct from plausible-but-wrong behavior;
7. deployment observation and rollback or roll-forward.

For R2, the domain reviewer records that the explain-back was adequate. For R3/R4, a reviewer poses concrete counterfactual or failure questions and records their disposition. “The model wrote it,” a pasted AI explanation, or an inability to answer is a failed comprehension check and blocks approval. Explain-back is a knowledge-spread control, not an oral performance contest; evaluate the team's operational ability to own the change, not speaking style.

## 7. End-to-end operating loop

Use this sequence:

1. **Frame:** name the outcome, owner, risk tier, and acceptance oracle.
2. **Design:** record invariants, boundaries, alternatives, tests, operation, and recovery; obtain the required pre-implementation review.
3. **Generate/implement:** give the agent only necessary context and tools; keep credentials and production authority outside its boundary.
4. **Verify:** run deterministic gates and independent oracles against the exact revision.
5. **Challenge:** use a clean-context adversarial reviewer; turn valid findings into design corrections or durable regression tests.
6. **Explain back:** confirm accountable humans can own, debug, operate, and recover the change.
7. **Admit/release:** require exact evidence, human quorum, trusted verification, and artifact binding.
8. **Learn:** measure delivery, rework, defects, comprehension, maintainability, and total cost; adjust the process instead of inferring productivity from generation speed.

Any substantive code, test, dependency, design, manifest, or policy change invalidates affected evidence and approvals. Re-run verification and challenge on the final diff.

## 8. Measure delivered value, not generated volume

The primary delivery clock runs from accepted problem or approved design to a verified production outcome, not from prompt submission to generated patch. Track the measures defined in [Governance and metrics](governance-and-metrics.md), including lead time, review and debug time, substantive rework, first-pass yield, escapes, change failure rate, recovery time, complexity and duplication deltas, comprehension, and total cost.

Compare AI-assisted and non-AI work only within comparable risk, stack, change type, and size cohorts, or with a controlled pre/post design. Treat developer perception as a separate survey measure. Missing lifecycle telemetry yields `unknown`; it must not be converted into a claim of acceleration.

Do not rank individuals or reward lines generated, prompts sent, acceptance rate, commit count, or raw merge volume. Those incentives encourage larger patches, hidden assistance, shallow review, and test gaming. Expand AI use only when delivery improves without deterioration in safety, quality, comprehension, maintainability, or operational outcomes.

## 9. Enforcement boundary

The bundled runner verifies repository policy, configured technical stages, artifacts, metrics, and the structural change/design contract. It can verify that a required design record was already present on the pull request base; that is useful Git chronology, not proof that human review preceded every off-repository implementation activity. It does **not** prove that prose is true, that a human understands the code, or that a challenger was genuinely independent. In the portable starter, protected human review and audit make these process requirements accountable.

Maximum-assurance deployments encode design, oracle, challenge, and explain-back as typed attestations bound to exact digests and authenticated identities. A protected verifier checks chronology, role separation, freshness, and completeness before merge. Until that integration exists, report these controls as `configured but not externally verified`, never as machine-proven.
