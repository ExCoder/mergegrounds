# End-to-end workflow

Use this sequence for bootstrap and hardening work. For an audit, stop before mutation and report the same evidence categories. Apply the process controls in [`../../../docs/ai-assisted-development.md`](../../../docs/ai-assisted-development.md) to AI-assisted changes. If a model, retrieval system, or agent is part of shipped behavior, also apply [`ai-product-assurance.md`](ai-product-assurance.md).

## 1. Discover without executing untrusted code

Read project instructions, manifests, lockfiles, existing CI definitions, ownership rules, deployment files, and test configuration. Inventory commands from configuration before running them. Treat repository scripts, package lifecycle hooks, build plugins, compiler plugins, test discovery, and containers as executable input.

Record:

- ecosystems and package managers;
- production entry points and release artifacts;
- secrets and privilege available in each automation context;
- generated, vendored, migration, infrastructure, authentication, cryptography, payment, and authorization paths;
- existing quality/security tools and their actual enforcement points;
- external controls that repository files cannot reveal.
- accountable product/domain owner, intended outcome, existing specification or acceptance oracle, and unresolved business-rule ambiguity;
- whether AI only assists development or is itself part of the shipped product.

Do not install dependencies or execute project code with credentials during discovery.

## 2. Classify risk and trust boundaries

Use `control-model.md`. Default internet-facing or ambiguous software to high risk. Elevate paths handling authorization, secrets, money, personal data, code execution, signing, deployment, or policy enforcement to critical even when the repository's overall tier is lower.

Separate four contexts:

1. untrusted pull-request validation;
2. trusted policy enforcement;
3. trusted artifact signing/publishing;
4. production deployment.

No credential should cross into an earlier context merely for convenience.

## 3. Frame the result and acceptance oracle

Before changing code or asking an agent to generate it, state the intended outcome and identify an acceptance oracle owned outside the implementation. Trace each material requirement to a specification, business-rule table, protocol/schema, approved test vector, independently prepared example, invariant, or explicit domain-owner decision. Record positive, boundary, prohibited, error, timeout, partial-failure, and recovery behavior.

Do not let an implementation or its authoring model silently become its own specification. A test whose expected value is inferred only from the code under test is a correlated check. Unresolved material ambiguity blocks implementation until its accountable owner decides it or records a bounded assumption.

## 4. Review design before implementation

For R2–R4, and whenever a trust boundary, public interface, business rule, persistent data, dependency, migration, or operational control changes, create and review the design before substantive implementation or code generation. Record scope and non-goals, business/security invariants, affected data/control flows, privileges, alternatives, failure and abuse cases, observability, rollout/recovery, and test strategy.

Bind design approval to its digest, base revision, reviewers, and time. Material design changes invalidate approval. A design written after implementation may be useful documentation, but it is not evidence of pre-implementation review. If chronology cannot be verified by a protected external system, report it as configured but externally unverified.

## 5. Design the admission contract

For each risk, write the required evidence, threshold, owner, and failure behavior. A required check has one stable name and exactly one meaning. Do not make required checks conditional on changed-file heuristics unless a separate trusted policy check validates the heuristic and fails closed.

High-risk defaults:

| Control | Pull request | Scheduled/full | Release |
|---|---:|---:|---:|
| Formatting, lint, types | required | required | inherited |
| Unit/integration tests | required | required | inherited |
| Line/branch coverage | changed + total floor | total floor | inherited |
| Mutation testing | changed production scope | full production scope | no regression |
| Secret/SAST/dependency review | required | full rescan | required on artifact |
| Fuzz/property/contract tests | targeted | extended | critical paths required |
| SBOM + artifact vulnerability scan | build candidate | refresh | required |
| Provenance/signature | no privileged signing | verify tooling | trusted release only |

The baseline thresholds are floors, not targets. Raise them from an existing stronger baseline and use changed-code thresholds to prevent legacy debt from hiding new weakness.

Model reasoning, a fluent rationale, confidence, and self-reported checking are never admission evidence. Define evidence in terms of observable outcomes, independent oracles, exact subjects, authenticated producers, and retained artifacts.

## 6. Integrate rather than replace

Preview `scripts/bootstrap.py`. On an existing repository, retain equivalent or stronger tools and map their outputs into MergeGrounds evidence. Do not introduce a second formatter, test framework, package manager, or vulnerability scanner without a clear gap.

Review every adapter command. Pin tools in the ecosystem's lock mechanism or in a reviewed runner image. Never download and execute “latest” tooling in an untrusted job.

Protect `.github`, `.mergegrounds`, MergeGrounds scripts, dependency/lock files, ownership rules, release definitions, and generator templates. Update the control-plane lock only after the changed controls receive the required review.

Run every Python control entry point in isolated mode (`python3 -I`). Protect and seal the complete `scripts/` tree, not only currently known filenames: otherwise a newly added sibling module can shadow a standard-library import and execute before policy validation. In credentialed operator helpers, every inline Python heredoc also uses `-I` so an untrusted repository-root module cannot inherit the operator's GitHub authority.

When an agent implements the design, give it only the context and tools needed for the scoped change. Do not assume that a document was used merely because it appeared in a long prompt or retrieval result. Require traceable references for material rules and inspect the final source rather than relying on the generated explanation.

## 7. Validate the controls

Run `doctor`, the repository policy check, and then the appropriate execution profile. A passing command without its required report is a policy failure. Confirm that evidence is tied to the tested commit and that no dirty generated inputs were silently omitted.

Forward-test at least these cases in an isolated branch or temporary fixture:

- a mutable GitHub Action reference is rejected;
- a candidate-local Action/reusable workflow and a dynamic runner/container/shell selector are rejected;
- a sibling standard-library shadow such as `scripts/json.py` cannot execute before the policy entry point;
- a changed protected control without a refreshed lock is rejected;
- a missing, malformed, post-hoc, or semantically altered structured change/design record is rejected;
- a real test assertion removed or inverted is caught by tests or mutation testing;
- a surviving mutation below threshold fails the job;
- a missing report, missing tool, timeout, or unparsable metric fails;
- an expired exception fails;
- a secret-like environment variable is absent from the project command environment.
- an AI-product report with a missing case, unrelated or undersized metric denominator, failed critical slice, contaminated fixture, or mismatched candidate/baseline identity is rejected.

Remove all test violations and reseal only the reviewed final state.

## 8. Challenge independently and explain back

After the first coherent implementation and deterministic checks, assign a clean-context adversarial challenge. Supply the acceptance oracle, reviewed design, exact final diff, relevant surrounding source, and gate evidence. Initially withhold the author's diagnosis, preferred conclusion, and confidence. Ask the challenger to falsify invariants, find counterexamples, inspect failure/privilege/data paths, and identify tests that merely mirror the implementation.

Rephrasing a question to the authoring model, extending the same session, or asking it to approve its own work is self-check, not independence. A separate agent or model can add defense in depth but cannot occupy a human approval role. For R3/R4, at least one negative or abuse test is designed independently of the author/AI operator. Record challenger identity and prior involvement, supplied-input digests, findings, dispositions, and tests or design changes produced.

Then require the accountable human operator to explain the final behavior, data/control flow, business and security invariants, important failures, why the tests discriminate correct from plausible-but-wrong behavior, and how to observe and recover the deployment. A pasted model summary or inability to answer fails the comprehension check. Any correction invalidates affected evidence and approvals; rerun them against the final diff.

## 9. Roll out without creating a paper shield

Use a short observation window only when legacy debt makes immediate enforcement impossible. Observation output must be visible, time-bounded, owned, and followed by an explicit enforcement date. Critical controls—secret isolation, no privileged untrusted execution, and protected release credentials—must not start in advisory mode.

Enable external GitHub rules and required workflows only after the repository checks are stable. Verify settings through the GitHub API or UI; a checked-in desired-state file is not evidence that the setting is active.

Measure the end-to-end path from accepted problem or reviewed design to verified production outcome. Generation or command duration alone is not productivity. Track lead, review, rework, debug and recovery time together with escapes, change-failure rate, maintainability, comprehension, and total cost as defined in [`../../../docs/governance-and-metrics.md`](../../../docs/governance-and-metrics.md).

## 10. Handoff

Provide the tested commit, commands, trusted/pinned tool versions (separating them from MergeGrounds's no-execution presence discovery), reports, declared and observed metrics, control-lock hash, external settings status, active exceptions, and residual risks. Distinguish:

- **verified here**;
- **configured but not externally verified**;
- **not applicable with reason**;
- **blocked or failed**.

Never collapse these states into a single green badge.

Include the acceptance-oracle/design references, challenge record, explain-back disposition, and any process control that remains only self-attested. Distinguish measured lifecycle outcomes from developer perception or model-generated estimates of time saved.
