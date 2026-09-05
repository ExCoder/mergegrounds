# Trusted control plane

## The repository-only limit

A workflow stored in the same repository as the code it judges can be changed by the same pull request. A control-plane content/mode lock plus CODEOWNERS makes review explicit, but a malicious change can still attempt to weaken the checker and update its expected entry. Branch rules and independent review are therefore part of the security boundary, not optional administration.

## High-assurance pattern

Use an organization-owned, tightly writable policy repository for the reusable admission workflow. Require that workflow through an organization ruleset where the GitHub plan supports it. Pin every referenced workflow/action to an immutable commit, protect the policy repository with stronger owners and no bypass, and keep its runner unprivileged for pull-request validation.

The application repository supplies declarative inputs and project commands. The trusted workflow independently validates those inputs before executing them. It must reject:

- unknown schema versions or adapters;
- mutable action/container references;
- policy changes without designated review;
- missing lockfiles, reports, thresholds, or evidence;
- fork/PR jobs requesting secrets, write permissions, self-hosted privileged runners, or deployment environments.

For `MG-SEC-002`, a SARIF file and digest emitted from the candidate workspace are never authoritative evidence, even if a later job reparses them. The trusted plane independently reruns every applicable SAST tool against a read-only/content-addressed source mount while keeping outputs inaccessible to candidate processes. It derives the exact expected changed-file and language manifest from trusted Git objects and binds expected/observed scope, report-native file identities, tool/query/runtime/policy identities, findings and baseline disposition, artifact identity/digest, and the exact subject. Missing or unsupported required scope, a candidate-produced sole report, any prohibited finding, or an unacceptable baseline maps to `not_evaluated` or `fail`.

Use a separate trusted release workflow. It consumes an immutable commit and verified build evidence, rebuilds or verifies the artifact, creates an SBOM and provenance, scans the final artifact, and only then receives short-lived OIDC-based publishing credentials. Never promote an artifact solely because a pull-request workflow uploaded it.

## Conditional AI-product authorities

When the shipped product uses AI/ML, the trusted control plane additionally owns or consumes independently administered records for:

- AI applicability rules, control materialization, critical slices, evaluation thresholds, and accepted evidence schemas;
- immutable model/provider snapshots, production baseline and promotion/revocation state;
- expected-case manifests, private/time-split holdout registry, evaluator/judge authorization and calibration, contamination-analysis policy, and governed production sampling;
- approved provider/service/model purposes, accounts/endpoints, data classes, training/secondary-use terms, retention/deletion, processing location/transfers, subprocessors, human/support access, contract/DPA state, incident duties, expiry, and revocation;
- retrieval corpus/ACL/freshness policy, model/tool capability and confirmation policy, sandbox images/profiles, egress/data-purpose rules, and resource budgets;
- canary/stop thresholds, runtime drift policy, immutable rollback targets, quarantine, and recovery authorization.

Repository configuration may propose component identities and reference these records; it cannot issue or replace them. In particular, a candidate branch or local MergeGrounds run cannot prove provider contract performance or internal deletion, human identity/qualification/independence, private-holdout secrecy, or production-sampling authorization. The independent verifier resolves signed records from the authority named by policy and maps missing, expired, revoked, or mismatched authority to `not_evaluated` or `fail`.

Keep authority narrow and separated. Product/model developers do not administer the private holdout or solely authorize their own promotion. The service that runs an untrusted candidate does not sign its own evidence. The model is not an authorization principal: an independently administered capability broker owns credentials, tool authorization, exact-effect confirmation, and revocation. Data/privacy/legal authorities govern provider/data-purpose facts; security/platform authorities govern sandbox and egress; release/operations authorities govern promotion, stop, and rollback.

Public benchmarks, model/provider assertions, confidence, chain-of-thought, self-review, and repository dashboards remain claims or advisory input. Signing such content by its claimant does not convert it into independent evidence.

## Required external settings

At minimum verify, rather than merely document:

- default branch rules apply to administrators with no routine bypass;
- pull requests, conversation resolution, code-owner review, fresh approvals, and required checks are enforced;
- force pushes and deletions are blocked; linear history and signed commits are required where feasible;
- required check names cannot be satisfied by an unrelated workflow;
- merge queue is configured consistently with required checks;
- environments protect signing, publishing, and deployment with reviewers and branch restrictions;
- GitHub Actions allows only reviewed actions and immutable references where organization policy supports it;
- self-hosted runners used for untrusted code are ephemeral and isolated, or are not used at all;
- secret scanning, push protection, dependency review, and code scanning alerts are enabled and owned.

For AI products, also verify externally that:

- the deployed model, prompt, retrieval/corpus, provider, tool, sandbox, and egress identities match the release decision;
- expected-case and private-holdout registries are inaccessible to candidate/model-development identities except through audited evaluation interfaces;
- provider approval matches the actual account, endpoint, model, purpose, data class, region, runtime settings, and current expiry/revocation state;
- the capability broker issues narrow short-lived credentials and enforces closed tool schemas, effect-bound confirmation, deny-by-default egress, redirect/DNS/IP/data-purpose checks, and resource limits;
- production sampling and telemetry follow approved minimization/access/retention rules, and critical drift or policy mismatch can stop, quarantine, revoke, and roll back the exact promoted configuration.

Repository bootstrap cannot assert any of these settings. `scripts/apply-github-ruleset.sh` must preview desired state by default and apply only with explicit authorization.

## Safe update path

1. Open a dedicated control-plane change.
2. Run policy unit tests and negative fixtures in isolation.
3. Obtain security/code-owner approval from someone other than the authoring agent or developer.
4. Update immutable references and the control lock.
5. Merge through the same protected path; never use an administrative bypass to “fix CI.”
6. Verify the external ruleset and required workflow still point at the intended identity.

Emergency bypasses require a named incident, two-person approval where possible, minimal scope, automatic expiry, audit retention, and immediate post-incident restoration. A bypass is a security event, not an ordinary exception.
