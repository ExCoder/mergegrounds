---
name: mergegrounds
description: Bootstrap, audit, or repair strict repository admission controls for AI-assisted code, including mutation testing, security, supply-chain, CI governance, and evidence. Use for secure AI development baselines or when only independently verified code may merge; do not use for ordinary feature implementation unless hardening is requested or clearly required.
---

# MergeGrounds

Treat AI-authored changes as untrusted input. Build a repository control plane that makes unsafe or unverified changes difficult to merge and makes every exception visible, owned, and temporary.

Do not claim that a repository is “safe.” Report which controls were verified, which depend on external settings, and what residual risks remain.

## Select the operating mode

- **Bootstrap**: add the baseline to a new or lightly configured repository.
- **Harden**: merge stronger controls into an existing engineering system without replacing working project conventions.
- **Audit**: inspect and report only. Do not edit files or external settings.
- **Repair**: diagnose and fix a failing MergeGrounds gate while preserving its security intent.

Infer the mode from the request when clear. Ask only if the choice would materially change authorized work.

## Mandatory start

1. Read repository-local instructions and inspect the worktree before changes.
2. Inventory languages, package managers, lockfiles, generated code, CI, release paths, data sensitivity, deployment targets, and existing security controls.
3. Identify the trust boundary. Never run pull-request-owned scripts with secrets, write tokens, signing keys, production credentials, or a privileged runner.
4. Assign an R0–R4 risk tier using [control-model.md](references/control-model.md). Default to **R3** for internet-facing software or when uncertainty remains; never silently lower an existing tier.
5. Before substantive implementation or generation, identify an accountable acceptance oracle and record the intended outcome, business/security invariants, error behavior, and non-goals. For R2–R4, require a reviewed design first; do not describe a post-hoc design as pre-implementation review.
6. Decide whether AI only assists development or is part of shipped product behavior. The latter also requires [AI product assurance](references/ai-product-assurance.md); ordinary code gates do not validate a stochastic model, retrieval system, or agent.
7. For a large repository, summarize and target inspection instead of loading huge generated files or dependency trees directly. Do not assume that content placed in a long context was understood or used.

## Non-negotiable invariants

- Fail closed when a required tool, test, report, lockfile, artifact, or policy is missing, malformed, stale, or inconclusive.
- Keep the control plane (`.github`, `.mergegrounds`, MergeGrounds scripts, ownership rules, release definitions) under explicit security ownership.
- Use immutable action references, least-privilege workflow permissions, deterministic lockfiles, isolated builds, and ephemeral credentials.
- Invoke repository policy entry points with Python isolated mode (`python3 -I`) and protect the complete `scripts/` tree; otherwise a sibling `json.py`, `argparse.py`, or compiled module can execute before the verifier starts.
- Reject candidate-local Actions and reusable workflows in admission jobs unless an external trusted-base verifier recursively resolves and scans their exact Git tree. A local `action.yml` can receive implicit platform context even when a workflow does not pass it explicitly.
- Do not use `pull_request_target` to build or execute untrusted pull-request code.
- Separate the untrusted build/test plane from any trusted signing, publishing, deployment, or policy-enforcement plane.
- Require independent human review for security-sensitive and control-plane changes. An authoring agent must not approve its own output.
- Treat model reasoning, confidence, fluent explanation, and self-critique as untrusted claims. Do not request or retain private chain-of-thought; verify observable results against an independent oracle.
- Asking the authoring model/session to “check again” is not an independent challenge. Use a clean-context adversarial reviewer to seek disconfirming cases, and retain required human approval.
- Require an accountable human to explain the final behavior, invariants, failure modes, test oracle, and recovery path from the source and design. A pasted AI summary is not explain-back evidence.
- Never weaken or skip a gate merely to make CI green. Follow the exception process in [exceptions.md](references/exceptions.md).
- Do not present an aggregate coverage or mutation percentage as complete scope evidence. Require the project verifier to bind the exact production/changed-path manifest to report-native file or mutant identities; until then, label the local score diagnostic only.
- Never expose secrets in commands, logs, evidence, fixtures, patches, or generated configuration.
- Do not treat prompt tone or requests to remember/forget as controls. Govern coding-assistant conversation history, memory, retention, training use, and deletion as provider/system data flows; minimize context and keep secrets/customer data out by default.
- Preserve user changes and existing controls. Bootstrap must preview conflicts and must not overwrite by default.

Repository-contained CI is not a complete root of trust because a pull request can propose changes to that CI. For the strongest mode, require an organization-owned workflow or GitHub ruleset outside the repository's writable boundary; read [trusted-control-plane.md](references/trusted-control-plane.md).

The bundled runner only lints repository exception records. It must never turn a local failure into `waived`; exception consumption requires the protected verifier and append-only ledger in [exceptions.md](references/exceptions.md).

## Build the control plan

Map each material risk to a preventive control, an independent detective control, a merge gate, an owner, and retained evidence. Prefer two dissimilar checks for high-impact failure modes—for example, tests plus mutation testing, a package audit plus an artifact scan, or static analysis plus a focused manual review.

Follow the design → implement → verify → challenge → explain-back loop in [AI-assisted development assurance](../../docs/ai-assisted-development.md). Give an independent challenger the oracle, reviewed design, exact diff, relevant source, and evidence, but initially withhold the author's conclusion and confidence to reduce anchoring. A second model/agent can add defense in depth but never fills a required human review role.

At minimum, a high-risk pull request must prove:

- formatting, strict linting, type checking, unit/integration tests, and coverage;
- changed-code mutation adequacy, with a scheduled full mutation run;
- secret, SAST, dependency, license, and supply-chain checks;
- reproducible build inputs, lockfile consistency, and generated-file provenance;
- traceability from acceptance criteria and business/security invariants to tests independent from the implementation;
- an adversarial challenge whose findings are resolved or converted into durable negative/regression tests;
- human explain-back sufficient to own, debug, operate, and recover the change;
- protected-path ownership and independent approval;
- a machine-readable evidence record tied to the commit;
- no unauthorized exception or degradation of the control plane.

Read [mutation-testing.md](references/mutation-testing.md) before adding or changing mutation gates. Read [stack-adapters.md](references/stack-adapters.md) only for detected ecosystems. Read [github-hardening.md](references/github-hardening.md) for GitHub workflows or rulesets. For process design, comprehension, independent challenge, and outcome measurement, follow [AI-assisted development assurance](../../docs/ai-assisted-development.md).

## Bootstrap or harden

For a genuinely new project, the target must be an existing, completely empty
directory. Preview and apply with `--allow-non-git`, then initialize that exact
directory as the Git root, tailor every control, and create the first
human-reviewed bootstrap commit while MergeGrounds is explicitly inactive. Only
after that clean commit may the project regenerate the seal and commit the lock
as a separate reviewed change. Never use `--allow-non-git` for a non-empty
directory or to bypass an enclosing worktree.

From this plugin repository, preview the baseline first:

```bash
python3 -I scripts/bootstrap.py --target /path/to/repository
```

Apply only after reviewing the plan:

```bash
python3 -I scripts/bootstrap.py --target /path/to/repository --apply
```

Never use `--force` without inspecting conflicts. Forced replacement must create a backup and remain within the requested repository.

Adapt `.mergegrounds/mergegrounds.toml` and detected stack adapters to real project commands. Bind a canonical production/changed-path manifest to report-native coverage and mutant identities in the protected project verifier; the local aggregate parsers do not prove source-scope completeness. Do not install or select a tool solely because it is listed in the starter; retain an existing equivalent when it provides equal or stronger evidence. Pin any new tool through the ecosystem's lock mechanism.

Use `scripts/scaffold_change.py` to create a design and design-only declaration, replace every deliberate `EDIT ME`, and merge the reviewed design before implementation. Then create the implementation declaration from that base-resident design. The structured contract—not PR prose or checkboxes—is the candidate-local input to `verify-change`.

If AI is part of shipped behavior, materialize `.mergegrounds/ai-assurance.toml` for the exact capabilities and require the project-specific trusted evaluator to produce the configured report. `ai_assurance.py evaluate` validates completeness, identity, case/slice membership, metrics, baseline comparison, and producer class; it does not generate domain truth or prove external independence.

Branch protection, rulesets, required workflows, merge queues, environments, and organization policies are external state. Repository files can describe them but cannot prove they are enabled. The ruleset helper must stay dry-run unless the user explicitly authorizes applying it.

## Validate

Run the smallest relevant profile during iteration. For the shipped R3 baseline,
`pr` is diagnostic only and protected admission requires `full` with a real
candidate-bound fuzz harness:

```bash
python3 -I scripts/mergegrounds.py doctor
python3 -I scripts/mergegrounds.py verify-repo --strict
python3 -I scripts/mergegrounds.py run --profile pr --evidence .mergegrounds/evidence/pr.json
python3 -I scripts/mergegrounds.py run --profile full --evidence .mergegrounds/evidence/full.json
python3 -I scripts/ai_assurance.py validate-policy
python3 -I scripts/ai_assurance.py evaluate
```

Repeat the full profile before release and on the scheduled trusted run:

```bash
python3 -I scripts/mergegrounds.py run --profile full --evidence .mergegrounds/evidence/full.json
```

In GitHub PR validation, validate the structured declaration and its immutable design blobs:

```bash
python3 -I scripts/mergegrounds.py verify-change --event "$GITHUB_EVENT_PATH"
```

Do not interpret a skipped, missing, timed-out, empty, or unparsable result as success. Test the controls themselves with at least one safe negative case: a deliberately failing fixture, temporary mutation, or isolated policy violation that must be rejected and then removed.

After the deterministic gates, run a clean-context adversarial review against the final coherent diff. Do not seed it with the author's preferred diagnosis. Resolve its findings, rerun affected gates, and then perform human explain-back before approval. Repeating the authoring model's self-review does not satisfy this step.

## Evidence and handoff

Report:

- exact commands and commit tested;
- passing, failing, skipped, and externally unverified controls separately;
- coverage and mutation scores with scope and thresholds;
- evidence paths and hashes;
- active exceptions with owners and expiry dates;
- external settings that still need verification;
- acceptance-oracle and reviewed-design references, independent challenge findings, and explain-back status;
- observed delivery/rework outcomes separately from any subjective speed claim;
- residual risks and the smallest next action to close each one.

Use [workflow.md](references/workflow.md) for the end-to-end implementation sequence and [evidence.md](references/evidence.md) for the evidence contract.
