# GitHub hardening profile

This profile treats every pull-request-controlled byte as hostile, including source, tests, build scripts, dependency metadata, filenames, PR text, and repository-local workflow changes. It is a strict baseline, not proof that a repository is secure. GitHub settings are external state and must be verified after the files are merged.

The baseline was checked against GitHub's current public documentation on 2026-09-05. Revalidate platform behavior before a new rollout because Actions runtimes, ruleset fields, and security-feature availability change.

## 1. Bootstrap without creating an unprotected window

1. Create the real security/platform team and give it explicit write access to the repository.
2. Replace every `@org/security-team` entry in `.github/CODEOWNERS` with the same reviewed user/team set. Keep the protected pattern block last and in its existing order; place any application-specific ownership rules between the leading `*` rule and that final block. Do not enable code-owner enforcement while the example owner remains; it is intentionally invalid for most repositories.
3. Enable squash merging. Disable merge commits; disable rebase merging if the organization wants one canonical merge path.
4. Commit the MergeGrounds files through a reviewed bootstrap change. If the default branch is not yet protected, use a temporary administrator-created protection rule during bootstrap.
5. Install an independently administered verifier GitHub App. It must emit `MergeGrounds / Admission` and `MergeGrounds / Independent Challenge` for the exact revision only after consuming the applicable local checks, project-specific SAST evidence, and authenticated human approvals. Record its numeric integration ID, slug, and owner outside candidate control. The helper validates all three against GitHub-owned check-run metadata and refuses GitHub-owned, GitHub Actions, and code-scanning identities. Enable GitHub Actions and the security features listed below; run both external contexts and every applicable supplemental check successfully on the default branch once.
6. Preview the repository ruleset:

   ```bash
   scripts/apply-github-ruleset.sh --repo your-org/your-repository \
     --verifier-app-id 123456 \
     --verifier-app-slug mergegrounds-verifier \
     --verifier-app-owner your-security-org
   ```

7. Review the complete JSON, then explicitly apply it:

   ```bash
   scripts/apply-github-ruleset.sh --repo your-org/your-repository \
     --verifier-app-id 123456 \
     --verifier-app-slug mergegrounds-verifier \
     --verifier-app-owner your-security-org \
     --apply
   ```

8. Fetch the active ruleset from GitHub and verify it from a second administrator identity. Exercise a safe negative PR that fails each required check, attempts a direct push, uses an unsigned commit, changes a protected file without code-owner approval, and leaves a review conversation unresolved.

The helper is fail-closed and idempotent by managed ruleset name. It validates the canonical repository identity, actual default branch, GitHub's strict under-3-MiB CODEOWNERS size limit, last-match-safe CODEOWNERS ordering, every trusted owner team's/user's write access, successful check runs, and the GitHub App source of every required check. Validation is bound to the observed default-branch SHA, and `--apply` aborts if that branch moves before mutation. It creates no bypass actor. It will not apply to an archived/disabled/empty repository, a repository without squash merging, or an unready control plane. Run it with an independently protected administrator identity; dry-run needs repository metadata/rules/check/CODEOWNERS read access, while `--apply` additionally needs repository Administration write access.

## 2. Required repository and organization settings

Configure these in the organization wherever possible so a repository administrator cannot silently weaken them:

- Default workflow token permission: **read repository contents**. Do not grant write by default and do not allow Actions to create/approve pull requests.
- Fork PRs: allow only read-only `GITHUB_TOKEN`; never send write tokens or repository/organization secrets. Require maintainer approval for first-time or untrusted contributors when appropriate.
- Actions allowlist: the exact GitHub-authored action repositories used here plus the reviewed `step-security/harden-runner` repository. Require every action to be pinned to a full commit SHA; control container registries and direct release downloads separately by digest/checksum and egress policy.
- Runners: use GitHub-hosted ephemeral runners for untrusted PRs. If self-hosted execution is unavoidable, use one-job ephemeral VMs with no host socket, cloud metadata, sibling-network access, persistent workspace, production route, or organization secrets.
- Enable the dependency graph, Dependabot alerts and security updates, code scanning, push protection, and secret scanning. Dependency Review and CodeQL require GitHub Advanced Security/GitHub Code Security for some private repositories and plans; inability to run a required control is a blocked rollout, not a reason to mark it passing.
- Use CodeQL advanced setup for the committed workflow. Disable CodeQL default setup before enabling the advanced workflow so two incompatible configurations do not compete.
- Require two-factor authentication for the organization. Prefer phishing-resistant passkeys/security keys for administrators and security reviewers. Use short-lived GitHub App or OIDC credentials instead of personal access tokens in automation.
- Restrict repository creation, visibility changes, Actions policy changes, ruleset editing, deploy keys, webhooks, and GitHub App installation to a small audited administrator group.

The repository ruleset created by the helper targets `~DEFAULT_BRANCH`, applies to administrators because it has no bypass actors, and requires:

- pull requests and two approving reviews;
- code-owner review and approval of the latest reviewable push by someone other than its pusher;
- stale-review dismissal and resolution of every review thread;
- strict required checks against the latest base branch;
- authoritative admission/challenge contexts whose persisted ruleset source is the explicitly supplied external verifier App integration ID, with GitHub Actions/code-scanning identities denied at activation;
- language-specific checks such as `CodeQL` consumed as supplemental evidence by the external App when applicable, rather than hard-coded as universal ruleset contexts;
- signed commits on the protected ref;
- squash-only, linear history;
- no branch deletion or force push.

The stable ruleset contexts are exactly `MergeGrounds / Admission` and `MergeGrounds / Independent Challenge`, both persisted with the configured external App's numeric `integration_id`; same-named GitHub Actions jobs are rejected by that integration binding. The supplied App slug and owner are activation-time preflight assertions against GitHub-owned check-run metadata, not fields GitHub continuously stores in the ruleset. External drift reconciliation must therefore re-resolve the integration ID and revalidate the current App slug and owner, especially after an App rename or transfer. `MergeGrounds / Policy`, `MergeGrounds / PR`, and applicable language-specific SAST contexts remain mandatory inputs evaluated by that verifier, but they are not authoritative roots of trust. This keeps the ruleset usable for supported stacks such as PHP that CodeQL does not analyze, without permitting SAST to disappear: the external admission App must deny until an independently trusted project-specific replacement is configured. Do not rename either authoritative context without changing, previewing, and atomically replacing the ruleset. If a merge queue is enabled, keep `merge_group` triggers and test the queue before making it mandatory.

## 3. The repository is not its own root of trust

CODEOWNERS plus a repository ruleset is necessary but not sufficient. A pull request can propose a modified workflow or MergeGrounds script that emits the same check name. Binding a local check to the GitHub Actions App prevents a different app from forging it, but does not distinguish a trusted workflow revision from a PR-modified workflow in the same repository. For that reason the helper refuses to install maximum-assurance rules without an explicit external verifier App ID, slug, and owner and rejects GitHub Actions as that verifier.

For the maximum assurance tier, create an organization-owned, separately administered workflow repository and add its workflow through an organization/enterprise ruleset's **Require workflows to pass before merging** rule. The central workflow must:

- be readable at the required visibility level but writable only by the platform/security owners;
- pin its actions, scanner, policy bundle, runner image, and reusable-workflow reference by immutable digest or commit;
- receive the candidate repository and exact PR/base SHAs as data;
- never select policy or executable validation logic from the candidate ref;
- checkout candidate code without credentials and run it in an isolated, secretless environment;
- verify the candidate's protected control files against a trusted policy/lock or explicitly route control-plane changes to a separate approval path;
- emit signed, subject-bound evidence or a status from a dedicated GitHub App whose installation cannot write source.

Use organization Actions workflow-execution protections to deny or tightly restrict `pull_request_target`, privileged `workflow_dispatch`, and low-trust actors. These controls live outside the candidate repository and close part of the self-modifying-CI gap. A separately protected admission service or merge controller is stronger when regulatory or high-impact systems require independent evidence verification.

## 4. Untrusted pull-request boundary

`.github/workflows/mergegrounds.yml` and `.github/workflows/codeql.yml` deliberately use `pull_request`, never `pull_request_target`. The candidate receives no configured secret and no source-write permission. Checkout disables credential persistence. The structured change verifier reads `GITHUB_EVENT_PATH` as bounded data and resolves declarations/designs from immutable Git blobs; PR prose is not an oracle.

Keep these invariants when adapting workflows:

- Do not add repository, environment, cloud, registry, signing, deployment, or model-provider secrets to a job that checks out or executes candidate code.
- Do not grant `contents: write`, `pull-requests: write`, `actions: write`, `checks: write`, `packages: write`, or `id-token: write` to an untrusted job.
- Do not pass untrusted issue titles, branch names, commit messages, matrix values, action outputs, or PR bodies directly into a shell command. Pass data through an environment variable or file and parse it without `eval`.
- Do not let PR-controlled expressions decide job/step `if`, select `runs-on`, a container/service image or options, `shell`, `working-directory`, an action, or a reusable workflow. These fields change whether, what, and where code executes; passing them through an environment variable does not make that authority safe. Do not publish PR text as a job output and consume it later through `needs.*.outputs.*`; that only launders the same untrusted authority across a job boundary.
- Pin every job and service container image by `sha256` digest. A static-looking registry tag such as `latest`, `stable`, or `1.2.3` remains mutable and cannot select admission code or its runtime.
- Reject `uses: ./...` in candidate-evaluated admission workflows. A repository-local action or reusable workflow is executable candidate code and can consume implicit Actions context such as `github.token` even when the caller does not list it under `with` or `env`. Maximum assurance may allow only a separately trusted base-tree resolver that recursively scans and pins the exact local action tree.
- Invoke repository Python controls as `python3 -I scripts/...`; invoke inline parser heredocs as `python3 -I -`. Without isolated mode, a candidate-added sibling/root module can shadow a standard-library import before policy starts, including while an administrator's authenticated ruleset helper is running.
- Do not mount the Docker socket into candidate containers. The portable workflow does not mount it into the digest-pinned secret-scanner container, but this is **not** socket isolation: adapter commands run on the GitHub-hosted runner, whose runner user may access the host Docker daemon. Treat that job as an untrusted baseline contour, never give it secrets or write authority, and use a separately administered sandbox/ephemeral runner with no host or daemon sockets for the maximum-assurance profile. Do not claim that candidate code lacks socket access until the execution platform has verified that boundary.
- Do not restore a privileged or write-capable cache created by an untrusted ref. Do not use untrusted artifacts as release inputs.
- Keep publishing, signing, deployment, and PR-commenting in a later trusted workflow that downloads only subject-verified artifacts and never executes them.
- Keep `persist-credentials: false`, explicit job permissions, timeouts, and `cancel-in-progress: false` for admission/full attempts so an older denial is not silently erased. The external ledger must also record platform-level cancellation.

MergeGrounds binds the complete shipped `mergegrounds.yml`, `full-scan.yml`,
`codeql.yml`, and `release.yml` bytes to
`TRUSTED_ADMISSION_WORKFLOW_SHA256` in the sealed `scripts/mergegrounds.py`.
This binding protects the reviewed final-enforcer topology, CodeQL
detector/matrix producer, raw-to-validation SARIF handoff, bounded zero-finding
parser, subject manifest, release tag/version/default-branch binding,
deterministic double build, inert candidate handoff, and narrow typed
output/`continue-on-error` plumbing as one unit. Only the exact reviewed release
workflow may receive `id-token: write`, `attestations: write`, and
`artifact-metadata: write`, and only in its no-checkout attestation job; any byte
change removes that permission exception
and raises `WORKFLOW_TOPOLOGY`. A legitimate workflow edit—including an action-
SHA bump or language-matrix change—must update the corresponding digest only
after reviewing the complete workflow diff, then commit the controls, regenerate
the control-plane seal, and commit the seal separately through the R4 control
path. An unexplained `WORKFLOW_TOPOLOGY` finding must never be bypassed or
silenced by loosening the scanner.

The release workflow activates only for semantic version tags. A no-checkout,
read-only identity job first requires the exact public maintainer identity and a
GitHub-verified commit signature. The build then requires an annotated tag
peeled to the event SHA, fetches the repository-reported default branch, proves
the release commit is its ancestor, and builds with read-only permissions. It
uploads a candidate artifact but does not create a GitHub
Release. Promotion follows `docs/releasing.md` and verifies the exact source ref,
source digest, signer workflow, subject digests, and GitHub/Sigstore provenance
before the already-built bytes are uploaded. This separation does not replace
protected default-branch governance: the workflow itself lives in the source
repository and is trusted only through its exact digest plus external branch
protections.

Candidate-selectable pull-request, push, merge-queue, and manual-dispatch workflows receive no write permission or repository secrets. CodeQL runs with `upload: never`; `tools: linked` pins the CodeQL CLI 2.26.4 selection from the immutable Action revision and excludes feature-flag/default-version drift. The Action may still reuse an exact-version Actions toolcache entry, so neither `linked` nor the SARIF semantic version attests the executed CLI bytes. Each matrix producer may transfer exactly one post-processed `upload.sarif` artifact into a separate no-checkout validation job. That job enforces regular-file, type, size, JSON/SARIF shape, the linked CLI version's exact output schema/tool/format contract, a non-empty unique rule inventory combined across the driver and query-pack extensions, language category, zero findings, and subject-manifest boundaries before retaining a diagnostic artifact. An optional exported-diagnostics invocation must be the sole invocation, explicitly successful, free of process-failure markers, and contain only descriptor-linked, bounded `none`/`note` configuration or execution notifications. The one expected `codeql-action/overlay-disabled` telemetry record is accepted only with its exact driver descriptor, empty telemetry message, `none` level, visibility, timestamp, and finite pinned-reason contract; a missing success bit, unlinked/ambiguous descriptor, warning, error, exception, nonzero exit, or malformed/multiple invocation fails closed. Pull-request file-coverage collection is explicitly enabled, but neither that metadata nor the bounded parser proves complete source scope.

The portable CodeQL artifact is a diagnostic claim, not authoritative `MG-SEC-002` evidence. Candidate-controlled build or source code can forge an empty SARIF before the handoff, and hashing or reparsing that file cannot repair its provenance. The external verifier MUST independently rerun every applicable project SAST tool in a protected executor against an exact read-only/content-addressed source mount, keep report output inaccessible to candidate processes, derive the expected changed-file and language manifest from trusted Git objects, reconcile those expectations to report-native analyzed-path identities, apply the protected finding/baseline policy, and sign the resulting subject-bound evidence. It may reparse the portable artifact only as a non-authoritative cross-check. A missing language/path, unsupported required scope, finding, prohibited baseline state, or candidate-produced sole report maps to `not_evaluated` or `fail`, never pass.

The separately isolated public Scorecard uploader is schedule-only on the default branch and is the baseline's only `security-events: write` job. The third-party Scorecard CLI runs in a separate read-only job; its result crosses into the uploader only as an immutable Actions artifact. CodeQL may build compiled languages, so that job still executes hostile build logic for some stacks. High-assurance deployments should use CodeQL `build-mode: none` where supported or an isolated builder with a manually reviewed build command. The supplemental `CodeQL` context proves only that the bounded diagnostic pipeline completed with zero reported findings; it does not prove report provenance, complete source coverage, or absence of vulnerabilities. Authorized publication, if any, belongs to the trusted external contour.

## 5. What each workflow enforces

### MergeGrounds

`MergeGrounds / Policy` validates repository/control-plane policy and, on pull requests, reads exactly one newly added `.mergegrounds/changes/<uuid>.json` declaration and its referenced `docs/decisions/<uuid>.json` directly from Git objects. An implementation declaration is accepted structurally only when the design already exists unchanged in the PR base and the digest plus canonical acceptance/failure definitions match. A design-only lane may add only its declaration and one design contract. Duplicate keys, unknown fields, non-finite values, malformed identities, symlinks/submodules, risk downgrades, post-hoc design, and author/model/self-review evidence classes fail closed. PR prose and checkboxes are never admission evidence.

`MergeGrounds / PR` is the stable check/job label, not the executed profile ID. It scans the candidate merge result and introduced history for verified and unknown secrets, rejects dependency changes with vulnerabilities at **low** severity or higher, then executes the complete `full` admission profile for the shipped R3 baseline plus the conditional AI-product evidence gate. The starter therefore remains red until a project owner configures a real candidate-bound fuzz harness. AI-enabled products must account for the exact expected cases and critical slices with identity-bound observations; missing or undersized denominators, aggregate-only success, stale/mismatched evidence, and author/model/self-review producer classes deny. The deterministic and AI decision files must parse as non-empty, bounded regular data opened without following a final symlink before the job can pass. Every attempt also produces an inert allow/deny receipt bound to the subject commit/tree, policy and complete stage result set; missing, malformed, unsafe, cancelled, skipped, time-invalid, or exit-inconsistent raw evidence becomes a deny receipt. Artifacts are uploaded with SHA/run/attempt identity. Actions artifacts are neither append-only nor cryptographic attestations, so the external verifier must retain/sign them in content-addressed durable storage and detect conflicting verdicts for the same subject/policy.

The Dependency Review action relies on GitHub's dependency graph/API. Add an ecosystem-specific license allowlist after legal review; a universal allowlist would be misleading. Keep stack package updates in detected adapters rather than adding speculative package managers to `dependabot.yml`.

The TruffleHog image is pinned to a multi-platform OCI digest corresponding to version 3.97.4 at template generation time. `--no-update` prevents runtime replacement; `--results=verified,unknown`, `--fail`, and `--fail-on-scan-errors` make findings and incomplete scans blocking. The image digest is embedded in a shell command and is not updated by Dependabot. At least monthly, compare the upstream signed release/checksums and image provenance, review release notes, then replace the digest through a normal security-owned PR. A detected credential is an incident: rotate/revoke it first, then consider history rewriting.

### CodeQL

The portable starter avoids CodeQL's incomplete implicit multi-language discovery. A deterministic detector maps tracked source extensions to an explicit per-language matrix for C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Rust, and Swift. It uses `none` where supported, limits `autobuild` to languages that require it, selects a macOS runner for Swift, pins the Action-linked CLI version selection while permitting exact-version toolcache reuse, enables pull-request file-coverage output, and runs the extended security and quality query suites. A separate no-checkout job downloads the exact current-run artifact and validates its file type, size, JSON/SARIF shape, exact CodeQL 2.26.4 output schema/tool/format identity, non-empty unique rule inventory across the driver and `tool.extensions` query packs, bounded healthy optional diagnostics invocation, language category, and zero-finding policy before emitting a subject-bound digest manifest containing the claimed Action and CLI semantic identities—not a CLI byte attestation. Matrix failures do not cancel sibling analyses; an `always()` aggregate job fails unless detection, every language analysis, and every validation succeeded, and exposes the stable supplemental context named exactly `CodeQL`.

Review the detected matrix during bootstrap, extend the mapping when GitHub adds a supported language or the repository uses nonstandard source extensions, and never remove a language merely to make the gate green. Any `autobuild` path still executes candidate-controlled build logic and must remain secretless and isolated; for a high-risk stack, replace it with a reviewed build mode and dedicated ephemeral runner while preserving the aggregate `CodeQL` context.

CodeQL deliberately fails when it detects no supported language; it does not
convert “not supported” into a green check. For a PHP-only or custom stack,
configure an independently trusted stack-native SAST producer and teach the
external `MergeGrounds / Admission` verifier to require its exact evidence before
removing CodeQL from that project's input set. CodeQL cannot cover unsupported
languages or all runtime/configuration flaws. Keep stack SAST, type/lint rules,
tests, mutation tests, dependency scanning, and human threat-focused review in
the MergeGrounds profile.

### Scheduled full scan

`MergeGrounds Full Scan` runs weekly on the default branch, validates policy, runs the full profile (including configured mutation and security stages), scans all reachable Git history for secrets, and retains evidence for 90 days. Scheduled workflows can be disabled by inactivity or platform policy; monitor expected-run freshness and alert when a scheduled result is missing or late.

### OpenSSF Scorecard

The Scorecard analysis job is isolated, scheduled, egress-audited, read-only, and limited to public repositories by default. It downloads the official v5.5.0 Linux release archive and verifies the exact SHA-256 recorded in the upstream release checksum list before execution. This avoids the v2.4.4 action metadata's mutable inner container tag: a full outer `uses:` SHA alone would not make that executed image immutable. A separate GitHub-action-only job receives `security-events: write`, accepts exactly one bounded regular SARIF 2.1.0 file without following symlinks, and uploads the immutable artifact. Result publication is disabled, no OIDC permission is granted, and SARIF remains in GitHub code scanning. For a private repository with the required GitHub security plan, make an explicit privacy and permission decision before enabling it. Scorecard is posture telemetry, not a merge authorization by itself.

## 6. Immutable dependencies and updates

Every `uses:` reference in the baseline is a full commit SHA with the reviewed release tag on the same line. GitHub documents a full-length SHA as the only immutable action reference. Dependabot monitors the `github-actions` ecosystem weekly and can update the SHA and adjacent version comment. Never auto-merge those updates: review upstream ownership changes, release notes, diffs, runtime changes, transitive downloads, permissions, and network behavior, then require all MergeGrounds checks.

The Scorecard release archive is checksum-pinned and the TruffleHog runtime is OCI-digest pinned inside shell steps because their update paths are not managed by the GitHub Actions ecosystem. Review and update those values manually through a security-owned pull request after verifying upstream provenance and release notes. A pinned outer action is insufficient when its metadata downloads an inner image by mutable tag.

Do not replace a SHA with a major tag to silence update noise. Restrict allowed actions centrally and, where the organization policy supports it, allow only the exact action repositories/SHAs in use. Local actions and repository scripts are candidate-controlled. The portable PR scanner therefore rejects local `uses:` entries in admission workflows and executes policy entry points in Python isolated mode; the external verifier must still execute its own trusted-base policy rather than the candidate's copy.

The baseline intentionally does not include Renovate. Dependabot covers SHA-pinned Actions without an additional privileged bot. Add Renovate only when a detected ecosystem needs a capability Dependabot cannot provide, using a GitHub App with read-only contents and pull-request creation only, no direct push, no automerge, and an allowlisted configuration protected by CODEOWNERS.

## 7. Deployment and release separation

No baseline PR job deploys or publishes. A production release path should:

1. start only from an admitted protected-branch SHA or immutable merge-queue result;
2. rebuild in a clean trusted builder, or promote a previously built artifact whose digest and provenance are independently verified;
3. create an SBOM and signed provenance bound to source, policy, dependencies, toolchain, and artifact digests;
4. use an environment with independent reviewers, narrow OIDC subject/audience claims, short session lifetime, and no long-lived repository secret;
5. deploy by digest, verify the deployed digest, retain an audit record, and support revocation/rollback.

Never grant the release workflow a general repository write token. Separate artifact publishing, source tagging, and deployment identities where practical.

## 8. Drift and incident checks

At least weekly, reconcile through the API or an external policy engine:

- active ruleset contents, enforcement state, target, required check names/persisted integration IDs, and empty bypass list;
- current verifier App metadata resolved independently from that integration ID, including the expected slug and owner; treat an unexplained rename, transfer, deletion, or ID reuse/mismatch as drift;
- Actions default token/fork settings and action SHA policy;
- CODEOWNERS parse errors and team write access;
- enabled security features and latest successful run age;
- administrator, team, app, deploy-key, webhook, secret, environment, and runner inventory;
- direct/default-branch ref changes against an admitted PR and evidence record;
- Dependabot backlog and pinned action/container age.

Treat a ruleset deletion, bypass addition, direct protected-ref update, missing required run, newly privileged workflow, invalid owner, or unexplained check-source change as a control-plane incident. Stop admission/release, preserve audit data, revoke affected credentials/producers, assess commits merged during the gap, restore controls through an independent administrator, and rerun the negative control tests.

## 9. Primary references

- [GitHub secure use reference: immutable action SHAs, untrusted input, and Dependabot comments](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Actions repository settings and fork permissions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [GitHub rules available in rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub repository ruleset REST API](https://docs.github.com/en/rest/repos/rules)
- [GitHub REST API versioning](https://docs.github.com/en/rest/about-the-rest-api/api-versions)
- [GitHub CODEOWNERS error API](https://docs.github.com/en/rest/repos/repos#list-codeowners-errors)
- [GitHub CODEOWNERS syntax, ownership, and file-size limit](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
- [GitHub organization rulesets and required workflows](https://docs.github.com/en/organizations/managing-organization-settings/creating-rulesets-for-repositories-in-your-organization)
- [GitHub workflow execution protections](https://docs.github.com/en/organizations/managing-organization-settings/actions-policies/workflow-execution-protections)
- [GitHub CodeQL workflow configuration](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options)
- [GitHub CodeQL build modes for compiled languages](https://docs.github.com/en/code-security/reference/code-scanning/codeql/build-options-for-compiled-languages)
- [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [GitHub Dependency Review action](https://github.com/actions/dependency-review-action)
- [GitHub Dependabot updates for Actions](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/auto-update-actions)
- [TruffleHog official repository and artifact-verification guidance](https://github.com/trufflesecurity/trufflehog)
- [OpenSSF Scorecard v5.5.0 release and checksum assets](https://github.com/ossf/scorecard/releases/tag/v5.5.0)
- [OpenSSF Scorecard action and workflow restrictions](https://github.com/ossf/scorecard-action)
