# Stack adapters

Stack adapters translate one admission policy into native, reviewable commands for each detected ecosystem. They are executable policy, not convenience snippets. A repository must tailor them to its real test topology before treating a MergeGrounds result as admission evidence.

## Adapter v1 contract

Every `.mergegrounds/adapters/*.toml` file uses this shape:

```toml
schema_version = 1
id = "unique-id"
ecosystem = "stable-ecosystem-name"
priority = 100

[detect]
all_files = ["manifest-that-must-exist"]
any_files = ["one-of-these"]
any_globs = ["**/*.language-file"]

[toolchain]
required_commands = ["runtime", "tool"]
required_files = ["lock-or-toolchain-file"]
required_any_files = ["accepted-lock-a", "accepted-lock-b"]
required_any_globs = ["**/accepted-lock-pattern"]
setup_hint = "Human-readable trusted provisioning instructions."

[commands]
format = ["command"]
lint = ["command"]
typecheck = ["command"]
unit = ["command"]
coverage = ["command one", "command two"]
mutation = ["command"]
security = ["command"]
build = ["command"]
# fuzz = ["command"] # optional because a target/harness is stack-specific

[thresholds]
line_coverage = 90
branch_coverage = 85
mutation_score = 85

[metrics.coverage]
format = "coverage-json"
paths = ["coverage/coverage-summary.json"]
required = true
branch_required = true

[metrics.mutation]
format = "stryker-json"
paths = ["reports/mutation/mutation.json"]
required = true

[artifacts]
unit = ["glob"]
coverage = ["glob"]
mutation = ["glob"]
security = ["glob"]
build = ["glob"]
```

Detection is deterministic. Every path in `all_files` must exist. The union of `any_files` and `any_globs` is one alternatives group: when that union is non-empty, at least one listed file must exist or one glob must match. An empty alternatives group imposes no additional condition. If several adapters match, run all materially distinct ecosystems; `priority` resolves only competing adapters for the same ecosystem. Never infer a pass merely because no adapter matched.

Each stage is an array of shell commands executed in order from the repository root. Stop the stage at the first non-zero exit and stop the profile when a required stage fails. Do not interpolate branch names, paths, issue text, commit messages, model output, or other untrusted strings into a command. A missing executable, empty required artifact, unparsable report, zero-test run, timeout, signal, skipped required stage, or unsupported report schema is a failure.

Metric descriptors make report parsing explicit. `format` selects a version-pinned parser, `paths` is an ordered list of fallback globs, and `required = true` makes no-match, empty-match, ambiguous duplicate, stale, malformed, or non-finite metrics fail closed. The verifier expands the first path expression that has matches, aggregates all non-overlapping reports from that expression, and ignores later fallback expressions. It rejects report-container traversal, unsafe links, duplicate report inputs, and the format-specific malformed or contradictory counters documented below. `branch_required = false` is the only supported declaration that a stack-native coverage format lacks portable branch data; it records branch coverage as not applicable and never as 100%. A risk-specific policy may still require a separate branch-capable tool.

Version 2 does **not** provide a universal production-source scope manifest across
all coverage and mutation formats. In particular, an internally consistent
aggregate-only coverage report can establish its arithmetic but cannot establish
that every production or changed file was instrumented; a mutation report can
likewise omit an unconfigured target. Before external admission, each project
must make its protected verifier bind a canonical production/changed-path
manifest to the tool configuration and report-native file/mutant identities,
reject missing or out-of-scope paths, and retain a scope digest. Until that
project-specific binding exists, local coverage/mutation results are diagnostic
threshold evidence, not proof of scope completeness. Never repair this gap by
assuming an absent path was non-production or covered.

Supported v1 coverage formats are `coverage-json`, `cobertura`, `jacoco`, `lcov`, `go-cover`, and `mergegrounds-json`. Supported mutation formats are `stryker-json`, `pit-xml`, `gremlins-json`, `mutmut-json`, `infection-json`, `cargo-mutants`, and `mergegrounds-json`. Unknown formats are configuration errors.

`toolchain.setup_hint` is deliberately not executable. Tool installation and dependency restoration belong in a reviewed runner image or trusted provisioning step. A pull request must not be allowed to replace its judge, install a different scanner, or turn a setup failure into a skipped gate.

Deterministic inputs are part of the executable contract. After an adapter matches and before any stage runs, every repository-relative regular file in `toolchain.required_files` must exist. The union of `toolchain.required_any_files` and `toolchain.required_any_globs` is one alternatives group: if non-empty, at least one listed file or glob match must exist. Empty arrays impose no requirement. Reject absolute paths, parent traversal, broken links, every symlink (even one currently resolving inside the checkout), and a local command file such as `gradlew`, `mvnw`, or `mergegrounds-custom` that is not executable. A match proves only presence; a frozen/locked restore and policy validation must still prove that the lock matches every manifest, covers development/test tools, uses immutable versions and hashes where supported, and was not rewritten during verification.

Missing deterministic input is a configuration failure, including the often-legitimate cases of a dependency-free Go module or a published Rust/PHP library that conventionally omits its lock. This max-strict starter refuses to infer safety from those conventions. The owner must either commit the required material, tailor the adapter to an equally deterministic mechanism, or obtain a narrow formal not-applicable/exception decision. A filename-only substitute, ordinary `requirements.txt`, floating Maven/plugin range, or silent unlocked restore is not equivalent.

## Stage artifact contract

Declared artifacts are bounded evidence, not proof merely because a pathname exists. MergeGrounds accepts only non-empty regular files inside the checkout and rejects an artifact larger than 100 MiB before hashing or parsing it. The runner must remove prior outputs before a stage, and each declared glob must identify only outputs created for the candidate being evaluated.

For a `unit` stage that declares artifacts, the artifact set must contain at least one supported, successfully parsed test-result report with a positive executed-test count. The v1 semantic formats are UTF-8 JUnit XML and Visual Studio TRX. JUnit input must have a `testsuite` or `testsuites` root, complete non-negative integer `tests`, `failures`, and `errors` counters, zero failures/errors, internally possible skip/disabled counts, and at least one executed test; when testcase detail is present, it must agree with the summary. TRX input must use the official 2010 TeamTest namespace, have exactly one completed summary/counter set, report at least one executed and passed result, report no adverse outcome, and agree with its uniquely identified `UnitTestResult` details. DTD and entity declarations are rejected throughout the bounded XML payload.

Files with an unsupported extension, and well-formed `.xml` files with an unknown root, remain hash/size integrity evidence with `semantic_validation = "unavailable"`. They are supplemental only: an opaque JSON log, console transcript, HTML page, or custom XML document cannot satisfy the positive unit-execution proof. A malformed XML file or a `.trx` file with an unsupported root/namespace fails rather than becoming opaque. Projects using another native test-result format must add a reviewed semantic parser or configure the test runner to emit JUnit/TRX; renaming an opaque file is not a conversion. The stock Go and Rust adapters intentionally declare no typed unit artifact because their standard test commands do not natively emit either format. They still reject zero tests: Go streams `go test -json` through a strict event counter and requires at least one passed test with no failure event, while Rust first executes the suite and then requires `libtest --list --format terse` to discover at least one `: test` entry. Bash `pipefail` binds producer failures to both checks. Their retained unit evidence remains limited to the fail-closed command result and captured log until the repository adds a version-pinned converter and a matching JUnit/TRX declaration.

## Maintainability contract

Faster code generation is not faster delivery when it increases review, debugging, or later refactoring. Bind each adapter's `lint` and `typecheck` stages to the repository's maintainability policy, using locked ecosystem-native tools. At minimum, executable changed code must not:

- introduce a function above the approved cognitive/cyclomatic complexity ceiling;
- add an unapproved duplicated block or increase the changed-code duplication ratio;
- add unreachable, unused, shadowed, or dead behavior that the stack can detect;
- add a blanket linter/type suppression, generated-code label, exclusion, or ignore merely to avoid analysis;
- violate reviewed module/dependency direction, layering, or public-API boundaries;
- increase an enumerated legacy maintainability baseline.

Greenfield repositories define finite complexity/size ceilings and zero unapproved duplication/suppression debt before admission. Existing repositories may use immutable, fingerprinted, owner-and-deadline baselines; touched code follows the current rule and total debt cannot increase. A threshold or exclusion cannot be raised in the same change that needs the relaxation.

There is no honest universal parser for every stack's complexity and clone-report formats in the bundled adapter schema v1. A project must make the locked native command fail on a policy breach or add a reviewed typed parser/external gate. A zero exit from a tool whose relevant rules are disabled is not maintainability evidence. Console prose, an AI code-quality opinion, and a self-reported percentage are supplemental only. Record complexity and duplication deltas through trusted analytics as described in [`../../../docs/governance-and-metrics.md`](../../../docs/governance-and-metrics.md), and do not claim that the bundled runner independently validated those values unless a supported parser actually did so.

## Profiles

Profiles select stages; they do not weaken adapter thresholds.

- `fast` gives fast workstation feedback and is never admission evidence.
- `pr` requires formatting, lint, type checking, unit tests, coverage, mutation, dependency/security checks, and a build.
- `full` requires a candidate-bound fuzz harness in addition to every PR gate. It is intentionally red until an R3/R4 project owner defines a real target, corpus, sanitizer/oracle, resource budget, and report artifact. A genuinely inapplicable fuzz requirement needs a formal, reviewed exception/not-applicable decision; absence is never a silent skip.

The `stages` list is what the runner attempts. `required_stages` is the minimum that must produce a valid pass. An optional stage that exists and fails still fails the run; “optional” means an adapter may omit it, not that a failure is ignored. The generic starter adapters omit fuzz because inventing a harness would create false assurance; this deliberate omission forces full-profile tailoring. R3/R4 candidates must complete the tailored `full` profile before admission. The global `pr` profile does not require fuzz for every repository, but a risk classifier may add a separate candidate-bound targeted fuzz job as a required check whenever a PR touches a critical parser, protocol, input boundary, unsafe-memory path, or other designated target.

An external `.mergegrounds/profiles/<id>.toml` file is an override only in format, never in authority: its ordered `stages` and `required_stages` arrays must exactly equal the matching inline `[profiles.<id>]` policy or MergeGrounds fails closed. Unknown external profile IDs are rejected. Change both representations together only through the protected R4 control path.

## Metric parser semantics

All ratios use `100 * covered / total`, preserve full precision for comparison, and display rounded values only after the decision. A zero denominator is not evaluated and therefore fails when the metric is required. Counts must be finite non-negative integers, declared percentages must be finite numbers in `[0, 100]`, and any declared percentage must agree with recomputation within 0.01 percentage point.

- `coverage-json`: for coverage.py JSON use `totals.covered_lines / totals.num_statements` and `totals.covered_branches / totals.num_branches`; for Istanbul summary JSON use `total.lines.covered / total.lines.total` and `total.branches.covered / total.branches.total`. Do not use coverage.py's combined `percent_covered` as line coverage.
- `cobertura`: use root `lines-covered / lines-valid` and `branches-covered / branches-valid`. Recompute from class/line details when root totals are absent; inconsistent duplicate source entries fail.
- `jacoco`: sum root `counter[type="LINE"]` and `counter[type="BRANCH"]` as `covered / (covered + missed)`. When aggregating modules, sum counters; never average module percentages.
- `lcov`: in every source record require exactly one non-negative integer `LF` and `LH`, with `LH <= LF`; when branch coverage is required, apply the same checks to exactly one `BRF` and `BRH`, with `BRH <= BRF`. Reject duplicate counter fields before summing records, so an invalid file cannot be hidden by an offsetting file. Deduplicate records by normalized source path and reject conflicting duplicates.
- `go-cover`: require the exact header `mode: set`, `mode: count`, or `mode: atomic` and at least one native block record. Source names must be canonical slash-separated relative/import paths ending in `.go`: absolute paths, drive prefixes, backslashes, whitespace/control characters, empty components, and `.`/`..` components fail. Every coordinate is positive and its end is strictly after its start; `set` counters are only `0` or `1`. Reject duplicate coordinate identities (even when counts differ), and reject overlapping ranges for the same source after sorting, so repeated blocks cannot inflate or offset the aggregate. Go profiles measure covered statements, not literal source lines: sum each block's statement count when execution count is positive and divide by all statement counts. This stack-native statement result occupies the `line_coverage` policy slot but evidence must label it `statement`; branch coverage remains not applicable. These constraints deliberately narrow the native profile grammar for admission evidence; generate a fresh profile with `go test -coverprofile`, rather than merging or hand-editing profiles. See the [official Go coverage-profile parser](https://go.dev/src/cmd/vendor/golang.org/x/tools/cover/profile.go).
- `mergegrounds-json`: require exactly one JSON object with finite numeric `line_coverage`, `branch_coverage`, and `mutation_score` values in `[0, 100]`. Missing or extra metric keys, strings, booleans, nulls, NaN, and Infinity fail.

For mutation formats, normalize native statuses before computing `100 * killed / (killed + survived + not_covered + timeout + invalid)`. `invalid` includes crash, runtime error, memory error, interrupted, pending, suspicious, and unknown statuses. Compile-error/unviable mutants are excluded from this ratio so tool incompatibility cannot dilute the denominator, but the max-strict default separately sets `fail_on_unviable = true`: any non-zero count fails unless a narrow reviewed exception defines an explicit tolerance and evidence binding. Ignored/skipped mutants are excluded only when the report can bind each exclusion to reviewed policy. Any unknown status, timeout, invalid outcome, unapproved unviable outcome, arithmetic inconsistency, or zero denominator fails even if the numeric threshold would otherwise pass.

- `stryker-json`: normalize `Killed` as killed; `Survived` as survived; `NoCoverage` as not-covered; `Timeout`, `RuntimeError`, `Pending`, and unknown statuses as invalid/adverse; `CompileError` as unviable; `Ignored` only under reviewed exclusion policy.
- `pit-xml`: normalize detected `KILLED` entries as killed; `SURVIVED` as survived; `NO_COVERAGE` as not-covered; `TIMED_OUT`, `RUN_ERROR`, `MEMORY_ERROR`, and unknown statuses as invalid/adverse; `NON_VIABLE` as unviable. The `detected` attribute and `status` must agree.
- `gremlins-json`: enumerate `files[].mutations[]` and normalize its `status` values; that list is the source of truth. Current Gremlins summary fields omit timed-out and skipped counts, and `mutants_total` also excludes not-covered mutants, so none of those summary fields is a safe denominator. Recompute overall MergeGrounds score as `100 * killed / (killed + lived + not_covered + timed_out + invalid)`, Gremlins efficacy as `100 * killed / (killed + lived)`, and mutant coverage as `100 * (killed + lived) / (killed + lived + not_covered)`. Cross-check the report's available summary counts and percentages against recomputation. Both native thresholds and the MergeGrounds score must pass; `TIMED OUT`, `RUNNABLE`, duplicate mutant coordinates, and unknown statuses fail, `SKIPPED` requires a reviewed exclusion, and `NOT VIABLE` is excluded from the score but fails the strict zero-unviable gate.
- `mutmut-json`: read `mutants/mutmut-cicd-stats.json`; current mutmut exports counts, not a score. Compute `tested = total - skipped` and `score = 100 * killed / tested`. Require `total > 0`; require `survived`, `no_tests`, `suspicious`, `timeout`, `check_was_interrupted_by_user`, and `segfault` all to be zero; reject negative counts and require `total` to equal the sum of every exported category. The internal total also includes `not_checked` and `caught_by_type_check`, but the compact export omits both fields, so either status appears only as an unexplained remainder and must fail; enabling mutmut's type-check filter therefore requires a richer reviewed adapter/parser.
- `infection-json`: require `stats.totalMutantsCount > 0` and set `tested = totalMutantsCount - skippedCount - ignoredCount`. Under this strict adapter, require `escapedCount`, `notCoveredCount`, `errorCount`, `syntaxErrorCount`, and `timeOutCount` to be zero; skipped/ignored counts require reviewed exclusions. Recompute `msi = 100 * killedCount / tested`, `mutationCodeCoverage = 100 * (tested - notCoveredCount) / tested`, and `coveredCodeMsi = 100 * killedCount / (tested - notCoveredCount)`, then cross-check all three declared values and the configured threshold. The compact summary's `killedCount` omits static-analysis kills while native MSI includes them, so enabling Infection static analysis makes this report non-recomputable and requires a richer reviewed report/parser. The command's `--with-timeouts` (timeouts count as escapes) and `--max-timeouts=0` are part of the evidence contract.
- `cargo-mutants`: read `outcomes.json`; enumerate mutant scenarios whose exact current `summary` strings are `CaughtMutant`, `MissedMutant`, `Unviable`, `Timeout`, `Success`, or `Failure`, while separately requiring the non-mutant `Baseline` scenario to be `Success`. Cross-check the enumerated outcomes with top-level `total_mutants`, `caught`, `missed`, `timeout`, `unviable`, and `success`, require a non-null `end_time`, and compute `100 * caught / (caught + missed + timeout)`. `Unviable` is excluded from the ratio but fails the strict zero-unviable gate; mutant `Success`/`Failure` or any unknown shape is ambiguous and fails. Exit 0 plus no missed/timeout/unviable is required by MergeGrounds; exit 4 means the unmutated baseline failed and cannot yield a score.

## Protect the policy itself

Adapter TOML, profiles, MergeGrounds code, workflows, lockfiles for control tools, and mutation configuration are security-sensitive executable policy. Protect `.mergegrounds/**`, `mergegrounds-custom`, CI definitions, and relevant tool configuration with CODEOWNERS/rulesets and independent security review. Evaluate changes to these paths using the last trusted policy from the protected base, never only the candidate version.

Run untrusted PR jobs without repository-write tokens, publishing/signing credentials, cloud credentials, production secrets, or privileged/self-hosted runner access. Package audits in these adapters use public metadata and need no secret. Projects with private dependencies need a separately designed read-only mirror or trusted dependency materialization step; do not expose registry credentials to candidate-controlled scripts. Captured stdout/stderr is evidence, but secrets must never be placed there.

Pin runtime and control-tool versions in ecosystem lockfiles or immutable runner images. Prefer committed wrappers (`mvnw`, `gradlew`) after reviewing their wrapper JARs and distribution checksums. Network should be disabled while candidate build/test commands execute whenever cached, verified inputs make that possible.

## Included adapters and required project wiring

### Node.js and TypeScript

The adapter detects every Node project from `package.json` and requires `package-lock.json`, canonical package scripts, and StrykerJS. A plain JavaScript project must still implement `npm run typecheck` with a real static contract such as TypeScript `checkJs`, checked JSDoc, or an equivalent analyzer; absence fails closed. Because the commands use npm, a pnpm/Yarn/Bun lock is not accepted without changing the commands and required inputs together. `npm ci` is the trusted provisioning command: npm documents that it requires a lock, fails when it disagrees with `package.json`, and does not rewrite either file. Mutation uses `npx --offline --no-install` so a missing local Stryker cannot trigger a network/cache install; npm currently preserves `--no-install` as the explicit no-install compatibility option. Configure the coverage runner's `json-summary` reporter so it writes `coverage/coverage-summary.json`; Istanbul's `coverage-final.json` has a different per-file shape and is not a substitute for this descriptor. Configure Stryker's JSON reporter and set `thresholds.break` to at least the adapter's `mutation_score`; otherwise Stryker can report a weak score without failing. Stryker's initializer is useful once, but its output must be reviewed and committed. Official references: [npm clean install](https://docs.npmjs.com/cli/v11/commands/npm-ci/), [npx local/remote execution and no-install behavior](https://docs.npmjs.com/cli/v11/commands/npx/), [StrykerJS getting started](https://stryker-mutator.io/docs/stryker-js/getting-started/), [configuration and thresholds](https://stryker-mutator.io/docs/stryker-js/configuration/), and [reporter plugins](https://stryker-mutator.io/docs/stryker-js/plugins/).

The canonical package scripts are intentional: test runners vary across Jest, Vitest, Mocha, Node test, and browser projects. Each script must fail on warnings or threshold misses and must not silently pass when no tests match.

### Python

The adapter uses Ruff, strict mypy, pytest, coverage.py, pip-audit, and mutmut. It requires at least one reviewed project lock: `uv.lock`, standardized `pylock.toml`, `poetry.lock`, `Pipfile.lock`, or a `requirements*.lock` convention. A requirements lock is acceptable only when every direct/transitive artifact is exactly pinned with hashes and the trusted provisioner uses a hash-enforcing frozen/sync mode; renaming an unconstrained `requirements.txt` does not qualify. Declare `source_paths` and pytest selection under `[tool.mutmut]`; do not rely on discovery in a monorepo. Current mutmut requires fork support and therefore Linux/macOS or WSL, not native Windows. `mutmut run` does not itself enforce a numeric score. Current `mutmut export-cicd-stats` writes `mutants/mutmut-cicd-stats.json` with counters (`killed`, `survived`, `total`, `no_tests`, `skipped`, `suspicious`, `timeout`, `check_was_interrupted_by_user`, `segfault`) but no ready-made score. MergeGrounds recomputes it and fails on every adverse/ambiguous status. A missing output is significant because the command can print “No previous mutation data” and still return normally. Official references: [uv lockfile](https://docs.astral.sh/uv/concepts/projects/layout/#the-lockfile), [Poetry lock behavior](https://python-poetry.org/docs/basic-usage/#installing-with-poetrylock), [Pipenv lockfile](https://pipenv.pypa.io/en/latest/pipfile.html), [PEP 751 `pylock.toml`](https://peps.python.org/pep-0751/), [mutmut installation/configuration/workflow](https://mutmut.readthedocs.io/en/latest/), [mutmut source](https://github.com/boxed/mutmut), and [pip-audit](https://github.com/pypa/pip-audit).

### Go

The adapter combines race-enabled, shuffled tests with atomic coverage, `go vet`, golangci-lint, govulncheck, and Gremlins. It requires committed `go.sum`; run package-loading commands with `GOFLAGS=-mod=readonly` (or equivalent explicit flags) so candidate verification cannot repair `go.mod`/`go.sum`. Gremlins `--integration` runs the whole suite for each mutant so cross-package effects are visible. It enforces both test efficacy (`KILLED / (KILLED + LIVED)`) and mutant coverage (covered mutants / all viable mutants) and emits `gremlins.json`. The native Go coverage profile is statement-oriented and has no portable branch metric, so `metrics.coverage.branch_required = false` records an explicit limitation; mutation coverage compensates but does not become branch coverage. MergeGrounds's stricter duplicate/overlap rules mean concatenated or merged native profiles are not accepted as evidence; generate one repository-scoped profile in the declared stage. Official references: [Go checksum files](https://go.dev/ref/mod#go-sum-files), [Go coverage-profile parser](https://go.dev/src/cmd/vendor/golang.org/x/tools/cover/profile.go), [Gremlins unleash flags, JSON and thresholds](https://gremlins.dev/latest/usage/commands/unleash/), [Gremlins configuration](https://gremlins.dev/latest/usage/configuration/), and [govulncheck](https://go.dev/doc/tutorial/govulncheck).

The race detector requires a supported target and may need CGO. If the production target cannot run it, keep a race-capable test job and add target-specific build/test jobs; do not simply remove `-race` from the only gate.

### Rust

The adapter treats committed `Cargo.lock` and `rust-toolchain.toml`, `cargo fmt`, warning-free Clippy, all-target/all-feature checks, cargo-llvm-cov, cargo-audit, and cargo-mutants as required. The toolchain file must name an exact release rather than floating `stable`, `beta`, or `nightly`. `--locked` is used on dependency-resolving native Cargo commands, and cargo-mutants receives it through `--cargo-arg`; mutation runs therefore use the same immutable dependency material in their copied worktree. cargo-mutants returns success only when every tested viable mutant is caught; its effective mutation threshold is therefore 100, stricter than a fractional parser gate. It writes detailed machine-readable outcomes under `mutants.out`. cargo-llvm-cov's branch support is explicitly unstable and LCOV output is line-only in its documented stable workflow, so `metrics.coverage.branch_required = false` records the limitation. Official references: [Cargo.lock guidance](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html), [cargo-mutants Cargo arguments](https://mutants.rs/cargo-args.html), [getting started](https://mutants.rs/getting-started.html), [exit codes](https://mutants.rs/exit-codes.html), [output directory](https://mutants.rs/mutants-out.html), [timeouts](https://mutants.rs/timeouts.html), [parallelism](https://mutants.rs/parallelism.html), and [cargo-llvm-cov branch caveat](https://github.com/taiki-e/cargo-llvm-cov).

Equivalent or intentionally untestable mutants may be suppressed only at the narrowest code/config scope, with a reason and security-owned review. A blanket exclusion is a policy change.

### JVM with Maven

The Maven adapter executes only the committed `mvnw`, requires `.mvn/wrapper/maven-wrapper.properties`, and requires the root `pom.xml` to pin every plugin and dependency source directly or through a trusted immutable parent/BOM. The wrapper properties must pin a release distribution and `distributionSha256Sum` (plus `wrapperSha256Sum` when a wrapper JAR is used). Maven has no universal native dependency lock comparable to the other adapters; repositories needing stronger transitive reproducibility must bind a reviewed repository snapshot/SBOM and verify resolved artifacts, not claim that wrapper pinning locks dependencies. The adapter assumes pinned Spotless, Checkstyle, JaCoCo, OWASP Dependency-Check, PIT, and the correct PIT test plugin (for example JUnit 5). Direct PIT properties enforce an 85 mutation and 90 coverage threshold while XML/HTML reports remain evidence. Official references: [Maven Wrapper and checksum verification](https://maven.apache.org/tools/wrapper/), [PIT Maven quick start and parameters](https://pitest.org/quickstart/maven/), and [OWASP Dependency-Check Maven configuration](https://jeremylong.github.io/DependencyCheck/dependency-check-maven/).

### JVM with Gradle

The Gradle adapter requires the checked-in `gradlew`, wrapper properties, and at least one root/module dependency lock. Wrapper distribution checksum verification and `LockMode.STRICT` for every resolvable configuration are mandatory; a single lockfile satisfying discovery is not proof that a multi-project build locked every configuration. Configure `info.solidsoft.pitest` with `mutationThreshold`, `coverageThreshold`, `outputFormats = ["XML", "HTML"]`, `timestampedReports = false`, and `failWhenNoMutations = true`. Multi-project builds should aggregate reports and must not let a testless module vanish from the denominator. Official references: [Gradle Wrapper](https://docs.gradle.org/current/userguide/gradle_wrapper.html), [dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html), [Gradle PIT plugin](https://github.com/szpak/gradle-pitest-plugin), [published plugin coordinates](https://plugins.gradle.org/plugin/info.solidsoft.pitest), and [PIT concepts](https://pitest.org/quickstart/basic_concepts/).

For both JVM adapters, configure JaCoCo rule verification for line and branch thresholds; report generation alone is not enforcement. PIN every build plugin rather than resolving `LATEST`.

### .NET

The adapter uses `dotnet format` for whitespace, style, and analyzer diagnostics down through `info`, warning-as-error release builds, test TRX, Coverlet, NuGet audit, and a project-local Stryker.NET tool. `--break-at 85` makes the mutation run fail below the threshold; JSON and HTML reporters preserve evidence. Ambiguous solutions must name solution, source project, and test projects in `stryker-config.json`. Official references: [dotnet format](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-format), [Stryker.NET installation and local tool manifest](https://stryker-mutator.io/docs/stryker-net/getting-started/), [configuration and break threshold](https://stryker-mutator.io/docs/stryker-net/configuration/), [reporters](https://stryker-mutator.io/docs/stryker-net/reporters/), and [pipeline threshold guidance](https://stryker-mutator.io/docs/stryker-net/stryker-in-pipeline/).

The adapter requires `global.json`, `.config/dotnet-tools.json`, and at least one `packages.lock.json`; `global.json` must select an exact SDK with roll-forward disabled, and `dotnet restore --locked-mode` makes dependency mismatch a failure. Every restored project in a multi-project solution must have lock coverage—the alternatives-group match is only a discovery minimum—and the local tool manifest must pin Stryker.NET. Coverlet MSBuild properties require `coverlet.msbuild` in test projects. The command uses separately ordered `90,85` line/branch thresholds and preserves the literal quoting Coverlet documents for comma-valued MSBuild properties. Coverlet documents that this integration depends on the VSTest execution model and does not run under Microsoft Testing Platform v2; a .NET 10 project using MTP v2 must explicitly select VSTest mode or replace both the command and metric descriptor through one reviewed policy change. If a solution has several test projects, aggregate coverage before applying repository-wide thresholds; do not average percentages. Official references: [NuGet lock files](https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies), [global.json SDK selection](https://learn.microsoft.com/en-us/dotnet/core/tools/global-json), [local tool manifests](https://learn.microsoft.com/en-us/dotnet/core/tools/global-tools#install-a-local-tool), and [Coverlet MSBuild integration](https://github.com/coverlet-coverage/coverlet/blob/master/Documentation/MSBuildIntegration.md).

### PHP

The adapter requires committed `composer.lock` and uses Composer validation/audit, PHP-CS-Fixer, PHP_CodeSniffer, PHPStan, PHPUnit, and Infection. Trusted provisioning must run `composer install`, never `update`; Composer documents that install consumes exact locked versions and warns when the manifest and lock disagree. Infection receives both MSI and covered-MSI limits, treats timeouts as escaped, permits zero timeouts, uses a conservative fixed worker count, and writes summary JSON plus HTML. The coverage stage requires Xdebug and `--path-coverage`, because PCOV and phpdbg cannot provide the required branch/path evidence. Official references: [Composer lock/install behavior](https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies), [PHPUnit coverage and driver capabilities](https://docs.phpunit.de/en/12.5/code-coverage.html), [PHPUnit coverage options](https://docs.phpunit.de/en/12.5/cli-options.html), [Infection installation](https://infection.github.io/guide/installation.html), [CI thresholds](https://infection.github.io/guide/using-with-ci.html), [strict timeout and summary JSON options](https://infection.github.io/guide/command-line-options.html), [report configuration](https://infection.github.io/guide/usage.html), and [Composer audit exit semantics](https://getcomposer.org/doc/03-cli.md#audit).

PHP branch coverage depends on the coverage driver and PHPUnit configuration. If the emitted Cobertura report lacks branches, the branch gate is `not_evaluated` and fails; it is never coerced to 100%.

## Generic custom adapter

For an unsupported stack, add an executable `mergegrounds-custom` dispatcher and the `.mergegrounds/custom.enabled` marker. Implement the eight required subcommands and atomically maintain `.mergegrounds/reports/metrics.json` in this exact canonical form:

```json
{
  "line_coverage": 93.25,
  "branch_coverage": 88.5,
  "mutation_score": 91.0
}
```

The values are percentages, not fractions. The runner removes the untrusted shared file before each metric stage, so both `coverage` and `mutation` must atomically recreate the complete object from current-run measurements; neither may rely on a report left by the preceding stage. Because this compact format exposes no outcome counts, the default strict `fail_on_survived` and `fail_on_unviable` policies accept its mutation result only when the custom dispatcher independently proves zero survivors/unviable/adverse outcomes and reports a score of 100%; a fractional result needs a reviewed native descriptor/parser that exposes every outcome count. Additional diagnostic artifacts belong below `.mergegrounds/reports/<stage>/`. Each subcommand must be deterministic, non-interactive, safe to run on hostile source, and return non-zero for warnings promoted by policy, zero tests, missing targets, threshold misses, or incomplete analysis.

Do not make the dispatcher download tools, obtain secrets, edit the working tree, publish artifacts, or deploy. Provision tools first. Protect both the dispatcher and marker as control-plane files. If a native adapter is later added, give it a higher priority and remove the custom marker in a separately reviewed policy change.

## Tailoring checklist

Before enabling any MergeGrounds profile as a required check—and especially `full` for shipped R3 admission:

1. Pin every runtime, package manager, wrapper, plugin, linter, scanner, and mutation tool.
2. Prove each detection rule against positive and negative fixtures.
3. Make every stage fail on no tests, no sources, warnings, malformed reports, and threshold misses.
4. Verify artifact globs match exactly one current run and cannot pick up stale files.
5. Run a clean baseline twice to find flakes and tune mutation timeouts conservatively.
6. Inject a safe test defect and prove coverage and mutation gates reject it; then remove it.
7. Seed a safe complexity, duplicate-block, dead-code, and suppression violation; prove the stack-native maintainability policy rejects each applicable case.
8. Trace material test expectations to an acceptance oracle outside the implementation; do not let generated tests merely restate generated code.
9. Protect adapter/config changes with CODEOWNERS and evaluate them with trusted-base policy.
10. Run PR code with no secrets or write privileges and retain evidence bound to the exact commit.
