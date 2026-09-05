# Mutation testing policy

Mutation testing asks whether tests detect small, systematic defects in production code. It is stronger evidence than reachability coverage, but it is not proof of correctness or security. MergeGrounds uses it as one independent admission signal alongside strict static checks, conventional tests, security analysis, review, and artifact verification.

## Required gate model

A valid mutation gate has four phases, all bound to the same candidate revision, base revision, tool version, configuration digest, and test inputs:

1. **Baseline:** the unmodified project builds and its selected tests pass in a clean, isolated workspace.
2. **Discovery:** the tool finds production mutation sites inside the declared scope. Zero generated or zero executed viable mutants is `not_evaluated`, unless a trusted, reviewed rule proves the diff contains no mutable production code.
3. **Execution:** each viable mutant is tested with bounded resources. Survived, not-covered, suspicious, interrupted, crashed, and infrastructure-error outcomes are not kills. Timeouts are failures by default because an overloaded runner must not inflate the score.
4. **Evaluation:** parse the native machine-readable report, validate it against the expected schema, recompute the score, enforce the threshold and scope, then retain the report and logs as commit-bound evidence.

Never decide from console color, a badge, process success alone, or a report left by an earlier run. Delete or isolate the output directory before execution and require report creation time/content to belong to the current run.

## Metrics

Use explicit formulas because tools use different names and denominators.

```text
mutation_score = 100 * killed / (killed + survived + not_covered + timeout + invalid_outcome)
covered_mutation_score = 100 * killed / (killed + survived + timeout + invalid_outcome)
mutation_coverage = 100 * (killed + survived + timeout + invalid_outcome) / all_viable_mutants
```

`invalid_outcome` includes suspicious, crashed, interrupted, and otherwise inconclusive executed mutants. Unviable/compile-error mutants are excluded from the score so tool incompatibility cannot improve or dilute the ratio, but they are not a pass: max-strict policy sets `fail_on_unviable = true` and requires their count to be zero. A narrow non-zero tolerance requires a formal reviewed exception bound to exact tools/scope and expiry. Ignored/skipped mutants are excluded only when each exclusion is narrow, reviewed, reasoned, and present in the evidence.

When a native tool deliberately defines a stricter denominator or exit policy, retain the stricter result. Examples: cargo-mutants fails if any tested viable mutant is missed; Gremlins separately gates efficacy and mutant coverage; Infection can treat timeouts as escaped. Do not translate a native 100%-kill requirement into an 85% pass.

## Threshold policy

Default greenfield minimums are:

- overall mutation score: **85%**;
- covered mutation score: **90%** when the tool exposes it;
- mutation coverage: **90%** when the tool exposes it;
- changed production lines: no surviving or not-covered mutant in critical code;
- timeouts, invalid outcomes, and unviable/compile-error mutants: **0**;
- unexplained zero-mutant run: fail.

The baseline mutation floor is 85%, including Python: MergeGrounds computes mutmut policy semantics from the exported CI counters instead of trusting a precomputed score. Rust remains at 100% because cargo-mutants' native exit contract is all-or-nothing. Adapter thresholds are floors: risk policy may raise them and may require all mutants killed in authentication, authorization, cryptography, money movement, tenancy boundaries, input validation, serialization, migrations, safety controls, and policy code.

For a legacy repository, record a trusted full-tree baseline and ratchet it: changed code must meet the target immediately, the full-tree score may never decrease, and the baseline has a fixed remediation expiry. Do not call a baseline an exception and do not subtract newly uncovered code from the denominator.

## PR and full-tree cadence

The iterative `pr` profile runs the configured mutation stage, and the shipped
R3 protected workflow repeats that stage inside `full`; only the complete
`full` result is admission-eligible for this baseline. On a large established
repository, a reviewed diff-aware mode may be used only when all of these hold:

- the merge base is fetched and verified;
- the tool's diff filter includes added and modified production lines plus directly affected units;
- shared utilities, public contracts, build logic, schemas, migrations, and control-plane changes trigger broader/full mutation;
- the last trusted full-tree run is fresh and passed;
- a scheduled full-tree run can revoke release eligibility when it finds a regression.

A diff-only score is not interchangeable with a full-tree score. Evidence must label scope as `changed`, `module`, or `full`. Changes only to tests still require mutation against the production scope those tests claim to improve.

## Flakes, isolation, and timeouts

Mutation testing multiplies existing nondeterminism. Before enforcement, run the clean suite repeatedly with randomized order and eliminate data, clock, network, locale, timezone, port, and concurrency dependencies. A mutation worker must not share a mutable database, filesystem namespace, cache key, external account, or port with another worker.

Start with conservative parallelism. cargo-mutants recommends two or three jobs; Gremlins offers explicit worker/test-CPU controls. Derive timeouts from a stable baseline with a safety margin, cap total wall time, and investigate changes in timeout rate. Retrying a mutant may diagnose a flake, but “passes on retry” does not convert ambiguous evidence into a kill.

PR mutation jobs execute candidate code and are therefore hostile workloads. Give them no secrets, repository-write token, signing identity, privileged container, host socket, production network, or shared writable cache. Enforce CPU, memory, process, disk, log-size, and wall-time limits. Mutation reports are data; sanitize them before rendering in privileged systems.

## Equivalent mutants and exclusions

Some syntactic mutations are behaviorally equivalent in the reachable domain. Treat equivalence as a review problem, not an automatic exemption.

An exclusion must identify the exact file/symbol/mutator, explain why behavior cannot differ, name an owner, link a review record, and have an expiry or permanent rationale. Prefer a source-level annotation beside the code when the tool supports it. Broad directory, namespace, generated-pattern, or mutator-class exclusions are control-plane changes and need security ownership.

Never exclude code merely because mutation is slow, a mutant is difficult to kill, or the score would fall. Generated code may be excluded only when its generator and generated-output verification are independently gated.

## Tool-specific enforcement

### StrykerJS

Run `npx stryker run` with JSON reporting. Set all three configured thresholds and make `thresholds.break` at least the MergeGrounds floor; Stryker's default `break` is null and does not fail a weak score. Its command test runner cannot perform the same coverage analysis as native runner plugins, so prefer the matching maintained test-runner plugin. Sources: [usage](https://stryker-mutator.io/docs/stryker-js/usage/), [thresholds and JSON reporter configuration](https://stryker-mutator.io/docs/stryker-js/configuration/), and [plugins](https://stryker-mutator.io/docs/stryker-js/plugins/).

### mutmut

Run `mutmut run`, then `mutmut export-cicd-stats`; require `mutants/mutmut-cicd-stats.json`. The export command writes that path but contains counters rather than a score. Compute `tested = total - skipped` and `mutation_score = 100 * killed / tested`. Require a positive denominator and zero `survived`, `no_tests`, `suspicious`, `timeout`, `check_was_interrupted_by_user`, and `segfault`; require `total` to equal the sum of exported categories. The internal total includes `not_checked` and `caught_by_type_check`, but the export omits both, so either becomes an unexplained remainder and fails. Current mutmut is incremental and invalidates result-affecting configuration, but dependency/data changes still need explicit cache-invalidation policy. It requires fork support. MergeGrounds must not count timeout as killed merely because badge-oriented tooling does. Sources: [official mutmut documentation](https://mutmut.readthedocs.io/en/latest/) and [official source](https://github.com/boxed/mutmut).

### Gremlins

Use `gremlins unleash --integration` where cross-package behavior matters, emit JSON with `--output`, and set both `--threshold-efficacy` and `--threshold-mcover`. Parse `files[].mutations[].status` rather than trusting `mutants_total`: current Gremlins JSON omits timeout/skipped summary counts and its total excludes not-covered mutants. Efficacy alone ignores not-covered mutants; mutant coverage alone says nothing about assertion strength. Excluded files do not participate in threshold calculation and therefore require policy review. Sources: [unleash command](https://gremlins.dev/latest/usage/commands/unleash/), [configuration](https://gremlins.dev/latest/usage/configuration/), and the [upstream report schema](https://github.com/go-gremlins/gremlins/blob/main/internal/report/internal/structure.go).

### cargo-mutants

Run `cargo mutants` with a conservative job count and retain `mutants.out/outcomes.json` plus outcome lists. Require the completed baseline scenario to be `Success`, enumerate the exact `CaughtMutant`, `MissedMutant`, `Unviable`, and `Timeout` summaries, and cross-check them against top-level counts; a mutant-level `Success` or `Failure` is ambiguous and fails. Cargo-mutants' exit 0 means every tested viable mutant was caught, but MergeGrounds additionally requires zero `Unviable` outcomes under its strict default. Exit 2 means missed mutants; exit 3 means timeouts; exit 4 means the baseline failed. The output schema can change between versions, so pin the tool and validate its version before parsing. Sources: [exit codes](https://mutants.rs/exit-codes.html), [output directory](https://mutants.rs/mutants-out.html), [using results](https://mutants.rs/using-results.html), and the [upstream outcome schema](https://github.com/sourcefrog/cargo-mutants/blob/main/src/outcome.rs).

### PIT for Maven and Gradle

Configure XML and HTML output, a numeric `mutationThreshold`, `coverageThreshold`, and `failWhenNoMutations=true`. Pin PIT and the correct test-framework plugin. Maven can run `test-compile org.pitest:pitest-maven:mutationCoverage`; Gradle uses the `pitest` task from `info.solidsoft.pitest`. Multi-module projects need explicit aggregation/cross-module design so code is not silently omitted. Sources: [PIT Maven quick start/parameters](https://pitest.org/quickstart/maven/) and [Gradle PIT plugin](https://github.com/szpak/gradle-pitest-plugin).

### Stryker.NET

Use a project-local `dotnet-stryker` tool manifest, JSON reporting, and `--break-at` equal to the policy floor. Run from an unambiguous solution/test-project context; .NET Framework needs a solution path. Do not use dashboard upload from an untrusted PR job because it introduces credentials and external state. Sources: [getting started](https://stryker-mutator.io/docs/stryker-net/getting-started/), [configuration](https://stryker-mutator.io/docs/stryker-net/configuration/), and [reporters](https://stryker-mutator.io/docs/stryker-net/reporters/).

### Infection

Use both `--min-msi` and `--min-covered-msi`, `--with-timeouts`, `--max-timeouts=0`, and `--logger-summary-json`. Recompute and cross-check MSI, mutation coverage, and covered-code MSI from the summary counts; reject the compact summary if static-analysis kills make `killedCount` insufficient to reproduce native MSI. Keep the initial clean-test run enabled. Do not use `--ignore-msi-with-no-mutations` in a full gate. Infection requires a coverage driver and should be pinned with its compatible PHP/test-framework versions. Sources: [CI thresholds](https://infection.github.io/guide/using-with-ci.html), [command options](https://infection.github.io/guide/command-line-options.html), [usage/report formats](https://infection.github.io/guide/usage.html), and the [upstream summary schema](https://github.com/infection/infection/blob/master/src/Reporter/SummaryJsonReporter.php).

## Evidence requirements

Retain at least:

- candidate and base commit/tree identifiers;
- adapter/profile identifiers and digests;
- runtime, test runner, mutation tool, and plugin versions;
- exact argv, working directory, environment allowlist, start/end time, and exit status;
- selected source/test scope and exclusions with reasons;
- baseline test result and duration;
- counts for generated, executed, killed, survived, not-covered, timeout, unviable, skipped, and invalid mutants;
- recomputed metrics and thresholds;
- native machine-readable report digest and bounded diagnostic logs;
- runner identity/isolation class and evidence signature.

The evidence verifier fails closed on unknown statuses, arithmetic inconsistencies, non-finite or out-of-range metrics, zero denominators, duplicate mutant identities, absent source files, stale timestamps, unexpected tool versions, or a report whose subject/configuration cannot be bound to the candidate. `survived > 0`, `timeout > 0`, or `unviable > 0` is always a failing finding in strict mode even when the aggregate score remains above its floor.

## Control tests

Before making mutation a required check, prove the gate itself:

1. Run a clean full baseline twice and confirm stable counts.
2. Introduce a safe temporary production defect that existing tests should detect; confirm a killed mutant or equivalent negative fixture.
3. Temporarily weaken/remove an assertion; confirm a survivor and a failing MergeGrounds decision.
4. Feed an empty, stale, malformed, and unknown-status report to the verifier; each must fail.
5. Force a timeout and missing-tool condition; both must fail without exposing credentials.
6. Restore the repository, rerun, and retain the negative-test evidence separately from admission evidence.

Mutation testing is ready for admission only after these control tests pass and the configuration is protected as executable policy.
