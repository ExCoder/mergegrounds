# MergeGrounds 1.0.0 release evidence

Status: release candidate. This record is supporting context, not release
authentication. Treat 1.0.0 as published only after the public immutable GitHub
Release, exact artifacts, attestations, and final server-side settings pass the
verification procedure in [releasing.md](releasing.md).

## Candidate scope

- Product and plugin version: `1.0.0`.
- Public maintainer account: [`@ExCoder`](https://github.com/ExCoder).
- Intended assurance claim: Portable starter and reference implementation.
- Explicitly excluded claim: no assertion that arbitrary code is safe or that
  Maximum Assurance is deployed by installing this repository alone.
- Control-plane lock: schema-v2 content and mode entries bind 69 critical files
  to reviewed source commit `908e627c8dd0b4dd2f1205f83744bc2123bfa43b`;
  reseal commit `806fc6a32ad7994e3c9570a988f681681997afa1` changes only the lock.

The final release commit may contain documentation-only changes after that
reseal. The release workflow must still prove a clean exact checkout, control
integrity, version agreement, deterministic archives, and equality with the
exact current default-branch HEAD on the final tagged commit. It must run
`scripts/validate_release.py` against the commit-, tree-, and ref-bound bundle
before retention and again in a separate job without OIDC authority. Only those
re-uploaded prevalidated bytes may reach the no-checkout/no-candidate-code
attestation job.

## Reproduced candidate checks

The following results were reproduced on the clean release candidate on
2026-09-05 before public promotion:

| Evidence | Result | Boundary |
|---|---|---|
| Standard-library unit suite | 327 tests passed | Test success is not proof of absence of defects |
| Source coverage | 90.37% line; 85.17% branch | Aggregate coverage does not prove required semantic scope |
| Curated critical mutations | 6/6 killed | Curated source mutations do not replace a project mutation engine |
| Parser and hostile-input probes | 7 known-bad classes plus 2,000 randomized cases denied or handled as specified | Fuzzing is bounded by the implemented harness and seed space |
| Strict lint and types | Ruff and strict mypy passed | Static tools cover their configured rules and analyzed paths only |
| Workflow policy | actionlint and repository workflow hardening checks passed | Repository checks cannot prove external GitHub settings |
| Full self-dogfood profile | 18/18 stages passed | The upstream source-only adapter is not copied as an activated downstream adapter |
| Deterministic source build | repeated archives matched | Reproducibility applies to the declared source package inputs |
| CodeQL | GitHub run `33984687386` passed, including zero-finding SARIF validation | The workflow uses `upload: never`, so GitHub Code Scanning UI/API is intentionally not populated; portable CodeQL remains diagnostic until an external verifier reruns applicable SAST against the trusted subject and proves scope |
| MergeGrounds GitHub workflow | GitHub run `33984687316` passed | Final tagged commit requires a fresh successful run |

The local evidence file was generated as
`.mergegrounds/evidence/core-release-v1.0.0.json` with SHA-256
`8c6c1eb9f542b8382d23f0164868e489c6b05376d45d02b20946802ba0eba2e0`.
It is intentionally ignored because evidence tied to a local execution context
must not be mistaken for independently retained release evidence.

## Promotion gates

Promotion is denied until every item below is rechecked against external state:

1. The repository is public and the final default-branch commit is
   GitHub-verified with reason `valid`; GitHub's REST identity links the author
   to `ExCoder` and the committer to `web-flow`.
2. The final commit has successful MergeGrounds and CodeQL required checks.
3. The active ruleset applies to administrators with no bypass, requires pull
   requests, linear history, signed commits, and the stable admission checks,
   and rejects force-push and deletion.
4. Private vulnerability reporting, dependency and secret alerts, immutable
   releases, topics, description, and community surfaces are verified from
   GitHub state. The custom CodeQL check and its locally validated SARIF are
   verified through the required workflow; no GitHub Code Scanning UI/API
   analysis is claimed while SARIF upload remains disabled.
5. The unsigned annotated `v1.0.0` tag peels to the exact verified current
   default-branch HEAD. A stale ancestor is denied. The tag is not represented
   as GPG- or SSH-signed.
6. The tag-triggered workflow succeeds and retains exactly two archives,
   `release-manifest.json`, and `SHA256SUMS`; each candidate file is at most
   32 MiB and the source snapshot stays within the builder's matching bound.
   The SHA-1 blob identities are independently recomputed; portable-path
   collisions, the reserved generated manifest path, duplicate archive members,
   and member/decompressed resource-bound violations are denied.
7. All four retained files pass checksums and GitHub/Sigstore attestation
   verification constrained to the expected repository, workflow, tag ref,
   source digest, signer digest, and GitHub-hosted runner. Raw equality with the
   independently regenerated expected bundle is established before candidate
   parsers run, and the OIDC job executes no repository candidate code.
8. The retained bytes are promoted without rebuilding, the GitHub Release is
   immutable, and `gh release verify v1.0.0` succeeds.
9. Anonymous users can reach the repository, release, documentation, demo,
   security process, issues, and Discussions; primary links return the expected
   content rather than an authenticated/private view.

## Consumer verification

Use the complete commands in [releasing.md](releasing.md). Do not select a run
only by recency, trust a checksum delivered beside its artifact as an
independent signature, or infer protected settings from repository files.

If any identity, digest, provenance, ancestry, setting, or artifact check is
missing or inconclusive, do not install or promote the candidate as 1.0.0.
