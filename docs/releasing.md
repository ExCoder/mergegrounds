# Release verification and promotion

The tag-triggered `Release Candidate` workflow first uses a no-checkout,
read-only job to require a GitHub-verified, GitHub-authored merge attributed to
the public `ExCoder` account. It then validates the version, requires an annotated
tag, binds its peeled commit to the event SHA and the exact current default-
branch HEAD, requires a clean checkout, runs the policy and unit suite, and
compares two deterministic builds made from immutable Git objects. Both builds
must be byte-identical before either archive parser runs, then both pass
`scripts/validate_release.py` before retention. A separate no-OIDC validation
job rechecks the reviewed tool hashes, annotated tag, commit, tree, portable
inventory, raw expected bundle bytes, and bounded archive structure. It uploads
those exact prevalidated bytes under a new artifact identity. The OIDC-enabled
attestation job never checks out or executes candidate repository code; it only
checks the fixed inert bundle shape and creates GitHub artifact attestations
backed by Sigstore.

The workflow deliberately **does not publish a GitHub Release** and has no
`contents: write` permission. Promotion is a separate maintainer action after
verification.

## One-time repository prerequisites

Before pushing a release tag:

1. Make the repository public. GitHub artifact attestations are available to
   public repositories on current plans; private/internal use requires an
   eligible GitHub Enterprise Cloud plan.
2. Protect the default branch, require the admission controls, prohibit bypass,
   and verify the rules on GitHub. Repository files cannot prove those settings.
3. Enable GitHub immutable releases. This setting is external state and must be
   checked again before promotion.
4. Put the final release commit on the protected default branch, confirm GitHub
   reports its signature as `verified: true` with reason `valid`, and confirm the
   REST identity links the author to `ExCoder` and the committer to GitHub's
   `web-flow` account. Raw Git author names and emails are mutable profile fields
   and are not used as authentication claims. Ensure `VERSION`, plugin
   manifest, changelog, tag name, and release notes agree.
5. Push the protected branch first. Only then push its annotated version tag.
   The tag target must still be the exact current default-branch HEAD when the
   workflow fetches it; a merely ancestral or stale release commit is denied.

The exact bytes of `.github/workflows/release.yml` are digest-bound inside the
sealed policy runner. It also pins the reviewed SHA-256 digests of
`scripts/build_release.py` and `scripts/validate_release.py` before either tool
executes. Candidate building and parsing stay in jobs without OIDC authority.
Only the final no-checkout, no-Python job receives narrowly scoped
`id-token: write` and `attestations: write`, and it downloads only the artifact
re-uploaded by the independent validation job. This is still a repository-owned
workflow: a maintainer reviewing a control-plane change must review the workflow,
the two pinned digests, and their source together, while protected-branch
admission and the control-plane seal remain part of the root of trust.

## Locate and download the exact successful candidate

Use a current authenticated GitHub CLI. Bind the lookup to the release tag's
peeled commit and the successful tag-push workflow run:

```bash
repository=ExCoder/mergegrounds
tag=v1.0.0
release_sha="$(gh api "repos/$repository/commits/$tag" --jq .sha)"
release_tree="$(gh api "repos/$repository/commits/$release_sha" --jq .commit.tree.sha)"
gh api "repos/$repository/commits/$release_sha" --jq -e '
  .commit.verification.verified == true and
  .commit.verification.reason == "valid" and
  .author.login == "ExCoder" and
  .committer.login == "web-flow"'
run_id="$(gh run list -R "$repository" -w release.yml -c "$release_sha" \
  -e push -s success -L 1 --json databaseId --jq '.[0].databaseId // empty')"
run_attempt="$(gh run view "$run_id" -R "$repository" \
  --json attempt,headSha --jq \
  'if .headSha == "'"$release_sha"'" then .attempt else empty end')"
test -n "$release_sha" && test -n "$release_tree" && test -n "$run_id" && test -n "$run_attempt"
candidate_dir="$(mktemp -d)"
gh run download "$run_id" -R "$repository" \
  -n "mergegrounds-validated-${release_sha}-${run_id}-${run_attempt}" \
  -D "$candidate_dir"
```

Do not substitute a run selected only by recency, a branch name, or an artifact
copied from another run.

## Verify checksums and Sigstore/GitHub provenance

The bundle must contain exactly the two versioned archives,
`release-manifest.json`, and `SHA256SUMS`. Every candidate file is limited to
32 MiB. The builder also limits every source blob and the aggregate source
snapshot to 32 MiB so a candidate cannot cross the validator's boundary after
packaging. The source repository must use Git's SHA-1 object format: the builder
recomputes `SHA1("blob " + decimal_length + NUL + bytes)` for every blob and
rejects any mismatch. It also rejects tracked `release-manifest.json`, non-NFC
paths, case-fold collisions, Windows device names, and trailing-dot/space path
aliases. The archive validators cap member count, individual members, and total
expanded bytes and reject duplicate member names.

Validate from a fresh checkout of the exact annotated tag. The validator first
requires that `refs/tags/<version>` peels to the exact supplied commit, rebuilds
the expected four files from immutable Git objects, and compares raw SHA-256
digests and bytes before invoking parsers on candidate content. It then checks
exact manifest keys and types; binds version, commit, tree, inventory, modes,
byte counts, and digests to Git blobs; requires canonical `SHA256SUMS`; and
verifies the exact member inventory, bytes, metadata, and embedded manifest in
both archives:

```bash
version="${tag#v}"
source_dir="$(mktemp -d)"
git clone --quiet --depth 1 --branch "$tag" \
  "https://github.com/${repository}.git" "$source_dir"
test "$(git -C "$source_dir" rev-parse HEAD^{commit})" = "$release_sha"
test "$(git -C "$source_dir" rev-parse HEAD^{tree})" = "$release_tree"
(
  cd "$source_dir"
  python3 -I scripts/validate_release.py --bundle-dir "$candidate_dir" \
    --expected-commit "$release_sha" --expected-tree "$release_tree" \
    --expected-ref "refs/tags/$tag"
)
```

Verify every retained file against the expected repository, signer workflow,
source tag, and source commit. The default predicate check is SLSA provenance:

```bash
for artifact in \
  "$candidate_dir/mergegrounds-${version}.tar.gz" \
  "$candidate_dir/mergegrounds-${version}.zip" \
  "$candidate_dir/release-manifest.json" \
  "$candidate_dir/SHA256SUMS"
do
  gh attestation verify "$artifact" --repo "$repository" \
    --signer-workflow ExCoder/mergegrounds/.github/workflows/release.yml \
    --signer-digest "$release_sha" \
    --source-ref "refs/tags/$tag" \
    --source-digest "$release_sha" \
    --deny-self-hosted-runners
done
```

The local validator establishes structural and Git-object consistency; it is
not an independent signature because its code comes from the same repository.
Checksums likewise detect byte changes but are not independent when delivered
beside the files. The attestation proves which GitHub workflow identity signed
which subject bytes; it does not make unreviewed source correct.

## Promote without rebuilding

Upload the already verified candidate bytes; do not rebuild on the maintainer's
machine:

```bash
gh release create "$tag" \
  "$candidate_dir/mergegrounds-${version}.tar.gz" \
  "$candidate_dir/mergegrounds-${version}.zip" \
  "$candidate_dir/release-manifest.json" \
  "$candidate_dir/SHA256SUMS" \
  -R "$repository" --verify-tag --notes-from-tag \
  --title "MergeGrounds ${version}"
gh release verify "$tag" -R "$repository"
```

`--verify-tag` checks that the remote tag exists; it is not cryptographic tag
signature verification. GitHub immutable releases prevent later tag or asset
replacement after publication and provide the release-level attestation checked
by `gh release verify`.

## Current tag-signature boundary

The local `v1.0.0` object is an **unsigned annotated Git tag** even though its
target release commit is required to be GitHub-verified. Consequently,
`git verify-tag v1.0.0` does not succeed and documentation must not call the tag
GPG/SSH-signed. For this release, authentication comes from protected default-
commit verification, equality with the exact current default-branch HEAD, the exact digest-bound
Actions workflow, GitHub OIDC/Sigstore
artifact provenance constrained above, and the immutable GitHub release
attestation after promotion. A consumer whose policy requires a maintainer-key
Git tag signature must deny this release until such a signature is published;
checksums do not close that boundary.
