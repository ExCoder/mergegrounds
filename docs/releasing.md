# Release verification and promotion

The tag-triggered `Release Candidate` workflow first uses a no-checkout,
read-only job to require a GitHub-verified release commit with the public
`ExCoder` noreply identity. It then validates the version, requires an annotated
tag, binds its peeled commit to the event SHA, proves that commit is an ancestor
of the fetched default branch, requires a clean checkout, runs the policy and
unit suite, and compares two deterministic builds. A final no-checkout job
validates the downloaded candidate as bounded inert files and creates GitHub
artifact attestations backed by Sigstore for the exact archive, manifest, and
checksum bytes.

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
   reports its signature as `verified: true` with reason `valid`, and confirm it
   carries the documented public maintainer identity. Ensure `VERSION`, plugin
   manifest, changelog, tag name, and release notes agree.
5. Push the protected branch first. Only then push its annotated version tag so
   the workflow can prove default-branch ancestry.

The exact bytes of `.github/workflows/release.yml` are digest-bound inside the
sealed policy runner. Only that reviewed topology receives the narrowly scoped
`id-token: write` and `attestations: write` authority. Candidate building stays
in a read-only job; the attestation job only parses and signs the retained file
bytes. This is still a repository-owned workflow, so protected-branch admission
and review are part of its trust boundary.

## Locate and download the exact successful candidate

Use a current authenticated GitHub CLI. Bind the lookup to the release tag's
peeled commit and the successful tag-push workflow run:

```bash
repository=ExCoder/mergegrounds
tag=v1.0.0
release_sha="$(gh api "repos/$repository/commits/$tag" --jq .sha)"
gh api "repos/$repository/commits/$release_sha" --jq -e '
  .commit.verification.verified == true and
  .commit.verification.reason == "valid" and
  .author.login == "ExCoder" and
  .commit.author.name == "ExCoder" and
  .commit.author.email == "3510267+ExCoder@users.noreply.github.com"'
run_id="$(gh run list -R "$repository" -w release.yml -c "$release_sha" \
  -e push -s success -L 1 --json databaseId --jq '.[0].databaseId // empty')"
run_attempt="$(gh run view "$run_id" -R "$repository" \
  --json attempt,headSha --jq \
  'if .headSha == "'"$release_sha"'" then .attempt else empty end')"
test -n "$release_sha" && test -n "$run_id" && test -n "$run_attempt"
candidate_dir="$(mktemp -d)"
gh run download "$run_id" -R "$repository" \
  -n "mergegrounds-release-${release_sha}-${run_id}-${run_attempt}" \
  -D "$candidate_dir"
```

Do not substitute a run selected only by recency, a branch name, or an artifact
copied from another run.

## Verify checksums and Sigstore/GitHub provenance

The bundle must contain exactly the two versioned archives,
`release-manifest.json`, and `SHA256SUMS`. From Bash:

```bash
version="${tag#v}"
test "$(find "$candidate_dir" -type f | wc -l | tr -d ' ')" = 4
test -f "$candidate_dir/mergegrounds-${version}.tar.gz"
test -f "$candidate_dir/mergegrounds-${version}.zip"
test -f "$candidate_dir/release-manifest.json"
test -f "$candidate_dir/SHA256SUMS"
(cd "$candidate_dir" && shasum -a 256 -c SHA256SUMS)
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

Inspect `release-manifest.json` as data and confirm its version, commit, tree,
file inventory, and digests match the intended source. Checksums detect byte
changes but are not an independent signature when delivered beside the files.
The attestation proves which GitHub workflow identity signed which subject bytes;
it does not make unreviewed source correct.

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
commit verification, protected default-branch ancestry, the exact digest-bound
Actions workflow, GitHub OIDC/Sigstore
artifact provenance constrained above, and the immutable GitHub release
attestation after promotion. A consumer whose policy requires a maintainer-key
Git tag signature must deny this release until such a signature is published;
checksums do not close that boundary.
