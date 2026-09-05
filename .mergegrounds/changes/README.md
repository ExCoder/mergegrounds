# Structured change declarations

Every pull request adds exactly one `.mergegrounds/changes/<change-id>.json`, where
`change-id` is a lowercase UUID. Declarations are append-only inputs to review;
they are not proof that a claim is true. PR prose and checked boxes never satisfy
an admission control.

The declaration records a risk classification, the immutable design record it
implements, observable acceptance criteria, failure modes, an independent
challenge plan, and AI provenance. Do not store prompts, chain-of-thought,
credentials, customer data, or proprietary context here.

## Lanes

- `design-only` may add only its declaration and one
  `docs/decisions/<design-id>.json`. It cannot include implementation changes.
- `implementation` must reference a design record that already exists unchanged
  in the pull request base revision. Its declared digest and every reused
  acceptance/failure definition must match that reviewed record exactly.

There is deliberately no PR-level bootstrap bypass. During first adoption, place
the baseline and initial design records through an explicitly governed migration
before enabling branch protection. Once enforcement is active, all implementation
work uses the two-step design-only then implementation flow.

Generated scaffolds are shape-valid drafts, not merge-ready declarations. Every
`EDIT ME`, `TODO`, `TBD`, or MergeGrounds template sentinel must be replaced with a
concrete, reviewable statement; admission rejects placeholders even when the
surrounding field satisfies the minimum length.

Use `python3 -I scripts/mergegrounds.py verify-change --event "$GITHUB_EVENT_PATH"` to
validate the contract. The command reads contracts from immutable Git blobs, not
from the mutable worktree.

The repository-local result remains candidate-produced evidence. Maximum
assurance additionally requires an independently administered verifier bound to
the exact head, policy digest, reviewer identities, and retained CI evidence.
