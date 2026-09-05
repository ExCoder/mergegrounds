## Structured change contract

- Change declaration: `.mergegrounds/changes/<change-id>.json`
- Design record: `docs/decisions/<design-id>.json`
- Lane: `design-only` or `implementation`

MergeGrounds reads the declaration and design from Git objects and validates them
against the exact PR base and head. The structured files, not this prose, are the
source of review inputs.

## Reviewer notes

Call out material questions, blocking findings, and the evidence that resolved
them. CI and the independent verifier attach result links; an author-provided link
or summary does not turn a claim into evidence.

## AI provenance and data handling

AI tools, models, purposes, and affected paths belong in the declaration. Do not
paste prompts, hidden reasoning/chain-of-thought, secrets, customer data, or
proprietary context into the PR.

Checked boxes, model confidence, author assertions, and model self-review are
never admission evidence. Missing, stale, malformed, skipped, inconclusive, or
subject-mismatched evidence remains a denial.

Maximum assurance requires an external root of trust. The repository-local
workflow cannot independently prove reviewer identity or protect itself from a
same-change control-plane modification.
