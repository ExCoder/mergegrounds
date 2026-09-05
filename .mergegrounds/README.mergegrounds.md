# Imported MergeGrounds controls

The MergeGrounds files installed under `.mergegrounds/`, `.github/`, `scripts/`, and
the other bootstrap paths are an admission-control starter, not proof that this
repository or its software is safe.

Before enforcement, the repository owner must:

1. replace placeholder CODEOWNERS with real accountable owners;
2. bind every detected stack to pinned project-specific tools and reports;
3. add a meaningful fuzz harness for the full profile;
4. configure a product-specific evaluator when AI is shipped at runtime;
5. seal the reviewed control plane and prove safe negative fixtures are denied;
6. provision protected rules, an independent verifier, and isolated execution
   outside the candidate repository's writable trust boundary.

Repository-local results are diagnostic evidence. A lock stored beside the
files it protects is a tamper tripwire, not an independent root of trust.
Candidate-owned commands, tests, workflows, reports, and self-review remain
untrusted until a protected verifier validates the exact revision, complete
evidence, required independent review, and absence of a non-waivable denial.

The imported MergeGrounds material is distributed under Apache License
2.0. The starter keeps identical full terms in its repository-root `LICENSE`
and protected `.mergegrounds/LICENSE.mergegrounds`; bootstrap copies the
namespaced control file to the target. It does not replace or determine the
license of the surrounding project.
