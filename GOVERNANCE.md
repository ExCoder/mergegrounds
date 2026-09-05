# Governance

MergeGrounds uses maintainer stewardship with evidence-gated changes. The
current accountable maintainer is [@ExCoder](https://github.com/ExCoder), as
recorded in `.github/CODEOWNERS`.
Additional maintainers are added only through a public governance change that
documents scope, sustained contribution history, conflicts of interest, and the
independent security review of their privileges.

## Decision rights

- Maintainers triage, release, and decide the roadmap.
- Code owners approve changes in their protected scope.
- Security-sensitive R4 changes require independent security and platform review;
  the author cannot fill either independent seat.
- Vulnerability handling follows `SECURITY.md` and may be temporarily private.
- No AI system, vote count, popularity signal, or author declaration can approve a
  change or satisfy an evidence gate.

Material proposals should state the user problem, threat model, alternatives,
observable acceptance criteria, negative tests, migration and rollback. If rough
consensus is absent, maintainers publish the decision and rationale. Contributors
may request reconsideration with new evidence. Forking remains the final safeguard
provided by the Apache-2.0 license.

## Releases

Releases are cut from reviewed commits on the protected default branch. The
version in `VERSION`, plugin manifest, changelog, Git tag, release notes, archive
manifest, and checksums must agree. A release is not authoritative until the
project's documented signature/provenance verification succeeds. Compromise of a
maintainer or release identity triggers key/token revocation, disclosure, and a
replacement release rather than silent artifact replacement.
