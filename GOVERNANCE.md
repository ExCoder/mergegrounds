# Governance

MergeGrounds uses maintainer stewardship with evidence-gated changes. The
current accountable maintainer is [@ExCoder](https://github.com/ExCoder), as
recorded in `.github/CODEOWNERS`.

## Bootstrap state and independence boundary

Before and including the founding `v1.0.0` publication, the project is in a
single-maintainer bootstrap state. The initial release establishes the public
baseline and makes its implementation available for inspection; it does **not**
claim that two independent human security/platform reviewers approved the code
that created that baseline. This disclosure is a one-time description of how
the governance system was founded, not a reusable exception and not evidence of
maximum-assurance production independence.

At present, no additional eligible human security or platform reviewer seat is
recorded. Contributions, review evidence, and candidate changes can be prepared
publicly, but after the founding release no R4 control-plane change or new
release is authoritative until all of the following are true:

- two humans other than the change author approve the final diff;
- one fills the security-review role and one fills the platform/operations role,
  and they are independent of both the author and each other;
- their public governance records document identity, relevant qualifications,
  scope, conflicts of interest, and recusal conditions;
- GitHub protections enforce the required approvals and the protected admission
  checks on the exact revision.

If those seats are unavailable, merge and release remain blocked. AI agents,
the maintainer acting as a second persona, popularity, and repeated review do not
fill either seat. A downstream production deployment must establish its own
independent administration and reviewers; it may never cite the `v1.0.0`
bootstrap state as a waiver.

Additional maintainers or reviewers are seated only through a public governance
change that documents sustained contribution history where applicable,
qualification, access scope, conflicts, and independent approval of the new
privileges.

## Decision rights

- Maintainers triage, release, and propose roadmap decisions within the gates
  above.
- Code owners approve changes in their protected scope.
- Security-sensitive R4 changes require the two independent human roles defined
  above; the author cannot fill either seat.
- Vulnerability handling follows `SECURITY.md` and may be temporarily private.
- No AI system, vote count, popularity signal, or author declaration can approve
  a change or satisfy an evidence gate.

Material proposals should state the user problem, threat model, alternatives,
observable acceptance criteria, negative tests, migration, and rollback. If
rough consensus is absent, maintainers publish the decision and rationale.
Contributors may request reconsideration with new evidence. Forking remains the
final safeguard provided by the Apache-2.0 license.

## Releases

Releases are cut from reviewed commits on the protected default branch. The
version in `VERSION`, plugin manifest, changelog, Git tag, release notes, archive
manifest, and checksums must agree. The tag-triggered workflow must require a
GitHub-verified public maintainer identity, validate the clean tagged revision,
prove default-branch ancestry, reproduce the archives, and issue GitHub/Sigstore
provenance for the exact candidate. A maintainer then
follows `docs/releasing.md` to verify and promote those retained bytes without
rebuilding them.

A release is not authoritative until the documented artifact provenance and
immutable GitHub Release verification succeed. The current `v1.0.0` tag is an
unsigned annotated tag; consumers requiring a maintainer-key Git tag signature
must fail closed. Compromise of a maintainer, reviewer, workflow, or release
identity triggers credential revocation, disclosure, and a replacement release
rather than silent tag or artifact replacement.
