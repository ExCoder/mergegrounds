# Roadmap

The roadmap is ordered by trust value, not by generated feature count. Dates are
intentions, not promises; each item still needs a reviewed design and evidence.

## Now: public baseline

- Keep the upstream repository green under its own policy while bootstrapped
  targets remain deliberately red until bound to real owners, stacks, and fuzzing.
- Publish reproducible archives, checksums, release notes, and a documented
  install/update/uninstall path.
- Add runnable red/green example repositories for Python and TypeScript.
- At public launch, enable and verify repository rules, private vulnerability
  reporting, Discussions, immutable releases, and community profile settings;
  repository files alone do not prove these external controls are active.

## Next: independent admission

- Publish a reference verifier with an independently administered GitHub App.
- Bind trusted checks to exact commit/tree identities and authenticated producer
  identities.
- Add isolated replay-resistant evidence storage and negative-control fixtures.
- Ship tested Go, Rust, JVM, .NET, and PHP example repositories.

## Later: ecosystem and assurance

- Add documented interfaces for non-GitHub forges without weakening the trust
  boundary.
- Publish opt-in, privacy-preserving aggregate evidence about blocked failure
  classes and activation quality.
- Pursue OpenSSF Best Practices and improve Scorecard posture.
- Add signed distribution channels only when their update and revocation models
  preserve the same fail-closed guarantees.

Requests belong in the feature or integration issue forms. A roadmap item is not
an admission promise and must not be used as evidence that a control exists.
