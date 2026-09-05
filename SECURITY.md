# Security policy

## Supported versions

Security fixes are made on the repository's current default branch and the latest supported release line. Older releases are unsupported unless their release notes explicitly state otherwise. Consumers should track signed releases or immutable commit/artifact digests and update promptly.

## Report privately

Do not open a public issue, pull request, discussion, or CI log for a suspected vulnerability. Use **Security → Advisories → Report a vulnerability** in this repository. If private vulnerability reporting is unavailable, use the organization's pre-established private security channel and provide only enough non-sensitive detail to establish contact.

Include, when safe:

- affected version, commit, or artifact digest;
- impact and realistic attack prerequisites;
- minimal reproduction steps or a proof of concept with secrets and personal data removed;
- suggested mitigations and whether exploitation is known;
- a secure way to continue the conversation.

Never include live credentials, customer data, production payloads, proprietary prompts, or exploit details in public artifacts. If a credential may have been exposed, revoke or rotate it immediately; deleting it from a later commit is not remediation.

## Response targets

The security team aims to acknowledge a complete report within two business days, provide an initial severity assessment within five business days, and send an update at least every seven days while remediation is active. Targets may change for incomplete, duplicate, or coordinated multi-party disclosures. Disclosure timing is agreed with the reporter after affected users have a practical mitigation.

## Security acceptance policy

- Candidate code, including AI-generated code, is untrusted until independent deterministic checks and human review pass.
- Model reasoning, confidence, self-review, author checkboxes, and repeated model answers are never treated as proof of correctness.
- Shipped model, retrieval, fine-tuning, provider, or agent-tool behavior requires the conditional AI-product assurance controls in addition to ordinary source gates.
- Critical or high-confidence exploitable findings block merge and release.
- A scanner error, timeout, missing evidence, partial result, or unsupported path is not a pass.
- Changes to `.github`, `.mergegrounds`, MergeGrounds scripts, ownership, exceptions, release/signing logic, or this policy require code-owner review and fresh control-plane validation.
- Ordinary exceptions must be narrow, owned, justified, time-limited, and independently approved. They never authorize committing a live secret or giving untrusted code production/signing credentials.

## Safe harbor

Good-faith research that respects privacy, avoids persistence and data destruction, uses the minimum access needed, and reports promptly through the private channel will be handled constructively. Do not degrade availability, access data belonging to others, use social engineering, or retain data beyond what is needed to report the issue.
