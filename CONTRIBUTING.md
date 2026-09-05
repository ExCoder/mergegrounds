# Contributing

MergeGrounds is itself control-plane code. Every change is R4: it can affect which future code is admitted.

## Required process

1. Land and approve the design record before substantive implementation. Bind the implementation change to that exact base-resident design digest.
2. Open a focused change with a structured `.mergegrounds/changes/<uuid>.json` declaration, observable acceptance criteria, failure modes, and an explicit threat/control rationale.
3. Do not mix policy relaxation with unrelated implementation work.
4. Add or update a negative fixture that would have caught the old failure. Generated tests are evidence only when their expected results trace to an independent acceptance oracle.
5. Run the standard-library test suite:

   ```bash
   python3 -I -m unittest discover -s tests -v
   ```

6. Validate the skill and plugin with the bundled Codex validators.
7. Run shell/YAML/workflow validation and audit every external action/container reference.
8. Obtain an adversarial challenge from a reviewer who did not author or operate the change, then complete human explain-back on the final diff. AI review is advisory and never fills a required human seat.
9. Obtain independent security and platform approval of the final diff.
10. Update `.mergegrounds/control-plane.lock.json` only after the final control files are reviewed.

Never make a gate advisory, lower a threshold, broaden an exclusion, convert an error into success, or add an exception solely to merge a change. Missing tools, unsupported formats, timeouts, zero tests/mutants, malformed reports, and stale artifacts remain non-pass states.

Author declarations, model reasoning, confidence, self-review, and repeated answers are claims—not admission evidence. Do not commit private chain-of-thought, raw prompts, customer data, credentials, or unnecessary retrieved context.

External dependencies must be justified, immutable or lock-resolved, and covered by provenance/vulnerability/license review. The core runner intentionally uses only the Python standard library.

For suspected vulnerabilities, do not open a public issue; follow [SECURITY.md](SECURITY.md).
