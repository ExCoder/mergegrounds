# Support

## Before asking

Use a supported Python version, start from the latest supported release, and run:

```bash
python3 -I scripts/mergegrounds.py doctor
python3 -I scripts/mergegrounds.py verify-repo --strict
```

Read the expected-red section in `README.md`: an unbound skeleton is supposed to
fail rather than claim protection it does not yet have.

## Where to ask

- Use [GitHub Discussions](https://github.com/ExCoder/mergegrounds/discussions) for setup questions, design proposals, and usage ideas.
- Use the [bug form](https://github.com/ExCoder/mergegrounds/issues/new?template=bug-report.yml) for a reproducible defect with sanitized diagnostics.
- Use the [integration form](https://github.com/ExCoder/mergegrounds/issues/new?template=integration-request.yml) for a new stack, report format, or CI provider.
- Use the [feature form](https://github.com/ExCoder/mergegrounds/issues/new?template=feature-request.yml) for a falsifiable product capability.
- Follow `SECURITY.md` for suspected vulnerabilities; never post them publicly.

Maintainers aim to triage complete public requests within five business days, but
the project is community-supported and offers no guaranteed response time or
production support SLA. A reproducible minimal repository or redacted failing
fixture is much more useful than screenshots or model-generated explanations.

Do not include credentials, customer code, private prompts, proprietary data, or
full CI environment dumps in public support material.
