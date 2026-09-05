from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apply-github-ruleset.sh"


def required_check_resolver() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    invocation = (
        'python3 -I - "$checks_file" "$verifier_app_id" '
        '"$verifier_app_slug" "$verifier_app_owner"'
    )
    start = text.index("\nimport json\n", text.index(invocation)) + 1
    end = text.index("\nPY\n\npayload_file=", start)
    return text[start:end]


def existing_ruleset_resolver() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    invocation = 'existing_id=$(python3 -I - "$rulesets_file" "$RULESET_NAME"'
    start = text.index("\nimport json\n", text.index(invocation)) + 1
    end = text.index('\nPY\n) || die "could not determine existing managed ruleset"', start)
    return text[start:end]


def check_run(name: str, app: dict[str, object]) -> dict[str, object]:
    return {
        "name": name,
        "status": "completed",
        "conclusion": "success",
        "completed_at": "2026-09-05T00:00:00Z",
        "app": app,
    }


def run_required_check_resolver(
    runs: list[dict[str, object]],
    *,
    app_id: int = 42,
    slug: str = "mergegrounds-independent-verifier",
    owner: str = "security-control-plane",
    page_runs: list[list[dict[str, object]]] | None = None,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as directory:
        checks = Path(directory) / "checks.json"
        payload: object
        if page_runs is None:
            payload = {"check_runs": runs}
        else:
            payload = [{"check_runs": page} for page in page_runs]
        checks.write_text(json.dumps(payload), encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", "-", str(checks), str(app_id), slug, owner],
            input=required_check_resolver(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )


class RulesetRootOfTrustTests(unittest.TestCase):
    def test_authoritative_checks_are_bound_to_explicit_external_app(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("--verifier-app-id", text)
        self.assertIn("--verifier-app-slug", text)
        self.assertIn("--verifier-app-owner", text)
        self.assertIn('"MergeGrounds / Admission"', text)
        self.assertIn('"MergeGrounds / Independent Challenge"', text)
        self.assertIn('app.get("id") == verifier_app_id', text)
        self.assertIn('app.get("slug") == verifier_app_slug', text)
        self.assertIn('app_owner(app).casefold() == verifier_app_owner.casefold()', text)
        self.assertIn(
            'resolved.append({"context": context, "integration_id": verifier_app_id})',
            text,
        )

    def test_candidate_github_actions_are_not_authoritative(self) -> None:
        actions = {"id": 15368, "slug": "github-actions", "owner": {"login": "github"}}
        runs = [
            check_run("MergeGrounds / Admission", actions),
            check_run("MergeGrounds / Independent Challenge", actions),
            check_run("CodeQL", actions),
        ]
        result = run_required_check_resolver(
            runs,
            app_id=15368,
            slug="github-actions",
            owner="github",
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("belongs to GitHub Actions/code scanning", result.stderr)

        cli = subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--repo",
                "example/project",
                "--verifier-app-id",
                "15368",
                "--verifier-app-slug",
                "github-actions",
                "--verifier-app-owner",
                "github",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(0, cli.returncode)
        self.assertIn("independently administered", cli.stderr)

        github_owned = {
            "id": 909090,
            "slug": "some-other-official-app",
            "owner": {"login": "GitHub"},
        }
        github_owned_result = run_required_check_resolver(
            [
                check_run("MergeGrounds / Admission", github_owned),
                check_run("MergeGrounds / Independent Challenge", github_owned),
            ],
            app_id=909090,
            slug="some-other-official-app",
            owner="GitHub",
        )
        self.assertNotEqual(0, github_owned_result.returncode)
        self.assertIn("not observed from verifier app", github_owned_result.stderr)

        github_owned_cli = subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--repo",
                "example/project",
                "--verifier-app-id",
                "909090",
                "--verifier-app-slug",
                "some-other-official-app",
                "--verifier-app-owner",
                "GitHub",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(0, github_owned_cli.returncode)
        self.assertIn("independently administered", github_owned_cli.stderr)

    def test_external_app_identity_is_exact_and_codeql_is_not_universally_required(self) -> None:
        external = {
            "id": 42,
            "slug": "mergegrounds-independent-verifier",
            "owner": {"login": "security-control-plane"},
        }
        actions = {"id": 15368, "slug": "github-actions", "owner": {"login": "github"}}
        runs = [
            check_run("MergeGrounds / Admission", external),
            check_run("MergeGrounds / Independent Challenge", external),
            check_run("CodeQL", actions),
        ]
        result = run_required_check_resolver(runs)
        self.assertEqual(0, result.returncode, result.stderr)
        resolved = json.loads(result.stdout)
        self.assertEqual(
            [
                {"context": "MergeGrounds / Admission", "integration_id": 42},
                {"context": "MergeGrounds / Independent Challenge", "integration_id": 42},
            ],
            resolved,
        )

        mismatched_owner = run_required_check_resolver(runs, owner="attacker")
        self.assertNotEqual(0, mismatched_owner.returncode)
        self.assertIn("not observed from verifier app", mismatched_owner.stderr)

    def test_paginated_checks_and_managed_rulesets_are_resolved_across_all_pages(self) -> None:
        external = {
            "id": 42,
            "slug": "mergegrounds-independent-verifier",
            "owner": {"login": "security-control-plane"},
        }
        page_two = [
            check_run("MergeGrounds / Admission", external),
            check_run("MergeGrounds / Independent Challenge", external),
        ]
        check_result = run_required_check_resolver([], page_runs=[[], page_two])
        self.assertEqual(0, check_result.returncode, check_result.stderr)
        self.assertEqual(2, len(json.loads(check_result.stdout)))

        with tempfile.TemporaryDirectory() as directory:
            rulesets = Path(directory) / "rulesets.json"
            rulesets.write_text(
                json.dumps(
                    [
                        [],
                        [
                            {
                                "id": 9876,
                                "name": "MergeGrounds: default branch",
                                "source_type": "Repository",
                            }
                        ],
                    ]
                ),
                encoding="utf-8",
            )
            ruleset_result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-",
                    str(rulesets),
                    "MergeGrounds: default branch",
                ],
                input=existing_ruleset_resolver(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertEqual(0, ruleset_result.returncode, ruleset_result.stderr)
        self.assertEqual("9876", ruleset_result.stdout.strip())

        script = SCRIPT.read_text(encoding="utf-8")
        self.assertEqual(2, script.count("api --paginate --slurp --method GET"))

    def test_ruleset_has_no_bypass_actors(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"bypass_actors": []', text)
        self.assertIn('"strict_required_status_checks_policy": True', text)

    def test_ruleset_validates_the_complete_canonical_codeowners_suffix(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        for pattern in (
            "/.codex-plugin/",
            "/.agents/",
            "/.github/",
            "/.mergegrounds/",
            "/.gitattributes",
            "/mergegrounds-custom",
            "/scripts/",
            "/skills/mergegrounds/",
            "/SECURITY.md",
        ):
            self.assertIn(f'    "{pattern}",', text)

    def test_every_inline_python_parser_uses_isolated_mode(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        invocations = [
            line.strip()
            for line in text.splitlines()
            if "python3 " in line and not line.strip().startswith("Required tools:")
        ]
        self.assertGreaterEqual(len(invocations), 10)
        self.assertTrue(
            all("python3 -I -" in line for line in invocations),
            "every credential-adjacent inline Python parser must exclude candidate cwd imports",
        )

    def test_isolated_stdin_cannot_import_candidate_root_shadow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "shadow-executed"
            (root / "json.py").write_text(
                "from pathlib import Path\nPath('shadow-executed').write_text('owned')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-I", "-"],
                cwd=root,
                input="import json\nprint(json.__name__)\n",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("json", result.stdout.strip())
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
