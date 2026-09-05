from __future__ import annotations

import datetime as dt
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mergegrounds_exceptions_under_test", ROOT / "scripts" / "mergegrounds.py")
assert SPEC and SPEC.loader
mergegrounds = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mergegrounds
SPEC.loader.exec_module(mergegrounds)


class ExceptionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / ".mergegrounds").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def record(self, risk: str = "R1", expires_delta: int = 1, points: int = 1) -> str:
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        issued = now - dt.timedelta(minutes=1)
        expires = now + dt.timedelta(days=expires_delta)
        fix = now + dt.timedelta(days=2)
        digest = "sha256:" + "a" * 64
        commit = "b" * 40
        return f'''schema_version = 1
[[exceptions]]
schema = "mergegrounds/exception/v1"
exception_id = "EXC-2026-0001"
class = "XQ"
control_id = "MG-QLT-004"
control_domain = "coverage"
underlying_evidence_digest = "{digest}"
risk_tier = "{risk}"
blast_radius = "component"
reason = "A pinned scanner defect prevents complete analysis; repair is underway."
residual_risk = "One bounded non-security coverage edge remains visible."
compensating_controls = ["Independent targeted test and review cover the exact branch."]
validation_evidence = ["{digest}"]
issued_at = {issued.isoformat()}
expires_at = {expires.isoformat()}
must_fix_by = {fix.isoformat()}
allowed_actions = ["merge"]
allowed_environments = ["staging"]
max_uses = 1
uses = 0
points = {points}
remediation_issue = "SEC-1"
remediation_change = "planned"
renewals = 0

[exceptions.subject]
repository = "example/service"
candidate_commit = "{commit}"
base_commit = "{commit}"
diff_digest = "{digest}"

[exceptions.affected_object]
finding_fingerprint = "coverage:src/example.py:42"
paths = ["src/example.py"]

[exceptions.owner]
identity = "user:owner@example.invalid"
role = "service-owner"

[[exceptions.approvers]]
identity = "user:reviewer@example.invalid"
role = "domain-owner"
'''

    def write(self, content: str) -> None:
        (self.root / ".mergegrounds/exceptions.toml").write_text(content, encoding="utf-8")

    def test_valid_narrow_exception(self) -> None:
        self.write(self.record())
        self.assertEqual([], mergegrounds.exception_findings(self.root))

    def test_r4_ordinary_exception_is_rejected(self) -> None:
        self.write(self.record(risk="R4", points=8))
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertIn("EXCEPTION_R4", codes)

    def test_expired_exception_is_rejected(self) -> None:
        self.write(self.record(expires_delta=-1))
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertIn("EXCEPTION_EXPIRED", codes)

    def test_xs_requires_security_and_contextual_authority(self) -> None:
        content = self.record(risk="R1", points=4)
        content = content.replace('class = "XQ"', 'class = "XS"')
        content = content.replace('control_id = "MG-QLT-004"', 'control_id = "MG-SEC-003"')
        content = content.replace('control_domain = "coverage"', 'control_domain = "security"')
        content = content.replace('role = "domain-owner"', 'role = "release-owner"')
        content += '''\n[[exceptions.approvers]]
identity = "user:legal@example.invalid"
role = "legal-owner"
'''
        self.write(content)
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertIn("EXCEPTION_AUTHORITY", codes)

    def test_xs_accepts_distinct_security_and_domain_authorities(self) -> None:
        content = self.record(risk="R1", points=4)
        content = content.replace('class = "XQ"', 'class = "XS"')
        content = content.replace('control_id = "MG-QLT-004"', 'control_id = "MG-SEC-003"')
        content = content.replace('control_domain = "coverage"', 'control_domain = "security"')
        content = content.replace('role = "domain-owner"', 'role = "security-owner"')
        content += '''\n[[exceptions.approvers]]
identity = "user:domain@example.invalid"
role = "domain-owner"
'''
        self.write(content)
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertNotIn("EXCEPTION_AUTHORITY", codes)

    def test_coverage_r2_rejects_unrelated_legal_specialist(self) -> None:
        content = self.record(risk="R2", points=2)
        content += '''\n[[exceptions.approvers]]
identity = "user:legal@example.invalid"
role = "legal-owner"
'''
        self.write(content)
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertIn("EXCEPTION_AUTHORITY", codes)

    def test_coverage_r2_accepts_testing_specialist(self) -> None:
        content = self.record(risk="R2", points=2)
        content += '''\n[[exceptions.approvers]]
identity = "user:testing@example.invalid"
role = "testing-owner"
'''
        self.write(content)
        self.assertEqual([], mergegrounds.exception_findings(self.root))

    def test_license_exception_requires_legal_owner(self) -> None:
        content = self.record(risk="R1", points=4)
        content = content.replace('class = "XQ"', 'class = "XS"')
        content = content.replace('control_id = "MG-QLT-004"', 'control_id = "MG-SEC-003"')
        content = content.replace('control_domain = "coverage"', 'control_domain = "license"')
        content = content.replace('role = "domain-owner"', 'role = "security-owner"')
        content += '''\n[[exceptions.approvers]]
identity = "user:domain@example.invalid"
role = "domain-owner"
'''
        self.write(content)
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertIn("EXCEPTION_AUTHORITY", codes)

        content += '''\n[[exceptions.approvers]]
identity = "user:legal@example.invalid"
role = "legal-owner"
'''
        self.write(content)
        self.assertEqual([], mergegrounds.exception_findings(self.root))

    def test_unmapped_control_and_mismatched_domain_fail_closed(self) -> None:
        unmapped = self.record().replace('control_id = "MG-QLT-004"', 'control_id = "MG-NEW-999"')
        self.write(unmapped)
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertIn("EXCEPTION_CONTROL_UNMAPPED", codes)

        mismatch = self.record().replace('control_domain = "coverage"', 'control_domain = "license"')
        self.write(mismatch)
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertIn("EXCEPTION_CONTROL_DOMAIN", codes)

    def test_noncanonical_identity_and_scope_are_rejected(self) -> None:
        content = self.record()
        content = content.replace('identity = "user:reviewer@example.invalid"', 'identity = "reviewer with spaces"')
        content = content.replace('paths = ["src/example.py"]', 'paths = ["../outside"]')
        self.write(content)
        codes = {finding.code for finding in mergegrounds.exception_findings(self.root)}
        self.assertIn("EXCEPTION_APPROVER", codes)
        self.assertIn("EXCEPTION_SCOPE", codes)


if __name__ == "__main__":
    unittest.main()
