import datetime as dt
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tls_check


class TlsGradingTests(unittest.TestCase):
    def test_modern_host_scores_100(self):
        supported = {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
        cert = {"notAfter": "Jan  1 00:00:00 2030 GMT"}
        score, findings = tls_check.grade(supported, cert, now=dt.date(2026, 1, 1))
        self.assertEqual(score, 100)
        self.assertEqual(findings, [])

    def test_legacy_protocols_penalised(self):
        supported = {"TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False}
        cert = {"notAfter": "Jan  1 00:00:00 2030 GMT"}
        score, findings = tls_check.grade(supported, cert, now=dt.date(2026, 1, 1))
        issues = {f["issue"] for f in findings}
        self.assertIn("legacy-tls", issues)
        self.assertIn("no-tls13", issues)
        self.assertLess(score, 100)

    def test_expired_certificate(self):
        supported = {"TLSv1.2": True, "TLSv1.3": True}
        cert = {"notAfter": "Jan  1 00:00:00 2020 GMT"}
        score, findings = tls_check.grade(supported, cert, now=dt.date(2026, 1, 1))
        self.assertIn("expired", {f["issue"] for f in findings})

    def test_missing_certificate(self):
        supported = {"TLSv1.2": True, "TLSv1.3": True}
        _, findings = tls_check.grade(supported, {}, now=dt.date(2026, 1, 1))
        self.assertIn("no-certificate", {f["issue"] for f in findings})

    def test_render_contains_protocols(self):
        supported = {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
        text = tls_check.render("example.com", 443, supported, {}, 100, [])
        self.assertIn("TLSv1.3", text)
        self.assertIn("findings: none", text)


if __name__ == "__main__":
    unittest.main()
