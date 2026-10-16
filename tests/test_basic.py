"""Offline unit tests — no network required.

Run with:  python -m pytest tests/  (or: python -m unittest discover tests)
"""
import unittest

from scanner.utils import normalize_target, registrable_domain
from scanner.models import ScanResult, ModuleResult, Severity, Status
from scanner.scoring import scorer
from scanner.email.checker import _dmarc_policy, _dkim_has_key, _find_spf  # noqa


class TestUtils(unittest.TestCase):
    def test_normalize_strips_scheme_and_path(self):
        self.assertEqual(normalize_target("https://Example.com/foo"), "example.com")
        self.assertEqual(normalize_target("example.com"), "example.com")
        self.assertEqual(normalize_target("  http://sub.example.org  "), "sub.example.org")

    def test_normalize_rejects_empty(self):
        with self.assertRaises(ValueError):
            normalize_target("   ")

    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("www.example.com"), "example.com")
        self.assertEqual(registrable_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("example.com"), "example.com")


class TestScoring(unittest.TestCase):
    def _result_with(self, *severities):
        r = ScanResult(target="t")
        mod = ModuleResult(name="http")
        for s in severities:
            mod.add_finding(s, "x", "fix")
        r.modules["http"] = mod
        return r

    def test_perfect_score(self):
        r = scorer.score(self._result_with())
        self.assertEqual(r.score, 100)
        self.assertEqual(r.grade, "A")

    def test_high_finding_deducts(self):
        r = scorer.score(self._result_with(Severity.HIGH))
        self.assertEqual(r.score, 80)

    def test_bucket_cap(self):
        # 10 LOW findings * 3 = 30, capped at 20.
        r = scorer.score(self._result_with(*([Severity.LOW] * 10)))
        self.assertEqual(r.score, 80)

    def test_counts(self):
        r = self._result_with(Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.LOW)
        c = r.counts()
        self.assertEqual(c, {"HIGH": 1, "MEDIUM": 1, "LOW": 2})


class TestRemediation(unittest.TestCase):
    def test_plan_orders_by_severity_and_numbers(self):
        from scanner import remediation
        r = ScanResult(target="t")
        mod = ModuleResult(name="http")
        mod.add_finding(Severity.LOW, "low one", "fix low", code="http.header.referrer-policy")
        mod.add_finding(Severity.HIGH, "high one", "fix high", code="http.no_https")
        r.modules["http"] = mod
        plan = remediation.build_plan(r.all_findings)
        self.assertEqual(plan[0]["severity"], "HIGH")
        self.assertEqual(plan[0]["priority"], 1)
        # known code pulls detailed steps from the catalog, not just the recommendation
        self.assertTrue(len(plan[0]["steps"]) >= 2)
        self.assertTrue(plan[0]["why"])

    def test_plan_falls_back_to_recommendation(self):
        from scanner import remediation
        r = ScanResult(target="t")
        mod = ModuleResult(name="x")
        mod.add_finding(Severity.MEDIUM, "unknown", "do the thing", code="no.such.code")
        r.modules["x"] = mod
        plan = remediation.build_plan(r.all_findings)
        self.assertEqual(plan[0]["steps"], ["do the thing"])


class TestEmailParsing(unittest.TestCase):
    def test_dmarc_policy(self):
        self.assertEqual(_dmarc_policy("v=DMARC1; p=reject; rua=x"), "reject")
        self.assertEqual(_dmarc_policy("v=DMARC1; p=none"), "none")
        self.assertIsNone(_dmarc_policy("v=DMARC1; rua=x"))

    def test_dkim_null_key_rejected(self):
        # example.com's wildcard null key must NOT count as configured DKIM.
        self.assertFalse(_dkim_has_key("v=DKIM1; p="))
        self.assertFalse(_dkim_has_key("v=DKIM1; p=  "))
        self.assertTrue(_dkim_has_key("v=DKIM1; k=rsa; p=MIGfMA0GCSq..."))


class TestEmailExtras(unittest.TestCase):
    def test_spf_lookup_count(self):
        from scanner.email.checker import _spf_lookup_count
        spf = "v=spf1 include:_spf.google.com include:sendgrid.net a mx -all"
        self.assertEqual(_spf_lookup_count(spf), 4)  # 2 includes + a + mx

    def test_dmarc_tags(self):
        from scanner.email.checker import _dmarc_tags
        tags = _dmarc_tags("v=DMARC1; p=reject; pct=50; sp=none; rua=mailto:x@y")
        self.assertEqual(tags["p"], "reject")
        self.assertEqual(tags["pct"], "50")
        self.assertEqual(tags["sp"], "none")
        self.assertTrue(tags["rua"].startswith("mailto:"))


class TestHeaderAnalyzer(unittest.TestCase):
    def _codes(self, result):
        return {f.code for f in result.findings}

    def test_spoof_detected(self):
        from scanner.email_headers.analyzer import analyze
        raw = (
            "Received: from evil.ru (evil.ru [1.2.3.4]) by mx.victim.com;\n"
            "Authentication-Results: mx.victim.com; spf=fail; dkim=fail; dmarc=fail\n"
            "From: \"PayPal Support\" <billing@paypa1-secure.ru>\n"
            "Return-Path: <bounce@evil.ru>\n"
            "Reply-To: <collect@attacker.com>\n"
            "To: victim@victim.com\n"
            "Subject: Your account is locked\n"
        )
        r = analyze(raw)
        codes = self._codes(r)
        self.assertIn("hdr.spf_fail", codes)
        self.assertIn("hdr.dmarc_fail", codes)
        self.assertIn("hdr.from_returnpath_mismatch", codes)
        self.assertIn("hdr.reply_to_mismatch", codes)

    def test_clean_message(self):
        from scanner.email_headers.analyzer import analyze
        raw = (
            "Received: from mail.acme.com (mail.acme.com [9.9.9.9]) by mx.dest.com;\n"
            "Authentication-Results: mx.dest.com; spf=pass; dkim=pass; dmarc=pass\n"
            "From: Jane <jane@acme.com>\n"
            "Return-Path: <jane@acme.com>\n"
            "To: bob@dest.com\n"
            "Subject: Hello\n"
        )
        r = analyze(raw)
        # no MEDIUM/HIGH spoofing findings on a clean, aligned, passing message
        sev = {f.severity.value for f in r.findings}
        self.assertNotIn("HIGH", sev)
        self.assertNotIn("MEDIUM", sev)

    def test_empty_input(self):
        from scanner.email_headers.analyzer import analyze
        r = analyze("   ")
        self.assertTrue(r.error)

    def test_verdict_and_sender(self):
        from scanner.email_headers.analyzer import analyze
        raw = (
            "Received: from mail.acme.com (mail.acme.com [45.79.10.20]) by mx.dest.com;\n"
            "Authentication-Results: mx.dest.com; spf=pass; dkim=pass; dmarc=pass\n"
            "From: =?UTF-8?B?zqDOu86test= <news@mail.acme.com>\n"
            "Return-Path: <bounce@mail.acme.com>\n"
            "To: bob@dest.com\nSubject: Hi\n"
        )
        r = analyze(raw)
        self.assertEqual(r.data["verdict"]["level"], "legit")
        self.assertEqual(r.data["sending_ip"], "45.79.10.20")
        self.assertTrue(r.data["verdict"]["next_steps"])

    def test_verdict_suspicious(self):
        from scanner.email_headers.analyzer import analyze
        raw = (
            "Received: from evil.ru (evil.ru [185.60.216.35]) by mx.v.com;\n"
            "Authentication-Results: mx.v.com; spf=fail; dkim=fail; dmarc=fail\n"
            "From: <billing@paypa1.ru>\nReturn-Path: <x@evil.ru>\nTo: me@v.com\n"
        )
        r = analyze(raw)
        self.assertEqual(r.data["verdict"]["level"], "suspicious")
        self.assertEqual(r.data["sending_ip"], "185.60.216.35")

    def test_verdict_unverified_no_auth(self):
        from scanner.email_headers.analyzer import analyze
        raw = "From: <a@b.com>\nTo: c@d.com\nSubject: hi\n"
        r = analyze(raw)
        self.assertEqual(r.data["verdict"]["level"], "unverified")

    def test_decode_encoded_word(self):
        from scanner.email_headers.analyzer import _decode
        # "Πλαίσιο" base64-encoded word should decode without raising
        out = _decode("=?UTF-8?B?zqDOu86xzq/Pg865zr8=?=")
        self.assertIsInstance(out, str)
        self.assertNotIn("=?", out)


class TestUrlCheck(unittest.TestCase):
    def test_bare_domain_assumes_https(self):
        from scanner.urlcheck import analyze
        r = analyze("example.com", fetch=False)
        self.assertEqual(r.data["scheme"], "https")
        self.assertEqual(r.data["verdict"]["level"], "safe")

    def test_explicit_http_is_flagged(self):
        from scanner.urlcheck import analyze
        r = analyze("http://example.com", fetch=False)
        codes = {f.code for f in r.findings}
        self.assertIn("url.no_https", codes)

    def test_javascript_scheme_suspicious(self):
        from scanner.urlcheck import analyze
        r = analyze("javascript:alert(1)", fetch=False)
        self.assertEqual(r.data["verdict"]["level"], "suspicious")
        self.assertIn("url.dangerous_scheme", {f.code for f in r.findings})

    def test_userinfo_at_trick(self):
        from scanner.urlcheck import analyze
        r = analyze("https://paypal.com@evil.tld/", fetch=False)
        self.assertIn("url.userinfo", {f.code for f in r.findings})
        self.assertEqual(r.data["host"], "evil.tld")

    def test_phishing_combo_is_flagged(self):
        from scanner.urlcheck import analyze
        # Two low signals (risky TLD + phish words) -> at least "caution".
        r = analyze("https://verify-account.secure-login.tk/signin", fetch=False)
        self.assertIn(r.data["verdict"]["level"], ("caution", "suspicious"))
        # A medium signal on top (punycode) tips it to suspicious.
        r2 = analyze("https://paypal.verify.xn--secure.tk/signin", fetch=False)
        self.assertEqual(r2.data["verdict"]["level"], "suspicious")

    def test_shortener_flagged(self):
        from scanner.urlcheck import analyze
        r = analyze("https://bit.ly/abc", fetch=False)
        self.assertIn("url.shortener", {f.code for f in r.findings})

    def test_all_url_codes_have_remediation(self):
        from scanner import remediation
        from scanner.urlcheck import analyze
        urls = ["javascript:alert(1)", "http://192.168.0.1/login",
                "https://a.b.c.d.e.tk/verify", "https://bit.ly/x"]
        for u in urls:
            r = analyze(u, fetch=False)
            for f in r.findings:
                entry = remediation.CATALOG.get(f.code)
                self.assertIsNotNone(entry, f"no remediation for {f.code}")


class TestReputation(unittest.TestCase):
    def test_fallback_never_raises_and_degrades(self):
        from scanner.reputation import check
        r = check("example.com", use_cache=False)
        # With no API keys configured, must fall back to heuristics.
        self.assertTrue(r["degraded"])
        self.assertIn(r["verdict"], ("unknown", "suspicious", "clean", "malicious"))
        self.assertIn("provider_status", r)

    def test_heuristic_never_claims_malicious(self):
        from scanner.reputation import check
        r = check("https://verify-account.secure-login.tk/signin", use_cache=False)
        self.assertTrue(r["degraded"])
        self.assertNotEqual(r["verdict"], "malicious")

    def test_cache_returns_same_object(self):
        from scanner.reputation import check
        a = check("cache-test.example", use_cache=True)
        b = check("cache-test.example", use_cache=True)
        self.assertEqual(a["host"], b["host"])


if __name__ == "__main__":
    unittest.main()
