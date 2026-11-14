import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jwtverify import algorithms, decoder, keys, validator
from jwtverify.report import build_report

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SECRET = "test-shared-secret"
ALT_SECRET = "rotated-shared-secret"
ISSUER = "test-issuer"
AUD = "test-client"
KEYS = {"key-1": SECRET}
NOW = 1_800_000_000  # 固定参考时间，测试不依赖真实时钟


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_token(header, payload, key=SECRET, alg="HS256", raw_sig=None):
    header = {"typ": "JWT", "kid": "key-1", **header}
    head = b64(json.dumps(header, separators=(",", ":")).encode())
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = (head + "." + body).encode("ascii")
    if raw_sig is not None:
        sig = raw_sig
    else:
        sig = b64(algorithms.sign(alg, key.encode(), signing_input))
    return head + "." + body + "." + sig


def base_payload(**overrides):
    payload = {
        "iss": ISSUER,
        "aud": [AUD, "other-client"],
        "sub": "user-1",
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 600,
    }
    payload.update(overrides)
    return payload


def validate(token, key_table=KEYS, now=NOW):
    return validator.validate_token(
        token, key_table, issuer=ISSUER, audience=AUD, now=now, token_id="t"
    )


def six_fixtures():
    """按判定口径构造的 6 条令牌：恰好第 1 条合法。"""
    return [
        make_token({"alg": "HS256"}, base_payload()),                       # valid
        make_token({"alg": "none"}, base_payload(), raw_sig=""),            # alg_none
        make_token({"alg": "HS256"}, base_payload(exp=NOW - 60)),           # expired
        make_token({"alg": "HS256"}, base_payload(nbf=NOW + 60)),           # not_yet_valid
        make_token({"alg": "HS256", "kid": "../../etc/passwd"}, base_payload()),  # bad_kid
        make_token({"alg": "HS384"}, base_payload(), alg="HS256"),          # alg_mismatch
    ]


class DecoderTests(unittest.TestCase):
    def test_unpadded_and_urlsafe_variants(self):
        self.assertEqual(decoder.b64url_decode("-_8"), (b"\xfb\xff", None))
        self.assertEqual(decoder.b64url_decode("QQ"), (b"A", None))
        self.assertEqual(decoder.b64url_decode("QQ="), (b"A", None))

    def test_decode_failure_returns_error_not_exception(self):
        value, err = decoder.b64url_decode("!!!")
        self.assertIsNone(value)
        self.assertTrue(err)
        value, err = decoder.b64url_decode("A")  # 非法长度
        self.assertIsNone(value)
        self.assertTrue(err)

    def test_split_requires_three_segments(self):
        *_, err = decoder.split_token("a.b")
        self.assertTrue(err)
        *_, err = decoder.split_token("a.b.c.d")
        self.assertTrue(err)


class SixFixtureTests(unittest.TestCase):
    def test_exactly_one_valid_and_five_distinct_reasons(self):
        results = [validate(tok) for tok in six_fixtures()]
        valids = [r for r in results if r["valid"]]
        self.assertEqual(len(valids), 1)
        self.assertEqual(valids[0]["reason"], "")
        reasons = [r["reason"] for r in results if not r["valid"]]
        self.assertEqual(
            sorted(reasons),
            sorted(["alg_none", "expired", "not_yet_valid", "bad_kid", "alg_mismatch"]),
        )

    def test_alg_mismatch_criterion(self):
        # header 声明 HS384、实际按 HS256 签名 -> alg_mismatch
        confused = make_token({"alg": "HS384"}, base_payload(), alg="HS256")
        self.assertEqual(validate(confused)["reason"], "alg_mismatch")
        # 签名用错密钥、任何白名单算法都匹配不上 -> bad_signature
        wrong_key = make_token({"alg": "HS256"}, base_payload(), key=ALT_SECRET)
        self.assertEqual(validate(wrong_key)["reason"], "bad_signature")

    def test_alg_whitelist(self):
        # header 里不带 alg 字段（alg_missing 先于签名校验判定）
        header = {"typ": "JWT", "kid": "key-1"}
        head = b64(json.dumps(header).encode())
        body = b64(json.dumps(base_payload()).encode())
        sig = b64(algorithms.sign("HS256", SECRET.encode(), (head + "." + body).encode()))
        no_alg = head + "." + body + "." + sig
        self.assertEqual(validate(no_alg)["reason"], "alg_missing")
        rs256 = make_token({"alg": "RS256"}, base_payload())
        self.assertEqual(validate(rs256)["reason"], "alg_not_allowed")


class TimingTests(unittest.TestCase):
    def test_exp_tolerance_boundary(self):
        self.assertTrue(validate(make_token({"alg": "HS256"}, base_payload(exp=NOW - 30)))["valid"])
        self.assertEqual(
            validate(make_token({"alg": "HS256"}, base_payload(exp=NOW - 31)))["reason"],
            "expired",
        )
        self.assertEqual(
            validate(make_token({"alg": "HS256"}, base_payload(exp=NOW - 60)))["reason"],
            "expired",
        )
        self.assertTrue(validate(make_token({"alg": "HS256"}, base_payload(exp=NOW + 30)))["valid"])

    def test_nbf_tolerance_boundary(self):
        self.assertTrue(validate(make_token({"alg": "HS256"}, base_payload(nbf=NOW + 30)))["valid"])
        self.assertEqual(
            validate(make_token({"alg": "HS256"}, base_payload(nbf=NOW + 31)))["reason"],
            "not_yet_valid",
        )


class AudienceAndIssuerTests(unittest.TestCase):
    def test_aud_array_containing_target_is_valid(self):
        token = make_token({"alg": "HS256"}, base_payload(aud=[AUD, "other"]))
        self.assertTrue(validate(token)["valid"])

    def test_aud_string_form_is_valid(self):
        token = make_token({"alg": "HS256"}, base_payload(aud=AUD))
        self.assertTrue(validate(token)["valid"])

    def test_aud_array_without_target_is_invalid_and_names_expected(self):
        token = make_token({"alg": "HS256"}, base_payload(aud=["someone-else"]))
        result = validate(token)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "bad_aud")
        self.assertIn(AUD, result["detail"])

    def test_wrong_issuer_rejected(self):
        token = make_token({"alg": "HS256"}, base_payload(iss="evil-issuer"))
        self.assertEqual(validate(token)["reason"], "bad_iss")


class KidTests(unittest.TestCase):
    def test_path_traversal_kid_rejected_without_file_access(self):
        token = make_token({"alg": "HS256", "kid": "../../etc/passwd"}, base_payload())
        with mock.patch("builtins.open", side_effect=AssertionError("file access")):
            result = validate(token)
        self.assertEqual(result["reason"], "bad_kid")

    def test_unknown_and_missing_kid_rejected(self):
        unknown = make_token({"alg": "HS256", "kid": "no-such-key"}, base_payload())
        self.assertEqual(validate(unknown)["reason"], "bad_kid")
        header = {"alg": "HS256", "typ": "JWT"}
        head = b64(json.dumps(header).encode())
        body = b64(json.dumps(base_payload()).encode())
        sig = b64(algorithms.sign("HS256", SECRET.encode(), (head + "." + body).encode()))
        self.assertEqual(validate(head + "." + body + "." + sig)["reason"], "bad_kid")


class SignatureTests(unittest.TestCase):
    def test_constant_time_compare_is_used(self):
        token = make_token({"alg": "HS256"}, base_payload())
        with mock.patch.object(
            algorithms.hmac, "compare_digest", wraps=algorithms.hmac.compare_digest
        ) as spy:
            validate(token)
        self.assertTrue(spy.called)

    def test_key_rotation_flips_valid_token_to_bad_signature(self):
        token = make_token({"alg": "HS256"}, base_payload())
        self.assertTrue(validate(token, key_table=KEYS)["valid"])
        rotated = validate(token, key_table={"key-1": ALT_SECRET})
        self.assertFalse(rotated["valid"])
        self.assertEqual(rotated["reason"], "bad_signature")


class ReportTests(unittest.TestCase):
    def test_report_fields_and_reason_empty_iff_valid(self):
        results = [
            validator.validate_token(tok, KEYS, issuer=ISSUER, audience=AUD,
                                     now=NOW, token_id="token-%03d" % (i + 1))
            for i, tok in enumerate(six_fixtures())
        ]
        report = build_report(results)
        for entry in report["tokens"]:
            for field in ("token_id", "valid", "reason"):
                self.assertIn(field, entry)
            self.assertEqual(entry["reason"] == "", entry["valid"])

    def test_report_contains_no_secrets_or_raw_tokens(self):
        tokens = six_fixtures()
        results = [
            validator.validate_token(tok, KEYS, issuer=ISSUER, audience=AUD,
                                     now=NOW, token_id="token-%03d" % (i + 1))
            for i, tok in enumerate(tokens)
        ]
        blob = json.dumps(build_report(results))
        self.assertNotIn(SECRET, blob)
        for tok in tokens:
            self.assertNotIn(tok, blob)


class DemoCliTests(unittest.TestCase):
    def test_demo_command_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.json")
            proc = subprocess.run(
                [sys.executable, "-m", "jwtverify.cli",
                 "--tokens", "demo/tokens.txt",
                 "--keys", "demo/keys.json",
                 "--out", out],
                cwd=REPO_ROOT, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("tokens=6", proc.stdout)
            self.assertIn("valid=1", proc.stdout)
            self.assertIn("rejected=5", proc.stdout)
            with open(out, encoding="utf-8") as fh:
                report = json.load(fh)
            summary = report["summary"]
            self.assertEqual(summary["total"], 6)
            self.assertEqual(summary["valid"], 1)
            self.assertEqual(
                summary["reasons"],
                {"alg_mismatch": 1, "alg_none": 1, "bad_kid": 1,
                 "expired": 1, "not_yet_valid": 1},
            )
            blob = json.dumps(report)
            self.assertNotIn("demo-hmac-shared-secret-9f27c1", blob)


if __name__ == "__main__":
    unittest.main()
