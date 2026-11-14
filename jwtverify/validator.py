"""单条令牌的判定逻辑：结构、算法、签名、时效、签发方、受众。"""

import time

from . import algorithms, decoder, keys
from .claims import audience_list, parse_claims

CLOCK_TOLERANCE = 30  # 时钟容差，单位秒


def validate_token(token, key_table, issuer=None, audience=None, now=None, token_id=""):
    """校验一条 JWT，返回判定字典 {token_id, valid, reason, detail, claims}。"""
    if now is None:
        now = time.time()
    result = {"token_id": token_id, "valid": False, "reason": "", "detail": "", "claims": {}}

    def fail(reason, detail=""):
        result["reason"] = reason
        result["detail"] = detail
        return result

    header_b64, payload_b64, sig_b64, err = decoder.split_token(token)
    if err:
        return fail("malformed", err)

    header, err = decoder.decode_json_object(header_b64)
    if err:
        return fail("malformed", "header: " + err)

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        return fail("alg_missing", "header alg is missing")
    if alg.lower() == "none":
        return fail("alg_none", "alg=none is not accepted")
    if not algorithms.is_allowed(alg):
        return fail("alg_not_allowed", "alg %r is not in the whitelist" % alg)

    payload, err = decoder.decode_json_object(payload_b64)
    if err:
        return fail("malformed", "payload: " + err)

    key, err = keys.lookup_key(key_table, header.get("kid"))
    if err:
        return fail("bad_kid", err)

    signature, err = decoder.b64url_decode(sig_b64)
    if err:
        return fail("malformed", "signature: " + err)

    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    if not algorithms.verify(alg, key, signing_input, signature):
        for other in algorithms.WHITELIST:
            if other != alg and algorithms.verify(other, key, signing_input, signature):
                return fail(
                    "alg_mismatch",
                    "header declares %s but the signature was made with %s" % (alg, other),
                )
        return fail("bad_signature", "HMAC signature verification failed")

    claims, err = parse_claims(payload)
    if err:
        return fail("invalid_claims", err)
    result["claims"] = claims

    exp = claims.get("exp")
    if exp is not None and exp < now - CLOCK_TOLERANCE:
        return fail("expired", "exp %s is earlier than now-%ds tolerance" % (exp, CLOCK_TOLERANCE))
    nbf = claims.get("nbf")
    if nbf is not None and nbf > now + CLOCK_TOLERANCE:
        return fail("not_yet_valid", "nbf %s is later than now+%ds tolerance" % (nbf, CLOCK_TOLERANCE))

    if issuer is not None and claims.get("iss") != issuer:
        return fail("bad_iss", "expected iss %r" % issuer)

    if audience is not None and audience not in audience_list(claims):
        return fail("bad_aud", "expected aud %r" % audience)

    result["valid"] = True
    result["reason"] = ""
    result["detail"] = ""
    return result

