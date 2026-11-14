"""标准声明解析：exp、nbf、iat、iss、aud、sub。"""

STANDARD_CLAIMS = ("exp", "nbf", "iat", "iss", "aud", "sub")
_NUMERIC_CLAIMS = ("exp", "nbf", "iat")


def parse_claims(payload):
    """从 payload 字典提取标准声明并做类型检查。

    返回 (claims, error)；claims 只包含标准声明。
    """
    if not isinstance(payload, dict):
        return None, "payload is not an object"
    claims = {}
    for name in STANDARD_CLAIMS:
        if name in payload:
            claims[name] = payload[name]
    for name in _NUMERIC_CLAIMS:
        if name in claims:
            value = claims[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return None, "claim %r must be a number" % name
    for name in ("iss", "sub"):
        if name in claims and not isinstance(claims[name], str):
            return None, "claim %r must be a string" % name
    aud = claims.get("aud")
    if aud is not None:
        if isinstance(aud, str):
            pass
        elif isinstance(aud, list) and all(isinstance(item, str) for item in aud):
            pass
        else:
            return None, "claim 'aud' must be a string or a list of strings"
    return claims, None


def audience_list(claims):
    """把 aud 统一成字符串列表（字符串形态包成单元素列表）。"""
    aud = claims.get("aud")
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list):
        return [item for item in aud if isinstance(item, str)]
    return []

