"""JWT 三段结构拆分与 base64url 解码。

所有解码函数都返回 (value, error) 二元组：失败时 error 为非空
字符串，绝不向上抛异常。
"""

import base64
import binascii
import json
import re

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")


def b64url_decode(segment):
    """解码 base64url 片段，接受无填充写法与 -/_ 变体。"""
    if not isinstance(segment, str):
        return None, "segment is not a string"
    if not _B64URL_RE.match(segment):
        return None, "segment contains characters outside the base64url alphabet"
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii")), None
    except (binascii.Error, ValueError):
        return None, "segment is not valid base64url"


def split_token(token):
    """把 JWT 拆成 header.payload.signature 三段。"""
    if not isinstance(token, str):
        return None, None, None, "token is not a string"
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None, "token must have exactly 3 segments"
    return parts[0], parts[1], parts[2], None


def decode_json_object(segment):
    """把 base64url 片段解码成 JSON 对象。"""
    raw, err = b64url_decode(segment)
    if err:
        return None, err
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "segment is not valid JSON"
    if not isinstance(value, dict):
        return None, "segment JSON is not an object"
    return value, None

