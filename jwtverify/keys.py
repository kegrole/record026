"""共享密钥表加载与 kid 校验。

kid 只作为密钥表字典的键使用，绝不参与文件路径拼接。
"""

import json

_FORBIDDEN_KID_PARTS = ("/", "\\", "..")


def load_config(path):
    """加载密钥配置，返回 (config, error)。

    配置格式：{"issuer": ..., "audience": ..., "keys": {kid: secret}}
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return None, "cannot load key config: %s" % exc
    if not isinstance(data, dict) or not isinstance(data.get("keys"), dict):
        return None, "key config must be an object with a 'keys' object"
    config = {
        "issuer": data.get("issuer"),
        "audience": data.get("audience"),
        "keys": {str(k): str(v) for k, v in data["keys"].items()},
    }
    return config, None


def lookup_key(key_table, kid):
    """按 kid 查密钥。含路径字符或未命中密钥表一律拒绝。"""
    if not isinstance(kid, str) or not kid:
        return None, "missing kid"
    if any(part in kid for part in _FORBIDDEN_KID_PARTS):
        return None, "kid %r contains forbidden path characters" % kid
    if kid not in key_table:
        return None, "unknown kid %r" % kid
    return key_table[kid].encode("utf-8"), None

