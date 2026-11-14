"""HMAC 算法白名单与常量时间签名比较。"""

import hashlib
import hmac

WHITELIST = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
}


def is_allowed(alg):
    return alg in WHITELIST


def sign(alg, key, signing_input):
    """按白名单算法计算 HMAC 签名。"""
    return hmac.new(key, signing_input, WHITELIST[alg]).digest()


def verify(alg, key, signing_input, signature):
    """常量时间比较签名，避免时序侧信道。"""
    expected = sign(alg, key, signing_input)
    return hmac.compare_digest(expected, signature)

