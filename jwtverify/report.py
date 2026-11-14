"""JSON 报告构建。报告只含判定结论与声明摘要，不含令牌原文与密钥。"""

import json
from collections import Counter


def build_report(results):
    entries = []
    for res in results:
        entry = {
            "token_id": res["token_id"],
            "valid": res["valid"],
            "reason": res["reason"],
            "claims": res.get("claims", {}),
        }
        if res.get("detail"):
            entry["detail"] = res["detail"]
        entries.append(entry)
    return {"tokens": entries, "summary": summarize(entries)}


def summarize(entries):
    reasons = Counter(entry["reason"] for entry in entries if not entry["valid"])
    return {
        "total": len(entries),
        "valid": sum(1 for entry in entries if entry["valid"]),
        "rejected": sum(1 for entry in entries if not entry["valid"]),
        "reasons": dict(sorted(reasons.items())),
    }


def summary_line(report):
    s = report["summary"]
    dist = " ".join("%s=%d" % (name, count) for name, count in s["reasons"].items()) or "-"
    return "tokens=%d valid=%d rejected=%d reasons: %s" % (
        s["total"],
        s["valid"],
        s["rejected"],
        dist,
    )


def write_report(report, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")

