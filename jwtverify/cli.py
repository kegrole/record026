"""命令行入口。

用法：python -m jwtverify.cli --tokens demo/tokens.txt --keys demo/keys.json --out out/report.json
"""

import argparse
import os
import sys
import time

from . import keys
from . import report as report_mod
from . import validator


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="jwtverify",
        description="Validate HMAC-signed JWTs against a shared-key table.",
    )
    parser.add_argument("--tokens", required=True, help="file with one JWT per line")
    parser.add_argument("--keys", required=True, help="JSON key config (issuer/audience/keys)")
    parser.add_argument("--out", required=True, help="path to write the JSON report")
    args = parser.parse_args(argv)

    config, err = keys.load_config(args.keys)
    if err:
        print(err, file=sys.stderr)
        return 2
    try:
        with open(args.tokens, "r", encoding="utf-8") as fh:
            tokens = [
                line.strip()
                for line in fh
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except OSError as exc:
        print("cannot read tokens file: %s" % exc, file=sys.stderr)
        return 2

    now = time.time()
    results = [
        validator.validate_token(
            token,
            config["keys"],
            issuer=config["issuer"],
            audience=config["audience"],
            now=now,
            token_id="token-%03d" % (index + 1),
        )
        for index, token in enumerate(tokens)
    ]
    rep = report_mod.build_report(results)
    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    report_mod.write_report(rep, args.out)
    print(report_mod.summary_line(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())

