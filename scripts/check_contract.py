#!/usr/bin/env python3
"""
Static sanity checks for the contract file (no network, no GenVM needed).

    python scripts/check_contract.py
"""
import ast
import re
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "contracts" / "AdvisoryReachGate.py"
EXPECTED_DEPENDS = '"py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng"'


def main() -> int:
    src = PATH.read_text()
    lines = src.splitlines()
    errors = []

    if lines[0].strip() != "# v0.3.0":
        errors.append("line 1 must be '# v0.3.0'")
    if EXPECTED_DEPENDS not in lines[1] or "latest" in lines[1]:
        errors.append("line 2 must pin the py-genlayer hash (never :latest)")

    tree = ast.parse(src)
    contracts = [
        n for n in tree.body
        if isinstance(n, ast.ClassDef)
        and any(ast.unparse(b) == "gl.contract.Contract" for b in n.bases)
    ]
    if len(contracts) != 1:
        errors.append(f"expected exactly one gl.contract.Contract class, found {len(contracts)}")
    else:
        for fn in contracts[0].body:
            if isinstance(fn, ast.FunctionDef) and not fn.name.startswith("_"):
                decos = [ast.unparse(d) for d in fn.decorator_list]
                if not any(d.startswith("gl.public.") for d in decos):
                    errors.append(f"public method {fn.name} lacks a gl.public decorator")
                if fn.returns is None:
                    errors.append(f"public method {fn.name} lacks a return annotation")
            if isinstance(fn, ast.FunctionDef) and fn.name.startswith("_") and fn.name != "__init__":
                if any(ast.unparse(d).startswith("gl.public.") for d in fn.decorator_list):
                    errors.append(f"private method {fn.name} must not be public")

    if re.search(r"\bfloat\b", src.replace("float32", "")):
        errors.append("floats are not allowed in contract state or logic")
    if "import random" in src or "time.time" in src:
        errors.append("non-deterministic sources found outside gl.nondet")

    if errors:
        print("FAILED")
        for e in errors:
            print(" -", e)
        return 1
    print("OK: header, single contract class, annotated public methods")
    return 0


if __name__ == "__main__":
    sys.exit(main())
