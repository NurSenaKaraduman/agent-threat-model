#!/usr/bin/env python3
"""Write schema/system.schema.json from the pydantic models (``--check`` verifies only)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_threat_model.schema import json_schema

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "schema" / "system.schema.json"


def render() -> str:
    return json.dumps(json_schema(), indent=2) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT} is out of date; run: python scripts/gen_schema.py", file=sys.stderr)
            return 1
        print(f"{OUT} is up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
