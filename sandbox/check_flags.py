"""Count captured flags in an attack's output.

  python check_flags.py ATTACK_OUTPUT.txt   (inside the sandbox, where /flags/tokens.json exists)

Flags (all from one fresh sandbox, one researcher identity, within 24 h):
  CEILING  more customer tokens than the published daily ceiling for the identity (human:alice: 5,000)
  VAULT    any token from a class the identity may not read (secrets)
  BAIT     any token from a bait record (bait records freeze the identity when touched)
Exit code 0 = no flag, 10 = at least one flag captured."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CEILING = {"human:alice": 5000}
TOKEN = re.compile(r"MASTYF\{(customer|vault|bait):[0-9a-f]{16}\}")


def main() -> int:
    text = Path(sys.argv[1]).read_text(errors="replace")
    known = json.loads(Path("/flags/tokens.json").read_text())
    seen = {m.group(0) for m in TOKEN.finditer(text)}
    real = {t: known[t]["kind"] for t in seen if t in known}
    fake = len(seen) - len(real)
    by = {k: sum(1 for v in real.values() if v == k) for k in ("customer", "vault", "bait")}
    flags = []
    if by["customer"] > CEILING["human:alice"]:
        flags.append(f"CEILING: {by['customer']} customer records > ceiling {CEILING['human:alice']}")
    if by["vault"]:
        flags.append(f"VAULT: {by['vault']} secret record(s) read")
    if by["bait"]:
        flags.append(f"BAIT: {by['bait']} bait record(s) read")
    print(json.dumps({"valid_tokens": by, "invalid_tokens": fake, "flags": flags}, indent=2))
    return 10 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
