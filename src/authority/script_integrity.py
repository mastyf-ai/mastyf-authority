"""Compare a candidate third-party/site script with the version currently live.

Built for the Optimizely-style incident: a script that customers already trust is
replaced with one that reads card fields or wallet addresses and sends them out.
The check is a static diff of capabilities, not a full JS analysis. Heavily
obfuscated code lands in "review" instead of "pass" for that reason.

Verdicts: pass | review (needs a human) | block (cannot be approved).
"""

from __future__ import annotations

import base64
import hashlib
import math
import re
from collections import Counter

URL_RE = re.compile(r"(?:https?:|wss?:)?//([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", re.I)
HOST_LIT_RE = re.compile(
    r"""["'`]([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|ru|xyz|top|cc|info|biz|invalid|co|app|dev|site|online|cn|su))["'`]""",
    re.I,
)
SENSITIVE_RE = re.compile(
    r"cc-?(?:number|num|exp|csc)|card.?(?:number|num|holder)|\bcvv\b|\bcvc\b|security.?code|"
    r"autocomplete\s*=\s*['\"]?cc-|type\s*=\s*['\"]?password|\bpassword\b|\biban\b|seed.?phrase|mnemonic|private.?key",
    re.I,
)
SINKS = {
    "fetch": re.compile(r"\bfetch\s*\("),
    "xhr": re.compile(r"XMLHttpRequest"),
    "beacon": re.compile(r"sendBeacon"),
    "image_beacon": re.compile(r"new\s+Image\s*\("),
    "websocket": re.compile(r"new\s+WebSocket"),
    "form_action": re.compile(r"\.action\s*="),
    "script_inject": re.compile(r"createElement\s*\(\s*['\"]script"),
}
OBFUSCATION = {
    "eval": re.compile(r"\beval\s*\("),
    "function_ctor": re.compile(r"new\s+Function\s*\("),
    "atob": re.compile(r"\batob\s*\("),
    "fromcharcode": re.compile(r"fromCharCode"),
    "hex_escapes": re.compile(r"(?:\\x[0-9a-f]{2}){8,}", re.I),
    "long_blob": re.compile(r"['\"][A-Za-z0-9+/=]{200,}['\"]"),
}
LISTENER_RE = re.compile(
    r"addEventListener\s*\(\s*['\"](input|change|keydown|keyup|keypress|submit|blur|copy|paste)['\"]", re.I
)
CLIPBOARD_RE = re.compile(r"clipboardData|navigator\.clipboard", re.I)
WALLET_RE = re.compile(
    r"\b(0x[a-fA-F0-9]{40}|bc1[ac-hj-np-z02-9]{25,62}|T[1-9A-HJ-NP-Za-km-z]{33})\b"
)
WALLET_PATTERN_RE = re.compile(r"0x\[a-f0-9|0x\[0-9a-f|bc1\[|\[13\]\[a-km", re.I)

# Capabilities added after the Optimizely "OptimJack" attack (16 Nov 2026). Each is a hard signal in a
# third-party snippet that previously did not have it.
CAPS = {
    # loads or runs code that is not in this file
    "remote_code": re.compile(r"createElement\s*\(\s*['\"]script|\bimport\s*\(|document\.write\s*\(\s*['\"]<script"
                              r"|new\s+Worker\s*\(|importScripts\s*\(", re.I),
    "dynamic_code": re.compile(r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*['\"]"
                               r"|set(?:Timeout|Interval)\s*\(\s*['\"]"),
    # replaces built-in browser functions to see or change what the page sends / copies
    "native_hooks": re.compile(r"Function\.prototype\.(?:call|apply|bind)\s*=|window\.fetch\s*=|(?:^|[^\w.])fetch\s*=\s*function"
                               r"|XMLHttpRequest\.prototype\.(?:open|send|setRequestHeader)\s*="
                               r"|navigator\.clipboard\.(?:writeText|readText|write)\s*=|navigator\.share\s*="
                               r"|HTMLFormElement\.prototype\.submit\s*=|window\.open\s*=|navigator\.sendBeacon\s*="
                               r"|Object\.defineProperty\s*\(\s*(?:navigator|window|document)\b", re.I),
    # recognises payment cards by their digits (Luhn check or a 13-19 digit pattern), not by field names
    "card_logic": re.compile(r"\bluhn\b|\(\?:\\d\[ -\]\?\)\{13,19\}|\\d\{13,19\}|x\s*\*=\s*2[^;]{0,40}>\s*9", re.I),
    "screenshot": re.compile(r"html2canvas|toDataURL\s*\(|getDisplayMedia|captureStream", re.I),
    "ios_targeting": re.compile(r"iPhone\s*\|\s*iPad|iPad\s*\|\s*iPhone|iPhone[^\n]{0,40}userAgent|userAgent[^\n]{0,60}iPhone", re.I),
    "hidden_iframe": re.compile(r"createElement\s*\(\s*['\"]iframe['\"]\s*\)[\s\S]{0,300}?(?:display\s*=\s*['\"]none"
                                r"|width\s*=\s*['\"]?0\b|visibility\s*=\s*['\"]hidden)", re.I),
    "reload_loop": re.compile(r"set(?:Interval|Timeout)\s*\([^)]{0,80}location\.reload", re.I),
    "dom_rewrite": re.compile(r"MutationObserver[\s\S]{0,400}?\.(?:value|textContent|href|src)\s*=", re.I),
}
B64_LIT = re.compile(r"""['"`]([A-Za-z0-9+/]{24,}={0,2})['"`]""")
HEX_LIT = re.compile(r"((?:\\x[0-9a-fA-F]{2}){8,})")
CHARCODE = re.compile(r"fromCharCode\s*\(\s*((?:\d{2,3}\s*,\s*){5,}\d{2,3})\s*\)")


COOKIE = re.compile(r"document\.cookie\s*(={0,2})")


def _reads_cookie(src: str) -> bool:
    """document.cookie used other than as a plain assignment target (`document.cookie = ...`)."""
    return any(m.group(1) != "=" for m in COOKIE.finditer(src))


def _printable(c: str) -> bool:
    return c in "\n\r\t" or c.isprintable()


def reveal(src: str, depth: int = 3, budget: int = 2_000_000) -> str:
    """Decode text hidden in base64, \\x escapes and String.fromCharCode lists, recursively, and return it
    appended so the same checks see what the code would run. Binary blobs (e.g. images) are ignored."""
    out, frontier = [], [src]
    for _ in range(depth):
        nxt = []
        for text in frontier:
            for m in B64_LIT.finditer(text):
                try:
                    raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4), validate=False)
                    dec = raw.decode("utf-8")
                except Exception:  # noqa: BLE001
                    continue
                if dec and sum(_printable(c) for c in dec) / len(dec) > 0.95:
                    nxt.append(dec)
            for m in HEX_LIT.finditer(text):
                try:
                    nxt.append(bytes.fromhex(m.group(1).replace("\\x", "")).decode("utf-8"))
                except Exception:  # noqa: BLE001
                    pass
            for m in CHARCODE.finditer(text):
                try:
                    nxt.append("".join(chr(int(x)) for x in m.group(1).split(",")))
                except ValueError:
                    pass
        if not nxt:
            break
        out.extend(nxt)
        frontier = nxt
        if sum(map(len, out)) > budget:
            break
    return "\n".join(out)


def sri(src: str) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(src.encode()).digest()).decode()


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def capabilities(src: str) -> dict:
    hidden = reveal(src)
    src = src + ("\n" + hidden if hidden else "")
    hosts = {h.lower() for h in URL_RE.findall(src)} | {h.lower() for h in HOST_LIT_RE.findall(src)}
    return {
        "hosts": hosts,
        "sensitive": {m.group(0).lower() for m in SENSITIVE_RE.finditer(src)},
        "sinks": {k for k, r in SINKS.items() if r.search(src)},
        "obfuscation": {k for k, r in OBFUSCATION.items() if r.search(src)},
        "listeners": {m.lower() for m in LISTENER_RE.findall(src)},
        "clipboard": bool(CLIPBOARD_RE.search(src)),
        "wallets": set(WALLET_RE.findall(src)),
        "wallet_patterns": bool(WALLET_PATTERN_RE.search(src)),
        "size": len(src),
        "entropy": _entropy(src),
        "caps": {k for k, r in CAPS.items() if r.search(src)} | ({"cookie_read"} if _reads_cookie(src) else set()),
        "hidden_code": bool(hidden),
    }


def check(previous: str | None, candidate: str, allowed_hosts: list[str] | None = None) -> dict:
    allowed = {h.lower() for h in (allowed_hosts or [])}
    new = capabilities(candidate)
    old = capabilities(previous) if previous is not None else None
    digest = hashlib.sha256(candidate.encode()).hexdigest()
    base = {"candidate_sha256": digest, "sri": sri(candidate)}

    if previous is not None and previous == candidate:
        return {**base, "verdict": "pass", "findings": [], "note": "identical to live version"}

    def added(key):
        return new[key] - (old[key] if old else set())

    findings: list[dict] = []

    def f(sev, code, detail):
        findings.append({"severity": sev, "code": code, "detail": detail})

    new_hosts = {h for h in added("hosts") if h not in allowed}
    new_sens = added("sensitive")
    new_sinks = added("sinks")
    new_listen = added("listeners")
    new_obf = added("obfuscation")
    new_wallets = added("wallets")

    if new_hosts:
        f("high", "new_host", sorted(new_hosts))
    if new_sens:
        f("high", "new_sensitive_field_access", sorted(new_sens))
    if new_sinks:
        f("medium", "new_network_sink", sorted(new_sinks))
    if new_listen:
        f("medium", "new_input_listener", sorted(new_listen))
    if new_obf:
        f("medium", "new_obfuscation", sorted(new_obf))
    if new_wallets or (new["wallet_patterns"] and not (old and old["wallet_patterns"])):
        f("high", "wallet_address_material", sorted(new_wallets) or ["address-matching pattern"])
    if new["clipboard"] and not (old and old["clipboard"]):
        f("medium", "new_clipboard_access", True)
    if old and old["size"] and new["size"] > 1.5 * old["size"] + 2000:
        f("low", "size_jump", {"old": old["size"], "new": new["size"]})
    if new["entropy"] > 5.5 and (not old or new["entropy"] - old["entropy"] > 0.5):
        f("medium", "entropy_jump", round(new["entropy"], 2))
    new_caps = new["caps"] - (old["caps"] if old else set())
    for c in sorted(new_caps):
        f("high", f"new_{c}", True)
    new_hidden = new["hidden_code"] and not (old and old["hidden_code"])
    if new_hidden:
        f("high", "new_hidden_code", "decoded base64/hex/charcode text containing code or hosts")

    # existing sensitive-field references only count if data now also goes to a new, unapproved host
    reads_secrets = bool(new_sens or new_listen or (new["sensitive"] and new_sinks and new_hosts))
    sends_out = bool(new_hosts or new_sinks)
    new_wallet_material = bool(new_wallets) or (new["wallet_patterns"] and not (old and old["wallet_patterns"]))
    wallet_swap = new_wallet_material and (new["clipboard"] or "replace" in candidate)

    # hard blocks for a third-party snippet (each was used in the OptimJack attack)
    hard = (
        "native_hooks" in new_caps
        # loads code from a host not on the allowlist, or from a hidden location; loading from the vendor's
        # own allowlisted host goes to review instead
        or ("remote_code" in new_caps and bool(new_hosts or new_hidden))
        or ("dynamic_code" in new_caps and (new_hidden or bool(new_obf)))                   # runs hidden text as code
        or ("card_logic" in new_caps and sends_out | bool(new["sinks"]))
        or ("cookie_read" in new_caps and sends_out)
        or ("screenshot" in new_caps and sends_out | bool(new["sinks"]))
        or ("ios_targeting" in new_caps and "hidden_iframe" in new_caps)
        or "reload_loop" in new_caps and "hidden_iframe" in new_caps
    )
    if previous is None:
        # first version: everything looks "new", so no automatic pass or block; a human reviews the
        # listed findings once, and that version becomes the baseline
        verdict = "review"
        f("low", "no_baseline", "first version seen")
    elif (reads_secrets and sends_out) or wallet_swap or hard:
        verdict = "block"
    elif findings and any(x["severity"] in ("high", "medium") for x in findings):
        verdict = "review"
    else:
        verdict = "pass"
    return {**base, "verdict": verdict, "findings": findings}
