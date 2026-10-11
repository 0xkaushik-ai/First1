"""
BUG: Graphify only checks secret FILE NAMES, never file CONTENTS
=================================================================
Repo     : https://github.com/Graphify-Labs/graphify   (v0.9.86)
Run this file to see the bug and the fix:   python3 bug.py

Three places in the Graphify source are involved:

  [A] graphify/detect.py   lines 286-319   _is_sensitive()      <- reads only the name
  [B] graphify/detect.py   line  2104      call site            <- the only gate
  [C] graphify/extract.py  lines 1794-1810 _add_rationale()     <- copies comments raw
  (+) graphify/skill.md    line  240       sends 'document' files to the LLM

Section 1 = ORIGINAL code (copied from the repo, line numbers given).
Section 2 = FIXED code (my proposed solution, not applied upstream).
Section 3 = a runnable demo proving the bug and the fix.
"""

import re
import tempfile
from pathlib import Path


# =============================================================================
# SECTION 1 - ORIGINAL CODE (the bug)
# =============================================================================

# -----------------------------------------------------------------------------
# [A] FILE: graphify/detect.py   LINES: 286-319
# -----------------------------------------------------------------------------
ORIGINAL_A = r'''
def _is_sensitive(path: Path) -> bool:                                   # L286
    """Return True if this file likely contains secrets and should be skipped."""
    parents = path.parts[:-1]
    if any(part.lower() in _CREDENTIAL_STORE_DIRS for part in parents):  # L297  dir NAME
        return True
    if any(part.lower() in _AMBIGUOUS_SENSITIVE_DIRS for part in parents) and not _is_graphable_source(path):
        return True                                                      # L299-300
    name = path.name
    if any(p.search(name) for p in _SENSITIVE_PATTERNS) and not _is_env_template(name):
        return True                                                      # L305-306 file NAME regex
    if _generic_keyword_hit(name):                                       # L315     file NAME keyword
        return not (_is_graphable_source(path) or _is_prose_note(path))  # L318
    return False                                                         # L319  <-- BUG:
                                                                         #   "safe" if the NAME looks fine.
                                                                         #   The file is NEVER opened.
'''
# The name patterns it relies on (graphify/detect.py L132-):
#   re.compile(r'\.(pem|key|p12|pfx|cert|crt|der|p8)$', re.IGNORECASE)
#   re.compile(r'(^|[^A-Za-z0-9])(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$', re.IGNORECASE)
# They anchor on the END of the name ($), so  id_rsa.md  and  truststore.p12.md  slip through.
# Keyword list: credential|secret|passwd|password|private_key  -> 'oncall.md' matches nothing.

# -----------------------------------------------------------------------------
# [B] FILE: graphify/detect.py   LINES: 2104-2106   (the only place files are admitted)
# -----------------------------------------------------------------------------
ORIGINAL_B = r'''
        if _is_sensitive(p):                  # L2104  <-- only a name check
            skipped_sensitive.append(str(p))  # L2105
            continue                          # L2106
        ftype = classify_file(p)              # L2107  anything that passed is now indexed
'''

# -----------------------------------------------------------------------------
# [C] FILE: graphify/extract.py   LINES: 1794-1810   (function _add_rationale)
# -----------------------------------------------------------------------------
ORIGINAL_C = r'''
    def _add_rationale(text: str, line: int, parent_nid: str) -> None:   # L1794
        label = _shorten_rationale_label(text)   # L1799  only trims whitespace/length
        rid = _make_id(stem, "rationale", str(line))
        if rid not in seen_ids:
            seen_ids.add(rid)
            nodes.append({
                "id": rid,
                "label": label,                  # L1805  <-- BUG: raw comment text, e.g.
                "file_type": "rationale",        #     "# WHY: prod token is ghp_abc..." is
                "source_file": str_path,         #     stored and later written to graph.json,
                "source_location": f"L{line}",   #     graph.html, GRAPH_REPORT.md and cache/
            })
'''

# -----------------------------------------------------------------------------
# (+) FILE: graphify/skill.md   LINE: 240   (where passing files go to the LLM)
# -----------------------------------------------------------------------------
ORIGINAL_SKILL = r'''
all_files = [f for cat in ('document', 'paper', 'image') for f in detect['files'].get(cat, [])]
# every file that got past _is_sensitive() ends up here and is sent to a subagent / Gemini
'''


# =============================================================================
# SECTION 2 - THE FIX (proposed solution)
# =============================================================================
# Idea: add a CONTENT scan in addition to the NAME scan, and redact secrets that
# appear in comments before they become graph labels.

_SECRET_RE = re.compile(
    r"AKIA[0-9A-Z]{16}"                                   # AWS access key id
    r"|ghp_[A-Za-z0-9]{36}"                               # GitHub token
    r"|gh[ousr]_[A-Za-z0-9]{36}"                          # other GitHub tokens
    r"|sk_live_[A-Za-z0-9]{10,}"                          # Stripe live key
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"                      # Slack token
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"                # PEM / OpenSSH private key
)
_SCAN_BYTES = 200_000   # don't read whole huge files


# ---- FIX for [A]/[B]: add to graphify/detect.py, next to _is_sensitive() ----
def contains_secret(path: Path) -> bool:
    """True if the file CONTENT looks like it holds a credential."""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return bool(_SECRET_RE.search(f.read(_SCAN_BYTES)))
    except OSError:
        return False


# and change detect.py L2104 from:
#       if _is_sensitive(p):
# to:
#       if _is_sensitive(p) or contains_secret(p):


# ---- FIX for [C]: add to graphify/extract.py, use inside _add_rationale() ----
def redact_secrets(text: str) -> str:
    return _SECRET_RE.sub("[REDACTED]", text)


# and change extract.py L1799 from:
#       label = _shorten_rationale_label(text)
# to:
#       label = _shorten_rationale_label(redact_secrets(text))


# =============================================================================
# SECTION 3 - DEMO (run:  python3 bug.py)
# =============================================================================
def _original_is_sensitive_by_name_only(path: Path) -> bool:
    """Simplified copy of the ORIGINAL name-only logic, enough to show the bug."""
    name_patterns = [
        re.compile(r"\.(pem|key|p12|pfx|cert|crt|der|p8)$", re.I),
        re.compile(r"(^|[^A-Za-z0-9])(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$", re.I),
        re.compile(r"(?<![a-zA-Z0-9])(credential|secret|passwd|password|private_key)s?(?![a-zA-Z])", re.I),
    ]
    return any(p.search(path.name) for p in name_patterns)


def demo() -> None:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        files = {
            "oncall.md":      "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
            "runbook.md":     "aws key: AKIAIOSFODNN7EXAMPLE\n",
            "id_rsa.md":      "-----BEGIN RSA PRIVATE KEY-----\nxyz\n",
            "notes.md":       "just some harmless architecture notes\n",
            "secrets.md":     "password: hunter2\n",          # caught by name already
        }
        for n, c in files.items():
            (root / n).write_text(c)

        print(f"{'file':<12} {'ORIGINAL (name only)':<24} {'FIXED (name + content)':<24}")
        print("-" * 62)
        for n in files:
            p = root / n
            orig = _original_is_sensitive_by_name_only(p)
            fixed = orig or contains_secret(p)
            print(f"{n:<12} {'skipped' if orig else 'INDEXED -> LLM':<24} {'skipped' if fixed else 'indexed':<24}")

        print("\nComment redaction ([C]):")
        comment = "# WHY: the prod token is ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        print("  original label:", comment)
        print("  fixed label   :", redact_secrets(comment))


if __name__ == "__main__":
    demo()
