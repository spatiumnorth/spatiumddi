"""``firewall_extra`` allowlist-grammar lint (#285 Phase 3d).

``firewall_extra`` is the operator's free-text nft escape hatch — appended
VERBATIM into the rendered drop-in (``compile_firewall_from_policies`` tail).
The merge sanitises *derived* CIDRs (``_validated_cidrs``), but this block is
unparsed today. This linter is a thin, regex-free pre-flight that classifies
findings two ways:

* ``error`` — genuinely dangerous patterns that get a hard 422 in the write
  path: nft-injection / shell metacharacters (``; ` $ \\ | &``), unbalanced
  braces, and any rule that DROPs port 22 (the mgmt floor, which a rule
  may never remove — #1009's ``ssh_lockdown`` scopes it as a SETTING,
  which is a different surface with its own guards).
* ``warning`` — grammar the linter doesn't love but ``nft -c -f`` (the
  ultimate authority on the host) may still accept: an unscoped rule (no
  ``ip/ip6 saddr``), a missing action, ``dport`` on icmp, a family-mismatched
  or invalid CIDR, an unquoted comment. These are ADVISORY — surfaced in the
  preview UI, never write-blocking — so a too-strict grammar can't disagree
  with ``nft`` and refuse a valid rule.

§6.3 grammar (informal):
    rule_line    := saddr_clause? proto_clause+ action comment?
    saddr_clause := ("ip" | "ip6") "saddr" "{" cidr ("," cidr)* "}"
    proto_clause := ("tcp"|"udp") "dport" port_spec | ("icmp"|"icmpv6") ...
    action       := "accept" | "drop"
    comment      := "comment" QUOTED_STRING

The write path lints ONLY the delta (when ``firewall_extra`` is in the PATCH
body), so a pre-3d value that predates the grammar is never retro-rejected.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# nft-injection / shell metacharacters that have no place in a single
# accept/drop rule line (scanned OUTSIDE the quoted comment value). ';'
# separates nft statements; backtick / '$' are shell; '\' line-continues;
# '|' / '&' are shell. Unbalanced braces are checked separately.
_FORBIDDEN_CHARS = ";`$\\|&"
_ACTIONS = ("accept", "drop")


@dataclass(frozen=True)
class LintFinding:
    line: int
    severity: str  # "error" | "warning"
    message: str


def lint_firewall_extra(text: str | None) -> list[LintFinding]:
    """Lint a ``firewall_extra`` block line-by-line. Blank + ``#`` comment
    lines are skipped. Returns all findings (both severities)."""
    findings: list[LintFinding] = []
    for i, raw in enumerate((text or "").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        _lint_line(i, line, findings)
    return findings


def errors(findings: list[LintFinding]) -> list[LintFinding]:
    return [f for f in findings if f.severity == "error"]


def warnings(findings: list[LintFinding]) -> list[LintFinding]:
    return [f for f in findings if f.severity == "warning"]


# ── line parsing (regex-free) ─────────────────────────────────────────


def _split_off_comment(line: str) -> tuple[str, str | None]:
    """Split a rule line into (pre-comment part, comment value or None).

    The comment value is free text (quoted) so it's NOT metachar-scanned —
    splitting it off lets ``comment "web (prod)"`` keep its parentheses.
    """
    parts = line.split()
    if "comment" not in parts:
        return line, None
    ci = parts.index("comment")
    return " ".join(parts[:ci]), " ".join(parts[ci + 1 :])


def _tokens(s: str) -> list[str]:
    for ch in "{},":
        s = s.replace(ch, f" {ch} ")
    return s.split()


def _braced_after(toks: list[str], anchor: str) -> list[str]:
    """Values inside the ``{ … }`` immediately following ``anchor`` (e.g.
    ``saddr``), excluding the braces + commas."""
    if anchor not in toks:
        return []
    try:
        start = toks.index("{", toks.index(anchor))
    except ValueError:
        return []
    out: list[str] = []
    for t in toks[start + 1 :]:
        if t == "}":
            break
        if t not in ("{", ","):
            out.append(t)
    return out


def _dport_ports(toks: list[str]) -> set[int]:
    """Integer ports following any ``dport`` token (bare, set, or range)."""
    ports: set[int] = set()
    for idx, t in enumerate(toks):
        if t != "dport":
            continue
        for tok in toks[idx + 1 :]:
            if tok in ("{", ",", "}"):
                continue
            piece = tok
            for part in piece.split("-"):  # range PORT-PORT
                if part.isascii() and part.isdigit():
                    ports.add(int(part))
            if not piece.replace("-", "").isdigit() and piece not in ("{", "}", ","):
                break  # left the port-spec
    return ports


def _comment_quoted(value: str) -> bool:
    v = value.strip()
    return len(v) >= 2 and v.startswith('"') and v.endswith('"')


def _lint_line(i: int, line: str, findings: list[LintFinding]) -> None:
    pre, comment_value = _split_off_comment(line)

    bad = sorted({c for c in pre if c in _FORBIDDEN_CHARS})
    if bad:
        findings.append(
            LintFinding(
                i,
                "error",
                f"forbidden character(s) {bad} — firewall_extra is appended verbatim "
                "into nft; injection / shell metacharacters are rejected",
            )
        )
        return
    # Brace-balance on the comment-stripped portion only — nft allows literal
    # ``{``/``}`` inside a quoted ``comment "…"`` string, so scanning the whole
    # line would false-reject a valid rule whose comment text contains a brace.
    if pre.count("{") != pre.count("}"):
        findings.append(LintFinding(i, "error", "unbalanced braces { }"))
        return

    toks = _tokens(pre)
    ports = _dport_ports(toks)

    if "drop" in toks and 22 in ports:
        findings.append(
            LintFinding(
                i,
                "error",
                "must not drop port 22 (ssh) — the management floor is not " "removable by a rule",
            )
        )

    if not any(a in toks for a in _ACTIONS):
        findings.append(
            LintFinding(i, "warning", "no accept/drop action — nft will reject this at apply")
        )

    has_saddr = len(toks) >= 2 and toks[0] in ("ip", "ip6") and "saddr" in toks
    if not has_saddr:
        findings.append(
            LintFinding(
                i,
                "warning",
                "operator rules should scope a source (ip/ip6 saddr { … }); an "
                "unscoped rule belongs in a builtin role policy",
            )
        )
    else:
        fam = toks[0]
        for c in _braced_after(toks, "saddr"):
            try:
                net = ipaddress.ip_network(c, strict=False)
            except (ValueError, TypeError):
                if any(ch in c for ch in ".:"):  # looked like an address
                    findings.append(LintFinding(i, "warning", f"invalid CIDR {c!r}"))
                continue
            if fam == "ip" and net.version == 6:
                findings.append(
                    LintFinding(i, "warning", f"v6 CIDR {c} inside an ip (v4) saddr set")
                )
            elif fam == "ip6" and net.version == 4:
                findings.append(LintFinding(i, "warning", f"v4 CIDR {c} inside an ip6 saddr set"))

    if "dport" in toks and ("icmp" in toks or "icmpv6" in toks):
        findings.append(LintFinding(i, "warning", "dport has no meaning on icmp/icmpv6"))

    if comment_value is not None and not _comment_quoted(comment_value):
        findings.append(
            LintFinding(i, "warning", 'comment value must be double-quoted, e.g. comment "web"')
        )


__all__ = ["LintFinding", "errors", "lint_firewall_extra", "warnings"]
