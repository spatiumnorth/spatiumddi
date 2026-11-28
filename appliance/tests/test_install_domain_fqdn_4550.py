"""An appliance can be given a DNS domain (#4550).

The hostname screen refused dots and nothing rendered a domain, so
``hostname -f`` returned the short name, NetworkManager carried no
``dns-search`` and the self-signed Web UI certificate had no FQDN SAN.

Asserted on rendered output (the parsed preseed environment, the generated
``/etc/hosts`` line, the keyfile search line), not on prose.

HOW TO RUN:
    python3 -m pytest appliance/tests/test_install_domain_fqdn_4550.py -v
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest
from _installer_source import BIN, SRC, extract_fn

PARSER = BIN / "spatium-preseed-parse"
ETC_RENDER = (BIN / "spatium-etc-render").read_text(encoding="utf-8")
FIRSTBOOT = (BIN / "spatiumddi-firstboot").read_text(encoding="utf-8")

BASE = """\
spatium_preseed:
  role: control-plane
  hostname: ddi1
  admin_password: "ChangeMe!12345"
  network:
    mode: dhcp
%s
"""


def _check_field(kind: str, value: str, *ctx: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", str(PARSER), "--check-field", kind, value, *ctx],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _parse(tmp_path: Path, extra: str) -> tuple[subprocess.CompletedProcess, str]:
    conf = tmp_path / "p.yaml"
    conf.write_text(BASE % extra, encoding="utf-8")
    env, sec = tmp_path / "env", tmp_path / "sec"
    r = subprocess.run(
        ["python3", str(PARSER), str(conf), str(env), str(sec)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return r, env.read_text(encoding="utf-8") if env.exists() else ""


# ── Validation ────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", ["corp.example.com", "Corp.Example.COM.", "lab", "a-b.c1.io"])
def test_domain_accepts_valid(value: str) -> None:
    assert _check_field("domain", value, "ddi1").returncode == 0


@pytest.mark.parametrize(
    "value",
    ["bad..dom", "-lead.example.com", "trail-.example.com", "sp ace.com", "under_score.com",
     "a" * 64 + ".com", ".leading"],
)
def test_domain_rejects_invalid(value: str) -> None:
    r = _check_field("domain", value, "ddi1")
    assert r.returncode == 2 and r.stdout.strip()


def test_domain_total_fqdn_length_is_bounded() -> None:
    dom = ".".join(["a" * 60] * 4)  # 243 chars
    assert _check_field("domain", dom, "h").returncode == 0
    r = _check_field("domain", dom, "h" * 20)
    assert r.returncode == 2 and "253" in r.stdout


def test_dns_search_limits() -> None:
    assert _check_field("dns_search", "a.example b.example").returncode == 0
    assert _check_field("dns_search", "a.example,b.example").returncode == 0
    r = _check_field("dns_search", " ".join(f"d{i}.example" for i in range(7)))
    assert r.returncode == 2 and "at most 6" in r.stdout
    assert _check_field("dns_search", "bad..x").returncode == 2


# ── Preseed ───────────────────────────────────────────────────────────


def test_preseed_domain_and_search_land_in_env(tmp_path: Path) -> None:
    r, env = _parse(tmp_path, "  domain: Corp.Example.com.\n  dns_search: [corp.example.com, example.com]")
    assert r.returncode == 0, r.stderr
    assert "DOMAIN_NAME=corp.example.com" in env
    assert re.search(r"DNS_SEARCH='?corp.example.com example.com'?", env)
    assert "PRESEED_HAS_DOMAIN=1" in env and "PRESEED_HAS_DNS_SEARCH=1" in env


def test_preseed_without_domain_sets_nothing(tmp_path: Path) -> None:
    r, env = _parse(tmp_path, "")
    assert r.returncode == 0, r.stderr
    assert "DOMAIN_NAME" not in env and "DNS_SEARCH" not in env


def test_preseed_bad_domain_is_an_error(tmp_path: Path) -> None:
    r, _ = _parse(tmp_path, "  domain: bad..dom")
    assert r.returncode == 2


# ── Installer wiring ──────────────────────────────────────────────────


def test_installer_writes_fqdn_to_hosts_and_state() -> None:
    assert "127.0.1.1 ${DOMAIN_NAME:+$HOSTNAME.$DOMAIN_NAME }$HOSTNAME" in SRC
    assert 'domain: "$DOMAIN_NAME"' in SRC
    assert 'dns_search: "$(_effective_dns_search)"' in SRC


def test_installer_hosts_line_renders_fqdn_then_short_name() -> None:
    line = 'echo "127.0.1.1 ${DOMAIN_NAME:+$HOSTNAME.$DOMAIN_NAME }$HOSTNAME"'
    run = lambda d: subprocess.run(  # noqa: E731
        ["bash", "-c", f'HOSTNAME=ddi1 DOMAIN_NAME="{d}"; {line}'],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert run("corp.example.com") == "127.0.1.1 ddi1.corp.example.com ddi1"
    assert run("") == "127.0.1.1 ddi1"


def test_effective_search_defaults_to_domain() -> None:
    fn = extract_fn("_effective_dns_search")
    out = subprocess.run(
        ["bash", "-c", f'{fn}\nDNS_SEARCH=""; DOMAIN_NAME=corp.example.com; _effective_dns_search; echo; '
         'DNS_SEARCH="x.example"; _effective_dns_search'],
        capture_output=True, text=True, check=True,
    ).stdout.split("\n")
    assert out == ["corp.example.com", "x.example"]


def test_wizard_asks_domain_and_review_shows_fqdn() -> None:
    assert "_ask_domain" in extract_fn("ask_hostname")
    review = SRC
    assert 'FQDN:        $HOSTNAME.$DOMAIN_NAME' in review
    assert 'DNS search:  $DNS_SEARCH' in review
    assert '${HOSTNAME}${DOMAIN_NAME:+.$DOMAIN_NAME}' in review


# ── Render (spatium-etc-render) ───────────────────────────────────────


def _etc_render_fn(name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{$.*?^\}}$", ETC_RENDER, re.MULTILINE | re.DOTALL)
    assert m
    return m.group(0)


def _search_line(cfg: str, tmp_path: Path) -> str:
    conf = tmp_path / "spatium-config.yaml"
    conf.write_text(cfg, encoding="utf-8")
    script = f'CONFIG={conf}\n' + _etc_render_fn("get_cfg") + "\n" + _etc_render_fn("_dns_search_line") + "\n_dns_search_line"
    return subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=True).stdout.strip()


def test_keyfile_search_line(tmp_path: Path) -> None:
    assert _search_line('dns_search: "corp.example.com example.com"\n', tmp_path) == "dns-search=corp.example.com;example.com;"
    assert _search_line('dns_search: ""\n', tmp_path) == ""
    # Anything that is not a plain domain name is dropped, not written.
    assert _search_line('dns_search: "ok.example bad;x -y a..b"\n', tmp_path) == "dns-search=ok.example;"


def _hosts_block() -> str:
    m = re.search(r"^DOMAIN_VAL=.*?^fi$", ETC_RENDER, re.MULTILINE | re.DOTALL)
    assert m, "the /etc/hosts block moved"
    return m.group(0)


def _render_hosts(tmp_path: Path, cfg: str, hosts: str) -> str:
    conf = tmp_path / "spatium-config.yaml"
    conf.write_text(cfg, encoding="utf-8")
    hf = tmp_path / "hosts"
    hf.write_text(hosts, encoding="utf-8")
    block = _hosts_block().replace("/etc/hosts", str(hf))
    script = (
        f"CONFIG={conf}\n{_etc_render_fn('get_cfg')}\n"
        f'HOSTNAME_VAL="$(get_cfg hostname)"\n{block}\n'
    )
    subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=True, cwd=tmp_path)
    return hf.read_text(encoding="utf-8")


HOSTS = "127.0.0.1 localhost\n127.0.1.1 ddi1\n10.0.0.9 mine.example\n::1 ip6-localhost\n"


def test_hosts_gets_fqdn_first_and_keeps_other_lines(tmp_path: Path) -> None:
    out = _render_hosts(tmp_path, 'hostname: "ddi1"\ndomain: "corp.example.com"\n', HOSTS)
    assert out.splitlines() == [
        "127.0.0.1 localhost",
        "127.0.1.1 ddi1.corp.example.com ddi1",
        "10.0.0.9 mine.example",
        "::1 ip6-localhost",
    ]


def test_hosts_drops_the_fqdn_when_the_domain_is_removed(tmp_path: Path) -> None:
    out = _render_hosts(tmp_path, 'hostname: "ddi1"\ndomain: ""\n', "127.0.0.1 localhost\n127.0.1.1 ddi1.old.example ddi1\n")
    assert out.splitlines() == ["127.0.0.1 localhost", "127.0.1.1 ddi1"]


# ── Certificate ───────────────────────────────────────────────────────


def test_firstboot_adds_fqdn_san_and_env() -> None:
    assert 'san_parts="$san_parts,DNS:$APPLIANCE_FQDN_VAL"' in FIRSTBOOT
    assert "- name: APPLIANCE_FQDN" in FIRSTBOOT
