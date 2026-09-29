"""nmap ``extra_args`` is an allowlist, not a blocklist (#1223).

The scan endpoint is gated on ``manage_nmap_scans``, which the builtin
Network Editor role holds, so ``extra_args`` is a delegated user's input.
It used to be checked only for shell metacharacters and for ``/`` in
``--script`` values, which let through ``-iL <file>`` (nmap reads the file
and echoes the lines it cannot resolve into the scan output the caller
streams), ``-oN <path>`` (writes a file as the api user), ``--datadir``,
``--resume``, ``--script-args`` file paths, and every intrusive / exploit /
dos / brute script. Every refusal below is one of those, or a way around
the target checks (a bare extra target, ``-iR``) or the no-outbound rule
(``external`` scripts, non-negotiable #17).

Scripts are classified from a fixture ``script.db`` in nmap's own format,
plus one test against the real file when the image carries nmap.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from app.services.nmap import runner
from app.services.nmap.runner import NmapArgError, build_argv

_SCRIPT_DB = """\
Entry { filename = "http-title.nse", categories = { "default", "discovery", "safe", } }
Entry { filename = "ssh-hostkey.nse", categories = { "default", "discovery", "safe", } }
Entry { filename = "http-enum.nse", categories = { "discovery", "intrusive", "vuln", } }
Entry { filename = "whois-ip.nse", categories = { "discovery", "external", "safe", } }
Entry { filename = "smb-vuln-ms17-010.nse", categories = { "safe", "vuln", } }
Entry { filename = "http-slowloris.nse", categories = { "dos", "vuln", } }
"""


@pytest.fixture(autouse=True)
def script_db(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    path = tmp_path / "script.db"
    path.write_text(_SCRIPT_DB)
    monkeypatch.setattr(runner, "_NMAP_SCRIPT_DB", str(path))
    return path


@pytest.mark.parametrize(
    "extra",
    [
        "",
        "--reason -Pn",
        "-T4 --top-ports 100",
        "-T aggressive",
        "-p22,80 -sV",
        "-p 1-1000 --exclude-ports 25",
        "-p-",
        "--max-retries=2 --host-timeout 30s --scan-delay 200ms",
        "-PS22,443 -PE -PA",
        "-vv --open --packet-trace",
        "-sU -F -r",
        "--version-intensity 5 --version-all",
        "-6 -n",
        "--script http-title,ssh-hostkey",
        "--script=http-title.nse",
        # safe AND vuln, and nothing forbidden: a check, not an attack.
        "--script smb-vuln-ms17-010",
    ],
)
def test_scan_shaping_options_are_accepted(extra: str) -> None:
    argv = build_argv("192.0.2.10", "custom", None, extra)
    assert argv[-1] == "192.0.2.10"


@pytest.mark.parametrize(
    "extra",
    [
        # the issue's list: file read, file write, datadir, resume, script args
        "-iL /etc/passwd",
        "-iL",
        "-oN /tmp/out",
        "-oA /tmp/out",
        "-oG -",
        "-oX /tmp/out.xml",
        "-oS /tmp/out",
        "--datadir /tmp",
        "--datadir=/tmp",
        "--resume /tmp/scan.log",
        "--script-args userdb=/etc/passwd",
        "--script-args=http.useragent=x",
        "--script-args-file /tmp/args",
        "--excludefile /etc/passwd",
        "--stylesheet http://example.com/x.xsl",
        "--servicedb /tmp/x",
        "--versiondb /tmp/x",
        # scripts: forbidden categories, and every way to name a set of them
        "--script http-enum",
        "--script whois-ip",
        "--script http-slowloris",
        "--script http-title,http-enum",
        "--script exploit",
        "--script vuln",
        "--script default",
        "--script safe",
        "--script http-*",
        "--script 'not intrusive'",
        "--script /tmp/evil.nse",
        "--script ../evil",
        "--script no-such-script",
        "--script",
        "--script-updatedb",
        # extra targets, past target validation and the #722 policy
        "8.8.8.8",
        "-Pn 10.0.0.0/8",
        "-iR 100",
        # spoofing / evasion / privilege
        "-S 192.0.2.1",
        "-D RND:10",
        "-e eth0",
        "--spoof-mac 0",
        "-sI zombie.example",
        "-b ftp.example",
        "--proxies http://proxy:8080",
        "--privileged",
        "-f",
        "--data-string x",
        # presets exist for these
        "-sC",
        "-A",
        # malformed values
        "-p",
        "--top-ports abc",
        "-p22;id",
        "-T9",
        "--host-timeout forever",
        "--version-intensity 10",
        "-PS22;id",
    ],
)
def test_everything_else_is_refused(extra: str) -> None:
    with pytest.raises(NmapArgError):
        build_argv("192.0.2.10", "custom", None, extra)


def test_the_refusal_names_the_token() -> None:
    with pytest.raises(NmapArgError, match=r"'-iL'"):
        build_argv("192.0.2.10", "custom", None, "--reason -iL /etc/passwd")


def test_a_forbidden_script_names_its_category() -> None:
    with pytest.raises(NmapArgError, match="external"):
        build_argv("192.0.2.10", "custom", None, "--script whois-ip")


def test_script_is_refused_when_the_database_is_unreadable(
    script_db: pathlib.Path,
) -> None:
    """Unknown is not safe. Other options keep working."""
    script_db.unlink()
    with pytest.raises(NmapArgError, match="script database"):
        build_argv("192.0.2.10", "custom", None, "--script http-title")
    build_argv("192.0.2.10", "custom", None, "-sV --reason")


def test_the_base_output_flags_are_ours_alone() -> None:
    """The runner's own -oN - / -oX <tmp> stay; extra_args cannot add more."""
    argv = build_argv("192.0.2.10", "quick", "22", "--reason", xml_output_path="/tmp/s.xml")
    assert argv[:3] == ["nmap", "-oN", "-"]
    assert argv.count("-oX") == 1
    assert argv[-1] == "192.0.2.10"


_REAL_DB = "/usr/share/nmap/scripts/script.db"


@pytest.mark.skipif(not os.path.exists(_REAL_DB), reason="nmap not installed in this image")
def test_the_real_script_database_classifies_as_expected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Against the database the api image actually ships."""
    monkeypatch.setattr(runner, "_NMAP_SCRIPT_DB", _REAL_DB)
    build_argv("192.0.2.10", "custom", None, "--script http-title,ssh-hostkey")
    for script in ("http-enum", "whois-ip", "http-slowloris", "ssh-brute"):
        with pytest.raises(NmapArgError):
            build_argv("192.0.2.10", "custom", None, f"--script {script}")
