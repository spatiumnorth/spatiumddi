"""The DNS engine images run as ids outside the host's system-account range.

On the appliance the PowerDNS and Technitium state / data directories are
hostPaths under /var/lib/spatiumddi/agents, so whatever uid the image runs as
is the owner of files on the host. Ids below 1000 there belong to the host's
own system accounts, and 101 / 102 (what these images used to pin) are among
them. The images now use dedicated ids; the PowerDNS image and the dnsdist
front share theirs on purpose (the front reads a 0600 listener key the agent
writes), and the entrypoints re-own existing state on every start.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
IMAGES = REPO / "agent" / "dns" / "images"
POWERDNS_PY = REPO / "agent" / "dns" / "spatium_dns_agent" / "drivers" / "powerdns.py"
DNS_DRIVERS_DOC = REPO / "docs" / "drivers" / "DNS_DRIVERS.md"

# supervisor 10001 (#4596), api 1000.
EXPECTED = {"powerdns": 10002, "dnsdist": 10002, "technitium": 10003}
OLD_IDS = {101, 102}


def _ids(image: str) -> tuple[int, int]:
    text = (IMAGES / image / "Dockerfile").read_text()
    gid = re.search(r"(?:addgroup -S|groupadd) -g (\d+) spatium", text)
    uid = re.search(r"(?:adduser -S|useradd) -u (\d+) ", text)
    assert gid and uid, f"{image}: pinned spatium ids not found"
    return int(uid.group(1)), int(gid.group(1))


def test_images_use_dedicated_ids_outside_the_system_range() -> None:
    for image, want in EXPECTED.items():
        uid, gid = _ids(image)
        assert uid == gid == want, (image, uid, gid)
        assert uid >= 1000 and uid not in OLD_IDS


def test_powerdns_and_dnsdist_agree_and_technitium_is_distinct() -> None:
    assert _ids("powerdns") == _ids("dnsdist")
    assert _ids("technitium") != _ids("powerdns")
    # supervisor (10001) and api (1000) own their own ids
    assert {_ids("powerdns")[0], _ids("technitium")[0]}.isdisjoint({1000, 10001})


def test_entrypoints_reown_existing_state_before_dropping_privileges() -> None:
    pdns = (IMAGES / "powerdns" / "entrypoint.sh").read_text()
    assert "chown -R spatium:spatium /var/lib/spatium-dns-agent /var/lib/powerdns" in pdns
    assert pdns.index("chown -R spatium:spatium") < pdns.index("exec su-exec spatium")
    tech = (IMAGES / "technitium" / "entrypoint.sh").read_text()
    assert "chown -R spatium:spatium /var/lib/spatium-dns-agent /etc/dns" in tech
    assert tech.index("chown -R spatium:spatium") < tech.index("exec gosu spatium")
    # dnsdist holds no state and runs unprivileged from the Dockerfile
    assert "USER spatium" in (IMAGES / "dnsdist" / "Dockerfile").read_text()


def test_no_chart_or_host_code_names_the_old_ids_for_these_workloads() -> None:
    for chart in ("spatiumddi-appliance", "spatiumddi"):
        for name in ("dns-powerdns", "dns-technitium", "dns-agent"):
            f = REPO / "charts" / chart / "templates" / f"{name}.yaml"
            if not f.exists():
                continue
            for line in f.read_text().splitlines():
                m = re.match(r"\s*(runAsUser|runAsGroup|fsGroup):\s*(\d+)", line)
                if m:
                    assert int(m.group(2)) not in OLD_IDS, (f.name, line)
    firstboot = (REPO / "appliance/mkosi.extra/usr/local/bin/spatiumddi-firstboot").read_text()
    for line in firstboot.splitlines():
        if "agents/dns-" in line and "chown" in line:
            assert not re.search(r"chown\s+(-R\s+)?10[12]\b", line), line


def test_docs_and_agent_comments_name_the_current_uid() -> None:
    for f in (POWERDNS_PY, DNS_DRIVERS_DOC):
        text = f.read_text()
        assert "uid 101" not in text, f.name
        assert "uid 10002" in text, f.name
