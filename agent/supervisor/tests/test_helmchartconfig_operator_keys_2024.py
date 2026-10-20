"""An operator's keys in a supervisor-written HelmChartConfig survive (#2024).

``docs/deployment/APPLIANCE.md`` sends an operator to the
``spatiumddi-appliance`` HelmChartConfig to raise ``dnsBind9.resources``.
The supervisor writes the same CR on every heartbeat to carry the data-plane
VIP keys, and it used to replace ``spec.valuesContent`` with those three keys
alone — so the documented override was reverted within a minute.

These tests drive the real write path against a stateful kubeapi stand-in
that applies the PATCHes it receives, so "survives repeated beats" is a
statement about the stored CR, not about one rendered string.
"""

from __future__ import annotations

import json

import yaml

from spatium_supervisor import k8s_api

_CFG = "/helmchartconfigs/"


class _Kube:
    """kubeapi stand-in holding one HelmChartConfig + one HelmChart per name.

    PATCH honours a ``metadata.resourceVersion`` precondition (409 on
    mismatch) and applies the merge-patch to ``spec.valuesContent``; each
    write bumps the resourceVersion, as the apiserver does.
    """

    def __init__(
        self, *, config: dict[str, str] | None = None, chart: dict[str, str] | None = None
    ):
        self.config: dict[str, str] = dict(config or {})
        self.chart: dict[str, str] = dict(chart or {})
        self.rv: dict[str, int] = {n: 1 for n in self.config}
        self.writes: list[tuple[str, str, dict]] = []
        # Called after every GET of a Config, to simulate an operator edit
        # racing the supervisor's read-merge-write.
        self.after_config_get = None

    @staticmethod
    def _name(path: str) -> str:
        return path.rstrip("/").rsplit("/", 1)[-1]

    def __call__(self, method, path, body=None, content_type=None):
        if method == "GET":
            name = self._name(path)
            store = self.config if _CFG in path else self.chart
            if name not in store:
                return (404, "")
            meta = {"resourceVersion": str(self.rv.get(name, 1))} if _CFG in path else {}
            resp = json.dumps({"metadata": meta, "spec": {"valuesContent": store[name]}})
            if _CFG in path and self.after_config_get is not None:
                hook, self.after_config_get = self.after_config_get, None
                hook(self)
            return (200, resp)
        payload = json.loads(body)
        if method == "PATCH":
            name = self._name(path)
            want = (payload.get("metadata") or {}).get("resourceVersion")
            if want is not None and want != str(self.rv[name]):
                return (409, '{"reason":"Conflict"}')
            self.config[name] = payload["spec"]["valuesContent"]
            self.rv[name] += 1
            self.writes.append((method, name, payload))
            return (200, "{}")
        if method == "POST":
            name = payload["metadata"]["name"]
            if name in self.config:
                return (409, '{"reason":"AlreadyExists"}')
            self.config[name] = payload["spec"]["valuesContent"]
            self.rv[name] = 1
            self.writes.append((method, name, payload))
            return (201, "{}")
        raise AssertionError(f"unexpected {method} {path}")

    def doc(self, name: str) -> dict:
        return yaml.safe_load(self.config[name]) or {}

    def operator_edit(self, name: str, doc: dict) -> None:
        """What ``kubectl apply`` / ``kubectl edit`` does: replace the body."""
        self.config[name] = yaml.safe_dump(doc)
        self.rv[name] = self.rv.get(name, 0) + 1


_OPERATOR_LIMIT = {"dnsBind9": {"resources": {"limits": {"memory": "4Gi"}}}}


def _beat(dns_vip: str = "", relay_vip: str = "", mem: int | None = None):
    return k8s_api.apply_dataplane_vip_overrides(
        dns_vip=dns_vip, dhcp_relay_vip=relay_vip, mem_total_mib=mem
    )


# --------------------------------------------------------------------------
# spatiumddi-appliance — the reported case
# --------------------------------------------------------------------------
def test_the_documented_memory_override_survives_repeated_beats(monkeypatch) -> None:
    """The APPLIANCE.md recipe, applied verbatim (it replaces valuesContent,
    dropping the supervisor's keys), then several heartbeats."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    assert _beat() == (True, None)  # supervisor creates the CR

    kube.operator_edit("spatiumddi-appliance", _OPERATOR_LIMIT)

    for _ in range(5):
        _beat()

    doc = kube.doc("spatiumddi-appliance")
    assert doc["dnsBind9"]["resources"]["limits"]["memory"] == "4Gi"
    assert doc["dns"] == {"useMetalLBVIP": False, "vip": ""}
    assert doc["dhcpKea"] == {"relayVIP": ""}


def test_operator_keys_beside_supervisor_keys_survive_exactly(monkeypatch) -> None:
    operator = {
        "dnsBind9": {"resources": {"limits": {"memory": "4Gi"}, "requests": {"cpu": "100m"}}},
        "dns": {"someOperatorKnob": 7},  # a sibling INSIDE an owned block
        "dhcpKea": {"resources": {"limits": {"memory": "1Gi"}}},
    }
    kube = _Kube(config={"spatiumddi-appliance": yaml.safe_dump(operator)})
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _beat("192.0.2.53") == (True, None)

    doc = kube.doc("spatiumddi-appliance")
    assert doc["dnsBind9"] == operator["dnsBind9"]
    assert doc["dhcpKea"]["resources"] == operator["dhcpKea"]["resources"]
    assert doc["dns"]["someOperatorKnob"] == 7
    assert doc["dns"]["useMetalLBVIP"] is True
    assert doc["dns"]["vip"] == "192.0.2.53"


def test_supervisor_keys_are_added_changed_and_cleared(monkeypatch) -> None:
    kube = _Kube(config={"spatiumddi-appliance": yaml.safe_dump(_OPERATOR_LIMIT)})
    monkeypatch.setattr(k8s_api, "_request", kube)

    # added
    assert _beat("192.0.2.53", "192.0.2.67") == (True, None)
    doc = kube.doc("spatiumddi-appliance")
    assert doc["dns"] == {"useMetalLBVIP": True, "vip": "192.0.2.53"}
    assert doc["dhcpKea"] == {"relayVIP": "192.0.2.67"}

    # changed
    assert _beat("192.0.2.54", "192.0.2.67") == (True, None)
    assert kube.doc("spatiumddi-appliance")["dns"]["vip"] == "192.0.2.54"

    # cleared — a merge cannot delete, so "off" is written as explicit values
    assert _beat("", "") == (True, None)
    doc = kube.doc("spatiumddi-appliance")
    assert doc["dns"] == {"useMetalLBVIP": False, "vip": ""}
    assert doc["dhcpKea"] == {"relayVIP": ""}
    assert doc["dnsBind9"] == _OPERATOR_LIMIT["dnsBind9"]


def test_an_unchanged_beat_does_not_write(monkeypatch) -> None:
    """A converged document — operator keys AND the supervisor's — is left
    alone: no PATCH, so no helm revision and no helm-install Job."""
    converged = _OPERATOR_LIMIT | {
        "dns": {"useMetalLBVIP": True, "vip": "192.0.2.53"},
        "dhcpKea": {"relayVIP": ""},
    }
    kube = _Kube(config={"spatiumddi-appliance": yaml.safe_dump(converged)})
    monkeypatch.setattr(k8s_api, "_request", kube)

    for _ in range(3):
        assert _beat("192.0.2.53") == (False, None)

    assert not kube.writes, "an unchanged beat issued a write (a helm revision for nothing)"


def test_operator_formatting_alone_is_not_a_change(monkeypatch) -> None:
    """The comparison is on the parsed document, so an operator's own key
    order / quoting is not rewritten (and their comments not dropped) by a
    beat whose keys already agree."""
    raw = (
        "# raised for the 580k blocklist\n"
        "dnsBind9:\n  resources:\n    limits:\n      memory: 4Gi\n"
        "dns:\n  vip: ''\n  useMetalLBVIP: false\n"
        "dhcpKea:\n  relayVIP: ''\n"
    )
    kube = _Kube(config={"spatiumddi-appliance": raw})
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _beat() == (False, None)
    assert kube.config["spatiumddi-appliance"] == raw


def test_the_upgrade_from_the_old_string_format_does_not_write(monkeypatch) -> None:
    """A CR written by the previous supervisor (hand-rendered string) is the
    same document, so upgrading must not add a helm revision."""
    old = 'dns:\n  useMetalLBVIP: true\n  vip: "192.0.2.53"\ndhcpKea:\n  relayVIP: ""\n'
    kube = _Kube(config={"spatiumddi-appliance": old})
    monkeypatch.setattr(k8s_api, "_request", kube)
    assert _beat("192.0.2.53") == (False, None)
    assert not kube.writes


def test_a_concurrent_operator_edit_is_not_overwritten(monkeypatch) -> None:
    """The PATCH is conditional on the resourceVersion it merged into."""
    kube = _Kube(config={"spatiumddi-appliance": yaml.safe_dump({"dns": {"vip": ""}})})
    monkeypatch.setattr(k8s_api, "_request", kube)
    kube.after_config_get = lambda k: k.operator_edit("spatiumddi-appliance", _OPERATOR_LIMIT)

    ok, err = _beat("192.0.2.53")
    assert ok is False and err and "retrying" in err
    assert kube.doc("spatiumddi-appliance") == _OPERATOR_LIMIT

    # Next beat merges into the operator's document.
    assert _beat("192.0.2.53") == (True, None)
    doc = kube.doc("spatiumddi-appliance")
    assert doc["dnsBind9"] == _OPERATOR_LIMIT["dnsBind9"]
    assert doc["dns"]["vip"] == "192.0.2.53"


def test_an_unreadable_document_is_not_replaced(monkeypatch) -> None:
    kube = _Kube(config={"spatiumddi-appliance": "- not\n- a mapping\n"})
    monkeypatch.setattr(k8s_api, "_request", kube)
    ok, err = _beat("192.0.2.53")
    assert ok is False and err
    assert not kube.writes


# --------------------------------------------------------------------------
# the other supervisor-owned Configs share the path
# --------------------------------------------------------------------------
def test_metallb_operator_keys_survive(monkeypatch) -> None:
    operator = {"metallb": {"speaker": {"logLevel": "debug"}}, "extra": {"a": 1}}
    kube = _Kube(config={"spatium-metallb": yaml.safe_dump(operator)})
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert k8s_api.apply_metallb_overrides(
        metallb_enabled=True, pool_addresses=["192.0.2.10/32"]
    ) == (True, None)
    doc = kube.doc("spatium-metallb")
    assert doc["metallb"]["speaker"] == {"logLevel": "debug"}
    assert doc["extra"] == {"a": 1}
    assert doc["metallb"]["enabled"] is True
    assert doc["metallb"]["ipPool"]["addresses"] == ["192.0.2.10/32"]

    # turning it off is explicit, and again leaves the operator's keys alone
    assert k8s_api.apply_metallb_overrides(metallb_enabled=False, pool_addresses=[]) == (True, None)
    doc = kube.doc("spatium-metallb")
    assert doc["metallb"]["enabled"] is False
    assert doc["metallb"]["ipPool"]["addresses"] == []
    assert doc["metallb"]["speaker"] == {"logLevel": "debug"}

    n = len(kube.writes)
    k8s_api.apply_metallb_overrides(metallb_enabled=False, pool_addresses=[])
    assert len(kube.writes) == n


def test_control_plane_operator_keys_survive(monkeypatch) -> None:
    operator = {"api": {"extraEnv": [{"name": "X", "value": "1"}]}, "image": {"tag": "t"}}
    kube = _Kube(config={"spatium-control": yaml.safe_dump(operator)})
    monkeypatch.setattr(k8s_api, "_request", kube)

    for _ in range(3):
        k8s_api.apply_control_plane_overrides(3, "192.0.2.1", web_ui_allowed_cidrs=[])

    doc = kube.doc("spatium-control")
    assert doc["api"]["extraEnv"] == [{"name": "X", "value": "1"}]
    assert doc["image"] == {"tag": "t"}
    assert doc["api"]["replicas"] == 3
    assert len(kube.writes) == 1


# --------------------------------------------------------------------------
# absent / empty documents — "cannot read" must never mean "not there"
# --------------------------------------------------------------------------
def test_an_absent_cr_is_created(monkeypatch) -> None:
    """A 404 is "no document", not "unknown": the supervisor must still
    CREATE the CR (a fresh appliance, or an operator who deleted it)."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _beat("192.0.2.53") == (True, None)
    assert [m for m, _, _ in kube.writes] == ["POST"]
    assert kube.doc("spatiumddi-appliance")["dns"] == {
        "useMetalLBVIP": True,
        "vip": "192.0.2.53",
    }

    # Deleted out from under us: the next beat re-creates it.
    del kube.config["spatiumddi-appliance"]
    assert _beat("192.0.2.53") == (True, None)
    assert [m for m, _, _ in kube.writes] == ["POST", "POST"]


def test_a_comments_only_document_is_empty_not_unreadable(monkeypatch) -> None:
    """An operator who comments their override out leaves a YAML empty
    document (it parses to null). That is nothing to preserve, not an
    unknown state — refusing it would freeze the VIP keys in this CR for
    good."""
    raw = "# dnsBind9:\n#   resources:\n#     limits:\n#       memory: 4Gi\n"
    kube = _Kube(config={"spatiumddi-appliance": raw})
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _beat("192.0.2.53") == (True, None)
    assert kube.doc("spatiumddi-appliance")["dns"]["vip"] == "192.0.2.53"


def test_an_unparseable_document_says_how_to_recover(monkeypatch) -> None:
    kube = _Kube(config={"spatiumddi-appliance": "dns: [unclosed\n"})
    monkeypatch.setattr(k8s_api, "_request", kube)
    for _ in range(2):  # every beat, not once
        ok, err = _beat("192.0.2.53")
        assert ok is False
        assert err and "fix or delete the HelmChartConfig spatiumddi-appliance" in err
    assert not kube.writes


# --------------------------------------------------------------------------
# #2240 — dns-bind9's memory limit, sized from the seed's RAM, and an
# operator's own value still wins
# --------------------------------------------------------------------------
_APPLIANCE = "spatiumddi-appliance"


def _bind9_limit(doc: dict) -> object:
    return ((doc.get("dnsBind9") or {}).get("resources") or {}).get("limits", {}).get("memory")


def test_dns_bind9_memory_table() -> None:
    """A quarter of what the 2 GiB platform reserve leaves, clamped 2-8 GiB:
    the chart's own 2Gi is the floor, so a small node renders what it did."""
    table = {m: k8s_api.dns_bind9_memory_mib(m) for m in (
        1024, 6144, 8192, 10240, 12288, 16384, 24030, 24576, 32768, 34816, 65536
    )}
    assert table == {
        1024: 2048,
        6144: 2048,
        8192: 2048,
        10240: 2048,
        12288: 2560,
        16384: 3584,
        24030: 5495,
        24576: 5632,   # the #2240 lab's 24 GiB node: ~5.5 GiB
        32768: 7680,
        34816: 8192,
        65536: 8192,
    }


def test_unknown_ram_sizes_nothing() -> None:
    assert k8s_api.dataplane_resources(None, {}) == {}
    assert k8s_api.dataplane_resources(0, {}) == {}


def test_the_seed_sizes_dns_bind9_on_its_first_beat(monkeypatch) -> None:
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _beat(mem=24576) == (True, None)

    doc = kube.doc(_APPLIANCE)
    assert _bind9_limit(doc) == "5632Mi"
    # ...with the record of what the supervisor wrote, in the same document.
    assert doc["supervisorSizing"] == {"dnsBind9MemoryLimit": "5632Mi"}
    assert doc["dns"] == {"useMetalLBVIP": False, "vip": ""}
    assert doc["dhcpKea"] == {"relayVIP": ""}

    # Converged: later beats write nothing.
    n = len(kube.writes)
    for _ in range(3):
        assert _beat(mem=24576) == (False, None)
    assert len(kube.writes) == n


def test_a_small_seed_writes_the_charts_own_floor(monkeypatch) -> None:
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    assert _beat(mem=8192) == (True, None)
    assert _bind9_limit(kube.doc(_APPLIANCE)) == "2048Mi"


def test_the_seeds_own_limit_follows_its_ram(monkeypatch) -> None:
    """The live value is the one the supervisor recorded, so it is the
    supervisor's to re-size (a seed whose RAM grew)."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    assert _beat(mem=16384) == (True, None)
    assert _bind9_limit(kube.doc(_APPLIANCE)) == "3584Mi"

    assert _beat(mem=24576) == (True, None)
    doc = kube.doc(_APPLIANCE)
    assert _bind9_limit(doc) == "5632Mi"
    assert doc["supervisorSizing"] == {"dnsBind9MemoryLimit": "5632Mi"}


def test_the_documented_override_wins_over_the_sizing(monkeypatch) -> None:
    """APPLIANCE.md's recipe, applied verbatim after the supervisor sized the
    limit (it replaces valuesContent, so the record goes with it): the
    operator's 4Gi is kept on every beat."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    assert _beat(mem=24576) == (True, None)

    kube.operator_edit(_APPLIANCE, _OPERATOR_LIMIT)
    for _ in range(5):
        _beat(mem=24576)

    doc = kube.doc(_APPLIANCE)
    assert _bind9_limit(doc) == "4Gi"
    assert "supervisorSizing" not in doc
    assert doc["dns"] == {"useMetalLBVIP": False, "vip": ""}


def test_an_override_from_before_the_sizing_is_kept(monkeypatch) -> None:
    """Every operator value written before #2240 has no record beside it:
    an upgrade must not take it away."""
    kube = _Kube(config={_APPLIANCE: yaml.safe_dump(_OPERATOR_LIMIT)})
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _beat(mem=24576) == (True, None)  # the VIP keys are new

    doc = kube.doc(_APPLIANCE)
    assert doc["dnsBind9"] == _OPERATOR_LIMIT["dnsBind9"]
    assert "supervisorSizing" not in doc
    n = len(kube.writes)
    assert _beat(mem=24576) == (False, None)
    assert len(kube.writes) == n


def test_an_in_place_edit_of_the_limit_is_the_operators(monkeypatch) -> None:
    """``kubectl edit`` keeps the record and changes the value: the value
    now differs from what the supervisor wrote, so it is the operator's,
    even through a RAM change."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    assert _beat(mem=24576) == (True, None)

    doc = kube.doc(_APPLIANCE)
    doc["dnsBind9"]["resources"]["limits"]["memory"] = "7Gi"
    kube.operator_edit(_APPLIANCE, doc)

    for mem in (24576, 32768):
        _beat(mem=mem)
    doc = kube.doc(_APPLIANCE)
    assert _bind9_limit(doc) == "7Gi"
    assert doc["supervisorSizing"] == {"dnsBind9MemoryLimit": "5632Mi"}


def test_deleting_the_override_hands_the_limit_back(monkeypatch) -> None:
    kube = _Kube(config={_APPLIANCE: yaml.safe_dump(_OPERATOR_LIMIT)})
    monkeypatch.setattr(k8s_api, "_request", kube)
    _beat(mem=24576)
    assert _bind9_limit(kube.doc(_APPLIANCE)) == "4Gi"

    doc = kube.doc(_APPLIANCE)
    del doc["dnsBind9"]
    kube.operator_edit(_APPLIANCE, doc)

    assert _beat(mem=24576) == (True, None)
    doc = kube.doc(_APPLIANCE)
    assert _bind9_limit(doc) == "5632Mi"
    assert doc["supervisorSizing"] == {"dnsBind9MemoryLimit": "5632Mi"}


def test_operator_siblings_beside_the_sized_limit_survive(monkeypatch) -> None:
    """An operator who set only a request (or the agent's own knobs) keeps
    them; the supervisor's limit lands beside them."""
    operator = {"dnsBind9": {"resources": {"requests": {"cpu": "500m"}}, "logLevel": "debug"}}
    kube = _Kube(config={_APPLIANCE: yaml.safe_dump(operator)})
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _beat(mem=24576) == (True, None)

    doc = kube.doc(_APPLIANCE)
    assert doc["dnsBind9"] == {
        "resources": {"requests": {"cpu": "500m"}, "limits": {"memory": "5632Mi"}},
        "logLevel": "debug",
    }


def test_without_a_size_no_dns_limit_is_written(monkeypatch) -> None:
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    assert _beat("192.0.2.53") == (True, None)
    doc = kube.doc(_APPLIANCE)
    assert "dnsBind9" not in doc and "supervisorSizing" not in doc


def test_the_sizing_does_not_write_when_the_chart_already_carries_it(monkeypatch) -> None:
    """The #1005 guard covers the new keys too: a role HelmChart that
    already renders them (and a Config that already says so) is left alone."""
    converged = {
        "dns": {"useMetalLBVIP": False, "vip": ""},
        "dhcpKea": {"relayVIP": ""},
        "dnsBind9": {"resources": {"limits": {"memory": "5632Mi"}}},
        "supervisorSizing": {"dnsBind9MemoryLimit": "5632Mi"},
    }
    kube = _Kube(
        config={_APPLIANCE: yaml.safe_dump(converged)},
        chart={_APPLIANCE: yaml.safe_dump({"dnsBind9": {"enabled": True}})},
    )
    monkeypatch.setattr(k8s_api, "_request", kube)
    assert _beat(mem=24576) == (False, None)
    assert not kube.writes
