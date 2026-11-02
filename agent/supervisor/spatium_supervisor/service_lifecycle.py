"""Supervisor service-lifecycle module (#183 Phase 7 — k3s-only).

Owns the supervisor's orchestration plane: applies role assignments
from the control-plane heartbeat to the local k3s by PATCHing
``HelmChart`` Custom Resources into the kubeapi. k3s's bundled
helm-controller picks the CRs up + runs ``helm upgrade --install``
for us on the next reconcile cycle.

Before Phase 7 there was a parallel docker-compose path in this
module + ``docker_api.py``. Phase 7 retires docker entirely; both
are deleted, and the k3s path graduates to the only path.

Design notes:

* The supervisor doesn't run ``helm`` itself. We construct a
  ``HelmChart`` CR carrying ``spec.chartContent`` (base64-encoded
  tarball) + ``spec.valuesContent`` (rendered YAML) and PATCH it.

* The chart tarball is **baked into the slot** at
  ``/usr/lib/spatiumddi/charts/spatiumddi-appliance.tgz`` by the
  build-time ``appliance/scripts/bake-chart.sh`` script. Air-gap
  friendly: no chart registry, no internet calls, no ``helm pull``
  at runtime.

* Values are derived from the heartbeat-response ``role_assignment``
  shape (rendered by ``role_orchestrator``).
  ``COMPOSE_PROFILES`` keys translate to per-role
  ``<role>.enabled: true`` flags + the agent keys / group names /
  control-plane URL.

Failures are surfaced as ``state="failed"`` with a single-line
``reason`` so the Fleet drilldown's red banner stays readable.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import structlog

from . import appliance_state, cp_tls, k8s_api


@dataclass(frozen=True)
class LifecycleResult:
    """Outcome of one ``apply_role_assignment`` or
    ``tear_down_supervised_services`` pass.

    ``state`` mirrors what the supervisor reports in the next
    heartbeat under ``role_switch_state``: ``idle`` / ``ready`` /
    ``failed``. ``reason`` carries the failure detail (kubeapi
    error first line is usually enough) so the operator can triage
    without SSH-ing in.
    """

    state: str  # ready | failed | idle
    reason: str | None = None
    started: tuple[str, ...] = ()
    stopped: tuple[str, ...] = ()
    # #1750 — the apply wrote nothing because this node may not write the
    # chart right now (it shares a cluster it is not a member of). Reported as
    # ``idle``, but the heartbeat must not stamp its apply key on it, or the
    # node would never write its own chart once it is allowed to again (a
    # demoted node's fresh standalone cluster after ``left``).
    deferred: bool = False


# Service names the appliance can run. Match the chart's component
# names (``app.kubernetes.io/component`` labels). The watchdog uses
# this set to enumerate "which pods should I expect".
#
# #566 — ``looking-glass`` (the BGP Looking Glass / GoBGP collector)
# uses an identity profile↔component mapping, same as the DNS roles
# (only ``dhcp``'s profile token diverges from its ``dhcp-kea``
# component name).
SUPERVISED_SERVICES: tuple[str, ...] = (
    "dns-bind9",
    "dns-powerdns",
    "dns-technitium",
    "dhcp-kea",
    "looking-glass",
)

log = structlog.get_logger(__name__)

# Baked-chart path the build-time script writes (#183 Phase 3).
# Slot-baked at build time (mkosi.extra/ copy), like the image tarballs
# under /var/lib/rancher/k3s/agent/images/.
_BAKED_CHART_TARBALL = Path("/usr/lib/spatiumddi/charts/spatiumddi-appliance.tgz")

# HelmChart CR name + namespaces. Single chart per appliance — one
# install drives every assigned role via per-role enabled flags.
# The CR itself lives in kube-system (where helm-controller watches);
# the deployed pods live in the dedicated "spatium" namespace.
_HELMCHART_NAME = "spatiumddi-appliance"
_CHART_NAMESPACE = "kube-system"
_TARGET_NAMESPACE = "spatium"

# Profile → Helm chart key mapping. ``compose_profiles`` from the
# rendered env file uses compose-style names; the chart's values.yaml
# uses camelCase per-role blocks.
_PROFILE_TO_HELM_KEY = {
    "dns-bind9": "dnsBind9",
    "dns-powerdns": "dnsPowerdns",
    "dns-technitium": "dnsTechnitium",
    "dhcp": "dhcpKea",
    "looking-glass": "lookingGlass",
}

# Phase 10 (#183) — every role the chart templates have a per-role
# nodeSelector for. The supervisor labels the node with
# ``spatium.io/role-<key>=true`` for each role in the desired set
# and clears the label for each role leaving. Pod scheduling gates
# on the label being present, so role swap = label flip.
#
# Keep in lock-step with the per-template ``nodeSelector`` blocks in
# charts/spatiumddi-appliance/templates/*.yaml (service-agent
# workloads) and charts/spatiumddi/templates/*.yaml (control-plane
# workloads).
_ROLE_LABEL_KEYS = {
    "dns-bind9": "spatium.io/role-dns-bind9",
    "dns-powerdns": "spatium.io/role-dns-powerdns",
    "dns-technitium": "spatium.io/role-dns-technitium",
    "dhcp": "spatium.io/role-dhcp",
    # #566 — BGP Looking Glass collector (GoBGP). Same per-role
    # node-label gating shape as DNS/DHCP (non-negotiable #16).
    "looking-glass": "spatium.io/role-looking-glass",
    # #272 — gate the umbrella chart's frontend / api / worker / beat /
    # postgres / redis workloads onto the control-plane variant (never
    # an appliance). Multi-node HA selects between control-plane members
    # via this label.
    "control-plane": "spatium.io/role-control-plane",
}

# #2190 — the agent DaemonSet each role label schedules, and the role-env key
# whose value the chart renders into that DaemonSet's ``AGENT_GROUP``
# (``serverGroupName`` in ``_build_values``). A label is only ever SET once the
# DaemonSet's live template carries the group this node is assigned, so a label
# flip cannot start a pod from the previous chart revision: the node labels
# land in milliseconds, the values only once helm-controller's upgrade job has
# run (~6-11 s), and a pod scheduled in between registered with the previous
# group. Keep in lock-step with the per-role ``serverGroupName`` keys in
# ``_build_values`` (a test asserts they agree).
#
# #3202: no ``dhcp`` entry. The dhcp-kea template carries no group (the one
# pod template of every node cannot carry one node's), so there is nothing to
# wait for, and a Kea agent registers into the group its appliance is assigned
# whatever its env says. An entry here would hold every dhcp label for the full
# ``_LABEL_HOLD_MAX_SECONDS``.
_ROLE_AGENT_GROUP: dict[str, tuple[str, str]] = {
    "dns-bind9": ("dns-bind9", "AGENT_GROUP"),
    "dns-powerdns": ("dns-powerdns", "AGENT_GROUP"),
    "dns-technitium": ("dns-technitium", "AGENT_GROUP"),
}

# How long the apply waits, after its values write, for helm-controller to roll
# the new template before it gives up for this tick (the next heartbeat's
# reconcile sets the label once the template is current), and how often it
# re-reads. And the longest a label is held across ticks before it is set
# regardless: a template that never matches (a shared chart another node writes,
# a template edited out of band) must not keep a role off a node for ever. The
# control plane's registration is the backstop past that (#2190 backend half).
_LABEL_WAIT_SECONDS = 30.0
_LABEL_WAIT_STEP_SECONDS = 2.0
_LABEL_HOLD_MAX_SECONDS = 300.0
_sleep = time.sleep
_monotonic = time.monotonic
# role label -> monotonic time it was first held back.
_label_held_since: dict[str, float] = {}


# #272 — per-variant FORCED role set. The supervisor reads its variant
# from ``/etc/spatiumddi-host/role-config:ROLE`` and always asserts
# these labels on the node, on top of whatever operator-assigned roles
# arrive via the heartbeat response. The supervisor is the single
# source of truth for node labels; install-time drop-ins are only a
# boot bootstrap (so pods can schedule before the supervisor is up).
#
# Two variants, and only ``control-plane`` is forced:
#   * control-plane — forces the control-plane label so the umbrella
#     workloads (api / frontend / db / redis / worker / beat) never
#     lose their node. DNS/DHCP/looking-glass are NOT forced here AND
#     NOT auto-assigned at register — the operator enables them per
#     node via the Fleet role toggle (so the data plane is always a
#     deliberate fleet decision, and a promoted control-plane node can
#     shed them).
#   * appliance — nothing forced. Operator-assigned roles only.
# Forcing DNS/DHCP here would re-add the labels every tick and make the
# Fleet toggle a no-op, so they must stay out of every forced set.
_VARIANT_FIXED_ROLES: dict[str, frozenset[str]] = {
    "control-plane": frozenset({"control-plane"}),
    "appliance": frozenset(),
}


@dataclass(frozen=True)
class K3sEnvironment:
    """Result of probing whether k3s is the live runtime."""

    available: bool
    reason: str | None = None
    # #1716 — the kube API did not answer ``/readyz`` this tick: a miss to try
    # again, not a slot that has no k3s path at all.
    kubeapi_unready: bool = False


def k3s_available() -> K3sEnvironment:
    """Return whether the k3s path is ready to use.

    Checks (all must pass):
      * Chart tarball baked into the slot
      * Kubeapi reachable (``/readyz`` returns ok)

    Returns an ``unavailable`` with a human reason when any fails
    so heartbeat-level logging can show *why* the supervisor stayed
    on docker compose this tick."""
    if not _BAKED_CHART_TARBALL.exists():
        return K3sEnvironment(available=False, reason="chart tarball not baked")
    if not k8s_api.check_kubeapi_ready():
        return K3sEnvironment(
            available=False, reason="kubeapi /readyz not ok", kubeapi_unready=True
        )
    return K3sEnvironment(available=True)


def _parse_env_file(env_file: Path) -> dict[str, str]:
    """Read the rendered role-compose env file into a dict. Same
    format render_env_file produces: ``KEY=value`` lines, comments
    prefixed with ``#``, blanks ignored."""
    out: dict[str, str] = {}
    if not env_file.exists():
        return out
    try:
        text = env_file.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("supervisor.k3s_lifecycle.env_read_failed", error=str(exc))
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _build_values(profiles: list[str], env_vars: dict[str, str]) -> dict[str, object]:
    """Construct the Helm values dict from the active profile set +
    rendered env. Mirrors the per-role values.yaml structure in
    ``charts/spatiumddi-appliance/``.

    Air-gap defaults are inherited from the chart's values.yaml;
    here we only override what changes per-appliance (per-role
    enabled flags + agent keys + group names + control-plane URL).
    """
    control_plane_url = role_control_plane_url(env_vars)
    image_tag = role_image_tag(env_vars)

    # Phase 10 wave 2 — ``enabled`` flags here are RELEASE-ownership
    # scope (which helm release owns which Deployment), NOT
    # role-scheduling scope. Scheduling is gated by node labels
    # exclusively (``spatium.io/role-<role>=true``); the supervisor
    # toggles those on every heartbeat via reconcile_node_labels.
    #
    # The role release renders every agent DaemonSet whose KEY it has
    # (so the chart renders + helm tracks the DaemonSet); the bootstrap
    # release sets them all false (so spatium-bootstrap doesn't fight
    # us for ownership). A role swap between DNS engines is still a
    # pure label flip — one ``DNS_AGENT_KEY`` renders all three engines.
    #
    # #1062 — gated on the key, not rendered unconditionally. Every
    # agent entrypoint refuses an empty key by design and exits 2
    # (``bind9/entrypoint.sh:6``, ``kea/entrypoint.sh:38``,
    # ``gobgp/entrypoint.sh:9``), so a DaemonSet rendered before its key
    # exists is an object that can only crash. The supervisor's FIRST
    # apply is the idle one — the heartbeat before any role or key has
    # arrived — and it used to create every agent DaemonSet keyless
    # (revision 1). When the roles then arrived the node label landed
    # in milliseconds while the keyed re-render took helm-controller's
    # Job ~11 s, so the DaemonSet scheduled a revision-1 pod that died
    # twice and was replaced by revision 2 — on every fresh install.
    # Rendering the DaemonSet only once its key is in the role env
    # means the first revision that exists is keyed, and the pod the
    # label schedules is the one that serves. A role assigned without a
    # configured key is held back (logged by apply_role_assignment, and
    # ``missing`` in the watchdog's role_health) rather than crash-looped;
    # a role removed takes its DaemonSet with it (its key leaves the env),
    # which is the same chart upgrade the key's departure caused before.
    dns_key = env_vars.get("DNS_AGENT_KEY", "")
    dhcp_key = env_vars.get("DHCP_AGENT_KEY", "")
    lg_key = env_vars.get("LG_AGENT_KEY", "")
    values: dict[str, object] = {
        "global": {
            "imageTag": image_tag,
            "imagePullPolicy": "Never",
        },
        # #992 — the PriorityClasses are CLUSTER-SCOPED and this chart is
        # installed twice per appliance, under two release names. Helm
        # stamps ``meta.helm.sh/release-name`` on everything it creates and
        # refuses an install WHOLE when it meets an object owned by another
        # release, so the second install fails with ``invalid ownership
        # metadata`` and NO role DaemonSet is ever created — which is what
        # every fresh install between #988 and #992 did, silently, because
        # the helm-install job retries forever (backoffLimit: 1000) and
        # nothing in Fleet reports a chart that never installed.
        #
        # ``spatium-bootstrap`` owns them: firstboot writes that manifest
        # before the supervisor exists to write this one, and re-renders it
        # from the running slot's baked chart on EVERY boot, so a slot
        # upgrade re-applies it. ``external: true`` is what keeps the
        # chart's own guard satisfied while ``create`` is false — the guard
        # otherwise asks the apiserver, and an answer of "absent" here would
        # only ever mean bootstrap has not finished, not that the values are
        # wrong.
        "priorityClasses": {
            "create": False,
            "external": True,
        },
        # #1281 — the role agents on the external URL verify against this
        # supervisor's pin, unless this supervisor was started with the skip:
        # then it pins nothing, and the agents would wait for ever.
        "controlPlaneTls": {
            "insecureSkipVerify": cp_tls.skip_verify(),
        },
        "agentLanding": {
            "enabled": False,
        },
        "supervisor": {
            "enabled": False,
        },
        "dnsBind9": {
            "enabled": bool(dns_key),
            "controlPlaneUrl": control_plane_url,
            "agentKey": dns_key,
            "serverGroupName": env_vars.get("AGENT_GROUP", ""),
        },
        "dnsPowerdns": {
            "enabled": bool(dns_key),
            "controlPlaneUrl": control_plane_url,
            "agentKey": dns_key,
            "serverGroupName": env_vars.get("AGENT_GROUP", ""),
        },
        "dnsTechnitium": {
            "enabled": bool(dns_key),
            "controlPlaneUrl": control_plane_url,
            "agentKey": dns_key,
            "serverGroupName": env_vars.get("AGENT_GROUP", ""),
        },
        "dhcpKea": {
            "enabled": bool(dhcp_key),
            "controlPlaneUrl": control_plane_url,
            "agentKey": dhcp_key,
            # #3202: NO DHCP group here, the node's own (``DHCP_AGENT_GROUP``)
            # included. Every node of a cluster writes this ONE chart, and the
            # chart rendered the group into the ONE dhcp-kea pod template, so
            # a Fleet DHCP group move of one node re-rendered it and replaced
            # the Kea pod on every node (a hot-standby pair stopped answering
            # for 15-25 s). The agent needs a group only for the server row
            # its registration creates, and the control plane places that row
            # in the group its appliance is assigned. (#555's point stands:
            # the DNS ``AGENT_GROUP`` never reaches the Kea agent either.)
            "networkMode": env_vars.get("DHCP_NETWORK_MODE", "host"),
        },
        # #566 — BGP Looking Glass collector (GoBGP). Same
        # release-ownership-not-scheduling-scope convention as every
        # other role block above — pod scheduling is gated purely by
        # the ``spatium.io/role-looking-glass`` node label — and the
        # same #1062 key gate. No group/serverGroupName concept (LG
        # peers aren't grouped like DNS/DHCP server groups).
        "lookingGlass": {
            "enabled": bool(lg_key),
            "controlPlaneUrl": control_plane_url,
            "agentKey": lg_key,
        },
    }
    return values


# #1439 — the agent blocks one role-env key renders (one ``DNS_AGENT_KEY`` renders
# all three DNS engines), with the roles whose node labels schedule them.
_AGENT_FAMILIES: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("dnsBind9", "dnsPowerdns", "dnsTechnitium"), ("dns-bind9", "dns-powerdns", "dns-technitium")),
    (("dhcpKea",), ("dhcp",)),
    (("lookingGlass",), ("looking-glass",)),
)

# #1439 — what only a node holding the role is given, in that role's block: its
# key, its server group and its DHCP group's network mode. A node that keeps a
# block on for the nodes holding the role has none of them, so they come from the
# live chart a holder wrote; the rest of the block is the node's own render.
_HOLDER_VALUES = ("agentKey", "serverGroupName", "networkMode")

# #3202: values of a block that no writer carries, so none is copied from the
# live chart either: dhcpKea holds no DHCP group (see ``_build_values``), and a
# live chart an older build wrote may still hold one.
_NEVER_KEPT: dict[str, tuple[str, ...]] = {"dhcpKea": ("serverGroupName",)}


def _agent_block_on(values: dict[str, object], block: str) -> bool:
    """Whether ``values`` renders ``block``'s DaemonSet: enabled, with its key."""
    b = values.get(block)
    return isinstance(b, dict) and b.get("enabled") is True and bool(b.get("agentKey"))


def keep_other_nodes_agents(
    values: dict[str, object], live: dict[str, object], other_roles: set[str]
) -> tuple[dict[str, object], list[str]]:
    """PURE — #1439: ``values`` with the agents other nodes serve kept on.

    A formed cluster has ONE ``spatiumddi-appliance`` HelmChart, and every
    node's supervisor applies it whole, from its own role env. A node renders an
    agent block only when its own env carries that role's key (#1062), and the
    control plane ships a key only to a node that holds the role. So a node that
    did not hold a role wrote that role's block disabled, and the helm upgrade
    deleted the DaemonSet on every node, including the nodes the role is
    assigned to. The chart's own contract is the other way round
    (``dns-bind9.yaml``): ``enabled`` is release ownership and scheduling is the
    node label.

    So whether a family this node renders off is written on is the cluster's
    answer, not this node's: on while another node carries one of its role
    labels (``other_roles``). The block is this node's own render, with what only
    a holder is given (:data:`_HOLDER_VALUES`) taken from the live chart
    (``live``, ``{}`` before there is one) that a holder wrote. A family no
    other node is labelled for is written off, as before: that is how the last
    holder's removal takes the DaemonSet away. So is one whose key the live chart
    does not hold: this node cannot render it, and a holder's own apply does.
    Returns ``(values, kept blocks)``.
    """
    out = dict(values)
    kept: list[str] = []
    for blocks, roles in _AGENT_FAMILIES:
        if any(_agent_block_on(values, b) for b in blocks):
            continue
        if not other_roles & set(roles):
            continue
        keyed = [b for b in blocks if _agent_block_on(live, b)]
        if not keyed:
            continue
        for b in blocks:
            held = live[b] if b in keyed else live[keyed[0]]
            own = values.get(b)
            block = dict(own) if isinstance(own, dict) else {}
            block["enabled"] = True
            if isinstance(held, dict):
                never = _NEVER_KEPT.get(b, ())
                block.update({k: held[k] for k in _HOLDER_VALUES if k in held and k not in never})
            out[b] = block
            kept.append(b)
    return out, kept


def _keep_agents_other_nodes_serve(
    values: dict[str, object],
) -> tuple[dict[str, object], list[str], str | None]:
    """``(values, kept, error)`` — :func:`keep_other_nodes_agents` against the
    other nodes' role labels and the live chart, read from the kubeapi.

    Only a control-plane member writes a chart other nodes share; an appliance
    off the cluster runs its own k3s and its own chart, and reads nothing. The
    labels are read first: when no other node is labelled for an agent this node
    renders off, there is nothing to keep and the chart is not read (a single
    node reads one node list). An unknown read is an error, never an empty
    answer: taken as "nothing to keep" it would write the very outage this
    guards, so the apply fails and the next heartbeat retries. A node that cannot
    name itself counts every node, which keeps rather than drops."""
    off = [
        roles
        for blocks, roles in _AGENT_FAMILIES
        if not any(_agent_block_on(values, b) for b in blocks)
    ]
    if not off or not appliance_state.is_control_plane_member():
        return values, [], None
    other_roles, err = k8s_api.node_role_labels(exclude=_resolve_node_name())
    if other_roles is None:
        return values, [], f"the cluster's node role labels could not be read: {err}"
    if not any(other_roles & set(roles) for roles in off):
        return values, [], None
    live = k8s_api._helmchart_values(_HELMCHART_NAME, namespace=_CHART_NAMESPACE)
    if live is None:
        return values, [], "the live role chart could not be read; not writing it blind"
    out, kept = keep_other_nodes_agents(values, live, other_roles)
    return out, kept, None


def _other_nodes(names: list[str]) -> list[str]:
    """The nodes of ``names`` other than this one. A node that cannot name
    itself takes one of them as itself, so two nodes still read as shared."""
    me = _resolve_node_name()
    return [n for n in names if n != me] if me else names[1:]


def shared_chart_write_refusal(member: bool | None = None) -> str | None:
    """Why this node must not write the ``spatiumddi-appliance`` HelmChart now,
    or ``None`` when it may (#1750).

    A formed cluster has ONE role chart, and every node's supervisor applies it
    whole. Only a control-plane member renders the values the cluster needs:
    the in-cluster api URL, and the agents other nodes serve kept on (#1439).
    Membership on a promoted appliance is its join state reading ``ready``
    (:func:`appliance_state.is_control_plane_member`), so a node whose join or
    leave is in flight (``joining`` / ``leaving``), whose leave was refused
    (``failed``, still a member) or whose verdict was consumed reads as a
    non-member while its kubeapi is still the cluster's. Its render then turns
    every agent off and points them at the external URL, and the helm upgrade
    deleted dns-bind9 and dhcp-kea on every node: a 3 -> 1 demote lost DNS for
    about four minutes, until the seed's watchdog wrote the chart again.

    So a member (the seed, or any promoted member reading ``ready``, which keeps
    the chart applied if the seed is gone) always may. A non-member may only
    when it is alone in its k3s, because then the chart is its own: an
    appliance never promoted, one whose leave finished (its fresh standalone
    cluster), or one a failed join rolled back. Not knowing whether another
    node is there is a refusal, never "alone".

    ``member`` is the caller's own read of membership, so the gate and the
    render it guards are judged on one answer; ``None`` reads it here."""
    if member is None:
        member = appliance_state.is_control_plane_member()
    if member:
        return None
    names, err = k8s_api.cluster_node_names()
    if names is None:
        return (
            "not writing the role chart: could not tell whether this node's "
            f"cluster is shared ({err})"
        )
    if _other_nodes(names):
        return (
            "not writing the role chart: this node shares a cluster it is not a "
            "control-plane member of (its join or leave is in flight), and "
            "only a member writes the chart the cluster shares"
        )
    return None


# #1710 — the rolling upgrade's hold on the shared charts, as the last
# heartbeat delivered it, kept beside the role env in the state dir (a
# hostPath): the watchdog applies before the next heartbeat's response, and
# so does the first pass after a reboot.
_SHARED_CHART_HOLD_FILENAME = "shared-chart-hold"


def _shared_chart_hold_path(env_file: Path) -> Path:
    return env_file.with_name(_SHARED_CHART_HOLD_FILENAME)


def record_shared_chart_hold(env_file: Path, hold: object) -> None:
    """Keep (or clear) the hold a heartbeat response carried (#1710).

    ``hold`` is the response's ``shared_chart_hold``: a mapping while a
    rolling upgrade holds the cluster's shared charts, or while the cluster's
    members run different versions with no run (#3136), else None, which is
    also what a control plane from before the hold sends. Best effort: a
    failed write leaves the last known hold, and the next heartbeat writes
    again."""
    path = _shared_chart_hold_path(env_file)
    try:
        if isinstance(hold, dict) and hold.get("target_version"):
            text = json.dumps(hold, sort_keys=True)
            if not path.exists() or path.read_text() != text:
                tmp = path.with_name(path.name + ".tmp")
                tmp.write_text(text)
                tmp.replace(path)
                log.info("supervisor.k3s_lifecycle.shared_chart_hold_recorded", hold=hold)
        elif path.exists():
            path.unlink()
            log.info("supervisor.k3s_lifecycle.shared_chart_hold_cleared")
    except OSError as exc:
        log.warning("supervisor.k3s_lifecycle.shared_chart_hold_write_failed", error=str(exc))


def read_shared_chart_hold(env_file: Path) -> dict[str, str] | None:
    """The hold :func:`record_shared_chart_hold` kept, or None."""
    try:
        hold = json.loads(_shared_chart_hold_path(env_file).read_text())
    except (OSError, ValueError):
        return None
    return hold if isinstance(hold, dict) else None


def shared_chart_hold_refusal(hold: dict[str, str] | None) -> str | None:
    """Why this node must not write the shared role chart now, or None
    (#1710, #1427).

    A rolling upgrade holds every shared chart on the tag the cluster ran
    until every node reports the target. This chart's image tag is the
    writer's own slot's, and the agents it runs are ``imagePullPolicy:
    Never``: a node that has already booted the target slot would hand the
    nodes still on the old slot images they do not have, and their DNS and
    DHCP went down mid-roll. So while the hold lasts such a node writes
    nothing; the nodes still on the old slot keep writing (and healing) the
    chart with the old chart AND the old tag.

    "Already on the target" is the host's installed version, the file the
    control plane's health gate reads too: not the tag in this process's
    env, which can lag a slot boot.

    A hold with no ``run_id`` comes from no run (#3136): the cluster is being
    upgraded node by node from Fleet, its members run different versions, and
    the control plane holds every one of them on the version it runs until
    they run one. The rule is the same; only the reason says so."""
    if not hold:
        return None
    target = str(hold.get("target_version") or "")
    # #3026 — not a string compare: a nightly run's target is its release
    # tag, which never equals the slot's ``0.0.0-nightly-…+<sha>``.
    if not appliance_state.installed_is_target(
        appliance_state.read_installed_version(), target
    ):
        return None
    if not hold.get("run_id"):
        others = hold.get("from_tag") or "another version"
        return (
            f"not writing the role chart: this node runs {target} and other "
            f"nodes of the cluster run {others}, so the cluster's shared role "
            "chart stays as it is until every node runs one version"
        )
    held = hold.get("from_tag") or "the version it runs"
    return (
        "not writing the role chart: a rolling upgrade holds the cluster's "
        f"shared charts on {held} until every node runs {target}, and this "
        "node already runs it"
    )


def roles_awaiting_key(profiles: list[str], values: dict[str, object]) -> set[str]:
    """The assigned profiles whose DaemonSet the values do NOT render yet
    (#1062): the role's chart block is ``enabled: False`` because its agent
    key is not in the role env. Pure; ``apply_role_assignment`` logs it."""
    out: set[str] = set()
    for profile in profiles:
        block = values.get(_PROFILE_TO_HELM_KEY.get(profile, ""))
        if isinstance(block, dict) and block.get("enabled") is False:
            out.add(profile)
    return out


def _read_chart_tarball() -> bytes:
    """Load the baked chart tarball off the slot rootfs. Raises
    ``FileNotFoundError`` if the bake didn't run — caller surfaces
    this as a ``failed`` LifecycleResult."""
    return _BAKED_CHART_TARBALL.read_bytes()


def role_image_tag(env_vars: dict[str, str]) -> str:
    """The image tag the role release is rendered with — the ONE definition.

    The role env never carries ``SPATIUMDDI_VERSION`` in practice (it holds only
    role-scoped values, see ``heartbeat``), so this is the supervisor's process
    env: the entrypoint exports it from the host ``.env``, which firstboot
    re-stamps from the slot's baked tag on every boot. ``_build_values`` and the
    heartbeat's apply key both read it here, so the key can never describe a tag
    other than the one the apply renders.
    """
    return env_vars.get("SPATIUMDDI_VERSION") or os.environ.get("SPATIUMDDI_VERSION", "dev")


_chart_digest_cache: tuple[tuple[str, int, int], str] | None = None


def _chart_digest() -> str:
    """sha256 of the baked chart tarball, or "" when it cannot be read.

    Cached on the file's (path, size, mtime) so the 30 s heartbeat does not
    re-hash an unchanged file; the chart only changes with the slot."""
    global _chart_digest_cache
    try:
        st = _BAKED_CHART_TARBALL.stat()
        stamp = (str(_BAKED_CHART_TARBALL), st.st_size, st.st_mtime_ns)
        if _chart_digest_cache is not None and _chart_digest_cache[0] == stamp:
            return _chart_digest_cache[1]
        digest = hashlib.sha256(_read_chart_tarball()).hexdigest()
    except OSError:
        return ""
    _chart_digest_cache = (stamp, digest)
    return digest


def role_control_plane_url(env_vars: dict[str, str]) -> str:
    """The control-plane URL the role agents are given (#1281).

    Off-cluster, the operator's URL, which the chart verifies against this
    supervisor's pinned certificate. On a control-plane member, empty, so the
    chart falls through to the in-cluster api Service over plain HTTP, the
    path a full-stack node's agents already take. It has to: a member's
    supervisor heartbeats in-cluster and so never re-pins, while a member
    joining re-mints the Web UI certificate, so agents verifying the external
    URL against that pin would fail on the first join after a promotion.
    """
    if appliance_state.is_control_plane_member():
        return ""
    return env_vars.get("CONTROL_PLANE_URL") or os.environ.get("CONTROL_PLANE_URL", "")


def role_release_fingerprint(env_file: Path) -> str:
    """What the role apply renders beyond the role env itself (#1203).

    ``apply_role_assignment`` PATCHes the role HelmChart with this slot's chart
    tarball and ``global.imageTag``. Neither is in the role env, so a heartbeat
    that keyed its skip on the env alone skipped the apply for ever after a slot
    upgrade, and the agent DaemonSets kept the previous release's chart and
    images. Both change only with a slot upgrade, so steady-state heartbeats
    still skip, and the first heartbeat on a new slot re-applies once.

    The agents' control-plane URL is in it too (#1281): it changes when the
    node is promoted into the control plane, with nothing in the role env
    moving, and without it the agents would keep verifying the external URL
    against a pin their supervisor no longer maintains. So is whether this
    supervisor skips verification, which decides between the pin and the
    skip in the agents' pods.
    """
    env_vars = _parse_env_file(env_file)
    tag = role_image_tag(env_vars)
    return (
        f"image_tag={tag}\nchart_sha256={_chart_digest()}\n"
        f"control_plane_url={role_control_plane_url(env_vars)}\n"
        f"skip_tls_verify={cp_tls.skip_verify()}\n"
        f"dns_bind9_memory={_dns_bind9_memory_key()}\n"
    )


def _dns_bind9_memory_key() -> str:
    """The dns-bind9 memory sizing as the role apply would render it (#2223),
    for the skip key: a node joining or leaving the cluster can move the
    smallest DNS node, with nothing in the role env changing. ``unknown`` when
    the node list cannot be read (the compose path, or a kubeapi that is
    down), which is stable, so it does not re-apply on every heartbeat."""
    mib, _err = k8s_api.dns_sizing_memory_mib()
    sized = k8s_api.dns_bind9_memory(mib)
    return sized.get("limit", "unknown")


def size_dns_bind9(values: dict[str, object], mem_mib: int | None) -> dict[str, object]:
    """PURE — #2223: ``values`` with ``dnsBind9.memory`` sized from
    ``mem_mib`` (see :func:`k8s_api.dns_bind9_memory`). Applied after the
    #1439 keep, so a block kept on for another node is sized too. A block that
    is off, or a size that is unknown, is left as it is."""
    block = values.get("dnsBind9")
    sized = k8s_api.dns_bind9_memory(mem_mib)
    if not isinstance(block, dict) or block.get("enabled") is not True or not sized:
        return values
    out = dict(values)
    out["dnsBind9"] = {**block, "memory": sized}
    return out


def role_label_diff(profiles: list[str]) -> dict[str, str | None]:
    """The label patch this node needs — the ONE definition of the WRITE.

    :func:`desired_role_set` unified what the desired set IS; this unifies
    what gets PATCHed from it. Both matter, and only unifying the first left
    the actual defect reachable: a writer could still build its own diff from
    ``profiles`` alone, which is precisely the #1003 item 3 bug, and a review
    of that fix showed the whole supervisor suite stayed green after
    reverting to it.
    """
    roles = desired_role_set(profiles)
    return {label: ("true" if role in roles else None) for role, label in _ROLE_LABEL_KEYS.items()}


def hold_stale_role_labels(
    label_diff: dict[str, str | None], env_vars: dict[str, str]
) -> tuple[dict[str, str | None], list[str]]:
    """``(diff, held)`` — ``label_diff`` without the role labels whose agent
    DaemonSet would still start a pod with the PREVIOUS group (#2190).

    A held label is left out of the patch, not cleared: a node that already
    carries it keeps it (its pod rolls with the DaemonSet), and a node that does
    not gets it on a later write, once the template carries the group from
    ``env_vars``. Clears are never held — taking a role away cannot start a pod.

    Not held: a DaemonSet that does not exist (nothing to schedule from; helm
    creates it from the new values), and one whose read FAILED — the label patch
    goes through the same kubeapi, and holding on a failed read would keep a role
    off for as long as one read keeps failing. A label held longer than
    ``_LABEL_HOLD_MAX_SECONDS`` is set anyway, logged: past that the template is
    not converging on its own, and the control plane's registration puts an
    appliance's agent in its assigned group whatever its env says.
    """
    out = dict(label_diff)
    held: list[str] = []
    for role, (daemonset, env_key) in _ROLE_AGENT_GROUP.items():
        label = _ROLE_LABEL_KEYS[role]
        if out.get(label) != "true":
            _label_held_since.pop(label, None)
            continue
        want = env_vars.get(env_key, "")
        exists, have, err = k8s_api.daemonset_template_env(daemonset, env_name="AGENT_GROUP")
        if exists is None:
            log.warning(
                "supervisor.k3s_lifecycle.label_gate_read_failed",
                label=label,
                daemonset=daemonset,
                error=err,
            )
            _label_held_since.pop(label, None)
            continue
        if not exists or (have or "") == want:
            _label_held_since.pop(label, None)
            continue
        first = _label_held_since.setdefault(label, _monotonic())
        if _monotonic() - first >= _LABEL_HOLD_MAX_SECONDS:
            log.warning(
                "supervisor.k3s_lifecycle.label_hold_expired",
                label=label,
                daemonset=daemonset,
                template_group=have,
                assigned_group=want,
            )
            _label_held_since.pop(label, None)
            continue
        del out[label]
        held.append(label)
    return out, held


def _resolve_node_name() -> str:
    """This node's k8s name, or "" when it cannot be determined."""
    node_name = os.environ.get("NODE_NAME") or os.environ.get("APPLIANCE_HOSTNAME") or ""
    if node_name:
        return node_name
    try:
        import socket as _socket

        return _socket.gethostname()
    except OSError:
        return ""


def desired_role_set(profiles: list[str]) -> set[str]:
    """Roles this node must be labelled for — the ONE definition (#1003 item 3).

    The union of:

      * operator-assigned ``profiles`` from the heartbeat role-assignment;
      * the fixed per-variant set (#272 Phase 7b) — full-stack and
        frontend-core always assert ``control-plane``;
      * ``control-plane`` for an ``appliance``-variant node promoted into the
        control-plane cluster (#277), keyed off the join-state sidecar.

    This used to exist twice, and only one copy had the last two terms.
    ``reconcile_node_labels`` unioned all three; ``apply_role_assignment``
    took ``profiles`` alone and then cleared every label not in it — so on any
    tick where the env hash changed (the first heartbeat, and every role
    toggle) it removed the ``control-plane`` label that the install baked and
    that the reconcile had asserted moments earlier on the same tick.

    Observed on a fresh single-node install: the same heartbeat's memory-limit
    re-render rolled api and worker, and the new pods hit "0/1 nodes are
    available: 1 node(s) didn't match Pod's node affinity/selector" until the
    next tick put the label back. Self-healing there, but on a #272 multi-node
    control plane, toggling DNS on a member makes that member briefly
    ineligible for every control-plane workload.

    Non-negotiable #16 makes the label the source of truth for placement, so a
    writer that clears labels has to know the whole desired set.
    """
    roles = {p for p in profiles if p in _ROLE_LABEL_KEYS}
    variant = appliance_state.detect_appliance_variant()
    if variant is not None:
        roles |= set(_VARIANT_FIXED_ROLES.get(variant, frozenset()))
    join_state, _ = appliance_state.read_cluster_join_state()
    if join_state == "ready":
        roles.add("control-plane")
    return roles


def apply_role_assignment(
    profiles: list[str],
    env_file: Path,
) -> LifecycleResult:
    """k3s analog of ``service_lifecycle.apply_role_assignment``.

    Reads the rendered env file for control-plane URL + per-role
    agent keys, builds the chart values block, base64-encodes the
    baked chart tarball, and PATCHes a HelmChart CR into the
    appliance's local kubeapi. k3s's helm-controller reconciles
    the CR into a Helm release on its next loop (typically <5s).

    Returns ``ready`` on PATCH success, ``idle`` when the slot has no
    chart baked (k3s isn't the runtime here), ``failed`` when the kubeapi
    did not answer ``/readyz`` (#1716) or on a kubeapi or serialisation
    error. #1750 — ``idle`` with ``deferred`` set when this node
    may not write the chart its cluster shares (:func:`shared_chart_write_refusal`).
    """
    env = k3s_available()
    if env.kubeapi_unready:
        # #1716 — a kubeapi that missed its 2 s ``/readyz`` on this tick is a
        # miss, not a settled outcome. Reported ``idle``, the heartbeat stamped
        # the apply as done and never tried it again, and the Fleet row read
        # ``idle`` with no reason after the kubeapi was back. ``failed`` is not
        # stamped, so the next tick tries again (as #1640's failures are), and
        # the row carries the reason.
        return LifecycleResult(state="failed", reason=env.reason)
    if not env.available:
        # ``idle`` instead of ``failed`` mirrors the compose path's
        # "compose not available" shape: the supervisor isn't broken,
        # this just isn't the runtime here. Caller (heartbeat) reads
        # ``state="idle"`` as "skip + report we did nothing".
        return LifecycleResult(state="idle", reason=env.reason)

    # #1750 — a node that shares a cluster it is not a member of writes
    # nothing: what it would render is a non-member's chart, and the chart is
    # every node's. Membership is read once here and again before the write,
    # so a leave that starts while this apply renders (``ready`` -> ``leaving``)
    # cannot ship values rendered as a non-member under a member's gate.
    was_member = appliance_state.is_control_plane_member()
    refusal = shared_chart_write_refusal(was_member)
    if refusal:
        log.info("supervisor.k3s_lifecycle.shared_chart_write_deferred", reason=refusal)
        return LifecycleResult(state="idle", reason=refusal, deferred=True)
    # #1710 — a node already on a rolling upgrade's target leaves the shared
    # chart to the nodes still on the old slot until the hold ends.
    refusal = shared_chart_hold_refusal(read_shared_chart_hold(env_file))
    if refusal:
        log.info("supervisor.k3s_lifecycle.shared_chart_write_deferred", reason=refusal)
        return LifecycleResult(state="idle", reason=refusal, deferred=True)

    env_vars = _parse_env_file(env_file)
    values = _build_values(profiles, env_vars)
    held_back = roles_awaiting_key(profiles, values)
    if held_back:
        # #1062 — an assigned role whose key is not in the role env is
        # not rendered (its DaemonSet could only crash); the next
        # heartbeat that brings the key re-applies with it.
        log.info("supervisor.k3s_lifecycle.roles_awaiting_key", roles=sorted(held_back))

    # #1439, #1427 — every agent this node does not hold stays on while another
    # node is labelled for its role. #1439: a member just promoted, before any
    # role reaches it (its promotion changes the role apply key, #1281's
    # control-plane URL), turned every agent off cluster-wide at every join and
    # every Replace, until the seed's watchdog wrote the chart again. #1427: a
    # node given some of the roles, or one a role was taken back from, turned
    # that role off the same way, on the nodes still assigned it.
    values, kept, keep_err = _keep_agents_other_nodes_serve(values)
    if keep_err:
        return LifecycleResult(state="failed", reason=keep_err)
    if kept:
        log.info(
            "supervisor.k3s_lifecycle.agents_kept",
            blocks=kept,
            reason="another node serves them",
        )

    # #2223 — named's memory limit, sized from the smallest DNS node's RAM.
    # Only when the DaemonSet renders: a DHCP-only node has nothing to size,
    # and failing its apply over a node list it does not need would be wrong.
    # An unknown read fails the apply (retried next heartbeat) rather than
    # writing the chart without the sizing, which would put every DNS node
    # back on the chart default and restart named cluster-wide.
    if _agent_block_on(values, "dnsBind9"):
        dns_mib, dns_err = k8s_api.dns_sizing_memory_mib()
        if dns_mib is None:
            return LifecycleResult(
                state="failed",
                reason=f"not writing the role chart: node memory unreadable ({dns_err})",
            )
        values = size_dns_bind9(values, dns_mib)

    try:
        chart_bytes = _read_chart_tarball()
    except OSError as exc:
        return LifecycleResult(state="failed", reason=f"chart read: {exc}")
    chart_b64 = base64.b64encode(chart_bytes).decode("ascii")

    if appliance_state.is_control_plane_member() != was_member:
        reason = (
            "not writing the role chart: this node's control-plane membership "
            "changed while it rendered"
        )
        log.info("supervisor.k3s_lifecycle.shared_chart_write_deferred", reason=reason)
        return LifecycleResult(state="idle", reason=reason, deferred=True)

    ok, err = k8s_api.apply_helmchart(
        _HELMCHART_NAME,
        chart_content_b64=chart_b64,
        values=values,
        target_namespace=_TARGET_NAMESPACE,
        chart_namespace=_CHART_NAMESPACE,
    )
    if not ok:
        # Compose stderr first-line is usually enough for the Fleet
        # UI banner; kubeapi errors are similarly short.
        return LifecycleResult(state="failed", reason=err or "kubeapi apply failed")

    # Phase 10 (#183) — alongside the values PATCH, label the node
    # with ``spatium.io/role-<role>=true`` for each desired role,
    # and clear the label for each role not in the desired set.
    # The chart's per-role nodeSelector gates scheduling on this,
    # so a role swap (BIND9 → PowerDNS) becomes "label flip" instead
    # of a chart upgrade race. Best-effort: a label-patch failure
    # doesn't block the apply (the values PATCH already landed and
    # the helm-install will sit Pending until the next reconcile
    # writes the labels).
    # #1003 item 3 — the desired set is shared with reconcile_node_labels.
    # This used to be `{p for p in profiles ...}`, which omitted the
    # variant-fixed roles and the promoted-member case, so this call CLEARED
    # the control-plane label that the reconcile had just asserted.
    #
    # #2190 — and only once the values just written are what a newly-labelled
    # node would schedule from. helm-controller rolls the DaemonSet template a
    # few seconds after this PATCH; a label set before that started a pod with
    # the previous ``AGENT_GROUP``, which registered in the old group (a BIND9 →
    # PowerDNS + group A → B save left the PowerDNS row in A). Wait a bounded
    # while for the roll; what is still stale is left to the next heartbeat's
    # reconcile, which applies the same gate.
    label_diff = role_label_diff(profiles)
    deadline = _monotonic() + _LABEL_WAIT_SECONDS
    while True:
        gated_diff, held = hold_stale_role_labels(label_diff, env_vars)
        if not held or _monotonic() >= deadline:
            break
        _sleep(_LABEL_WAIT_STEP_SECONDS)
    if held:
        log.info("supervisor.k3s_lifecycle.labels_held", held=held, reason="template not rolled")
    label_diff = gated_diff
    node_name = _resolve_node_name()
    if node_name:
        label_ok, label_err = k8s_api.patch_node_labels(node_name, label_diff)
        if not label_ok:
            log.warning(
                "supervisor.k3s_lifecycle.label_patch_failed",
                node=node_name,
                error=label_err,
            )
        else:
            log.info(
                "supervisor.k3s_lifecycle.labels_applied",
                node=node_name,
                set=[k for k, v in label_diff.items() if v is not None],
                cleared=[k for k, v in label_diff.items() if v is None],
            )

    desired_services = tuple(sorted(p for p in profiles if p in _PROFILE_TO_HELM_KEY))
    log.info(
        "supervisor.k3s_lifecycle.applied",
        profiles=list(profiles),
        services=list(desired_services),
        control_plane_url=(
            values["dnsBind9"]["controlPlaneUrl"]  # type: ignore[index]
            if isinstance(values.get("dnsBind9"), dict)
            else None
        ),
    )
    # ``started`` reports the FULL desired set; reconciliation
    # idempotency means re-applying with the same set is cheap
    # (helm-controller short-circuits when the release hash hasn't
    # moved). Watchdog confirms each pod is healthy independently.
    return LifecycleResult(state="ready", started=desired_services)


def reconcile_node_labels(
    profiles: list[str], env_file: Path | None = None
) -> tuple[bool, str | None]:
    """Reconcile the node's per-role labels against ``profiles``.

    Idempotent — setting a label to its current value is a kubeapi
    no-op. Cheap enough (single PATCH, <10 ms locally) to run on
    every heartbeat tick alongside the apply_role_assignment
    skip-check. Catches drift from an out-of-band ``kubectl label``
    or a manual unlabeling without waiting for the values-hash to
    change.

    The desired set comes from :func:`desired_role_set`, which
    ``apply_role_assignment`` also uses — see #1003 item 3 for why having
    two copies of it, only one complete, made this function's work get
    undone on the same tick.

    #2190 — with ``env_file`` (the rendered role env), a label is only SET once
    its agent DaemonSet's template carries the assigned group
    (:func:`hold_stale_role_labels`), the same gate ``apply_role_assignment``
    applies: this is what sets a label the apply had to hold back.

    Returns ``(ok, error_or_None)`` — caller logs but doesn't act
    on failure (next heartbeat re-attempts).
    """
    label_diff = role_label_diff(profiles)
    if env_file is not None:
        label_diff, held = hold_stale_role_labels(label_diff, _parse_env_file(env_file))
        if held:
            log.info(
                "supervisor.k3s_lifecycle.labels_held", held=held, reason="template not rolled"
            )
    node_name = _resolve_node_name()
    if not node_name:
        return False, "node_name unknown"
    return k8s_api.patch_node_labels(node_name, label_diff)


def tear_down_supervised_services() -> LifecycleResult:
    """k3s analog of ``service_lifecycle.tear_down_supervised_services``.

    Deletes the HelmChart CR. helm-controller catches the delete +
    runs ``helm uninstall`` against the spatium namespace. Idempotent
    — deleting a non-existent CR is a no-op.

    Called by heartbeat on revocation (control plane removed our
    approval) so the appliance stops running its assigned services.
    """
    env = k3s_available()
    if not env.available:
        return LifecycleResult(state="idle", reason=env.reason)

    # #1750 — deleting the chart uninstalls the release on every node. On a
    # node alone in its k3s that is its own release; on a node sharing a
    # cluster it is every other node's DNS and DHCP, so there the teardown only
    # clears this node's role labels below, which takes its own agents away.
    names, names_err = k8s_api.cluster_node_names()
    if names is None or _other_nodes(names):
        log.warning(
            "supervisor.k3s_lifecycle.teardown_chart_kept",
            reason="this node shares its cluster; only its role labels are cleared",
            error=names_err,
        )
    else:
        ok, err = k8s_api.delete_helmchart(_HELMCHART_NAME, chart_namespace=_CHART_NAMESPACE)
        if not ok:
            return LifecycleResult(state="failed", reason=err or "kubeapi delete failed")

    # Phase 10 (#183) — clear every per-role label so pods that
    # somehow survived the chart delete don't keep running on the
    # node. helm-controller's uninstall should remove the
    # Deployments first, but this is belt-and-braces.
    node_name = os.environ.get("NODE_NAME") or os.environ.get("APPLIANCE_HOSTNAME") or ""
    if not node_name:
        try:
            import socket as _socket

            node_name = _socket.gethostname()
        except OSError:
            node_name = ""
    if node_name:
        label_diff: dict[str, str | None] = {label: None for label in _ROLE_LABEL_KEYS.values()}
        k8s_api.patch_node_labels(node_name, label_diff)
    log.warning("supervisor.k3s_lifecycle.torn_down")
    # Report every supervised service as ``stopped`` — we deleted
    # the chart that owned every one of them. The Fleet drilldown's
    # role-switch banner reads the same shape regardless of runtime.
    return LifecycleResult(state="ready", stopped=tuple(SUPERVISED_SERVICES))


__all__ = [
    "apply_role_assignment",
    "k3s_available",
    "reconcile_node_labels",
    "roles_awaiting_key",
    "shared_chart_write_refusal",
    "tear_down_supervised_services",
]
