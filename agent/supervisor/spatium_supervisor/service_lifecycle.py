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
import os
from dataclasses import dataclass
from pathlib import Path

import structlog

from . import appliance_state, k8s_api


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
# Sibling to /usr/lib/spatiumddi/images/*.tar.zst — same lifecycle
# (slot-baked at build, mounted via mkosi.extra/ copy).
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
        return K3sEnvironment(available=False, reason="kubeapi /readyz not ok")
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
    control_plane_url = env_vars.get("CONTROL_PLANE_URL") or os.environ.get("CONTROL_PLANE_URL", "")
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
            # #555 — NO ``AGENT_GROUP`` fallback here. ``AGENT_GROUP`` is
            # written only for DNS roles (role_orchestrator writes
            # ``DHCP_AGENT_GROUP`` for DHCP), so the fallback could only ever
            # pull in a DNS group name — a node with both dns + dhcp roles but
            # no dhcp_group_name would silently register its Kea agent into
            # the DNS group. Absent → empty, which the backend treats as the
            # default group.
            "serverGroupName": env_vars.get("DHCP_AGENT_GROUP", ""),
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


def role_release_fingerprint(env_file: Path) -> str:
    """What the role apply renders beyond the role env itself (#1203).

    ``apply_role_assignment`` PATCHes the role HelmChart with this slot's chart
    tarball and ``global.imageTag``. Neither is in the role env, so a heartbeat
    that keyed its skip on the env alone skipped the apply for ever after a slot
    upgrade, and the agent DaemonSets kept the previous release's chart and
    images. Both change only with a slot upgrade, so steady-state heartbeats
    still skip, and the first heartbeat on a new slot re-applies once.
    """
    tag = role_image_tag(_parse_env_file(env_file))
    return f"image_tag={tag}\nchart_sha256={_chart_digest()}\n"


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

    Returns ``ready`` on PATCH success, ``idle`` when k3s isn't
    available (no chart baked / kubeapi unreachable — caller's
    fallback to the compose path), ``failed`` on a kubeapi or
    serialisation error.
    """
    env = k3s_available()
    if not env.available:
        # ``idle`` instead of ``failed`` mirrors the compose path's
        # "compose not available" shape: the supervisor isn't broken,
        # this just isn't the runtime here. Caller (heartbeat) reads
        # ``state="idle"`` as "skip + report we did nothing".
        return LifecycleResult(state="idle", reason=env.reason)

    env_vars = _parse_env_file(env_file)
    values = _build_values(profiles, env_vars)
    held_back = roles_awaiting_key(profiles, values)
    if held_back:
        # #1062 — an assigned role whose key is not in the role env is
        # not rendered (its DaemonSet could only crash); the next
        # heartbeat that brings the key re-applies with it.
        log.info("supervisor.k3s_lifecycle.roles_awaiting_key", roles=sorted(held_back))

    try:
        chart_bytes = _read_chart_tarball()
    except OSError as exc:
        return LifecycleResult(state="failed", reason=f"chart read: {exc}")
    chart_b64 = base64.b64encode(chart_bytes).decode("ascii")

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
    label_diff = role_label_diff(profiles)
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


def reconcile_node_labels(profiles: list[str]) -> tuple[bool, str | None]:
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

    Returns ``(ok, error_or_None)`` — caller logs but doesn't act
    on failure (next heartbeat re-attempts).
    """
    label_diff = role_label_diff(profiles)
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
    "tear_down_supervised_services",
]
