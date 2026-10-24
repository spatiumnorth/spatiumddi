"""Logs, self-test, and diagnostic bundle for the Fleet UI.

Phase 11 wave 4 (#183) rewrite. Appliance mode is now k3s-only
post-Phase-7; the docker-era checks (docker SDK + /var/log/
spatiumddi-host bind mount + sync localhost-loopback HTTP check)
have been replaced with kubeapi-driven equivalents that match the
new chart topology.

Three operator-facing surfaces:

* **Log viewer** — tails host-side log files when the api pod has
  ``/var/log/spatiumddi-host`` bind-mounted (control-plane appliance
  with k3s manifest-side host mount). Returns no sources when the
  bind mount is absent — that's the expected state on docker /
  K8s control planes and on agent-only appliances. Read-only.
* **Self-test** — runs a battery of checks ("DNS resolves",
  "kubeapi reachable via ServiceAccount", "all spatium pods
  healthy", "optional roles present"). Self-test runs inside the
  api worker; the api uses a single uvicorn worker so any check
  that loops back to the api's own listen port via
  ``127.0.0.1:8000`` would deadlock the event loop — none of the
  checks do that any more.
* **Diagnostic bundle** — zips logs + per-pod log tails + system
  info + redacted env into a single download. Container logs
  come from kubeapi via the ServiceAccount; the pre-Phase-11
  docker-socket path is gone.
"""

from __future__ import annotations

import io
import os
import socket
import zipfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from app.config import settings
from app.core.versions import canonical_version
from app.services.appliance import k8s
from app.services.appliance.containers import (
    DockerUnavailableError,
    get_container_logs,
    list_containers,
)
from app.services.support_bundle.scrub import redact_secrets, render_env, render_env_file

logger = structlog.get_logger(__name__)

# Host log dir bind-mounted by the appliance manifest (RO). Falls back
# to the container's own /var/log/spatiumddi on dev / when bind isn't
# present. On the k3s appliance this is mounted by the umbrella chart
# (api.hostPaths) only when the appliance role is assigned; agent-only
# and off-appliance installs leave it empty and the UI shows "no log
# files yet".
_HOST_LOG_DIR = Path("/var/log/spatiumddi-host")
_FALLBACK_LOG_DIR = Path("/var/log/spatiumddi")
# Sanitised /etc/spatiumddi/.env mount point — same gating as above.
_HOST_ENV_FILE = Path("/etc/spatiumddi-host/.env")
# Tail size for each log file in the bundle and for the UI's "show me
# what happened recently" panel. 500 lines is enough for support
# triage without making the bundle bloated.
_DEFAULT_TAIL = 500


def _log_dir() -> Path:
    """Return the path the api should read host logs from.

    Prefers the bind-mounted host dir; falls back to the in-container
    dir which the api uses for its own writes regardless.
    """
    return _HOST_LOG_DIR if _HOST_LOG_DIR.exists() else _FALLBACK_LOG_DIR


def list_log_sources() -> list[str]:
    """Names of log files the api can show on the Logs tab."""
    base = _log_dir()
    if not base.exists():
        return []
    out: list[str] = []
    for p in sorted(base.glob("*.log")):
        out.append(p.name)
    return out


def read_log_tail(name: str, lines: int = _DEFAULT_TAIL) -> str:
    """Return the last ``lines`` lines of a host log file.

    Verifies ``name`` against the allowlist returned by
    ``list_log_sources()`` (which itself glob-walks the log dir for
    ``*.log``) before constructing any path. The resolved path is
    then re-derived from the allowlist match rather than from the
    operator-supplied string, so CodeQL's path-injection tracker
    sees no tainted data crossing into the filesystem call.
    404-equivalent on miss — returns empty string + the router
    translates that.
    """
    allowed = set(list_log_sources())
    if name not in allowed:
        return ""
    base = _log_dir()
    # Re-derive the path from the verified allowlist member. Walking
    # ``base.iterdir()`` and matching ``.name == name`` keeps the
    # untrusted string out of the join entirely — CodeQL treats this
    # as a sanitizer because the Path object that reaches read_text()
    # is one we constructed ourselves from a directory listing.
    for candidate in base.iterdir():
        if candidate.name == name and candidate.is_file():
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("appliance_log_read_failed", name=name, error=str(exc))
                return ""
            return "\n".join(text.splitlines()[-lines:])
    return ""


# ── Self-test ───────────────────────────────────────────────────────


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


@dataclass
class SelfTestReport:
    run_at: datetime
    overall_ok: bool
    checks: list[CheckResult]


def run_self_test() -> SelfTestReport:
    """Run the appliance self-test battery.

    Synchronous + bounded — total runtime ~5 seconds worst-case. Each
    check has its own try/except so one failure doesn't blow up the
    report; the matching ``CheckResult`` carries the error message.
    """
    checks: list[CheckResult] = []
    checks.append(_check_dns_resolves())
    checks.append(_check_kubeapi_reachable())
    checks.append(_check_pods_healthy())
    checks.append(_check_role_present("dhcp", "DHCP role"))
    checks.append(_check_role_present("dns", "DNS role"))
    return SelfTestReport(
        run_at=datetime.now(tz=UTC),
        overall_ok=all(c.ok for c in checks),
        checks=checks,
    )


def _check_dns_resolves() -> CheckResult:
    """Resolve a stable public hostname — confirms host DNS works."""
    target = "registry-1.docker.io"
    try:
        ip = socket.gethostbyname(target)
        return CheckResult(
            name="DNS resolution",
            ok=True,
            detail=f"{target} -> {ip}",
        )
    except socket.gaierror as exc:
        return CheckResult(
            name="DNS resolution",
            ok=False,
            detail=f"{target} -> {exc}",
        )


def _check_kubeapi_reachable() -> CheckResult:
    """Verify the api pod can talk to kubeapi via its ServiceAccount.

    Replaces the pre-Phase-11 ``127.0.0.1:8000/health/live`` self-
    loopback check. The api runs ``--workers 1`` and self-test is
    synchronous, so a loopback HTTP call from inside the same
    worker deadlocked at the event loop. The kubeapi check is a
    different connection entirely and exercises something more
    useful — the path the Pods tab + Cert Manager use.
    """
    if not settings.appliance_mode:
        return CheckResult(
            name="Kubeapi reachable",
            ok=True,
            detail="not appliance mode — check skipped",
        )
    cfg = k8s.get_config()
    if cfg is None:
        return CheckResult(
            name="Kubeapi reachable",
            ok=False,
            detail=(
                "ServiceAccount not mounted at "
                "/var/run/secrets/kubernetes.io/serviceaccount/ — "
                "chart may need api.serviceAccount.enabled=true"
            ),
        )
    try:
        pods = k8s.list_pods()
    except k8s.KubeapiUnavailableError as exc:
        return CheckResult(
            name="Kubeapi reachable",
            ok=False,
            detail=str(exc),
        )
    return CheckResult(
        name="Kubeapi reachable",
        ok=True,
        detail=f"{len(pods)} pods visible in namespace {cfg.namespace}",
    )


def _check_pods_healthy() -> CheckResult:
    """Every spatium-labelled pod reports a healthy phase.

    "Healthy" means Running with all containers ready OR Succeeded
    (Jobs that finished cleanly). Pending pods are flagged only if
    they're stuck in a known-bad waiting reason (CrashLoopBackOff,
    ImagePullBackOff, ErrImagePull).
    """
    try:
        rows = list_containers()
    except DockerUnavailableError as exc:
        return CheckResult(
            name="Pod health",
            ok=False,
            detail=f"kubeapi unreachable: {exc}",
        )
    if not rows:
        if not settings.appliance_mode:
            return CheckResult(
                name="Pod health",
                ok=True,
                detail="not appliance mode — check skipped",
            )
        return CheckResult(
            name="Pod health",
            ok=False,
            detail="no pods visible — kubeapi or RBAC issue",
        )
    spatium = [c for c in rows if c.is_spatium]
    if not spatium:
        return CheckResult(
            name="Pod health",
            ok=False,
            detail="no spatium-labelled pods found",
        )
    # Running with healthy + Succeeded (Job that completed) are both fine.
    bad: list[str] = []
    for c in spatium:
        if c.state == "running" and c.health in (None, "healthy", "starting"):
            continue
        if c.state == "exited" and c.health is None:
            # Succeeded Jobs come through as state="exited" with no
            # health vocabulary attached — that's a normal end-of-life
            # for a one-shot pod (migrate, helm-install).
            continue
        bad.append(f"{c.name} ({c.status})")
    if bad:
        return CheckResult(
            name="Pod health",
            ok=False,
            detail=", ".join(bad),
        )
    return CheckResult(
        name="Pod health",
        ok=True,
        detail=f"{len(spatium)} spatium pods healthy",
    )


def _check_role_present(name_substring: str, label: str) -> CheckResult:
    """Informational check for an optional role's pods.

    Returns OK when no matching pods exist (operator hasn't assigned
    the role to this appliance) and OK when present + running. Only
    flags failure when a matching pod exists but is unhealthy.
    """
    try:
        rows = list_containers()
    except DockerUnavailableError as exc:
        return CheckResult(name=label, ok=False, detail=f"kubeapi unreachable: {exc}")
    matched = [c for c in rows if name_substring in c.name.lower() and c.is_spatium]
    if not matched:
        return CheckResult(
            name=label,
            ok=True,
            detail="role not assigned to this appliance",
        )
    bad = [
        c
        for c in matched
        if not (c.state == "running" and c.health in (None, "healthy", "starting"))
    ]
    if bad:
        return CheckResult(
            name=label,
            ok=False,
            detail=", ".join(f"{c.name} ({c.status})" for c in bad),
        )
    return CheckResult(
        name=label,
        ok=True,
        detail=", ".join(f"{c.name} ({c.state})" for c in matched),
    )


# ── Diagnostic bundle ───────────────────────────────────────────────


def _clean(text: str) -> str:
    """Strip secret-shaped substrings (Fernet blobs, JWTs, PEM keys, URL
    credentials, …) — the support bundle's hard-exclude pass, shared so
    the two bundles cannot drift apart again."""
    return redact_secrets(text)[0]


def _put(zf: zipfile.ZipFile, name: str, content: str) -> None:
    """Write one bundle member. EVERY member goes through here, so a log
    line that happens to carry a credential is redacted like the env dump
    is, instead of shipping verbatim."""
    zf.writestr(name, _clean(content))


def generate_diagnostic_bundle() -> bytes:
    """Build a zip with logs, pod info, system info, redacted env.

    Returns the zip bytes (in-memory; spatium installs are small
    enough this is fine — ~1-5 MB typical). Caller wraps it in a
    StreamingResponse.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        manifest = {
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "appliance_mode": settings.appliance_mode,
            "appliance_version": settings.appliance_version,
            "appliance_hostname": settings.appliance_hostname,
            "version": canonical_version(settings.version, settings.app_version),
        }
        _put(
            zf,
            "manifest.txt",
            "\n".join(f"{k}: {v}" for k, v in manifest.items()),
        )

        # Self-test snapshot at bundle-generation time
        report = run_self_test()
        _put(
            zf,
            "self-test.txt",
            _format_self_test_report(report),
        )

        # Every host log file we can see (will be empty when no bind
        # mount is present — that's the expected state on docker / K8s
        # control planes and on agent-only appliances).
        for name in list_log_sources():
            try:
                content = (_log_dir() / name).read_text(encoding="utf-8", errors="replace")
                _put(zf, f"logs/{name}", content)
            except OSError:
                pass

        # Last 500 lines for each spatium pod's stdout/stderr via kubeapi.
        try:
            for c in list_containers():
                if not c.is_spatium:
                    continue
                try:
                    logs = get_container_logs(c.name, tail=500)
                except DockerUnavailableError as exc:
                    logs = f"[unable to fetch logs: {exc}]"
                _put(zf, f"pods/{c.name}.log", logs)
        except DockerUnavailableError as exc:
            _put(zf, "pods/_error.txt", f"kubeapi unreachable: {exc}")

        # Sanitised /etc/spatiumddi/.env if accessible. Not currently
        # bind-mounted into the api pod by default; the placeholder
        # warns support reviewers if the env was unavailable.
        if _HOST_ENV_FILE.is_file():
            try:
                raw = _HOST_ENV_FILE.read_text(encoding="utf-8")
                _put(zf, "config/env.redacted", render_env_file(raw, _clean))
            except OSError as exc:
                _put(zf, "config/env.error", f"read failed: {exc}")
        else:
            _put(
                zf,
                "config/env.unavailable",
                "/etc/spatiumddi/.env is not bind-mounted into the api "
                "pod by default — operator can copy it manually after "
                "blanking every value with "
                "`sed -E 's/=.*/=[REDACTED]/' /etc/spatiumddi/.env`.",
            )

        # System info — uname, uptime, meminfo. /proc is in the api
        # pod's namespace which is fine: the host's kernel is
        # shared, so /proc/version reports the host kernel.
        for proc in ("/proc/version", "/proc/uptime", "/proc/meminfo", "/proc/cpuinfo"):
            try:
                _put(
                    zf,
                    f"system{proc}",
                    Path(proc).read_text(encoding="utf-8", errors="replace"),
                )
            except OSError as exc:
                # Record the failure inline so support can see why a
                # given /proc file is missing from the bundle instead
                # of guessing from its absence.
                _put(zf, f"system{proc}.error", f"{type(exc).__name__}: {exc}")

        # Environment variables visible to the api (handy for support).
        # Values are shown for allowlisted names only; see render_env.
        _put(zf, "system/env.redacted", render_env(os.environ, _clean))

    return buf.getvalue()


def _format_self_test_report(report: SelfTestReport) -> str:
    lines = [
        f"Self-test run at {report.run_at.isoformat()}",
        f"Overall: {'PASS' if report.overall_ok else 'FAIL'}",
        "",
    ]
    for c in report.checks:
        mark = "OK " if c.ok else "FAIL"
        lines.append(f"  [{mark}] {c.name}: {c.detail}")
    return "\n".join(lines)


def self_test_report_to_dict(report: SelfTestReport) -> dict[str, Any]:
    return {
        "run_at": report.run_at.isoformat(),
        "overall_ok": report.overall_ok,
        "checks": [asdict(c) for c in report.checks],
    }
