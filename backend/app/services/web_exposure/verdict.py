"""The verdict, with its evidence (#3651).

Never a bare "you are exposed": every verdict carries which outside networks,
how many requests, first / last seen and which endpoints (login page vs other
api paths), so the operator can judge it. The word is deliberately not
"breached": ``exposed`` means reachable and probed, nothing more.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.config import settings
from app.services.web_exposure import store
from app.services.web_exposure.config import WebExposureConfig

Verdict = Literal["exposed", "reached_from_outside", "not_observed", "unknown"]

# Signals that show the sign-in screen / api was reached without credentials.
_REACH_SIGNALS = (store.SIGNAL_LOGIN_PAGE, store.SIGNAL_UNAUTH)
# Signals that are attack evidence, not mere reachability.
_ATTACK_SIGNALS = (store.SIGNAL_LOGIN_FAILURE, store.SIGNAL_HOST_REFUSED)
#: Distinct submitted usernames from outside that read as a spray.
SPRAY_USERNAMES = 5


@dataclass
class BucketRow:
    bucket: str
    requests: int
    signals: dict[str, int]
    first_seen: str | None
    last_seen: str | None
    endpoints: list[str]
    addresses: list[str] | None  # superadmin only; None when withheld
    login_page: int
    other_api: int
    login_failures: int


@dataclass
class VerdictResult:
    verdict: Verdict
    severity: Literal["info", "warning", "critical"] | None
    window_hours: int
    threshold: int
    distinct_external_buckets: int
    since: str | None
    totals: dict[str, int]
    distinct_usernames: int
    attack_evidence: bool
    intentional: bool
    attribution_warning: bool
    deployment_shape: str
    fix_hint: str
    summary: str
    buckets: list[BucketRow] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _iso(ts: int) -> str | None:
    return datetime.fromtimestamp(ts, UTC).isoformat() if ts else None


def deployment_shape() -> str:
    """``appliance`` / ``kubernetes`` / ``compose`` / ``unknown``, from the
    config the api already has (no socket probe on a read path)."""
    if settings.appliance_mode:
        return "appliance"
    import os  # noqa: PLC0415

    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return "kubernetes"
    if os.path.exists("/.dockerenv"):
        return "compose"
    return "unknown"


_FIX_HINTS = {
    "appliance": (
        "Appliance → Firewall (Web UI access): restrict the Web UI to your networks "
        "(or use the one-click bridge from the trusted list below)."
    ),
    "compose": (
        "Bind HTTP_PORT / HTTPS_PORT to the LAN interface (e.g. 192.0.2.10:443:443) or "
        "put your own reverse proxy in front (docs/deployment/REVERSE_PROXY.md)."
    ),
    "kubernetes": (
        "Set frontend.loadBalancerSourceRanges (or an Ingress allow-list annotation) to "
        "your networks; behind an Ingress also set frontend.trustedProxyCidrs "
        "(docs/deployment/REVERSE_PROXY.md)."
    ),
    "unknown": "Restrict network access to the web UI at your firewall or reverse proxy.",
}


def build_verdict(
    data: store.WindowData | None,
    cfg: WebExposureConfig,
    *,
    include_addresses: bool,
    limit: int = 50,
) -> VerdictResult:
    shape = deployment_shape()
    base: dict[str, Any] = dict(
        window_hours=cfg.window_hours,
        threshold=cfg.threshold,
        intentional=cfg.intentional,
        deployment_shape=shape,
        fix_hint=_FIX_HINTS[shape],
    )
    if data is None:
        return VerdictResult(
            verdict="unknown",
            severity=None,
            distinct_external_buckets=0,
            since=None,
            totals={},
            distinct_usernames=0,
            attack_evidence=False,
            attribution_warning=False,
            summary="The counters could not be read (Redis unreachable); nothing can be said.",
            **base,
        )

    rows = [b for b in data.buckets if b.total > 0]
    totals: dict[str, int] = {}
    for b in rows:
        for k, v in b.counts.items():
            if k != store.SIGNAL_PROXY_NO_REAL_IP:
                totals[k] = totals.get(k, 0) + v

    reach_buckets = [b for b in rows if any(b.counts.get(s, 0) for s in _REACH_SIGNALS)]
    attack_buckets = [b for b in rows if any(b.counts.get(s, 0) for s in _ATTACK_SIGNALS)]
    attack = bool(attack_buckets)
    spray = data.distinct_usernames >= SPRAY_USERNAMES

    if len(reach_buckets) >= cfg.threshold or attack:
        verdict: Verdict = "exposed"
        severity: Literal["info", "warning", "critical"] | None = "warning"
        if totals.get(store.SIGNAL_LOGIN_FAILURE, 0) or spray:
            severity = "critical"
        elif cfg.intentional:
            severity = "info"
    elif rows:
        verdict, severity = "reached_from_outside", None
    else:
        verdict, severity = "not_observed", None

    since = min((b.first_seen for b in rows if b.first_seen), default=0)
    out_rows = [
        BucketRow(
            bucket=b.bucket,
            requests=b.total,
            signals={k: v for k, v in b.counts.items() if k != store.SIGNAL_PROXY_NO_REAL_IP},
            first_seen=_iso(b.first_seen),
            last_seen=_iso(b.last_seen),
            endpoints=list(b.paths),
            addresses=list(b.addresses) if include_addresses else None,
            login_page=b.counts.get(store.SIGNAL_LOGIN_PAGE, 0),
            other_api=b.counts.get(store.SIGNAL_UNAUTH, 0) + b.counts.get(store.SIGNAL_VERSION, 0),
            login_failures=b.counts.get(store.SIGNAL_LOGIN_FAILURE, 0),
        )
        for b in rows[:limit]
    ]
    summary = _summary(verdict, len(rows), len(reach_buckets), totals, data, cfg, attack)
    return VerdictResult(
        verdict=verdict,
        severity=severity,
        distinct_external_buckets=len(rows),
        since=_iso(since),
        totals=totals,
        distinct_usernames=data.distinct_usernames,
        attack_evidence=attack or spray,
        attribution_warning=data.proxy_no_real_ip > 0,
        summary=summary,
        buckets=out_rows,
        **base,
    )


def _summary(
    verdict: str,
    n_buckets: int,
    n_reach: int,
    totals: dict[str, int],
    data: store.WindowData,
    cfg: WebExposureConfig,
    attack: bool,
) -> str:
    h = cfg.window_hours
    if verdict == "not_observed":
        return (
            f"No requests from outside your networks in the last {h} h. That is "
            "not proof the install is unreachable, only that nobody has tried."
        )
    parts = [
        f"{n_buckets} outside network(s) reached this install in the last {h} h",
        f"{totals.get(store.SIGNAL_LOGIN_PAGE, 0)} login-page load(s)",
        f"{totals.get(store.SIGNAL_UNAUTH, 0)} unauthenticated api request(s)",
    ]
    if totals.get(store.SIGNAL_LOGIN_FAILURE):
        parts.append(
            f"{totals[store.SIGNAL_LOGIN_FAILURE]} failed sign-in(s) across "
            f"{data.distinct_usernames} distinct username(s)"
        )
    if totals.get(store.SIGNAL_HOST_REFUSED):
        parts.append(f"{totals[store.SIGNAL_HOST_REFUSED]} refused Host header(s)")
    text = ", ".join(parts) + "."
    if verdict == "reached_from_outside":
        return text + (
            f" Below the threshold ({n_reach} of {cfg.threshold} networks with a login-page "
            "load or 401): this may be a remote admin or a poller."
        )
    return text
