"""Self-signed cert bootstrap — Phase 4b.5 (issue #134).

Runs on appliance api startup, and settles on ONE active
``appliance_certificate`` row by trying three things in order:

1. **An active row already exists** (operator-uploaded, CSR-signed, or
   a previous bootstrap) — re-deploy it to the TLS Secret, but ONLY if
   the Secret doesn't already hold exactly it. Handles the case where the
   Secret was wiped (fresh upgrade, factory reset) but the DB row
   survived; each frontend pod reloads nginx once the kubelet updates
   its mounted copy (#1173). In the steady state this is a no-op.

2. **No active row, but the TLS Secret already holds a usable cert** —
   adopt it (#767). On a fresh appliance, firstboot mints a self-signed
   cert into ``spatium-appliance-tls`` via a k3s auto-deploy manifest
   *before* the chart bootstraps, so the frontend nginx has been serving
   it since its first request. Adopting records it as the active row and
   deploys nothing: the Secret is already correct, the frontend must not
   roll, and the operator must not be asked to trust a second cert
   halfway through a boot they are watching.

3. **Neither** — generate a self-signed cert valid 5 years with the
   appliance's hostname + every detected non-loopback IP as SANs, insert
   it ``source=self-signed`` + ``is_active=true``, and deploy it so nginx
   has something to serve.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import ipaddress
import uuid

import structlog
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.crypto import decrypt_str, encrypt_str
from app.db import AsyncSessionLocal
from app.models.appliance import (
    CERT_SOURCE_SELF_SIGNED,
    CERT_SOURCE_UPLOADED,
    ApplianceCertificate,
)
from app.services.appliance.deployment import (
    deploy_active_cert,
    deploy_and_reload,
    read_deployed_cert,
)
from app.services.appliance.tls import (
    TLSValidationError,
    _format_fingerprint,
    parse_pem_certificate,
    validate_key_matches_cert,
)

logger = structlog.get_logger(__name__)

# Self-signed certs default to 5 years — long enough that the operator
# won't trip "browser refuses connection" mid-deploy, short enough that
# leaving the appliance on its self-signed default forever is mildly
# uncomfortable (and motivates the operator to upload a real cert).
_SELF_SIGNED_DAYS = 5 * 365


async def ensure_self_signed_cert() -> None:
    """Idempotent: ensure an active cert exists + is materialised on disk.

    Path A — active row already exists:
        Re-deploy the cert to the TLS Secret (the frontend reloads it in
        place) — but ONLY when the Secret doesn't already hold this
        exact cert. Covers wipe-of-Secret edge cases; a no-op otherwise.

    Path B — no active row, but the TLS Secret holds a usable cert
    covering every desired SAN (the fresh-appliance case: firstboot
    put it there before the chart bootstrapped):
        Adopt it as the active row. Deploys NOTHING — see
        ``_adopt_deployed_cert``.

    Path C — no active row and nothing adoptable:
        Generate a fresh RSA-2048 self-signed cert. CN = appliance
        hostname; SANs = hostname + every non-loopback IPv4/IPv6
        bound to a local interface. Insert as is_active=true,
        source=self-signed. Deploy + reload.

    Failure-tolerant: any error logs + returns. The lifespan caller
    has a try/except wrapping this whole function — appliance boot
    should never fail because of TLS bootstrap.
    """
    if not settings.appliance_mode:
        return

    # #272 HA — the cert identity MUST be stable across api replicas.
    # In a multi-node control plane the api Deployment runs N pods (one
    # per control-plane node), all sharing one cluster-wide
    # spatium-appliance-tls Secret + one appliance_certificate row. If
    # we derived the CN/SANs from the running POD (socket.gethostname()
    # = the pod name, or the pod's own IP), every replica would see "the
    # active cert doesn't cover MY name/IP" and regenerate — three pods
    # → three certs, each overwriting the Secret (exactly the churn an
    # operator reported). So use ONLY the host-stable identity that
    # firstboot threads into the Deployment env (identical for every
    # replica): APPLIANCE_HOSTNAME + APPLIANCE_HOST_IPS + the
    # control-plane VIP. No per-pod fallbacks. The result: the first
    # node's cert is generated once and every replica just re-deploys
    # it; the operator adds more SANs (other node IPs) via a CSR.
    hostname = settings.appliance_hostname or "spatiumddi-appliance"
    ips = _parse_host_ips(settings.appliance_host_ips)
    # #272 Phase 6 — extra SANs the cert must also cover (the
    # control-plane VIP etc), threaded in from the chart on promote.
    extra_sans = _parse_extra_sans(settings.appliance_extra_cert_sans)
    desired_sans = _desired_sans(hostname, ips, extra_sans)

    async with AsyncSessionLocal() as db:
        active_row = (
            await db.execute(
                select(ApplianceCertificate).where(ApplianceCertificate.is_active.is_(True))
            )
        ).scalar_one_or_none()

        if active_row is not None and active_row.cert_pem:
            covered = _sans_cover(active_row.sans_json, desired_sans)
            # #272 Phase 6 — regenerate ONLY a self-signed cert that no
            # longer covers every desired SAN (e.g. a control-plane VIP
            # was added on promote). Operator-uploaded / CSR-signed certs
            # are left untouched — the operator owns those SANs; we just
            # warn that the VIP isn't covered.
            if active_row.source == CERT_SOURCE_SELF_SIGNED and not covered:
                logger.info(
                    "appliance_self_signed_cert_regenerating",
                    cert_id=str(active_row.id),
                    old_sans=active_row.sans_json,
                    new_sans=desired_sans,
                )
                active_row.is_active = False
                await _generate_activate_deploy(db, hostname, ips, extra_sans)
                return

            # Path A — replay the active cert to disk in case the volume
            # was reset. Decrypts the key inside this function only; the
            # plaintext never leaves the deployer's scope.
            try:
                key_pem = decrypt_str(active_row.key_encrypted)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "appliance_active_cert_decrypt_failed",
                    cert_id=str(active_row.id),
                    error=str(exc),
                )
                return
            if not covered:
                logger.warning(
                    "appliance_active_cert_missing_sans",
                    cert_id=str(active_row.id),
                    source=active_row.source,
                    missing=[s for s in desired_sans if not _sans_cover(active_row.sans_json, [s])],
                )
            # Only deploy when the Secret doesn't ALREADY hold exactly this
            # cert (#767). Path A exists to recover a wiped Secret, not to
            # re-push a cert that is already deployed. (Until #1173 a
            # re-push also rolled the frontend: live on the #767 test
            # appliance, the first api restart after adoption moved it to
            # a new ReplicaSet for no reason.) An unchanged Secret means the
            # mounted copy is already correct, so there is nothing for a
            # reload to pick up.
            if read_deployed_cert() == (active_row.cert_pem, key_pem):
                logger.info(
                    "appliance_active_cert_already_deployed",
                    cert_id=str(active_row.id),
                    name=active_row.name,
                    source=active_row.source,
                )
                return

            deploy_and_reload(active_row.cert_pem, key_pem, name=active_row.name)
            logger.info(
                "appliance_active_cert_redeployed",
                cert_id=str(active_row.id),
                name=active_row.name,
                source=active_row.source,
            )
            return

        # Path B — no active row. Before minting anything, try to ADOPT
        # the cert already sitting in the spatium-appliance-tls Secret
        # (#767). On a fresh appliance firstboot writes a self-signed
        # cert there via a k3s auto-deploy manifest BEFORE the chart
        # bootstraps, so the frontend nginx has been serving it since
        # its very first request — including on the "still initialising"
        # page the operator is looking at right now. Generating a rival
        # cert here would swap it out mid-boot and force a SECOND browser
        # trust prompt.
        if await _adopt_deployed_cert(db, desired_sans):
            return

        await _generate_activate_deploy(db, hostname, ips, extra_sans)


async def _adopt_deployed_cert(db: AsyncSession, desired_sans: list[str]) -> bool:
    """Adopt the cert already in the TLS Secret as the active row.

    Returns True when adoption succeeded — in which case the caller must
    NOT generate or deploy anything: the Secret already holds this cert,
    so there is deliberately no ``deploy_and_reload`` call (no Secret
    PATCH, so nothing for the frontend to reload).

    Returns False — leaving the caller to generate a fresh cert — when
    there is nothing to adopt: not on k8s, Secret absent, cert or key
    unparseable, the key doesn't match the cert, or the cert's real SANs
    don't cover everything this appliance needs.

    Startup has no advisory lock (unlike ``reconcile_cluster_cert_sans``),
    so N api replicas can race here. Adoption makes that race benign in a
    way generating never was: every replica adopts the SAME bytes out of
    the shared Secret, so the cert actually served is identical whoever
    wins, where before each replica minted a different one.
    """
    deployed = read_deployed_cert()
    if deployed is None:
        return False
    cert_pem, key_pem = deployed

    # Same two validators the operator-upload path runs, so an adopted
    # cert is held to exactly the standard an uploaded one is.
    try:
        validate_key_matches_cert(cert_pem, key_pem)
        info = parse_pem_certificate(cert_pem)
    except TLSValidationError as exc:
        logger.warning("appliance_deployed_cert_unusable", error=str(exc))
        return False

    if not _sans_cover(info.sans, desired_sans):
        logger.info(
            "appliance_deployed_cert_sans_insufficient",
            deployed_sans=info.sans,
            desired_sans=desired_sans,
        )
        return False

    # Only a genuinely self-signed cert may be recorded as such. A DB
    # reprovision (factory reset, restore into an empty schema) can leave
    # a real CA-issued cert — an operator upload, or an ACME one from
    # #438 — sitting in the Secret with no row describing it. Labelling
    # that "self-signed" would hand it to two loops that must never touch
    # an operator's cert: reconcile_cluster_cert_sans only auto-replaces
    # self-signed rows, so the next SAN growth would overwrite it. So
    # adopt it as ``uploaded`` — the "operator owns this" bucket, which
    # every auto-replace path already skips. It won't auto-renew (the
    # ACME account + order state died with the DB, so it couldn't
    # anyway), but the secret_expiring alert covers appliance_cert_tls,
    # so an operator gets warned rather than silently expiring.
    self_signed = info.issuer_cn == info.subject_cn
    source = CERT_SOURCE_SELF_SIGNED if self_signed else CERT_SOURCE_UPLOADED
    row = ApplianceCertificate(
        name=_unique_name("self-signed-firstboot" if self_signed else "adopted-from-secret"),
        source=source,
        cert_pem=cert_pem,
        key_encrypted=encrypt_str(key_pem),
        is_active=True,
        activated_at=_dt.datetime.now(_dt.UTC),
        subject_cn=info.subject_cn,
        sans_json=info.sans,
        issuer_cn=info.issuer_cn,
        fingerprint_sha256=info.fingerprint_sha256,
        valid_from=info.valid_from,
        valid_to=info.valid_to,
        notes=(
            (
                "Adopted from the appliance TLS Secret on first api start — "
                "this is the cert the OS wrote at first boot, kept so the "
                "appliance presents one cert identity across the whole boot. "
                "Replace it with an uploaded cert, a CSR-signed cert, or a "
                "Let's Encrypt cert via Appliance → Fleet → Web UI Certificate."
            )
            if self_signed
            else (
                "Adopted from the appliance TLS Secret, which held a "
                f"CA-issued cert (issuer: {info.issuer_cn}) with no matching "
                "database row — most likely a factory reset or a restore into "
                "an empty schema. Recorded as operator-owned so nothing "
                "auto-replaces it. It will NOT auto-renew: re-issue or "
                "re-upload it via Appliance → Fleet → Web UI Certificate "
                "before it expires."
            )
        ),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    logger.info(
        "appliance_deployed_cert_adopted",
        cert_id=str(row.id),
        source=source,
        subject_cn=info.subject_cn,
        issuer_cn=info.issuer_cn,
        sans=info.sans,
        fingerprint=info.fingerprint_sha256[:23] + "…",
    )
    return True


async def _generate_activate_deploy(
    db: AsyncSession, hostname: str, ips: list[str], extra_sans: list[str]
) -> None:
    """Generate a self-signed cert, persist it as the active row, deploy.

    Shared by Path B (no active cert) and the Phase 6 regenerate branch
    (a self-signed cert that no longer covers every desired SAN). The
    caller is responsible for deactivating any prior active row before
    calling this — there is only ever one ``is_active=True`` row.
    """
    cert_pem, key_pem, info = _generate_self_signed_cert(hostname, ips, extra_sans)

    row = ApplianceCertificate(
        name=_unique_name("self-signed-default"),
        source=CERT_SOURCE_SELF_SIGNED,
        cert_pem=cert_pem,
        key_encrypted=encrypt_str(key_pem),
        is_active=True,
        activated_at=_dt.datetime.now(_dt.UTC),
        subject_cn=info["subject_cn"],
        sans_json=info["sans"],
        issuer_cn=info["issuer_cn"],
        fingerprint_sha256=info["fingerprint_sha256"],
        valid_from=info["valid_from"],
        valid_to=info["valid_to"],
        notes=(
            "Auto-generated on first boot. Replace with an uploaded "
            "cert, a CSR-signed cert, or a Let's Encrypt cert via "
            "Appliance → Fleet → Web UI Certificate."
        ),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    logger.info(
        "appliance_self_signed_cert_generated",
        cert_id=str(row.id),
        hostname=hostname,
        sans=info["sans"],
        fingerprint=info["fingerprint_sha256"][:23] + "…",
    )

    deploy_and_reload(cert_pem, key_pem, name=row.name)


# #272 Phase 7c — advisory-lock key so only one api replica regenerates
# the shared self-signed cert at a time. The api Deployment runs N pods
# (one per control-plane node), all running the periodic reconcile loop
# below against one shared spatium-appliance-tls Secret + one active
# appliance_certificate row. A Postgres transaction-level advisory lock
# serialises them; losers no-op. Arbitrary stable bigint.
_CERT_RECONCILE_LOCK_KEY = 0x5350433727  # "SPC7c"-ish


# Where the api records the certificate the TLS Secret holds, for the
# ``secret_expiring`` alert (#1895). The alert is evaluated in the Celery
# worker, whose ServiceAccount cannot read the Secret (#983 / #1445), so
# the api — which reads it on every deploy tick anyway — publishes what it
# saw here. The TTL makes a snapshot nobody refreshes (api down) expire
# rather than describe the past; the alert then falls back to the stored
# row, which is what it judged before #1895.
SERVED_CERT_SNAPSHOT_KEY = "spatium:appliance:served-cert"
_SERVED_CERT_SNAPSHOT_TTL = 300


async def _write_served_cert_snapshot(cert_pem: str) -> None:
    """Publish the served cert's fingerprint + expiry. Best-effort."""
    import json  # noqa: PLC0415

    from app.core.redis_client import make_async_redis  # noqa: PLC0415

    try:
        info = parse_pem_certificate(cert_pem)
    except TLSValidationError:
        return
    payload = json.dumps(
        {
            "fingerprint_sha256": info.fingerprint_sha256,
            "valid_to": info.valid_to.isoformat() if info.valid_to else None,
        }
    )
    client = None
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        await client.set(SERVED_CERT_SNAPSHOT_KEY, payload, ex=_SERVED_CERT_SNAPSHOT_TTL)
    except Exception as exc:  # noqa: BLE001 — advisory; the alert falls back
        logger.warning("appliance_served_cert_snapshot_failed", error=str(exc))
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass


async def read_served_cert_snapshot() -> tuple[_dt.datetime | None, str | None]:
    """``(valid_to, sha256 fingerprint)`` of the cert the api last saw in
    the TLS Secret, or ``(None, None)`` when there is no fresh snapshot
    (not an appliance, api not running, Redis unreachable).

    Readable from any process — the worker included — which is the point:
    the worker cannot read the Secret itself.
    """
    import json  # noqa: PLC0415

    from app.core.redis_client import make_async_redis  # noqa: PLC0415

    client = None
    try:
        client = make_async_redis(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        raw = await client.get(SERVED_CERT_SNAPSHOT_KEY)
    except Exception as exc:  # noqa: BLE001 — unknown, fall back to the row
        logger.info("appliance_served_cert_snapshot_unreadable", error=str(exc))
        return None, None
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass
    if not raw:
        return None, None
    try:
        data = json.loads(raw)
        valid_to = _dt.datetime.fromisoformat(data["valid_to"]) if data.get("valid_to") else None
        fingerprint = data.get("fingerprint_sha256") or None
    except (ValueError, TypeError, KeyError):
        return None, None
    return valid_to, fingerprint


async def sync_active_cert_to_secret() -> dict[str, object]:
    """Deploy the active DB certificate into the TLS Secret when they differ.

    The api-side half of #1895: ACME issuance / renewal runs in the Celery
    worker, whose ServiceAccount cannot patch ``spatium-appliance-tls``, so
    the worker commits the row and wakes the api, which calls this. Also
    run on a periodic tick, so a missed wake only delays the deploy.

    The active row is the source of truth, exactly as for the startup
    bootstrap's Path A (which has always overwritten a Secret that differs
    from it); this makes that reconcile continuous instead of once per api
    start. A cert set by hand in the Secret is therefore replaced within a
    tick — upload it under Appliance → Fleet → Web UI Certificate instead.

    The Secret PATCH is the whole deploy: the frontend pods reload nginx
    themselves when their mounted copy changes (#1173), so there is no
    roll to start or to retry.

    Idempotent: when the Secret already holds exactly the active cert + key
    nothing is written. It shares the
    advisory lock of ``reconcile_cluster_cert_sans`` (held for the whole
    read-compare-patch), so N api replicas make one patch, and the SAN
    reconcile cannot commit a regenerated cert between this reading the
    active row and patching it.
    """
    if not settings.appliance_mode:
        return {"status": "disabled"}

    from sqlalchemy import text  # noqa: PLC0415

    async with AsyncSessionLocal() as db:
        # Transaction-scoped: held until this session's transaction ends,
        # i.e. across the kubeapi calls below.
        got = (
            await db.execute(
                text("select pg_try_advisory_xact_lock(:k)"), {"k": _CERT_RECONCILE_LOCK_KEY}
            )
        ).scalar()
        if not got:
            return {"status": "locked"}
        active_row = (
            await db.execute(
                select(ApplianceCertificate).where(ApplianceCertificate.is_active.is_(True))
            )
        ).scalar_one_or_none()
        if active_row is None or not active_row.cert_pem:
            return {"status": "no-active-cert"}
        try:
            key_pem = decrypt_str(active_row.key_encrypted)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "appliance_active_cert_decrypt_failed",
                cert_id=str(active_row.id),
                error=str(exc),
            )
            return {"status": "decrypt-failed"}
        cert_pem = active_row.cert_pem
        name = active_row.name

        # Blocking kubeapi round-trips: off the event loop (non-negotiable #2).
        deployed = await asyncio.to_thread(read_deployed_cert)
        if deployed is not None:
            await _write_served_cert_snapshot(deployed[0])
        if deployed == (cert_pem, key_pem):
            return {"status": "in-sync"}

        if not await asyncio.to_thread(deploy_active_cert, cert_pem, key_pem, name=name):
            return {"status": "deploy-failed"}
        await _write_served_cert_snapshot(cert_pem)
        logger.info("appliance_active_cert_synced", cert_id=str(active_row.id), name=name)
        return {"status": "deployed"}


async def reconcile_cluster_cert_sans() -> dict[str, object]:
    """Grow the self-signed Web UI cert's SANs to cover every settled
    control-plane member (hostname + node IP) plus the control-plane VIP
    (#272 Phase 7c).

    Only ever touches a **self-signed** active cert — an operator-uploaded
    or CSR-signed cert is left alone (the operator owns those SANs). SAN
    coverage only GROWS: a demoted node's SAN stays in the cert (harmless),
    so a demote never changes the cert. Idempotent + coverage-gated, so
    it's a cheap no-op once converged; on growth it regenerates the cert
    and updates the ``spatium-appliance-tls`` Secret (via
    ``_generate_activate_deploy`` → ``deploy_and_reload``), and every
    frontend pod reloads nginx in place (#1173).

    Runs from a periodic api-side loop (main.lifespan); a per-transaction
    advisory lock keeps the api replicas from regenerating concurrently.
    """
    if not settings.appliance_mode:
        return {"status": "disabled"}

    from sqlalchemy import text  # noqa: PLC0415

    from app.models.appliance import (  # noqa: PLC0415
        APPLIANCE_STATE_APPROVED,
        CLUSTER_ROLE_MEMBER,
        CLUSTER_ROLE_PRIMARY,
        Appliance,
    )
    from app.models.settings import PlatformSettings  # noqa: PLC0415

    async with AsyncSessionLocal() as db:
        # One regenerator at a time across the api replicas. The lock is
        # held until this transaction commits/rolls back; losers bail.
        got = (
            await db.execute(
                text("select pg_try_advisory_xact_lock(:k)"),
                {"k": _CERT_RECONCILE_LOCK_KEY},
            )
        ).scalar()
        if not got:
            return {"status": "locked"}

        active_row = (
            await db.execute(
                select(ApplianceCertificate).where(ApplianceCertificate.is_active.is_(True))
            )
        ).scalar_one_or_none()
        if active_row is None or not active_row.cert_pem:
            # No active cert yet — startup bootstrap owns the first issue.
            return {"status": "no-active-cert"}
        if active_row.source != CERT_SOURCE_SELF_SIGNED:
            # Operator owns this cert + its SANs — never auto-replace it.
            return {"status": "operator-cert"}

        # Stable seed identity, same inputs ensure_self_signed_cert uses.
        hostname = settings.appliance_hostname or "spatiumddi-appliance"
        ips = _parse_host_ips(settings.appliance_host_ips)
        extra_sans = _parse_extra_sans(settings.appliance_extra_cert_sans)

        # Union in every settled control-plane member: node IP as an IP
        # SAN, hostname as a DNS SAN.
        members = (
            (
                await db.execute(
                    select(Appliance).where(
                        Appliance.state == APPLIANCE_STATE_APPROVED,
                        Appliance.cluster_role.in_((CLUSTER_ROLE_PRIMARY, CLUSTER_ROLE_MEMBER)),
                    )
                )
            )
            .scalars()
            .all()
        )
        for m in members:
            if m.node_ip and m.node_ip not in ips:
                ips.append(m.node_ip)
            if m.hostname and m.hostname not in extra_sans:
                extra_sans.append(m.hostname)

        # Control-plane VIP (platform_settings singleton) as an IP SAN.
        ps = (
            await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
        ).scalar_one_or_none()
        if ps and ps.control_plane_vip and ps.control_plane_vip not in extra_sans:
            extra_sans.append(ps.control_plane_vip)

        desired = _desired_sans(hostname, ips, extra_sans)
        if _sans_cover(active_row.sans_json, desired):
            return {"status": "covered", "sans": desired}

        logger.info(
            "appliance_cluster_cert_regenerating",
            old_sans=active_row.sans_json,
            new_sans=desired,
            members=[m.hostname for m in members],
        )
        active_row.is_active = False
        await _generate_activate_deploy(db, hostname, ips, extra_sans)
        return {"status": "regenerated", "sans": desired}


# ── Helpers ─────────────────────────────────────────────────────────


async def _unique_name_exists(name: str) -> bool:
    async with AsyncSessionLocal() as db:
        existing = await db.execute(
            select(ApplianceCertificate).where(ApplianceCertificate.name == name)
        )
        return existing.scalar_one_or_none() is not None


def _unique_name(base: str) -> str:
    """Make a unique name, falling back to ``base-<uuid8>`` on collision.

    Collisions are vanishingly rare — they'd only happen if an operator
    manually pre-created a row named ``self-signed-default`` before
    the appliance came up. Belt-and-braces.
    """
    return f"{base}-{uuid.uuid4().hex[:8]}"


def _parse_host_ips(env: str) -> list[str]:
    """Parse the comma-separated APPLIANCE_HOST_IPS env into a clean list.

    Drops loopback / link-local / unspecified entries and anything that
    fails to parse as an IP — firstboot's ``ip -o addr`` output should
    only produce sane values, but be defensive against shell-escaping
    quirks or future format changes.
    """
    out: list[str] = []
    for raw in env.split(","):
        s = raw.strip()
        if not s:
            continue
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            continue
        if s not in out:
            out.append(s)
    return out


def _parse_extra_sans(env: str) -> list[str]:
    """Parse the comma-separated APPLIANCE_EXTRA_CERT_SANS env.

    Accepts both IPs (the common case — a control-plane VIP) and DNS
    names. Drops empties, loopback / link-local / unspecified IPs, and
    de-dupes while preserving order. DNS names pass through verbatim.
    """
    out: list[str] = []
    for raw in env.split(","):
        s = raw.strip()
        if not s:
            continue
        try:
            ip = ipaddress.ip_address(s)
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                continue
        except ValueError:
            pass  # not an IP → treat as a DNS name
        if s not in out:
            out.append(s)
    return out


def _desired_sans(hostname: str, ips: list[str], extra_sans: list[str]) -> list[str]:
    """Ordered, de-duped SAN list the active cert ought to cover."""
    out: list[str] = []
    for s in [hostname, *ips, *extra_sans]:
        if s and s not in out:
            out.append(s)
    return out


def _sans_cover(existing: object, desired: list[str]) -> bool:
    """True if every ``desired`` SAN is present in ``existing``.

    ``existing`` is the persisted ``sans_json`` (a list of strings, or
    None for legacy rows). A None / non-list existing set covers nothing,
    forcing a regenerate when desired SANs are present.
    """
    have = set(existing) if isinstance(existing, list) else set()
    return all(s in have for s in desired)


def _generate_self_signed_cert(
    hostname: str, ips: list[str], extra_sans: list[str] | None = None
) -> tuple[str, str, dict[str, object]]:
    """Generate a fresh RSA-2048 self-signed cert + key.

    Subject + Issuer are both ``CN=<hostname>`` so OpenSSL renders
    "self-signed" consistently. SANs include every detected IP plus
    the hostname plus any ``extra_sans`` (e.g. the control-plane VIP) —
    browsers only check SANs since 2017, ignore CN. Each extra SAN is
    emitted as an IPAddress SAN when it parses as an IP, else a DNSName.
    """
    extra_sans = extra_sans or []
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

    san_entries: list[x509.GeneralName] = [x509.DNSName(hostname)]
    for ip in ips:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
        except ValueError:
            pass
    for entry in extra_sans:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            san_entries.append(x509.DNSName(entry))

    now = _dt.datetime.now(_dt.UTC)
    not_after = now + _dt.timedelta(days=_SELF_SIGNED_DAYS)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    info: dict[str, object] = {
        "subject_cn": hostname,
        "issuer_cn": hostname,
        "sans": _desired_sans(hostname, ips, extra_sans),
        "fingerprint_sha256": _format_fingerprint(cert.fingerprint(hashes.SHA256())),
        "valid_from": now,
        "valid_to": not_after,
    }
    return cert_pem, key_pem, info
