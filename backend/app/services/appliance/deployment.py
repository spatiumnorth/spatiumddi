"""Cert deployer — pushes the active cert to the frontend nginx.

Phase 11 wave 4 (#183) rewrite. Pre-Phase-11 this wrote the cert to
a docker-compose volume and SIGHUPed the frontend container via the
docker socket. The appliance is k3s-only now, so we go through
kubeapi instead:

* PATCH the ``spatium-appliance-tls`` Secret in the spatium
  namespace with the new tls.crt / tls.key.
* Bump a ``checksum/secret`` annotation on the frontend Deployment's
  pod template so the Deployment controller rolls a new pod —
  the new pod re-reads the Secret on schedule. Plain-secret-update
  alone doesn't trigger a rollout; the annotation is the standard
  k8s pattern for "this Deployment depends on this Secret".

Called by:

* ``ensure_self_signed_cert`` on appliance api startup — populates
  the Secret on first boot (no-op now that firstboot writes the
  Secret manifest via k3s's auto-deploy directory before the
  chart applies; kept here as a safety net).
* ``activate_certificate`` / ``import_signed_cert`` endpoints —
  pushes the freshly-activated cert into the Secret + bumps the
  Deployment annotation.

Designed to be fully no-op on non-appliance deploys: if
``settings.appliance_mode`` is false we never reach kubeapi.

The exception-leaks-as-warnings semantic is preserved — by the
time the deployer runs the DB has already been committed (the
cert IS active, the deployment is just the materialisation), so
a failed PATCH gets logged + retried on the next API restart's
``ensure_self_signed_cert`` pass.
"""

from __future__ import annotations

import hashlib

import structlog

from app.config import settings
from app.services.appliance import k8s

logger = structlog.get_logger(__name__)

# Secret name + filenames inside the Secret. ``kubernetes.io/tls``
# secrets always use these two keys; the umbrella chart's frontend
# template mounts the secret at /etc/nginx/tls/ and the
# TLS-aware nginx config (frontend-tls-config.yaml) reads
# /etc/nginx/tls/tls.crt + /etc/nginx/tls/tls.key.
_TLS_SECRET_NAME = "spatium-appliance-tls"
_TLS_CRT_KEY = "tls.crt"
_TLS_KEY_KEY = "tls.key"
# The Deployment name + annotation key for the rollout trigger.
# Tracks the umbrella chart's release-fullname convention
# (``<release>-frontend``); since the appliance release is named
# ``spatium-control`` (see appliance/mkosi.extra/usr/local/bin/
# spatiumddi-firstboot), the resolved name is
# ``spatium-control-spatiumddi-frontend``. Kept configurable via
# ``settings.appliance_frontend_deployment`` so a future rename
# doesn't require a code change.
_DEFAULT_FRONTEND_DEPLOYMENT = "spatium-control-spatiumddi-frontend"
_ROLLOUT_ANNOTATION = "spatiumddi.io/tls-secret-checksum"


def read_deployed_cert() -> tuple[str, str] | None:
    """Return the ``(cert_pem, key_pem)`` currently in the TLS Secret.

    ``None`` when the api isn't on k8s, the Secret is absent, or either
    key is missing/empty. Used by the startup bootstrap (#767) to ADOPT
    the cert firstboot minted rather than replacing it with a rival
    self-signed one — an appliance must present exactly one cert
    identity across a cold boot, or the operator gets a second browser
    trust prompt the moment the api finishes starting.
    """
    if not settings.appliance_mode:
        return None
    status, data = k8s.get_secret(_TLS_SECRET_NAME)
    if not data:
        logger.info("appliance_deployed_cert_unreadable", status=status)
        return None
    cert_pem = data.get(_TLS_CRT_KEY) or ""
    key_pem = data.get(_TLS_KEY_KEY) or ""
    # Emptiness is judged on the stripped value, but the ORIGINAL bytes
    # are what we return. Persisting a stripped copy would make the row
    # differ from the Secret by a trailing newline, so the next api start
    # would take Path A, re-deploy it, genuinely change the Secret data,
    # shift the rollout checksum, and roll the frontend (Recreate — ~5 s
    # with no Web UI). That is the mid-boot roll this whole path exists
    # to avoid, merely deferred by one restart.
    if not cert_pem.strip() or not key_pem.strip():
        return None
    return cert_pem, key_pem


def deploy_active_cert(cert_pem: str, key_pem: str, *, name: str = "") -> bool:
    """PATCH the appliance TLS Secret with the active cert + key.

    Idempotent: re-applying the same cert+key produces the same
    base64'd Secret data + the same checksum annotation, which
    kubeapi treats as a no-op (no rollout triggered).

    Returns True if the PATCH succeeded; False otherwise (and a
    structured log line at warning level explains why).
    """
    if not settings.appliance_mode:
        return False
    ok, err = k8s.patch_secret(
        _TLS_SECRET_NAME,
        {_TLS_CRT_KEY: cert_pem, _TLS_KEY_KEY: key_pem},
    )
    if not ok:
        logger.warning(
            "appliance_cert_secret_patch_failed",
            secret=_TLS_SECRET_NAME,
            name=name,
            error=err,
        )
        return False
    logger.info(
        "appliance_cert_secret_patched",
        secret=_TLS_SECRET_NAME,
        name=name,
    )
    return True


def rollout_checksum(crt_b64: str, key_b64: str, resource_version: str) -> str:
    """The pod-template annotation value that makes the frontend roll.

    The Secret's content AND its ``resourceVersion``. Content alone was the
    #1219 strand: a k3s start on the seed puts the first-boot certificate back
    into the Secret (#1215), the frontend pod that starts then serves it, and
    the api's write-back of the active certificate restores exactly the
    content the annotation already names, so the Deployment saw no change,
    never rolled, and nginx served the first-boot certificate until the pod
    happened to restart. A supervisor pinned to the real certificate refuses
    that one, so every remote appliance lost the control plane after each
    reboot. Every real write to the Secret moves its ``resourceVersion``; a
    PATCH that changes nothing does not, so re-applying an unchanged
    certificate still rolls nothing.
    """
    src = (crt_b64 + key_b64 + ":" + resource_version).encode("utf-8")
    return hashlib.sha256(src).hexdigest()


def reload_frontend_nginx() -> bool:
    """Trigger a frontend Deployment rollout so pods re-read the Secret.

    Bumps the ``spatiumddi.io/tls-secret-checksum`` annotation on the
    Deployment's pod template to ``rollout_checksum`` of the freshly-PATCHed
    Secret (its data and its ``resourceVersion``). The Deployment controller treats the annotation
    change as a template change + rolls the pod. Single-replica
    appliance frontend uses the Recreate strategy (chart template
    handles this when hostNetwork=true) so the old pod terminates
    BEFORE the new one binds :443 — ~5 s of downtime.

    Returns True on successful PATCH. False otherwise.
    """
    if not settings.appliance_mode:
        return False
    # Read the active Secret back so we hash exactly what's on the
    # wire — covers the case where another caller updated the
    # Secret between deploy_active_cert's PATCH and this call.
    import json  # noqa: PLC0415

    cfg = k8s.get_config()
    if cfg is None:
        logger.warning("appliance_nginx_reload_no_kubeapi")
        return False
    deployment_name = getattr(
        settings, "appliance_frontend_deployment", _DEFAULT_FRONTEND_DEPLOYMENT
    )
    # Pull the Secret to hash. patch_secret didn't return the
    # post-patch body, so re-GET via the same _request helper.
    from urllib.parse import quote  # noqa: PLC0415

    path = f"/api/v1/namespaces/{quote(cfg.namespace)}" f"/secrets/{quote(_TLS_SECRET_NAME)}"
    try:
        status, body = k8s._request("GET", path)
    except k8s.KubeapiUnavailableError as exc:
        logger.warning("appliance_nginx_reload_secret_read_failed", error=str(exc))
        return False
    if status != 200:
        logger.warning(
            "appliance_nginx_reload_secret_read_status",
            status=status,
            body=body[:200] if isinstance(body, bytes) else None,
        )
        return False
    try:
        secret = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("appliance_nginx_reload_secret_bad_json", error=str(exc))
        return False
    data = secret.get("data") or {}
    checksum = rollout_checksum(
        data.get(_TLS_CRT_KEY) or "",
        data.get(_TLS_KEY_KEY) or "",
        (secret.get("metadata") or {}).get("resourceVersion") or "",
    )
    ok, err = k8s.patch_deployment_annotation(deployment_name, _ROLLOUT_ANNOTATION, checksum)
    if not ok:
        logger.warning(
            "appliance_nginx_reload_deployment_patch_failed",
            deployment=deployment_name,
            error=err,
        )
        return False
    logger.info(
        "appliance_nginx_reloaded",
        deployment=deployment_name,
        checksum=checksum[:12],
    )
    return True


def deploy_and_reload(cert_pem: str, key_pem: str, *, name: str = "") -> bool:
    """Convenience — PATCH the Secret, then trigger Deployment rollout.

    Returns True only when both steps succeeded. Failed deploys skip
    the reload (no point bumping the rollout annotation when the
    Secret didn't update).
    """
    if not deploy_active_cert(cert_pem, key_pem, name=name):
        return False
    return reload_frontend_nginx()
