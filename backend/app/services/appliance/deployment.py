"""Cert deployer — pushes the active cert to the frontend nginx.

Phase 11 wave 4 (#183) rewrite. Pre-Phase-11 this wrote the cert to
a docker-compose volume and SIGHUPed the frontend container via the
docker socket. The appliance is k3s-only now, so we go through
kubeapi instead:

* PATCH the ``spatium-appliance-tls`` Secret in the spatium
  namespace with the new tls.crt / tls.key.
* That is all (#1173). The frontend mounts the Secret as a directory,
  so the kubelet updates the files inside its running pods, and the
  image's ``40-tls-reload-watch.sh`` reloads nginx in place when they
  change: the web ports never stop accepting. This module used to bump
  a pod-template annotation so the Deployment rolled instead. The
  frontend is hostNetwork with host ports 80/443, so on a multi-node
  control plane that roll is terminate-first, and every node's web port
  refused connections until its replacement pod had started (about
  23 s on the seed when a member joined).

Called by:

* ``ensure_self_signed_cert`` on appliance api startup — populates
  the Secret on first boot (no-op now that firstboot writes the
  Secret manifest via k3s's auto-deploy directory before the
  chart applies; kept here as a safety net).
* ``activate_certificate`` / ``import_signed_cert`` endpoints —
  pushes the freshly-activated cert into the Secret.
* ``sync_active_cert_to_secret`` — the api's continuous reconcile
  (#1895): a Let's Encrypt cert the Celery worker issues or renews is
  deployed from here, on the worker's wake or the 60 s tick, because the
  worker's ServiceAccount cannot patch the Secret. It runs in the api only.

Designed to be fully no-op on non-appliance deploys: if
``settings.appliance_mode`` is false we never reach kubeapi.

The exception-leaks-as-warnings semantic is preserved — by the
time the deployer runs the DB has already been committed (the
cert IS active, the deployment is just the materialisation), so
a failed PATCH gets logged + retried by the api's
``sync_active_cert_to_secret`` tick (and on the next api start's
``ensure_self_signed_cert`` pass).
"""

from __future__ import annotations

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
    # would take Path A, re-deploy it and genuinely change the Secret
    # data: a certificate change nobody asked for (before #1173 it also
    # rolled the frontend, the mid-boot roll this path exists to avoid).
    if not cert_pem.strip() or not key_pem.strip():
        return None
    return cert_pem, key_pem


def deploy_active_cert(cert_pem: str, key_pem: str, *, name: str = "") -> bool:
    """PATCH the appliance TLS Secret with the active cert + key.

    Idempotent: re-applying the same cert+key produces the same
    base64'd Secret data, which kubeapi treats as a no-op (the mounted
    files do not change, so no frontend reloads).

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


def deploy_and_reload(cert_pem: str, key_pem: str, *, name: str = "") -> bool:
    """PATCH the Secret; every frontend pod then reloads nginx by itself.

    The frontend mounts the Secret as a directory, so the kubelet updates
    the files in its running pods (at each pod's next periodic sync:
    within about 90 s with the kubelet's default 1 min sync and its
    jitter), and the image's ``40-tls-reload-watch.sh`` runs ``nginx -s
    reload`` on that change, within its 5 s tick. The listening sockets stay open throughout.
    Nothing here touches the frontend Deployment any more (#1173): its
    roll was terminate-first on hostNetwork, so each node's web port
    refused connections until its replacement pod had started.

    Returns True when the Secret PATCH succeeded.
    """
    return deploy_active_cert(cert_pem, key_pem, name=name)
