import base64
import binascii
import re
import sys

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Sentinel default for ``secret_key``. Every deployment MUST override it
# via the ``SECRET_KEY`` env var (or ``.env``): the model validator below
# refuses to boot on it, or on any other weak key, unless
# ``ALLOW_INSECURE_SECRET_KEY=true`` (#1222).
_SECRET_KEY_DEV_SENTINEL = "change-me-to-a-random-32-char-string"

# Every placeholder this repository has ever shipped for SECRET_KEY. The
# k8s one is a DIFFERENT string from .env.example's, and so used to get no
# warning at all (#1222).
_KNOWN_SECRET_KEY_PLACEHOLDERS = frozenset(
    {
        _SECRET_KEY_DEV_SENTINEL,
        "CHANGEME-generate-with-openssl-rand-hex-32",
    }
)

# ``openssl rand -hex 32`` gives 64; 32 is the floor the error asks for.
_SECRET_KEY_MIN_LENGTH = 32


def signing_key_weakness(key: str) -> str | None:
    """Why ``key`` must not sign tokens, or None if it may.

    SECRET_KEY signs every session JWT and, unless
    ``CREDENTIAL_ENCRYPTION_KEY`` is set, derives the Fernet key for every
    stored credential. On a known key, any logged-in user can mint a
    superadmin token (user ids are visible in the audit log), and a
    database dump decrypts every stored LDAP / integration / AI secret.
    """
    if key in _KNOWN_SECRET_KEY_PLACEHOLDERS:
        return "it is a placeholder committed to the SpatiumDDI repository"
    # A placeholder reads like one: "change" plus a separator
    # ("change-me-...", "CHANGEME-generate-..."), or "changeme" run together
    # ("ChangeMeChangeMe..."). Neither generator a deployment uses produces
    # either in practice: `openssl rand -hex` cannot spell "change" at all,
    # and Helm's randAlphaNum emits no separators and would spell
    # "changeme" about once in 16 billion keys. Bare "change" in an
    # all-alphanumeric key is allowed for that reason: at six letters it
    # turns up in roughly one random key in 15 million. "change" must also
    # start a word, so a passphrase like "corp-exchange-..." is not refused.
    lowered = key.lower()
    if "changeme" in lowered or (
        re.search(r"(?<![a-z])change", lowered) is not None and not key.isalnum()
    ):
        return "it looks like a placeholder (it contains 'change')"
    if len(key) < _SECRET_KEY_MIN_LENGTH:
        return f"it is shorter than {_SECRET_KEY_MIN_LENGTH} characters"
    return None


def credential_key_problem(key: str) -> str | None:
    """Why ``key`` cannot be the CREDENTIAL_ENCRYPTION_KEY, or None if it can.

    Empty is fine (the key is then derived from SECRET_KEY). Anything else
    must be what ``Fernet`` accepts: 32 bytes, url-safe base64. Checked at
    boot rather than on first use, because ``app.core.crypto`` builds its
    Fernet lazily, so a bad key would otherwise boot and then fail every
    encrypt / decrypt with an error callers read as "undecryptable".
    """
    raw = key.strip()
    if not raw:
        return None
    try:
        decoded = base64.urlsafe_b64decode(raw.encode())
    except (binascii.Error, ValueError):
        return "it is not url-safe base64"
    if len(decoded) != 32:
        return f"it decodes to {len(decoded)} bytes, not 32"
    return None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://spatiumddi:changeme@postgres:5432/spatiumddi"
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # Redis
    redis_url: str = "redis://redis:6379/0"
    # Redis Sentinel (#272 Phase 3). When ``redis_url`` /
    # ``celery_broker_url`` carry a ``sentinel://`` scheme, the
    # connection helpers query Sentinel for the current master named
    # ``redis_sentinel_master``. ``redis_sentinel_password`` is the
    # password Sentinel itself requires (often the same as the data
    # password); empty falls back to the password embedded in the URL.
    redis_sentinel_master: str = "mymaster"
    redis_sentinel_password: str = ""

    # Security
    secret_key: str = _SECRET_KEY_DEV_SENTINEL
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    credential_encryption_key: str = ""

    # CORS — comma-separated allowed origins (e.g.
    # "https://ddi.example.com,https://ipam.example.com"). Default "*"
    # keeps dev / same-origin appliance deployments working out of the
    # box. When left as "*" we serve a wildcard WITHOUT
    # ``allow_credentials`` — that avoids the dangerous "reflect any origin
    # + allow credentials" combo Starlette produces for ``["*"]`` +
    # ``allow_credentials=True``. Set explicit origins to lock the API
    # down to your frontend(s); credentials are then enabled for them.
    #
    # NOTE (#484): API calls authenticate via the Bearer Authorization
    # header, but the auth endpoints under ``/api/v1/auth`` also set/read the
    # HttpOnly ``spatium_refresh`` cookie. That cookie only matters for a
    # cross-ORIGIN frontend, which requires explicit ``cors_origins`` anyway
    # (wildcard mode disables credentials); the default same-origin
    # (nginx-proxied) deployment needs no CORS credentials at all.
    #
    # SECURITY (#400 / M6): if ``"*"`` appears MIXED with explicit
    # origins (e.g. ``"*,https://app.example.com"``) we treat the whole
    # list as a wildcard (``cors_origins_list`` collapses to ``["*"]``),
    # which forces ``allow_credentials=False`` at the middleware. Without
    # this, the explicit entries would flip credentials on while the
    # ``"*"`` still reflected every Origin — the exact "trust any site +
    # send credentials" combo we guard against above.
    cors_origins: str = "*"

    # TrustedHostMiddleware allow-list (#400 / L3). Comma-separated host
    # patterns (e.g. "ddi.example.com,*.example.com"). Default "*"
    # accepts any Host header so existing deploys behind a trusted
    # reverse proxy / on the appliance keep working out of the box.
    # Operators who terminate TLS directly on the API (or want defence
    # against Host-header injection / DNS-rebinding / cache-poisoning)
    # set this to their real hostnames. Starlette's TrustedHostMiddleware
    # treats ``["*"]`` as "allow everything".
    trusted_hosts: str = "*"

    # External auth providers (LDAP / OIDC / SAML) are configured via the GUI at
    # /admin/auth-providers — see backend/app/models/auth_provider.py. Secrets are
    # encrypted with the Fernet helper in app.core.crypto using
    # credential_encryption_key (or falling back to secret_key).

    # Celery
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"

    # Features
    feature_discovery_enabled: bool = True
    feature_dhcp_enabled: bool = True
    feature_dns_enabled: bool = True

    # Observability
    log_level: str = "INFO"
    log_format: str = "json"
    prometheus_metrics_enabled: bool = True
    # #1159 — /metrics needs ``Authorization: Bearer <token>``: this scrape
    # token, or any valid API token. The web port proxies /metrics and Docker
    # Compose publishes the api port, so an anonymous endpoint was readable by
    # anyone who could reach the login page. The Helm chart generates the
    # scrape token into its app Secret; Compose reads it from .env.
    prometheus_metrics_token: str = ""
    # False restores anonymous scraping. Not recommended: see above.
    prometheus_metrics_require_auth: bool = True

    # DNS agent
    dns_agent_key: str = ""
    dns_agent_token_ttl_hours: int = 24
    dns_agent_longpoll_timeout: int = 30
    dns_require_agent_approval: bool = False
    # Pending record ops shipped per config bundle. The queue is drained a
    # page at a time (the agent acks a page, the next long-poll ships the
    # next); unbounded, a bulk seed's backlog was materialised whole into
    # one response — 500k ops took the api to 4.2 GB and a memcg kill on
    # every poll (appliance sizing campaign, 2026-09-02/03).
    dns_agent_ops_batch: int = 5000
    # #1111 — the bundle is rendered once per (server, watermark) and stored
    # in ``dns_agent_bundle``; this many versions per server are kept (the
    # agent's own N-1 rule, #882), older ones are pruned on store.
    dns_agent_bundle_keep_versions: int = 2
    # After a commit that dirtied a bundle, publish the render request to the
    # worker (the 30 s render-missing sweep is the backstop either way). Off
    # only for test suites that have no broker.
    dns_agent_bundle_enqueue_renders: bool = True
    # The per-server render lock and the fleet-wide render slot are a lease
    # of this many seconds, renewed every third of it for as long as the
    # render runs. A render killed mid-flight (the OOM killer never runs its
    # ``finally``) frees both within one lease, instead of holding every
    # server's render for as long as a render may take.
    dns_agent_bundle_render_lease_seconds: int = 60
    # The long-poll serves stored bundles only. While this is on — the
    # migration release, whose worker may still be one release behind — a
    # missing or stale bundle is built inline in the request exactly as
    # before, once per (server, version), because it stores what it built.
    # Default off once the worker path is proven.
    dns_agent_bundle_inline_fallback: bool = True
    # The fallback is bounded (#1111): the api builds a server's bundle
    # itself only when the server has never had one (the upgrade from a
    # release before stored bundles), or when its stale bundle has waited
    # this long for the worker (from ``bundle_dirty_at``, which every render
    # that lands restarts). While renders keep landing it never builds, so a
    # change storm costs the api nothing; with no worker rendering, agents
    # are still served within this bound.
    dns_agent_bundle_inline_fallback_after_seconds: int = 120
    # After an inline attempt fails (at a million records the records query
    # outlives the api's 30 s command_timeout) no replica tries that server
    # again for this long. One attempt per server at a time across replicas.
    dns_agent_bundle_inline_fallback_backoff_seconds: int = 600

    # DHCP agent
    dhcp_agent_key: str = ""
    dhcp_agent_token_ttl_hours: int = 24
    dhcp_agent_longpoll_timeout: int = 30

    # BGP Looking Glass collector agent (#566)
    lg_agent_key: str = ""
    dhcp_require_agent_approval: bool = False
    dhcp_sync_interval_seconds: int = 60
    dhcp_lease_sync_interval_minutes: int = 5

    # App
    app_title: str = "SpatiumDDI"
    debug: bool = False
    # Running version. Populated from the ``VERSION`` env var, which the
    # compose file threads in from ``SPATIUMDDI_VERSION`` (same value the
    # operator sets to pick which image tag to run). Falls back to ``dev``
    # so unversioned local builds are obvious in the sidebar and don't
    # misreport themselves as a release.
    version: str = "dev"

    # GitHub repo coordinates used by the release-check task. Overridable
    # so forks can point their update check at their own repo.
    github_repo: str = "spatiumnorth/spatiumddi"

    # Boot on a placeholder or weak SECRET_KEY (see ``signing_key_weakness``)
    # with a warning instead of refusing. For local development only:
    # docker-compose.dev.yml sets it, nothing else should. #216 chose
    # warn-by-default; #1222 reversed that, because the warning was the
    # only thing between a default install and forgeable superadmin tokens.
    allow_insecure_secret_key: bool = False

    # Deprecated (#1222): refusing a weak SECRET_KEY is now the default.
    # Still read so an existing ``.env`` carrying it keeps parsing; it has
    # no effect.
    strict_secret_key: bool = False

    # #565 — when ``True``, the Celery worker refuses to process tasks
    # while the DB schema is behind the bundled Alembic head. Default
    # ``False`` so a transient mid-rollout window (code up before
    # ``alembic upgrade head`` finishes) doesn't hard-stop the worker —
    # the schema drift is logged loudly + raised as an ``AlertEvent``
    # regardless. Set to ``True`` in environments where a stale-schema
    # task run is worse than a deferred one.
    strict_schema_check: bool = False

    # #296 Phase B — slot-image mirror config.
    #
    # ``slot_image_mirror_url`` — when set, the slot-image upload +
    # download + delete handlers stream byte ops to this URL instead
    # of touching local FS. The mirror is a single-replica Deployment
    # with a node-pinned local-path PVC (see
    # charts/spatiumddi/templates/slot-image-mirror.yaml). Empty on
    # docker-compose / single-instance shapes — the api keeps its
    # current "write to /var/lib/spatiumddi/slot-images" behaviour
    # via the existing named volume.
    slot_image_mirror_url: str = ""
    # ``slot_image_mirror_secret`` — shared HMAC secret between the
    # api and the mirror. The api adds an ``X-Mirror-Auth`` header on
    # every internal call; the mirror verifies it before serving any
    # byte op. Defence in depth alongside the in-cluster Service
    # isolation. Auto-populated from the chart-rendered k8s Secret.
    slot_image_mirror_secret: str = ""
    # ``slot_image_mirror_mode`` — set on the mirror Deployment only.
    # Flips the api process into "I am the byte store" mode so the
    # ``/internal/slot-images`` endpoints accept X-Mirror-Auth
    # traffic. Leave false on every other api Deployment.
    slot_image_mirror_mode: bool = False

    # Demo mode — locks down abusable mutation surfaces (nmap, AI
    # provider creates, webhook targets, integration targets,
    # outbound mail/audit/backup, factory reset, password change)
    # and force-disables a curated set of feature modules. Used by
    # the GitHub Codespaces public demo so a visitor can't weaponise
    # it as a scanner / SSRF / relay. See app.core.demo_mode.
    demo_mode: bool = False

    # Service control (#890) — lets a superadmin start / stop / restart
    # the stack's own services from the web UI. Default OFF, and
    # deliberately so on both backends it can use: on docker-compose the
    # action goes through a restart-capable ``docker.sock``, which is
    # equivalent to root on the host; on Kubernetes it needs RBAC the
    # chart only grants when ``api.serviceControlRBAC.enabled`` is set,
    # so turning this on without that produces an honest 403 rather than
    # a silent no-op. Appliance installs are exempt — ``appliance_mode``
    # implies the gate, because ``POST /appliance/containers/{name}/
    # {action}`` already ships the same control there and requiring a new
    # opt-in would remove a capability rather than add one.
    # See app/services/service_control/.
    service_control_enabled: bool = False

    # #972 Phase 2 — the UNAUTHENTICATED HELD device self-query, where a
    # phone asks for its own location and is answered from its TCP source
    # address (RFC 5985 §6).
    #
    # Off by default, and that is not timidity: it is an endpoint that tells
    # an anonymous caller which room the device at a given address is in.
    # Turning it on is a decision to expose that to everything that can
    # reach the API, so the operator is expected to firewall the path to the
    # voice VLANs as well. It is rate-limited fail-CLOSED regardless, and it
    # returns the location ONLY — never the MAC, the port or the hostname —
    # because a phone has no need for those and an attacker would.
    e911_self_query_enabled: bool = False

    # Appliance mode — set true by the appliance ISO compose env so
    # the API knows it's running on an appliance image (vs. plain
    # docker-compose / k8s). Gates the "Appliance" sidebar section
    # and the /api/v1/appliance/* router family that surfaces
    # appliance-only management (TLS cert upload, release manager,
    # container live-logs, host network config, maintenance mode,
    # diagnostic bundle download). Phase 4 — see issue #134.
    #
    # appliance_version and appliance_hostname are populated by
    # spatiumddi-firstboot at install time so the management UI can
    # render "SpatiumDDI Appliance v0.1.0 @ host-name" without an
    # extra round-trip into the OS.
    appliance_mode: bool = False

    # #1003 item 2 — the OS installer's "Time source" answer, stamped into
    # the api's environment by spatiumddi-firstboot from the STATE config.
    #
    # Seeds the INITIAL value of ``platform_settings.ntp_pool_servers``
    # only. Once that row exists the control plane is authoritative, or an
    # operator's later change in the UI would be undone on every boot.
    # Empty (the default, and every non-appliance deployment) leaves the
    # model's own ``pool.ntp.org`` in place.
    #
    # Space-separated, because that is the shape the installer prompt
    # collects and writes to STATE.
    initial_ntp_servers: str = ""
    appliance_version: str = ""
    appliance_hostname: str = ""
    # The k8s node this api pod runs on, from the downward API
    # (spec.nodeName) in the api Deployment. The api runs one replica per
    # control-plane node under hard anti-affinity, and several endpoints
    # read the HOST filesystem through node-local hostPath mounts — so on
    # a cluster their answer is about whichever node served the request.
    # Empty on docker-compose / non-appliance deploys, where there is only
    # one place the answer could have come from.
    node_name: str = ""
    # Comma-separated list of the host's real IPv4/IPv6 addresses,
    # detected by spatiumddi-firstboot via `ip -o addr show scope global`
    # and threaded through .env. Used by the self-signed cert bootstrap
    # so the SAN list carries the IPs a browser will see (the api
    # container's own socket-level view only knows the docker bridge IP).
    # Empty on non-appliance deploys.
    appliance_host_ips: str = ""
    # #272 Phase 6 — extra SAN entries the self-signed cert MUST cover
    # beyond the host's own IPs: the control-plane VIP (and any other
    # floating address the operator's browser / agents hit). The
    # umbrella chart threads ``frontend.controlPlaneVIP`` in here on
    # promote; when set, the self-signed bootstrap regenerates an
    # existing self-signed cert that doesn't already cover these, so a
    # cert served on the VIP validates. Comma-separated IPs or DNS
    # names. Empty on single-node / non-appliance deploys.
    appliance_extra_cert_sans: str = ""

    # Where the cert deployer (Phase 4b.2) writes the currently-active
    # TLS cert + key. Mounted as a shared volume between the api
    # container (writes) and the appliance frontend nginx container
    # (reads from the same path on its side, conventionally
    # /etc/nginx/certs). On dev / non-appliance deploys the directory
    # may not exist; the deployer no-ops gracefully in that case.
    appliance_cert_dir: str = "/var/lib/spatiumddi/certs"
    # Name (or label) of the frontend container the deployer signals
    # SIGHUP to when a new cert is activated, so nginx reloads its
    # TLS context. Matches the compose service name on the appliance.
    appliance_frontend_container: str = "spatiumddi-frontend"

    # BGP prefix-hijack monitoring (issue #527). The periodic RIPEstat
    # poll (``app.tasks.bgp_hijack_poll``) is the reliable source of
    # truth and runs on any standard Celery deployment — gated by the
    # ``PlatformSettings.bgp_monitoring_enabled`` DB toggle, not by env.
    # This flag opts into the OPTIONAL long-running RIS Live WebSocket
    # consumer (``python -m app.services.bgp.ris_live``), the real-time
    # upgrade. Default OFF — a persistent WS doesn't fit the worker
    # model and the feature never depends on it.
    bgp_ris_live_enabled: bool = False
    bgp_ris_live_url: str = "wss://ris-live.ripe.net/v1/ws/"

    @property
    def cors_origins_list(self) -> list[str]:
        """``cors_origins`` parsed into a list. ``"*"`` (the default)
        yields ``["*"]``; a comma-separated value yields the trimmed,
        non-empty entries.

        SECURITY (#400 / M6): if ``"*"`` is present ANYWHERE in the list
        (even mixed with explicit origins), the whole list collapses to
        ``["*"]``. The middleware keys ``allow_credentials`` off this
        result being exactly ``["*"]``, so a wildcard always disables
        credentials regardless of any explicit entries the operator
        also listed. This closes the "explicit origin enables creds while
        ``*`` still reflects every Origin" combo.
        """
        raw = self.cors_origins.strip()
        if raw == "*" or not raw:
            return ["*"]
        entries = [o.strip() for o in raw.split(",") if o.strip()]
        if "*" in entries:
            return ["*"]
        return entries

    @property
    def trusted_hosts_list(self) -> list[str]:
        """``trusted_hosts`` parsed into a list for TrustedHostMiddleware
        (#400 / L3). ``"*"`` (the default) yields ``["*"]`` — accept any
        Host header; a comma-separated value yields the trimmed,
        non-empty patterns."""
        raw = self.trusted_hosts.strip()
        if raw == "*" or not raw:
            return ["*"]
        entries = [h.strip() for h in raw.split(",") if h.strip()]
        if "*" in entries:
            return ["*"]
        return entries or ["*"]

    @model_validator(mode="after")
    def _check_secret_key(self) -> "Settings":
        # Refuse to boot on a malformed CREDENTIAL_ENCRYPTION_KEY (#1222):
        # falling back to the SECRET_KEY-derived key would encrypt under a
        # different key than the operator configured.
        cred_problem = credential_key_problem(self.credential_encryption_key)
        if cred_problem is not None and not self.allow_insecure_secret_key:
            raise ValueError(
                f"CREDENTIAL_ENCRYPTION_KEY is not a valid Fernet key: {cred_problem}. "
                'Generate one with `python3 -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"`, or leave it empty to derive '
                "the key from SECRET_KEY. If stored credentials were written while this "
                "value was malformed, they are under the SECRET_KEY-derived key: leave "
                "it empty to keep reading them."
            )
        # Refuse to boot on a placeholder or weak SECRET_KEY (#1222).
        weakness = signing_key_weakness(self.secret_key)
        if weakness is None:
            return self
        if not self.allow_insecure_secret_key:
            raise ValueError(
                f"SECRET_KEY is not safe to use: {weakness}. It signs every session "
                "token, so anyone who knows it can sign in as any user. Generate one "
                "with `openssl rand -hex 32` and set SECRET_KEY. If this install already "
                "has data, first set SECRET_KEY to the NEW key, then run "
                "`python -m app.core.rotate_secret_key` with OLD_SECRET_KEY set to the "
                "key you are replacing, before starting the api, so stored credentials "
                "are re-encrypted under the new key "
                "('Rotating SECRET_KEY' in docs/deployment/DOCKER.md, or k8s/README.md for "
                "k8s/base). For local development "
                "only, ALLOW_INSECURE_SECRET_KEY=true boots with a warning instead."
            )
        # Skip the stderr spam under pytest — Settings() is built at import
        # time, so it would print on every collection.
        if "pytest" not in sys.modules:
            # The reason is left out on purpose: it is derived from the key,
            # and CodeQL rightly treats anything derived from a secret as
            # sensitive in a log line. The refusal above carries it.
            print(
                "WARNING: SECRET_KEY is a placeholder or too weak to sign tokens; "
                "booting anyway because ALLOW_INSECURE_SECRET_KEY=true. Never set "
                "that outside local development.",
                file=sys.stderr,
                flush=True,
            )
        return self


settings = Settings()
