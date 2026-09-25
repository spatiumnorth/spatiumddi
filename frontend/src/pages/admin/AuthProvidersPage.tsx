import { useMemo, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  authProvidersApi,
  authApi,
  groupsApi,
  type AuthProvider,
  type AuthProviderType,
  type AuthGroupMapping,
  type AuthProviderTestResult,
} from "@/lib/api";
import {
  Plus,
  Pencil,
  Trash2,
  X,
  KeyRound,
  ShieldCheck,
  PlugZap,
  CheckCircle2,
  XCircle,
  Loader2,
} from "lucide-react";
import { useModalDialog } from "@/components/ui/use-draggable-modal";
import { cn } from "@/lib/utils";
import { ConfirmModal } from "@/components/ui/confirm-modal";

const TYPE_LABELS: Record<AuthProviderType, string> = {
  ldap: "LDAP / Active Directory",
  oidc: "OIDC (OAuth 2.0)",
  saml: "SAML 2.0",
  radius: "RADIUS",
  tacacs: "TACACS+",
};

const TYPE_BADGE: Record<AuthProviderType, string> = {
  ldap: "bg-blue-500/15 text-blue-700 dark:text-blue-400",
  oidc: "bg-violet-500/15 text-violet-700 dark:text-violet-400",
  saml: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  radius: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  tacacs: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
};

// JSON scaffolds — still used for OIDC/SAML (structured forms arrive with
// Waves A.3 / A.4) and as the default for new LDAP providers before the user
// switches to the structured form.
const CONFIG_EXAMPLES: Record<AuthProviderType, string> = {
  ldap: `{
  "host": "ldap.example.com",
  "port": 636,
  "use_ssl": true,
  "start_tls": false,
  "bind_dn": "CN=spatium-svc,OU=ServiceAccounts,DC=example,DC=com",
  "user_base_dn": "OU=Users,DC=example,DC=com",
  "user_filter": "(&(objectClass=user)(sAMAccountName={username}))",
  "group_base_dn": "OU=Groups,DC=example,DC=com",
  "attr_username": "sAMAccountName",
  "attr_email": "mail",
  "attr_display_name": "displayName",
  "attr_member_of": "memberOf"
}`,
  oidc: `{
  "discovery_url": "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration",
  "client_id": "00000000-0000-0000-0000-000000000000",
  "scopes": ["openid", "profile", "email", "groups"],
  "claim_username": "preferred_username",
  "claim_email": "email",
  "claim_display_name": "name",
  "claim_groups": "groups"
}`,
  saml: `{
  "idp_metadata_url": "https://idp.example.com/metadata.xml",
  "idp_entity_id": "https://idp.example.com/",
  "idp_sso_url": "https://idp.example.com/sso",
  "idp_x509_cert": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----",
  "sp_entity_id": "https://ddi.example.com/saml",
  "attr_username": "NameID",
  "attr_email": "email",
  "attr_display_name": "displayName",
  "attr_groups": "groups"
}`,
  radius: `{
  "server": "radius.example.com",
  "port": 1812,
  "timeout": 5,
  "retries": 3,
  "nas_identifier": "spatiumddi",
  "attr_groups": "Filter-Id"
}`,
  tacacs: `{
  "server": "tacacs.example.com",
  "port": 49,
  "timeout": 5,
  "attr_groups": "priv-lvl"
}`,
};

const SECRETS_EXAMPLES: Record<AuthProviderType, string> = {
  ldap: `{
  "bind_password": "..."
}`,
  oidc: `{
  "client_secret": "..."
}`,
  saml: `{
  "sp_private_key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----"
}`,
  radius: `{
  "secret": "shared-secret"
}`,
  tacacs: `{
  "secret": "shared-secret"
}`,
};

const LDAP_DEFAULTS = {
  host: "",
  port: 636,
  backup_hosts: "",
  use_ssl: true,
  start_tls: false,
  tls_insecure: false,
  bind_dn: "",
  user_base_dn: "",
  user_filter: "(&(objectClass=user)(sAMAccountName={username}))",
  group_base_dn: "",
  attr_username: "sAMAccountName",
  attr_email: "mail",
  attr_display_name: "displayName",
  attr_member_of: "memberOf",
  tls_ca_cert_file: "",
};

const OIDC_DEFAULTS = {
  discovery_url: "",
  client_id: "",
  scopes: ["openid", "profile", "email", "groups"] as string[],
  claim_username: "preferred_username",
  claim_email: "email",
  claim_display_name: "name",
  claim_groups: "groups",
};

const SAML_DEFAULTS = {
  idp_metadata_url: "",
  idp_entity_id: "",
  idp_sso_url: "",
  idp_slo_url: "",
  idp_x509_cert: "",
  sp_entity_id: "",
  attr_username: "NameID",
  attr_email: "email",
  attr_display_name: "displayName",
  attr_groups: "groups",
};

const RADIUS_DEFAULTS = {
  server: "",
  port: 1812,
  backup_servers: "",
  timeout: 5,
  retries: 3,
  nas_identifier: "spatiumddi",
  attr_groups: "Filter-Id",
  dictionary_path: "",
};

const TACACS_DEFAULTS = {
  server: "",
  port: 49,
  backup_servers: "",
  timeout: 5,
  attr_groups: "priv-lvl",
};

type ModalMode = "create" | "edit";

interface ProviderForm {
  name: string;
  type: AuthProviderType;
  is_enabled: boolean;
  priority: number;
  auto_create_users: boolean;
  auto_update_users: boolean;
  config_json: string;
  secrets_json: string;
  secrets_dirty: boolean;
  // Password-input value for LDAP; empty means "don't replace stored secret".
  bind_password: string;
  // Password-input value for OIDC; same semantics as bind_password.
  oidc_client_secret: string;
  // PEM-encoded SP private key for SAML (optional). Empty = don't replace.
  saml_sp_private_key: string;
  // Shared secret for RADIUS. Empty = don't replace stored value.
  radius_secret: string;
  // Shared secret for TACACS+. Empty = don't replace stored value.
  tacacs_secret: string;
}

function emptyForm(): ProviderForm {
  return {
    name: "",
    type: "ldap",
    is_enabled: true,
    priority: 100,
    auto_create_users: true,
    auto_update_users: true,
    config_json: JSON.stringify(LDAP_DEFAULTS, null, 2),
    secrets_json: SECRETS_EXAMPLES.ldap,
    secrets_dirty: false,
    bind_password: "",
    oidc_client_secret: "",
    saml_sp_private_key: "",
    radius_secret: "",
    tacacs_secret: "",
  };
}

// Build the payload for the dry-run `/auth-providers/test` endpoint from
// the live form state. Only the secret for the selected provider type is
// included; empty secrets are sent as an empty dict so the backend's probe
// fails fast with "missing secret" rather than bouncing off a Fernet error.
function buildDryRunPayload(form: ProviderForm): {
  type: AuthProviderType;
  config: Record<string, unknown>;
  secrets: Record<string, unknown>;
} {
  let config: Record<string, unknown> = {};
  try {
    config = JSON.parse(form.config_json || "{}");
  } catch {
    config = {};
  }
  const secrets: Record<string, unknown> = {};
  if (form.type === "ldap" && form.bind_password) {
    secrets.bind_password = form.bind_password;
  } else if (form.type === "oidc" && form.oidc_client_secret) {
    secrets.client_secret = form.oidc_client_secret;
  } else if (form.type === "saml" && form.saml_sp_private_key) {
    secrets.sp_private_key = form.saml_sp_private_key;
  } else if (form.type === "radius" && form.radius_secret) {
    secrets.secret = form.radius_secret;
  } else if (form.type === "tacacs" && form.tacacs_secret) {
    secrets.secret = form.tacacs_secret;
  }
  return { type: form.type, config, secrets };
}

// ── LDAP structured form ──────────────────────────────────────────────────────

function LdapConfigFields({
  form,
  setForm,
}: {
  form: ProviderForm;
  setForm: React.Dispatch<React.SetStateAction<ProviderForm>>;
}) {
  const cfg = useMemo(() => {
    try {
      const parsed = {
        ...LDAP_DEFAULTS,
        ...JSON.parse(form.config_json || "{}"),
      };
      // Older configs (and the API round-trip) may store backup_hosts as an
      // array. Normalise to a newline-separated string for the textarea.
      if (Array.isArray(parsed.backup_hosts)) {
        parsed.backup_hosts = parsed.backup_hosts.join("\n");
      }
      return parsed;
    } catch {
      return { ...LDAP_DEFAULTS };
    }
  }, [form.config_json]);

  function setCfg(patch: Partial<typeof LDAP_DEFAULTS>) {
    const next = { ...cfg, ...patch };
    setForm((prev) => ({
      ...prev,
      config_json: JSON.stringify(next, null, 2),
    }));
  }

  const label = "block text-xs font-medium text-muted-foreground";
  const input =
    "mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm";
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-[1fr_120px] gap-3">
        <div>
          <label className={label}>LDAP host</label>
          <input
            value={cfg.host}
            onChange={(e) => setCfg({ host: e.target.value })}
            placeholder="ldap.example.com"
            className={input}
          />
        </div>
        <div>
          <label className={label}>Port</label>
          <input
            type="number"
            value={cfg.port}
            onChange={(e) => setCfg({ port: Number(e.target.value) || 0 })}
            className={input}
          />
        </div>
      </div>
      <div>
        <label className={label}>Backup hosts</label>
        <textarea
          value={cfg.backup_hosts}
          onChange={(e) => setCfg({ backup_hosts: e.target.value })}
          placeholder="dc2.example.com&#10;dc3.example.com:636"
          rows={2}
          className={input}
        />
        <p className="mt-1 text-[11px] text-muted-foreground">
          Optional failover DCs — one per line, <code>host</code> or{" "}
          <code>host:port</code>. Tried in order if the primary is unreachable.
        </p>
      </div>
      <div className="flex gap-4">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={!!cfg.use_ssl}
            onChange={(e) => setCfg({ use_ssl: e.target.checked })}
          />
          Use SSL (ldaps://)
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={!!cfg.start_tls}
            onChange={(e) => setCfg({ start_tls: e.target.checked })}
          />
          StartTLS
        </label>
      </div>
      {(cfg.use_ssl || cfg.start_tls) && (
        <div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={!!cfg.tls_insecure}
              onChange={(e) => setCfg({ tls_insecure: e.target.checked })}
            />
            Ignore TLS certificate errors (insecure)
          </label>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Accepts self-signed certs and hostname mismatches. Useful when
            connecting by IP or against a lab cert that isn't trusted locally.
            Channel is still encrypted — but the server identity is not
            verified. <strong>Do not enable in production.</strong>
          </p>
        </div>
      )}

      <div>
        <label className={label}>Service bind DN</label>
        <input
          value={cfg.bind_dn}
          onChange={(e) => setCfg({ bind_dn: e.target.value })}
          placeholder="CN=spatium-svc,OU=ServiceAccounts,DC=example,DC=com"
          className={input}
        />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={label}>User search base DN</label>
          <input
            value={cfg.user_base_dn}
            onChange={(e) => setCfg({ user_base_dn: e.target.value })}
            placeholder="OU=Users,DC=example,DC=com"
            className={input}
          />
        </div>
        <div>
          <label className={label}>Group search base DN (optional)</label>
          <input
            value={cfg.group_base_dn}
            onChange={(e) => setCfg({ group_base_dn: e.target.value })}
            placeholder="OU=Groups,DC=example,DC=com"
            className={input}
          />
        </div>
      </div>

      <div>
        <label className={label}>
          User filter{" "}
          <span className="opacity-60">— must contain {"{username}"}</span>
        </label>
        <input
          value={cfg.user_filter}
          onChange={(e) => setCfg({ user_filter: e.target.value })}
          placeholder="(&(objectClass=user)(sAMAccountName={username}))"
          className={cn(input, "font-mono text-xs")}
        />
      </div>

      <details className="rounded-md border px-3 py-2">
        <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
          Attribute mapping (advanced)
        </summary>
        <div className="mt-3 grid grid-cols-2 gap-3">
          <div>
            <label className={label}>Username attribute</label>
            <input
              value={cfg.attr_username}
              onChange={(e) => setCfg({ attr_username: e.target.value })}
              className={input}
            />
          </div>
          <div>
            <label className={label}>Email attribute</label>
            <input
              value={cfg.attr_email}
              onChange={(e) => setCfg({ attr_email: e.target.value })}
              className={input}
            />
          </div>
          <div>
            <label className={label}>Display-name attribute</label>
            <input
              value={cfg.attr_display_name}
              onChange={(e) => setCfg({ attr_display_name: e.target.value })}
              className={input}
            />
          </div>
          <div>
            <label className={label}>Group-membership attribute</label>
            <input
              value={cfg.attr_member_of}
              onChange={(e) => setCfg({ attr_member_of: e.target.value })}
              className={input}
            />
          </div>
          <div className="col-span-2">
            <label className={label}>
              TLS CA certificate path (optional, in-container)
            </label>
            <input
              value={cfg.tls_ca_cert_file}
              onChange={(e) => setCfg({ tls_ca_cert_file: e.target.value })}
              placeholder="/etc/ssl/certs/corp-ca.pem"
              className={input}
            />
          </div>
        </div>
      </details>
    </div>
  );
}

// ── OIDC structured form ──────────────────────────────────────────────────────

function OidcConfigFields({
  form,
  setForm,
}: {
  form: ProviderForm;
  setForm: React.Dispatch<React.SetStateAction<ProviderForm>>;
}) {
  const cfg = useMemo(() => {
    try {
      return { ...OIDC_DEFAULTS, ...JSON.parse(form.config_json || "{}") };
    } catch {
      return { ...OIDC_DEFAULTS };
    }
  }, [form.config_json]);

  function setCfg(patch: Partial<typeof OIDC_DEFAULTS>) {
    const next = { ...cfg, ...patch };
    setForm((prev) => ({
      ...prev,
      config_json: JSON.stringify(next, null, 2),
    }));
  }

  const label = "block text-xs font-medium text-muted-foreground";
  const input =
    "mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm";

  const scopesText = Array.isArray(cfg.scopes)
    ? cfg.scopes.join(" ")
    : String(cfg.scopes ?? "");

  return (
    <div className="space-y-3">
      <div>
        <label className={label}>Discovery URL</label>
        <input
          value={cfg.discovery_url}
          onChange={(e) => setCfg({ discovery_url: e.target.value })}
          placeholder="https://login.example.com/.well-known/openid-configuration"
          className={cn(input, "font-mono text-xs")}
        />
        <p className="mt-1 text-xs text-muted-foreground">
          The IdP's OIDC metadata URL. Fetched at provider save + cached for one
          hour.
        </p>
      </div>

      <div>
        <label className={label}>Client ID</label>
        <input
          value={cfg.client_id}
          onChange={(e) => setCfg({ client_id: e.target.value })}
          placeholder="application-id-from-idp"
          className={input}
        />
      </div>

      <div>
        <label className={label}>Scopes (space-separated)</label>
        <input
          value={scopesText}
          onChange={(e) =>
            setCfg({
              scopes: e.target.value
                .split(/\s+/)
                .map((s) => s.trim())
                .filter(Boolean),
            })
          }
          placeholder="openid profile email groups"
          className={cn(input, "font-mono text-xs")}
        />
        <p className="mt-1 text-xs text-muted-foreground">
          <code>openid</code> is added automatically if missing. Most IdPs
          require <code>groups</code> (or equivalent) to surface the claim we
          map to internal groups.
        </p>
      </div>

      <details className="rounded-md border px-3 py-2">
        <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
          Claim mapping (advanced)
        </summary>
        <div className="mt-3 grid grid-cols-2 gap-3">
          <div>
            <label className={label}>Username claim</label>
            <input
              value={cfg.claim_username}
              onChange={(e) => setCfg({ claim_username: e.target.value })}
              className={input}
            />
          </div>
          <div>
            <label className={label}>Email claim</label>
            <input
              value={cfg.claim_email}
              onChange={(e) => setCfg({ claim_email: e.target.value })}
              className={input}
            />
          </div>
          <div>
            <label className={label}>Display-name claim</label>
            <input
              value={cfg.claim_display_name}
              onChange={(e) => setCfg({ claim_display_name: e.target.value })}
              className={input}
            />
          </div>
          <div>
            <label className={label}>Groups claim</label>
            <input
              value={cfg.claim_groups}
              onChange={(e) => setCfg({ claim_groups: e.target.value })}
              className={input}
            />
          </div>
        </div>
      </details>
    </div>
  );
}

// ── SAML structured form ──────────────────────────────────────────────────────

function SamlConfigFields({
  form,
  setForm,
  providerId,
}: {
  form: ProviderForm;
  setForm: React.Dispatch<React.SetStateAction<ProviderForm>>;
  providerId: string | null;
}) {
  const cfg = useMemo(() => {
    try {
      return { ...SAML_DEFAULTS, ...JSON.parse(form.config_json || "{}") };
    } catch {
      return { ...SAML_DEFAULTS };
    }
  }, [form.config_json]);

  function setCfg(patch: Partial<typeof SAML_DEFAULTS>) {
    const next = { ...cfg, ...patch };
    setForm((prev) => ({
      ...prev,
      config_json: JSON.stringify(next, null, 2),
    }));
  }

  const label = "block text-xs font-medium text-muted-foreground";
  const input =
    "mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm";

  return (
    <div className="space-y-3">
      <div>
        <label className={label}>IdP metadata URL (optional)</label>
        <input
          value={cfg.idp_metadata_url}
          onChange={(e) => setCfg({ idp_metadata_url: e.target.value })}
          placeholder="https://idp.example.com/saml/metadata"
          className={cn(input, "font-mono text-xs")}
        />
        <p className="mt-1 text-xs text-muted-foreground">
          If provided, the Test button will fetch + parse this URL. You still
          need to paste the resolved values below (auto-fill from metadata
          arrives later).
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={label}>IdP entity ID</label>
          <input
            value={cfg.idp_entity_id}
            onChange={(e) => setCfg({ idp_entity_id: e.target.value })}
            placeholder="https://idp.example.com/"
            className={input}
          />
        </div>
        <div>
          <label className={label}>IdP SSO URL</label>
          <input
            value={cfg.idp_sso_url}
            onChange={(e) => setCfg({ idp_sso_url: e.target.value })}
            placeholder="https://idp.example.com/sso"
            className={input}
          />
        </div>
      </div>

      <div>
        <label className={label}>IdP SLO URL (optional)</label>
        <input
          value={cfg.idp_slo_url}
          onChange={(e) => setCfg({ idp_slo_url: e.target.value })}
          placeholder="https://idp.example.com/slo"
          className={input}
        />
      </div>

      <div>
        <label className={label}>IdP signing certificate (PEM)</label>
        <textarea
          value={cfg.idp_x509_cert}
          onChange={(e) => setCfg({ idp_x509_cert: e.target.value })}
          rows={4}
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          className={cn(input, "font-mono text-xs")}
        />
      </div>

      <div>
        <label className={label}>SP entity ID (optional)</label>
        <input
          value={cfg.sp_entity_id}
          onChange={(e) => setCfg({ sp_entity_id: e.target.value })}
          placeholder="leave blank to derive from app base URL"
          className={input}
        />
      </div>

      {providerId && (
        <div className="rounded-md border bg-muted px-3 py-2 text-xs text-muted-foreground">
          <div className="font-medium">SP metadata URL</div>
          <div className="mt-1 flex items-center gap-2">
            <code className="flex-1 break-all font-mono">
              /api/v1/auth/{providerId}/metadata
            </code>
            <a
              href={`/api/v1/auth/${providerId}/metadata`}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-md border bg-background px-2 py-0.5 hover:bg-accent"
            >
              View
            </a>
          </div>
          <p className="mt-1">
            Register this URL (or its contents) with your IdP as the Service
            Provider metadata.
          </p>
        </div>
      )}

      <details className="rounded-md border px-3 py-2">
        <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
          Attribute mapping (advanced)
        </summary>
        <div className="mt-3 grid grid-cols-2 gap-3">
          <div>
            <label className={label}>Username attribute</label>
            <input
              value={cfg.attr_username}
              onChange={(e) => setCfg({ attr_username: e.target.value })}
              className={input}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              Use <code>NameID</code> to take the assertion's NameID value.
            </p>
          </div>
          <div>
            <label className={label}>Email attribute</label>
            <input
              value={cfg.attr_email}
              onChange={(e) => setCfg({ attr_email: e.target.value })}
              className={input}
            />
          </div>
          <div>
            <label className={label}>Display-name attribute</label>
            <input
              value={cfg.attr_display_name}
              onChange={(e) => setCfg({ attr_display_name: e.target.value })}
              className={input}
            />
          </div>
          <div>
            <label className={label}>Groups attribute</label>
            <input
              value={cfg.attr_groups}
              onChange={(e) => setCfg({ attr_groups: e.target.value })}
              className={input}
            />
          </div>
        </div>
      </details>
    </div>
  );
}

// ── RADIUS structured form ────────────────────────────────────────────────────

function RadiusConfigFields({
  form,
  setForm,
}: {
  form: ProviderForm;
  setForm: React.Dispatch<React.SetStateAction<ProviderForm>>;
}) {
  const cfg = useMemo(() => {
    try {
      const parsed = {
        ...RADIUS_DEFAULTS,
        ...JSON.parse(form.config_json || "{}"),
      };
      if (Array.isArray(parsed.backup_servers)) {
        parsed.backup_servers = parsed.backup_servers.join("\n");
      }
      return parsed;
    } catch {
      return { ...RADIUS_DEFAULTS };
    }
  }, [form.config_json]);

  function setCfg(patch: Partial<typeof RADIUS_DEFAULTS>) {
    const next = { ...cfg, ...patch };
    setForm((prev) => ({
      ...prev,
      config_json: JSON.stringify(next, null, 2),
    }));
  }

  const label = "block text-xs font-medium text-muted-foreground";
  const input =
    "mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm";

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-[1fr_120px] gap-3">
        <div>
          <label className={label}>RADIUS server</label>
          <input
            value={cfg.server}
            onChange={(e) => setCfg({ server: e.target.value })}
            placeholder="radius.example.com"
            className={input}
          />
        </div>
        <div>
          <label className={label}>Auth port</label>
          <input
            type="number"
            value={cfg.port}
            onChange={(e) => setCfg({ port: Number(e.target.value) || 0 })}
            className={input}
          />
        </div>
      </div>
      <div>
        <label className={label}>Backup servers</label>
        <textarea
          value={cfg.backup_servers}
          onChange={(e) => setCfg({ backup_servers: e.target.value })}
          placeholder="radius2.example.com&#10;radius3.example.com:1812"
          rows={2}
          className={input}
        />
        <p className="mt-1 text-[11px] text-muted-foreground">
          Optional failover servers — one per line, <code>host</code> or{" "}
          <code>host:port</code>. Share the shared secret with the primary.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={label}>Timeout (seconds)</label>
          <input
            type="number"
            value={cfg.timeout}
            onChange={(e) => setCfg({ timeout: Number(e.target.value) || 0 })}
            className={input}
          />
        </div>
        <div>
          <label className={label}>Retries</label>
          <input
            type="number"
            value={cfg.retries}
            onChange={(e) => setCfg({ retries: Number(e.target.value) || 0 })}
            className={input}
          />
        </div>
      </div>

      <div>
        <label className={label}>NAS identifier</label>
        <input
          value={cfg.nas_identifier}
          onChange={(e) => setCfg({ nas_identifier: e.target.value })}
          placeholder="spatiumddi"
          className={input}
        />
        <p className="mt-1 text-xs text-muted-foreground">
          Sent as <code>NAS-Identifier</code> in every Access-Request. Useful
          for server-side filtering / policy.
        </p>
      </div>

      <details className="rounded-md border px-3 py-2">
        <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
          Attribute mapping (advanced)
        </summary>
        <div className="mt-3 grid grid-cols-2 gap-3">
          <div>
            <label className={label}>Groups attribute</label>
            <input
              value={cfg.attr_groups}
              onChange={(e) => setCfg({ attr_groups: e.target.value })}
              placeholder="Filter-Id"
              className={input}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              Standard choices: <code>Filter-Id</code>, <code>Class</code>. Use
              a vendor-specific attribute name if your server emits one.
            </p>
          </div>
          <div>
            <label className={label}>
              Extra dictionary path (in-container, optional)
            </label>
            <input
              value={cfg.dictionary_path}
              onChange={(e) => setCfg({ dictionary_path: e.target.value })}
              placeholder="/etc/spatium/radius/dictionary.corp"
              className={input}
            />
          </div>
        </div>
      </details>
    </div>
  );
}

// ── TACACS+ structured form ───────────────────────────────────────────────────

function TacacsConfigFields({
  form,
  setForm,
}: {
  form: ProviderForm;
  setForm: React.Dispatch<React.SetStateAction<ProviderForm>>;
}) {
  const cfg = useMemo(() => {
    try {
      const parsed = {
        ...TACACS_DEFAULTS,
        ...JSON.parse(form.config_json || "{}"),
      };
      if (Array.isArray(parsed.backup_servers)) {
        parsed.backup_servers = parsed.backup_servers.join("\n");
      }
      return parsed;
    } catch {
      return { ...TACACS_DEFAULTS };
    }
  }, [form.config_json]);

  function setCfg(patch: Partial<typeof TACACS_DEFAULTS>) {
    const next = { ...cfg, ...patch };
    setForm((prev) => ({
      ...prev,
      config_json: JSON.stringify(next, null, 2),
    }));
  }

  const label = "block text-xs font-medium text-muted-foreground";
  const input =
    "mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm";

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-[1fr_120px] gap-3">
        <div>
          <label className={label}>TACACS+ server</label>
          <input
            value={cfg.server}
            onChange={(e) => setCfg({ server: e.target.value })}
            placeholder="tacacs.example.com"
            className={input}
          />
        </div>
        <div>
          <label className={label}>Port</label>
          <input
            type="number"
            value={cfg.port}
            onChange={(e) => setCfg({ port: Number(e.target.value) || 0 })}
            className={input}
          />
        </div>
      </div>
      <div>
        <label className={label}>Backup servers</label>
        <textarea
          value={cfg.backup_servers}
          onChange={(e) => setCfg({ backup_servers: e.target.value })}
          placeholder="tacacs2.example.com&#10;tacacs3.example.com:49"
          rows={2}
          className={input}
        />
        <p className="mt-1 text-[11px] text-muted-foreground">
          Optional failover servers — one per line, <code>host</code> or{" "}
          <code>host:port</code>. Share the shared secret with the primary.
        </p>
      </div>

      <div>
        <label className={label}>Timeout (seconds)</label>
        <input
          type="number"
          value={cfg.timeout}
          onChange={(e) => setCfg({ timeout: Number(e.target.value) || 0 })}
          className={input}
        />
      </div>

      <details className="rounded-md border px-3 py-2">
        <summary className="cursor-pointer text-xs font-medium text-muted-foreground">
          Attribute mapping (advanced)
        </summary>
        <div className="mt-3 grid grid-cols-1 gap-3">
          <div>
            <label className={label}>Groups AV-pair</label>
            <input
              value={cfg.attr_groups}
              onChange={(e) => setCfg({ attr_groups: e.target.value })}
              placeholder="priv-lvl"
              className={input}
            />
            <p className="mt-1 text-xs text-muted-foreground">
              When set to <code>priv-lvl</code> (the default), numeric values
              are emitted as <code>priv-lvl:N</code> so you can map e.g.{" "}
              <code>priv-lvl:15</code> → Admins in the group-mapping table. Use
              a custom AV-pair name (e.g. <code>group</code>) if your TACACS+
              server supplies one.
            </p>
          </div>
        </div>
      </details>
    </div>
  );
}

// ── Test connection panel (works in both create and edit mode) ──────────────
//
// In edit mode we call `POST /auth-providers/{id}/test` with the stored,
// already-encrypted secrets. In create mode (or when the form has dirty
// secrets that haven't been saved yet) we call the dry-run endpoint
// `POST /auth-providers/test` with the current form's plaintext config +
// secrets — nothing is persisted.
//
// The dry-run version is what lets admins iterate on LDAP TLS settings,
// bind DN, backup hosts, etc. without polluting the database with broken
// provider rows.

type DryRunTestPayload = {
  type: AuthProviderType;
  config: Record<string, unknown>;
  secrets: Record<string, unknown>;
};

function TestConnectionPanel({
  providerId,
  providerType,
  dryRunPayload,
}: {
  providerId?: string;
  providerType: AuthProviderType;
  /** If provided, the panel always uses the dry-run endpoint with this
   * snapshot of the form (overrides `providerId`). Pass this from create
   * mode, or from edit mode when secrets are dirty. */
  dryRunPayload?: () => DryRunTestPayload;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<AuthProviderTestResult | null>(null);
  const [showUser, setShowUser] = useState(false);
  const mut = useMutation({
    mutationFn: (body: { username?: string; password?: string }) => {
      if (dryRunPayload) {
        const snapshot = dryRunPayload();
        return authProvidersApi.testUnsaved({ ...snapshot, ...body });
      }
      if (providerId) {
        return authProvidersApi.test(providerId, body);
      }
      throw new Error("no providerId and no dryRunPayload — cannot test");
    },
    onSuccess: (r) => setResult(r),
    onError: (err: Error & { response?: { data?: { detail?: string } } }) =>
      setResult({
        ok: false,
        message: err.response?.data?.detail ?? err.message,
        details: {},
      }),
  });

  function testService() {
    setResult(null);
    mut.mutate({});
  }
  function testUser() {
    setResult(null);
    mut.mutate({ username, password });
  }

  const serviceLabel =
    providerType === "oidc"
      ? "Probe discovery URL"
      : providerType === "saml"
        ? "Probe metadata / settings"
        : providerType === "radius"
          ? "Probe RADIUS (shared secret)"
          : providerType === "tacacs"
            ? "Probe TACACS+ (shared secret)"
            : "Test service bind";

  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-medium text-muted-foreground">
          <PlugZap className="h-3 w-3" /> Test connection
        </div>
        <div className="flex gap-2">
          <button
            onClick={testService}
            disabled={mut.isPending}
            className="rounded-md border px-3 py-1 text-xs font-medium hover:bg-accent disabled:opacity-50"
          >
            {mut.isPending && !showUser ? (
              <Loader2 className="inline h-3 w-3 animate-spin" />
            ) : (
              serviceLabel
            )}
          </button>
          {providerType === "ldap" && (
            <button
              onClick={() => setShowUser((v) => !v)}
              className="rounded-md border px-3 py-1 text-xs font-medium hover:bg-accent"
            >
              {showUser ? "Hide" : "Test as user"}
            </button>
          )}
        </div>
      </div>

      {showUser && providerType === "ldap" && (
        <div className="flex items-end gap-2 pt-2">
          <div className="flex-1">
            <label className="block text-xs text-muted-foreground">
              Username
            </label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="alice"
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
            />
          </div>
          <div className="flex-1">
            <label className="block text-xs text-muted-foreground">
              Password (optional)
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="leave blank to search only"
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
            />
          </div>
          <button
            onClick={testUser}
            disabled={mut.isPending || !username.trim()}
            className="rounded-md bg-primary px-3 py-1 text-xs font-medium text-primary-foreground disabled:opacity-50"
          >
            {mut.isPending ? (
              <Loader2 className="inline h-3 w-3 animate-spin" />
            ) : (
              "Probe"
            )}
          </button>
        </div>
      )}

      {result && (
        <div
          className={cn(
            "rounded-md border px-3 py-2 text-xs",
            result.ok
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300"
              : "border-destructive/30 bg-destructive/10 text-destructive",
          )}
        >
          <div className="flex items-start gap-2">
            {result.ok ? (
              <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0" />
            ) : (
              <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
            )}
            <div className="min-w-0 flex-1">
              <div className="font-medium">{result.message}</div>
              {Object.keys(result.details).length > 0 && (
                <pre className="mt-1 whitespace-pre-wrap break-words font-mono text-[11px] opacity-80">
                  {JSON.stringify(result.details, null, 2)}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Group mappings editor (edit mode only) ───────────────────────────────────

function MappingsSection({ providerId }: { providerId: string }) {
  const qc = useQueryClient();
  const { data: mappings = [] } = useQuery({
    queryKey: ["auth-providers", providerId, "mappings"],
    queryFn: () => authProvidersApi.listMappings(providerId),
  });
  const { data: groups = [] } = useQuery({
    queryKey: ["groups"],
    queryFn: groupsApi.list,
  });

  const [draftExternal, setDraftExternal] = useState("");
  const [draftGroupId, setDraftGroupId] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editExternal, setEditExternal] = useState("");
  const [editGroupId, setEditGroupId] = useState("");
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const createMut = useMutation({
    mutationFn: (body: { external_group: string; internal_group_id: string }) =>
      authProvidersApi.createMapping(providerId, body),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["auth-providers", providerId, "mappings"],
      });
      qc.invalidateQueries({ queryKey: ["auth-providers"] });
      setDraftExternal("");
      setDraftGroupId("");
    },
  });
  const updateMut = useMutation({
    mutationFn: ({
      mappingId,
      body,
    }: {
      mappingId: string;
      body: { external_group?: string; internal_group_id?: string };
    }) => authProvidersApi.updateMapping(providerId, mappingId, body),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["auth-providers", providerId, "mappings"],
      });
      setEditingId(null);
    },
  });
  const deleteMut = useMutation({
    mutationFn: (mappingId: string) =>
      authProvidersApi.deleteMapping(providerId, mappingId),
    onSuccess: () => {
      qc.invalidateQueries({
        queryKey: ["auth-providers", providerId, "mappings"],
      });
      qc.invalidateQueries({ queryKey: ["auth-providers"] });
    },
  });

  function beginEdit(m: AuthGroupMapping) {
    setEditingId(m.id);
    setEditExternal(m.external_group);
    setEditGroupId(m.internal_group_id);
  }

  return (
    <div className="space-y-3 rounded-md border p-3">
      <div>
        <h3 className="text-sm font-semibold">Group mappings</h3>
        <p className="text-xs text-muted-foreground">
          Match an LDAP/AD group DN to an internal SpatiumDDI group. On login,
          the user's group memberships are replaced by the mapped groups. Users
          with no matching mapping are rejected.
        </p>
      </div>

      {mappings.length === 0 ? (
        <p className="text-xs italic text-muted-foreground">
          No mappings configured yet.
        </p>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-xs uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="px-2 py-1 text-left font-medium">
                External group
              </th>
              <th className="px-2 py-1 text-left font-medium">
                Internal group
              </th>
              <th className="w-20 px-2 py-1"></th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {mappings.map((m) =>
              editingId === m.id ? (
                <tr key={m.id}>
                  <td className="px-2 py-1">
                    <input
                      value={editExternal}
                      onChange={(e) => setEditExternal(e.target.value)}
                      className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
                    />
                  </td>
                  <td className="px-2 py-1">
                    <select
                      value={editGroupId}
                      onChange={(e) => setEditGroupId(e.target.value)}
                      className="w-full rounded-md border bg-background px-2 py-1 text-sm"
                    >
                      {groups.map((g) => (
                        <option key={g.id} value={g.id}>
                          {g.name}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="px-2 py-1">
                    <div className="flex justify-end gap-1">
                      <button
                        onClick={() =>
                          updateMut.mutate({
                            mappingId: m.id,
                            body: {
                              external_group: editExternal,
                              internal_group_id: editGroupId,
                            },
                          })
                        }
                        className="rounded-md bg-primary px-2 py-0.5 text-xs text-primary-foreground"
                        disabled={updateMut.isPending}
                      >
                        Save
                      </button>
                      <button
                        onClick={() => setEditingId(null)}
                        className="rounded-md border px-2 py-0.5 text-xs"
                      >
                        Cancel
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                <tr key={m.id}>
                  <td className="px-2 py-1 font-mono text-xs">
                    {m.external_group}
                  </td>
                  <td className="px-2 py-1">{m.internal_group_name}</td>
                  <td className="px-2 py-1">
                    <div className="flex justify-end gap-1">
                      <button
                        onClick={() => beginEdit(m)}
                        className="rounded-md p-1 text-muted-foreground hover:bg-accent"
                        title="Edit"
                      >
                        <Pencil className="h-3 w-3" />
                      </button>
                      <button
                        onClick={() => setConfirmDeleteId(m.id)}
                        className="rounded-md p-1 text-muted-foreground hover:bg-accent hover:text-destructive"
                        title="Delete"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </table>
      )}

      {groups.length === 0 ? (
        <p className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
          No internal groups exist yet. Group CRUD UI ships with Wave C (RBAC);
          for now you can insert rows directly into the <code>group</code>{" "}
          table.
        </p>
      ) : (
        <div className="flex items-end gap-2 border-t pt-3">
          <div className="flex-[2]">
            <label className="block text-xs text-muted-foreground">
              External group DN
            </label>
            <input
              value={draftExternal}
              onChange={(e) => setDraftExternal(e.target.value)}
              placeholder="CN=DDI Admins,OU=Groups,DC=example,DC=com"
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
            />
          </div>
          <div className="flex-1">
            <label className="block text-xs text-muted-foreground">
              Internal group
            </label>
            <select
              value={draftGroupId}
              onChange={(e) => setDraftGroupId(e.target.value)}
              className="mt-1 w-full rounded-md border bg-background px-2 py-1 text-sm"
            >
              <option value="">Select…</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={() =>
              createMut.mutate({
                external_group: draftExternal.trim(),
                internal_group_id: draftGroupId,
              })
            }
            disabled={
              !draftExternal.trim() || !draftGroupId || createMut.isPending
            }
            className="rounded-md bg-primary px-3 py-1 text-xs font-medium text-primary-foreground disabled:opacity-50"
          >
            Add
          </button>
        </div>
      )}
      <ConfirmModal
        open={confirmDeleteId !== null}
        title="Delete mapping"
        message="Delete this mapping?"
        confirmLabel="Delete"
        tone="destructive"
        onConfirm={() => {
          if (confirmDeleteId) deleteMut.mutate(confirmDeleteId);
          setConfirmDeleteId(null);
        }}
        onClose={() => setConfirmDeleteId(null)}
      />
    </div>
  );
}

// ── Main modal ────────────────────────────────────────────────────────────────

function ProviderModal({
  mode,
  initial,
  initialProvider,
  onClose,
  onSave,
  saving,
  error,
}: {
  mode: ModalMode;
  initial: ProviderForm;
  initialProvider: AuthProvider | null;
  onClose: () => void;
  onSave: (form: ProviderForm) => void;
  saving: boolean;
  error?: string;
}) {
  const [form, setForm] = useState<ProviderForm>(initial);
  const [jsonError, setJsonError] = useState<string>("");

  function set<K extends keyof ProviderForm>(key: K, value: ProviderForm[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function handleTypeChange(newType: AuthProviderType) {
    // Swap the scaffolds for the new type if the user hasn't meaningfully
    // edited them. Structured-form defaults (LDAP_DEFAULTS, OIDC_DEFAULTS,
    // …) count as "example" too so switching away from them does the right
    // thing.
    const ldapStructured = JSON.stringify(LDAP_DEFAULTS, null, 2);
    const oidcStructured = JSON.stringify(OIDC_DEFAULTS, null, 2);
    const samlStructured = JSON.stringify(SAML_DEFAULTS, null, 2);
    const radiusStructured = JSON.stringify(RADIUS_DEFAULTS, null, 2);
    const tacacsStructured = JSON.stringify(TACACS_DEFAULTS, null, 2);
    const unchangedConfigs = [
      ldapStructured,
      oidcStructured,
      samlStructured,
      radiusStructured,
      tacacsStructured,
      ...Object.values(CONFIG_EXAMPLES),
    ];
    const configIsExample = unchangedConfigs.includes(form.config_json);
    const secretsIsExample = Object.values(SECRETS_EXAMPLES).includes(
      form.secrets_json,
    );
    const newConfig =
      newType === "ldap"
        ? ldapStructured
        : newType === "oidc"
          ? oidcStructured
          : newType === "saml"
            ? samlStructured
            : newType === "radius"
              ? radiusStructured
              : tacacsStructured;
    setForm((prev) => ({
      ...prev,
      type: newType,
      config_json: configIsExample ? newConfig : prev.config_json,
      secrets_json: secretsIsExample
        ? SECRETS_EXAMPLES[newType]
        : prev.secrets_json,
      bind_password: newType === "ldap" ? prev.bind_password : "",
      oidc_client_secret: newType === "oidc" ? prev.oidc_client_secret : "",
      saml_sp_private_key: newType === "saml" ? prev.saml_sp_private_key : "",
      radius_secret: newType === "radius" ? prev.radius_secret : "",
      tacacs_secret: newType === "tacacs" ? prev.tacacs_secret : "",
    }));
  }

  function handleSubmit() {
    try {
      JSON.parse(form.config_json || "{}");
    } catch {
      setJsonError("Connection config is not valid JSON.");
      return;
    }
    setJsonError("");
    onSave(form);
  }

  const typeHint = null;

  const { dialogProps, titleProps } = useModalDialog(onClose);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        {...dialogProps}
        className="relative z-10 max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-xl border bg-card shadow-2xl focus:outline-none"
      >
        <div className="flex items-center justify-between border-b px-5 py-4">
          <h2 {...titleProps} className="font-semibold">
            {mode === "create" ? "New Auth Provider" : "Edit Auth Provider"}
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="rounded-md p-1 text-muted-foreground hover:bg-accent"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 p-5">
          {/* Basics */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-muted-foreground">
                Name
              </label>
              <input
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="Corporate AD"
                className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground">
                Type
              </label>
              <select
                value={form.type}
                onChange={(e) =>
                  handleTypeChange(e.target.value as AuthProviderType)
                }
                disabled={mode === "edit"}
                className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm disabled:opacity-60"
              >
                <option value="ldap">{TYPE_LABELS.ldap}</option>
                <option value="oidc">{TYPE_LABELS.oidc}</option>
                <option value="saml">{TYPE_LABELS.saml}</option>
                <option value="radius">{TYPE_LABELS.radius}</option>
                <option value="tacacs">{TYPE_LABELS.tacacs}</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-muted-foreground">
                Priority
              </label>
              <input
                type="number"
                value={form.priority}
                onChange={(e) => set("priority", Number(e.target.value))}
                className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm"
              />
              <p className="mt-1 text-xs text-muted-foreground">
                Lower = tried first. Local auth always runs first.
              </p>
            </div>
            <div className="flex flex-col justify-end gap-2">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.is_enabled}
                  onChange={(e) => set("is_enabled", e.target.checked)}
                />
                Enabled
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.auto_create_users}
                  onChange={(e) => set("auto_create_users", e.target.checked)}
                />
                Auto-create users on first login
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={form.auto_update_users}
                  onChange={(e) => set("auto_update_users", e.target.checked)}
                />
                Auto-update email / display name on login
              </label>
            </div>
          </div>

          {/* Connection */}
          <div className="border-t pt-4">
            <h3 className="mb-3 text-sm font-semibold">Connection</h3>
            {form.type === "ldap" ? (
              <LdapConfigFields form={form} setForm={setForm} />
            ) : form.type === "oidc" ? (
              <OidcConfigFields form={form} setForm={setForm} />
            ) : form.type === "saml" ? (
              <SamlConfigFields
                form={form}
                setForm={setForm}
                providerId={initialProvider?.id ?? null}
              />
            ) : form.type === "radius" ? (
              <RadiusConfigFields form={form} setForm={setForm} />
            ) : (
              <TacacsConfigFields form={form} setForm={setForm} />
            )}
            {typeHint && (
              <p className="mt-1 text-xs text-muted-foreground">{typeHint}</p>
            )}
          </div>

          {/* Secrets */}
          <div className="border-t pt-4">
            <div className="mb-2 flex items-center justify-between">
              <label className="flex items-center gap-1 text-sm font-semibold">
                <KeyRound className="h-3 w-3" />
                Secrets
                <span className="ml-2 text-xs font-normal text-muted-foreground">
                  encrypted at rest
                </span>
              </label>
              {mode === "edit" &&
                initialProvider?.has_secrets &&
                !form.secrets_dirty && (
                  <button
                    onClick={() => set("secrets_dirty", true)}
                    className="text-xs text-primary hover:underline"
                  >
                    Replace stored secrets
                  </button>
                )}
            </div>

            {mode === "edit" &&
            initialProvider?.has_secrets &&
            !form.secrets_dirty ? (
              <div className="rounded-md border bg-muted px-3 py-2 text-xs text-muted-foreground">
                <ShieldCheck className="mr-1 inline h-3 w-3" /> Secrets are
                stored. They will be left untouched unless you click
                &ldquo;Replace&rdquo;.
              </div>
            ) : form.type === "ldap" ? (
              <div>
                <label className="block text-xs text-muted-foreground">
                  Service bind password
                </label>
                <input
                  type="password"
                  value={form.bind_password}
                  onChange={(e) => {
                    set("bind_password", e.target.value);
                    set("secrets_dirty", true);
                  }}
                  placeholder="••••••••"
                  className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm"
                />
              </div>
            ) : form.type === "oidc" ? (
              <div>
                <label className="block text-xs text-muted-foreground">
                  Client secret
                </label>
                <input
                  type="password"
                  value={form.oidc_client_secret}
                  onChange={(e) => {
                    set("oidc_client_secret", e.target.value);
                    set("secrets_dirty", true);
                  }}
                  placeholder="••••••••"
                  className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm"
                />
              </div>
            ) : form.type === "saml" ? (
              <div>
                <label className="block text-xs text-muted-foreground">
                  SP private key (PEM, optional — only needed if you sign
                  AuthnRequests)
                </label>
                <textarea
                  value={form.saml_sp_private_key}
                  onChange={(e) => {
                    set("saml_sp_private_key", e.target.value);
                    set("secrets_dirty", true);
                  }}
                  rows={4}
                  placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                  className="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
                />
              </div>
            ) : form.type === "radius" ? (
              <div>
                <label className="block text-xs text-muted-foreground">
                  RADIUS shared secret
                </label>
                <input
                  type="password"
                  value={form.radius_secret}
                  onChange={(e) => {
                    set("radius_secret", e.target.value);
                    set("secrets_dirty", true);
                  }}
                  placeholder="••••••••"
                  className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm"
                />
              </div>
            ) : (
              <div>
                <label className="block text-xs text-muted-foreground">
                  TACACS+ shared secret
                </label>
                <input
                  type="password"
                  value={form.tacacs_secret}
                  onChange={(e) => {
                    set("tacacs_secret", e.target.value);
                    set("secrets_dirty", true);
                  }}
                  placeholder="••••••••"
                  className="mt-1 w-full rounded-md border bg-background px-3 py-1.5 text-sm"
                />
              </div>
            )}
          </div>

          {/* Test connection — all provider types, both create and edit.
              In create mode (or edit mode with dirty secrets) we pass a
              dryRunPayload so the backend uses the unsaved form state. */}
          <div className="border-t pt-4">
            <TestConnectionPanel
              providerId={mode === "edit" ? initialProvider?.id : undefined}
              providerType={form.type}
              dryRunPayload={
                mode === "create" || form.secrets_dirty
                  ? () => buildDryRunPayload(form)
                  : undefined
              }
            />
          </div>

          {/* Group mappings — edit mode only */}
          {mode === "edit" && initialProvider && (
            <div className="border-t pt-4">
              <MappingsSection providerId={initialProvider.id} />
            </div>
          )}

          {(jsonError || error) && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {jsonError || error}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-2 border-t px-5 py-3">
          <button
            onClick={onClose}
            className="rounded-md border px-4 py-2 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving || !form.name.trim()}
            className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

export function AuthProvidersPage() {
  const qc = useQueryClient();
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: authApi.me,
    staleTime: 60_000,
  });
  const isSuperadmin = me?.is_superadmin ?? false;

  const { data: providers = [], isLoading } = useQuery({
    queryKey: ["auth-providers"],
    queryFn: authProvidersApi.list,
  });

  const [modalMode, setModalMode] = useState<ModalMode | null>(null);
  const [editing, setEditing] = useState<AuthProvider | null>(null);
  const [initialForm, setInitialForm] = useState<ProviderForm>(emptyForm());
  const [mutateError, setMutateError] = useState<string>("");
  const [confirmDelete, setConfirmDelete] = useState<AuthProvider | null>(null);

  const createMut = useMutation({
    mutationFn: authProvidersApi.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["auth-providers"] });
      setModalMode(null);
      setEditing(null);
      setMutateError("");
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      setMutateError(err.response?.data?.detail ?? err.message);
    },
  });
  const updateMut = useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: string;
      body: Parameters<typeof authProvidersApi.update>[1];
    }) => authProvidersApi.update(id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["auth-providers"] });
      setModalMode(null);
      setEditing(null);
      setMutateError("");
    },
    onError: (err: Error & { response?: { data?: { detail?: string } } }) => {
      setMutateError(err.response?.data?.detail ?? err.message);
    },
  });
  const deleteMut = useMutation({
    mutationFn: authProvidersApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["auth-providers"] }),
  });

  function initialFormFromProvider(p: AuthProvider): ProviderForm {
    const storedConfig = p.config ?? {};
    const scaffoldConfig =
      p.type === "ldap"
        ? JSON.stringify(LDAP_DEFAULTS, null, 2)
        : p.type === "oidc"
          ? JSON.stringify(OIDC_DEFAULTS, null, 2)
          : p.type === "saml"
            ? JSON.stringify(SAML_DEFAULTS, null, 2)
            : p.type === "radius"
              ? JSON.stringify(RADIUS_DEFAULTS, null, 2)
              : JSON.stringify(TACACS_DEFAULTS, null, 2);
    const configJson =
      Object.keys(storedConfig).length > 0
        ? JSON.stringify(storedConfig, null, 2)
        : scaffoldConfig;
    return {
      name: p.name,
      type: p.type,
      is_enabled: p.is_enabled,
      priority: p.priority,
      auto_create_users: p.auto_create_users,
      auto_update_users: p.auto_update_users,
      config_json: configJson,
      secrets_json: SECRETS_EXAMPLES[p.type],
      secrets_dirty: false,
      bind_password: "",
      oidc_client_secret: "",
      saml_sp_private_key: "",
      radius_secret: "",
      tacacs_secret: "",
    };
  }

  function openCreate() {
    setEditing(null);
    setInitialForm(emptyForm());
    setMutateError("");
    setModalMode("create");
  }

  function openEdit(p: AuthProvider) {
    setEditing(p);
    setInitialForm(initialFormFromProvider(p));
    setMutateError("");
    setModalMode("edit");
  }

  function handleSave(form: ProviderForm) {
    const config = JSON.parse(form.config_json || "{}");
    let secrets: Record<string, unknown> | null | undefined;
    if (form.type === "ldap") {
      if (form.secrets_dirty && form.bind_password) {
        secrets = { bind_password: form.bind_password };
      } else if (form.secrets_dirty && !form.bind_password) {
        secrets = {}; // clear stored secret
      } else {
        secrets = undefined; // leave untouched
      }
    } else if (form.type === "oidc") {
      if (form.secrets_dirty && form.oidc_client_secret) {
        secrets = { client_secret: form.oidc_client_secret };
      } else if (form.secrets_dirty && !form.oidc_client_secret) {
        secrets = {};
      } else {
        secrets = undefined;
      }
    } else if (form.type === "saml") {
      if (form.secrets_dirty && form.saml_sp_private_key) {
        secrets = { sp_private_key: form.saml_sp_private_key };
      } else if (form.secrets_dirty && !form.saml_sp_private_key) {
        secrets = {};
      } else {
        secrets = undefined;
      }
    } else if (form.type === "radius") {
      if (form.secrets_dirty && form.radius_secret) {
        secrets = { secret: form.radius_secret };
      } else if (form.secrets_dirty && !form.radius_secret) {
        secrets = {};
      } else {
        secrets = undefined;
      }
    } else {
      // tacacs
      if (form.secrets_dirty && form.tacacs_secret) {
        secrets = { secret: form.tacacs_secret };
      } else if (form.secrets_dirty && !form.tacacs_secret) {
        secrets = {};
      } else {
        secrets = undefined;
      }
    }

    if (modalMode === "create") {
      createMut.mutate({
        name: form.name.trim(),
        type: form.type,
        is_enabled: form.is_enabled,
        priority: form.priority,
        auto_create_users: form.auto_create_users,
        auto_update_users: form.auto_update_users,
        config,
        secrets: secrets === undefined ? null : secrets,
      });
    } else if (editing) {
      updateMut.mutate({
        id: editing.id,
        body: {
          name: form.name.trim(),
          is_enabled: form.is_enabled,
          priority: form.priority,
          auto_create_users: form.auto_create_users,
          auto_update_users: form.auto_update_users,
          config,
          secrets,
        },
      });
    }
  }

  function handleDelete(p: AuthProvider) {
    setConfirmDelete(p);
  }

  if (!isSuperadmin) {
    return (
      <div className="p-8 text-sm text-muted-foreground">
        Superadmin required.
      </div>
    );
  }

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h1 className="text-2xl font-semibold">Auth Providers</h1>
          <p className="text-sm text-muted-foreground">
            Configure external authentication (LDAP / OIDC / SAML / RADIUS /
            TACACS+). Local authentication is always tried first; providers
            below are tried in priority order only after local auth fails.
          </p>
        </div>
        <button
          onClick={openCreate}
          className="flex shrink-0 items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          <Plus className="h-4 w-4" />
          Add Provider
        </button>
      </div>

      <div className="rounded-lg border bg-card">
        {isLoading ? (
          <div className="p-6 text-sm text-muted-foreground">Loading…</div>
        ) : providers.length === 0 ? (
          <div className="p-8 text-center text-sm text-muted-foreground">
            No providers configured. Click <strong>Add Provider</strong> to
            configure LDAP, OIDC, SAML, RADIUS, or TACACS+.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-muted/40 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Name</th>
                <th className="px-4 py-2 text-left font-medium">Type</th>
                <th className="px-4 py-2 text-left font-medium">Enabled</th>
                <th className="px-4 py-2 text-left font-medium">Priority</th>
                <th className="px-4 py-2 text-left font-medium">Mappings</th>
                <th className="px-4 py-2 text-left font-medium">Secrets</th>
                <th className="w-24 px-4 py-2"></th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {providers.map((p) => (
                <tr key={p.id}>
                  <td className="px-4 py-2 font-medium">{p.name}</td>
                  <td className="px-4 py-2">
                    <span
                      className={cn(
                        "rounded-md px-2 py-0.5 text-xs font-medium",
                        TYPE_BADGE[p.type],
                      )}
                    >
                      {TYPE_LABELS[p.type]}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    {p.is_enabled ? (
                      <span className="rounded-md bg-emerald-500/15 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                        enabled
                      </span>
                    ) : (
                      <span className="rounded-md bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
                        disabled
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground">
                    {p.priority}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground">
                    {p.mapping_count}
                  </td>
                  <td className="px-4 py-2">
                    {p.has_secrets ? (
                      <span className="text-xs text-muted-foreground">
                        stored
                      </span>
                    ) : (
                      <span className="text-xs text-amber-600">none</span>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex justify-end gap-1">
                      <button
                        onClick={() => openEdit(p)}
                        className="rounded-md p-1.5 text-muted-foreground hover:bg-accent"
                        title="Edit"
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(p)}
                        className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-destructive"
                        title="Delete"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modalMode && (
        <ProviderModal
          key={editing?.id ?? "new"}
          mode={modalMode}
          initial={initialForm}
          initialProvider={editing}
          onClose={() => {
            setModalMode(null);
            setMutateError("");
          }}
          onSave={handleSave}
          saving={createMut.isPending || updateMut.isPending}
          error={mutateError}
        />
      )}
      <ConfirmModal
        open={confirmDelete !== null}
        title="Delete auth provider"
        message={`Delete auth provider "${confirmDelete?.name ?? ""}"? Mappings will be deleted too; already-provisioned users remain.`}
        confirmLabel="Delete"
        tone="destructive"
        onConfirm={() => {
          if (confirmDelete) deleteMut.mutate(confirmDelete.id);
          setConfirmDelete(null);
        }}
        onClose={() => setConfirmDelete(null)}
      />
    </div>
  );
}
