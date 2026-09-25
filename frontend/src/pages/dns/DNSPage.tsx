import { useState, useEffect, useMemo, useRef } from "react";
import { useLocation, useSearchParams } from "react-router-dom";
import { useStickyLocation } from "@/lib/stickyLocation";
import { useSessionState } from "@/lib/useSessionState";
import { useRowHighlight } from "@/lib/useRowHighlight";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Globe,
  Plus,
  Trash2,
  Pencil,
  ChevronRight,
  Settings2,
  Shield,
  Eye,
  FileText,
  Layers,
  RefreshCw,
  X,
  Cpu,
  FolderOpen,
  Folder,
  Upload,
  Download,
  Ban,
  Lock,
  Info,
  Filter,
  Search,
  ListTree,
  Radar,
  Sparkles,
  Workflow,
  KeyRound,
  Copy,
  Pause,
  Play,
  Check,
  Clipboard,
  Cloud,
  ExternalLink,
  ArrowRightLeft,
  Database,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { ConfigApplyChip } from "@/components/ConfigApplyChip";
import { DaemonStateChip } from "@/components/DaemonStateChip";
import { SpoolChip } from "@/components/SpoolChip";
import { TagFilterChips } from "@/components/TagFilterChips";
import { PropagationCheckModal } from "./PropagationCheckModal";
import { BlocklistCatalogModal } from "./BlocklistCatalogModal";
import { DelegationModal } from "./DelegationModal";
import { DynamicUpdateAclModal } from "./DynamicUpdateAclModal";
import { ZoneTemplateModal } from "./ZoneTemplateModal";
import { ServerDetailModal } from "./ServerDetailModal";
import { PauseServerModal } from "@/components/ui/pause-server-modal";
import { PoolsView } from "./PoolsView";
import { DriftView } from "./DriftView";
import {
  CertsCompactTable,
  TLSStatePill,
} from "@/pages/network/CertificatesPage";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { HeaderMenu } from "@/components/ui/header-menu";
import {
  ADD_DNS_RECORD,
  formatCombo,
  isTypingTarget,
  matchesShortcut,
} from "@/lib/shortcuts";
import { Pager } from "@/components/ui/pager";
import { AskAIButton } from "@/components/copilot/AskAIButton";
import { ServicesUsingButton } from "@/components/ServicesUsingButton";
import { ZoneScopeHint, ZoneScopePill } from "@/components/ZoneScopePill";
import {
  applianceTlsApi,
  dnsApi,
  dnsBlocklistApi,
  ipamApi,
  domainsApi,
  formatApiError,
  tlsCertsApi,
  type DNSServerGroup,
  type DNSServer,
  type DNSZone,
  type ZoneNameScope,
  type ZoneServerState,
  type DNSView,
  type DNSAcl,
  type DNSRecord,
  type DNSGroupRecord,
  type DNSImportPreview,
  type DNSRecordChange,
  type DNSBlockList,
  type DNSBlockListEntry,
  type DNSBlockListException,
  type DNSTSIGKey,
  type WindowsDNSCredentials,
  type DNSGroupSyncResult,
  type ResolverPreset,
} from "@/lib/api";
import { copyToClipboard } from "@/lib/clipboard";
import { fqdnError, recordOwnerError } from "@/lib/dnsNames";
import { useTableSort, SortableTh } from "@/lib/useTableSort";
import { cn, swatchCls, zebraBodyCls } from "@/lib/utils";
import { SwatchPicker } from "@/components/ui/swatch-picker";
import { CustomerChip, CustomerPicker } from "@/components/ownership/pickers";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuLabel,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";

// ── Shared primitives ─────────────────────────────────────────────────────────

// Record-type badge colours live in ``./recordTypeBadge.ts`` so
// fast-refresh stays happy (this file exports components + can't
// also export constants without tripping the lint rule).
import {
  RECORD_TYPE_BADGE,
  RECORD_TYPE_BADGE_FALLBACK,
} from "./recordTypeBadge";
import {
  APPROVAL_QUEUED_MESSAGE,
  CHANGE_REQUEST_QUERY_KEY,
  handleApprovalQueued,
} from "@/lib/approvalQueue";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="block text-xs font-medium text-muted-foreground">
        {label}
      </label>
      {children}
    </div>
  );
}

type ApiError = { response?: { data?: { detail?: string } } };

function Btns({
  onClose,
  pending,
  label,
  disabled,
}: {
  onClose: () => void;
  pending: boolean;
  label?: string;
  disabled?: boolean;
}) {
  return (
    <div className="flex justify-end gap-2 pt-2">
      <button
        type="button"
        onClick={onClose}
        className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
      >
        Cancel
      </button>
      <button
        type="submit"
        disabled={pending || disabled}
        className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
      >
        {pending ? "Saving…" : (label ?? "Save")}
      </button>
    </div>
  );
}

// ── CLI setup-guide copy block (mirrors ProxmoxPage / DHCP CreateServerModal) ──

function CopyablePre({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function handle() {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }
  }
  return (
    <div className="relative">
      <pre className="overflow-auto rounded bg-background p-2 pr-20 font-mono text-[11px] leading-tight whitespace-pre-wrap">
        {text}
      </pre>
      <button
        type="button"
        onClick={handle}
        className="absolute right-1.5 top-1.5 inline-flex items-center gap-1 rounded border bg-background px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-accent hover:text-foreground"
        aria-label={`Copy ${label}`}
        title={`Copy ${label}`}
      >
        {copied ? (
          <>
            <Check className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
            Copied
          </>
        ) : (
          <>
            <Clipboard className="h-3 w-3" />
            Copy
          </>
        )}
      </button>
    </div>
  );
}

// ── Cloud DNS driver metadata (issue #37, Part B) ────────────────────────────
//
// The 4 cloud DNS drivers are agentless — record CRUD runs from the control
// plane against the provider API. The server modal hides the agent/host/api
// fields and renders a provider-specific credential form + setup guide.

const CLOUD_DNS_DRIVERS = [
  "cloudflare",
  "route53",
  "azure_dns",
  "google_dns",
  "digitalocean",
  "hetzner",
  "linode",
  "vultr",
] as const;
type CloudDNSDriver = (typeof CLOUD_DNS_DRIVERS)[number];

const CLOUD_DNS_LABELS: Record<CloudDNSDriver, string> = {
  cloudflare: "Cloudflare",
  route53: "AWS Route 53",
  azure_dns: "Azure DNS",
  google_dns: "Google Cloud DNS",
  digitalocean: "DigitalOcean",
  hetzner: "Hetzner DNS",
  linode: "Linode",
  vultr: "Vultr",
};

function isCloudDriver(d: string): d is CloudDNSDriver {
  return (CLOUD_DNS_DRIVERS as readonly string[]).includes(d);
}

// One credential field rendered in the provider form. ``textarea`` is used
// for the GCP service-account JSON blob; ``checkbox`` for technitium_api's
// verify_tls, which is the one credential field that is a real boolean.
interface CloudCredField {
  key: string;
  label: string;
  placeholder?: string;
  secret?: boolean;
  textarea?: boolean;
  checkbox?: boolean;
  // Only meaningful with ``checkbox``. Defaults on, matching the driver:
  // most self-hosted Technitium installs use a self-signed cert, so the
  // opt-out has to exist — but it has to be a deliberate one.
  checkboxDefault?: boolean;
  help?: string;
}

const CLOUD_DNS_FIELDS: Record<CloudDNSDriver, CloudCredField[]> = {
  cloudflare: [
    {
      key: "api_token",
      label: "API token",
      placeholder: "cloudflare scoped API token",
      secret: true,
    },
  ],
  route53: [
    {
      key: "access_key_id",
      label: "Access key ID",
      placeholder: "AKIA…",
    },
    {
      key: "secret_access_key",
      label: "Secret access key",
      placeholder: "secret access key",
      secret: true,
    },
  ],
  azure_dns: [
    { key: "tenant_id", label: "Tenant ID", placeholder: "00000000-0000-…" },
    { key: "client_id", label: "Client ID (app ID)", placeholder: "app id" },
    {
      key: "client_secret",
      label: "Client secret",
      placeholder: "client secret",
      secret: true,
    },
    {
      key: "subscription_id",
      label: "Subscription ID",
      placeholder: "subscription id",
    },
    {
      key: "resource_group",
      label: "Resource group",
      placeholder: "my-dns-rg",
    },
  ],
  google_dns: [
    {
      key: "service_account_json",
      label: "Service account key (JSON)",
      placeholder: "Paste the full service-account key JSON",
      secret: true,
      textarea: true,
    },
    { key: "project_id", label: "Project ID", placeholder: "my-gcp-project" },
  ],
  // Token-only providers (issue #327) — a single API token authenticates
  // both the DNS read + write surfaces.
  digitalocean: [
    {
      key: "api_token",
      label: "API token",
      placeholder: "DigitalOcean personal access token",
      secret: true,
    },
  ],
  hetzner: [
    {
      key: "api_token",
      label: "API token",
      placeholder: "Hetzner DNS API token",
      secret: true,
    },
  ],
  linode: [
    {
      key: "api_token",
      label: "API token",
      placeholder: "Linode personal access token",
      secret: true,
    },
  ],
  vultr: [
    {
      key: "api_token",
      label: "API key",
      placeholder: "Vultr API key",
      secret: true,
    },
  ],
};

// ── Self-hosted agentless drivers (issue #810) ────────────────────────
//
// Same credential lifecycle as the cloud providers — a driver-specific dict
// Fernet-encrypted into the same column, sent over the same
// ``cloud_credentials`` field — but NOT cloud drivers: the operator hosts
// the server, so host/port stay meaningful and there is no provider setup
// guide or hosted-zone import to link to.

const SELF_HOSTED_CRED_FIELDS: Record<string, CloudCredField[]> = {
  technitium_api: [
    {
      key: "api_url",
      label: "Technitium API URL",
      placeholder: "https://dns.example.com:53443",
      help: "Web-service root, not the /api path. Technitium serves HTTP on 5380 and HTTPS on 53443 when TLS is enabled. A scheme is required.",
    },
    {
      key: "api_token",
      label: "API token",
      placeholder: "permanent API token",
      secret: true,
      help: "Administration → Sessions → Create Token. Create it against a limited user (Zones: Modify + DnsClient: View), not the admin account — the token inherits that user's permissions.",
    },
    {
      key: "verify_tls",
      label: "Verify the TLS certificate",
      checkbox: true,
      checkboxDefault: true,
      help: "Turn off only for a self-signed certificate you have no way to trust — the token is sent on every request. When editing, this shows the default rather than the stored value (credentials are never returned); the stored value is kept unless you tick or untick it.",
    },
  ],
};

// Every driver that takes a credential dict, cloud or self-hosted. Mirrors
// the backend's CREDENTIALED_DNS_DRIVERS.
const CRED_FIELDS_BY_DRIVER: Record<string, CloudCredField[]> = {
  ...CLOUD_DNS_FIELDS,
  ...SELF_HOSTED_CRED_FIELDS,
};

const CRED_DRIVER_LABELS: Record<string, string> = {
  ...CLOUD_DNS_LABELS,
  technitium_api: "Technitium (remote API)",
};

function CloudSetupGuide({ driver }: { driver: CloudDNSDriver }) {
  return (
    <details className="rounded border bg-background/40 text-xs">
      <summary className="cursor-pointer px-3 py-2 font-medium select-none">
        {CLOUD_DNS_LABELS[driver]} setup guide — click to expand
      </summary>
      <div className="space-y-3 border-t px-3 py-2.5 text-muted-foreground">
        {driver === "cloudflare" && (
          <div>
            <p>
              In the Cloudflare dashboard go to{" "}
              <span className="font-medium text-foreground">
                My Profile → API Tokens → Create Token
              </span>{" "}
              and use the{" "}
              <span className="font-medium text-foreground">Edit zone DNS</span>{" "}
              template (grants{" "}
              <code className="font-mono">Zone : DNS : Edit</code> +{" "}
              <code className="font-mono">Zone : Zone : Read</code>), optionally
              scoped to specific zones. Paste the generated token into the field
              above.
            </p>
          </div>
        )}
        {driver === "route53" && (
          <div>
            <p>
              Create an IAM user (or role) and attach{" "}
              <code className="font-mono">AmazonRoute53ReadOnlyAccess</code> for
              import plus{" "}
              <code className="font-mono">
                route53:ChangeResourceRecordSets
              </code>{" "}
              on the hosted zone for writes. Then generate an access key and
              paste the key ID + secret above.
            </p>
          </div>
        )}
        {driver === "azure_dns" && (
          <div className="space-y-2">
            <p>
              Create a service principal scoped to the resource group holding
              your DNS zones with the{" "}
              <span className="font-medium text-foreground">
                DNS Zone Contributor
              </span>{" "}
              role:
            </p>
            <CopyablePre
              label="az service principal"
              text={
                'az ad sp create-for-rbac --role "DNS Zone Contributor" \\\n  --scopes /subscriptions/<sub>/resourceGroups/<rg>'
              }
            />
            <p>
              The command prints <code className="font-mono">appId</code>{" "}
              (client ID), <code className="font-mono">password</code> (client
              secret), and <code className="font-mono">tenant</code> (tenant
              ID).
            </p>
          </div>
        )}
        {driver === "google_dns" && (
          <div className="space-y-2">
            <p>
              Create a service account, grant it the{" "}
              <span className="font-medium text-foreground">DNS Admin</span>{" "}
              role, and download a JSON key:
            </p>
            <CopyablePre
              label="gcloud service account"
              text={
                "gcloud iam service-accounts create spatiumddi\n" +
                "gcloud projects add-iam-policy-binding <proj> \\\n" +
                "  --member serviceAccount:spatiumddi@<proj>.iam.gserviceaccount.com \\\n" +
                "  --role roles/dns.admin\n" +
                "gcloud iam service-accounts keys create key.json \\\n" +
                "  --iam-account spatiumddi@<proj>.iam.gserviceaccount.com"
              }
            />
            <p>
              Paste the contents of <code className="font-mono">key.json</code>{" "}
              into the field above.
            </p>
          </div>
        )}
        {driver === "digitalocean" && (
          <div>
            <p>
              In the DigitalOcean control panel go to{" "}
              <span className="font-medium text-foreground">
                API → Tokens → Generate New Token
              </span>
              , give it a name and{" "}
              <span className="font-medium text-foreground">Write</span> scope
              (the DNS API rides the same personal access token), then paste it
              above. The domains you manage must already be added under{" "}
              <span className="font-medium text-foreground">
                Networking → Domains
              </span>
              .
            </p>
          </div>
        )}
        {driver === "hetzner" && (
          <div>
            <p>
              Open the{" "}
              <span className="font-medium text-foreground">
                Hetzner DNS Console
              </span>{" "}
              (dns.hetzner.com) and go to{" "}
              <span className="font-medium text-foreground">
                API tokens → Create access token
              </span>
              . This is a DNS-specific token (separate from the Hetzner Cloud
              API). Paste it above.
            </p>
          </div>
        )}
        {driver === "linode" && (
          <div>
            <p>
              In the Linode Cloud Manager go to{" "}
              <span className="font-medium text-foreground">
                Profile → API Tokens → Create a Personal Access Token
              </span>{" "}
              and grant{" "}
              <span className="font-medium text-foreground">Domains</span>{" "}
              read/write access. Paste the token above.
            </p>
          </div>
        )}
        {driver === "vultr" && (
          <div>
            <p>
              In the Vultr customer portal go to{" "}
              <span className="font-medium text-foreground">Account → API</span>
              , enable the API, and copy your{" "}
              <span className="font-medium text-foreground">API key</span>. Add
              your IP to the access-control allowlist if enabled, then paste the
              key above.
            </p>
          </div>
        )}
      </div>
    </details>
  );
}

// ── Double-confirm destroy modal (matches IPAM pattern) ──────────────────────

function ConfirmDestroyModal({
  title,
  description,
  checkLabel,
  onConfirm,
  onClose,
  isPending,
  error,
  notice,
}: {
  title: string;
  description: React.ReactNode;
  checkLabel: string;
  onConfirm: () => void;
  onClose: () => void;
  isPending?: boolean;
  error?: string | null;
  // Non-error feedback shown in a neutral box — used for the #62
  // two-person approval queue "Submitted for approval" message, where
  // the delete returned 202 instead of executing.
  notice?: string | null;
}) {
  const [step, setStep] = useState<1 | 2>(1);
  const [checked, setChecked] = useState(false);

  if (step === 1) {
    return (
      <Modal title={title} onClose={onClose}>
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">{description}</p>
          {error && (
            <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {error}
            </div>
          )}
          {notice && (
            <div className="rounded-md border border-blue-500/40 bg-blue-500/5 px-3 py-2 text-xs text-blue-600 dark:text-blue-400">
              {notice}
            </div>
          )}
          <div className="flex justify-end gap-2">
            <button
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            >
              Cancel
            </button>
            <button
              onClick={() => setStep(2)}
              className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90"
            >
              Continue
            </button>
          </div>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Confirm Permanent Deletion" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm font-medium text-destructive">
          This action cannot be undone.
        </p>
        <p className="text-sm text-muted-foreground">{description}</p>
        <label className="flex cursor-pointer items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={checked}
            onChange={(e) => setChecked(e.target.checked)}
          />
          {checkLabel}
        </label>
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}
        {notice && (
          <div className="rounded-md border border-blue-500/40 bg-blue-500/5 px-3 py-2 text-xs text-blue-600 dark:text-blue-400">
            {notice}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={!checked || isPending}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {isPending ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

/** Single-step destructive confirm (no checkbox). Used for low-stakes deletes
 * like individual DNS records — the two-step modal above stays for group /
 * blocklist deletes where the blast radius is much larger. */
function ConfirmSingleModal({
  title,
  description,
  onConfirm,
  onClose,
  isPending,
  confirmLabel = "Delete",
}: {
  title: string;
  description: React.ReactNode;
  onConfirm: () => void;
  onClose: () => void;
  isPending?: boolean;
  confirmLabel?: string;
}) {
  return (
    <Modal title={title} onClose={onClose}>
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">{description}</p>
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={isPending}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
          >
            {isPending ? "Deleting…" : confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Download helper ──────────────────────────────────────────────────────────

function downloadBlob(
  data: Blob | string,
  filename: string,
  mime = "text/plain",
) {
  const blob = data instanceof Blob ? data : new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// UTC timestamp suffix used when the backend didn't send a Content-Disposition
// filename (rare — every export endpoint sets it). Matches the backend's
// "%Y%m%d-%H%M%S" format so fallback filenames sort alongside real ones.
function _utcTimestampSuffix(): string {
  return new Date()
    .toISOString()
    .slice(0, 19)
    .replace(/[-:]/g, "")
    .replace("T", "-");
}

// ── Import Zone Modal ────────────────────────────────────────────────────────

function ImportZoneModal({
  groupId,
  zone,
  onClose,
}: {
  groupId: string;
  zone: DNSZone;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [zoneFile, setZoneFile] = useState("");
  const [strategy, setStrategy] = useState<"merge" | "replace" | "append">(
    "merge",
  );
  const [preview, setPreview] = useState<DNSImportPreview | null>(null);
  const [error, setError] = useState<string | null>(null);

  const previewMut = useMutation({
    mutationFn: () =>
      dnsApi.importZonePreview(groupId, zone.id, {
        zone_file: zoneFile,
        zone_name: zone.name,
      }),
    onSuccess: (data) => {
      setPreview(data);
      setError(null);
    },
    onError: (err: ApiError) => {
      setPreview(null);
      setError(formatApiError(err, "Failed to parse zone file"));
    },
  });

  const commitMut = useMutation({
    mutationFn: () =>
      dnsApi.importZoneCommit(groupId, zone.id, {
        zone_file: zoneFile,
        zone_name: zone.name,
        conflict_strategy: strategy,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-records", zone.id] });
      qc.invalidateQueries({ queryKey: ["dns-zones", groupId] });
      onClose();
    },
    onError: (err: ApiError) => {
      setError(formatApiError(err, "Import failed"));
    },
  });

  const onFileChosen = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setZoneFile(text);
    setPreview(null);
  };

  const renderChanges = (
    label: string,
    items: DNSRecordChange[],
    color: string,
  ) =>
    items.length > 0 && (
      <details className="rounded border" open={items.length <= 10}>
        <summary
          className={`cursor-pointer px-2 py-1 text-xs font-medium ${color}`}
        >
          {label} ({items.length})
        </summary>
        <div className="max-h-40 overflow-auto">
          <table className="w-full text-xs">
            <tbody>
              {items.map((c, i) => (
                <tr key={i} className="border-t">
                  <td className="px-2 py-0.5 font-mono">{c.name}</td>
                  <td className="px-2 py-0.5">{c.record_type}</td>
                  <td className="px-2 py-0.5 font-mono text-muted-foreground truncate max-w-xs">
                    {c.value}
                  </td>
                  <td className="px-2 py-0.5 text-muted-foreground">
                    {c.ttl ?? "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    );

  return (
    <Modal title={`Import Zone File — ${zone.name}`} onClose={onClose} wide>
      <div className="space-y-3">
        <Field label="Zone file (RFC 1035 format)">
          <input
            type="file"
            accept=".zone,.db,.txt,text/plain,text/dns"
            onChange={onFileChosen}
            className="text-xs"
          />
        </Field>
        <Field label="…or paste contents">
          <textarea
            className={`${inputCls} font-mono text-xs`}
            rows={8}
            value={zoneFile}
            onChange={(e) => {
              setZoneFile(e.target.value);
              setPreview(null);
            }}
            placeholder="$ORIGIN example.com.&#10;$TTL 3600&#10;@ IN SOA ns1 hostmaster ( 1 86400 7200 3600000 3600 )"
          />
        </Field>

        <Field label="Conflict strategy">
          <select
            className={inputCls}
            value={strategy}
            onChange={(e) =>
              setStrategy(e.target.value as "merge" | "replace" | "append")
            }
          >
            <option value="merge">
              Merge — add new, update changed, keep existing
            </option>
            <option value="replace">
              Replace — make the zone match the file exactly
            </option>
            <option value="append">
              Append — only add records that do not exist
            </option>
          </select>
        </Field>

        {error && (
          <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}

        {preview && (
          <div className="space-y-2">
            <div className="text-xs text-muted-foreground">
              Parsed {preview.record_count} record
              {preview.record_count !== 1 ? "s" : ""}
              {preview.soa_detected &&
                " (SOA detected — zone SOA will not be changed)"}
            </div>
            {renderChanges("Create", preview.to_create, "text-emerald-600")}
            {renderChanges("Update", preview.to_update, "text-amber-600")}
            {renderChanges(
              "Delete (only with Replace)",
              preview.to_delete,
              "text-destructive",
            )}
            {renderChanges(
              "Unchanged",
              preview.unchanged,
              "text-muted-foreground",
            )}
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => previewMut.mutate()}
            disabled={!zoneFile || previewMut.isPending}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          >
            {previewMut.isPending ? "Parsing…" : "Preview"}
          </button>
          <button
            onClick={() => commitMut.mutate()}
            disabled={!preview || commitMut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {commitMut.isPending ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── DNS zone tree builder (recursive: com → test.com → sub.test.com) ─────────

interface DnsTreeNode {
  domain: string; // full domain name at this level, e.g. "test.com"
  zone?: DNSZone; // set if this node corresponds to a registered zone
  children: DnsTreeNode[];
}

function buildDnsTree(zones: DNSZone[]): DnsTreeNode[] {
  const nodeMap = new Map<string, DnsTreeNode>();

  function getOrCreate(domain: string): DnsTreeNode {
    if (!nodeMap.has(domain)) nodeMap.set(domain, { domain, children: [] });
    return nodeMap.get(domain)!;
  }

  const tldSet = new Set<string>();

  for (const z of zones) {
    const name = z.name.replace(/\.$/, ""); // strip trailing dot
    const parts = name.split("."); // ["sub", "test", "com"]

    tldSet.add(parts[parts.length - 1]);

    // Build ancestor chain from TLD down to zone
    for (let level = 0; level < parts.length; level++) {
      const startIdx = parts.length - 1 - level;
      const domain = parts.slice(startIdx).join(".");
      getOrCreate(domain);

      if (level > 0) {
        const parentDomain = parts.slice(startIdx + 1).join(".");
        const parent = getOrCreate(parentDomain);
        const child = getOrCreate(domain);
        if (!parent.children.find((c) => c.domain === domain)) {
          parent.children.push(child);
        }
      }
    }

    getOrCreate(name).zone = z;
  }

  function sortNode(n: DnsTreeNode) {
    n.children.sort((a, b) => a.domain.localeCompare(b.domain));
    n.children.forEach(sortNode);
  }

  const roots = [...tldSet]
    .sort()
    .map((tld) => nodeMap.get(tld)!)
    .filter(Boolean);
  roots.forEach(sortNode);
  return roots;
}

// ── Group Modal (create / edit) ───────────────────────────────────────────────

function GroupModal({
  group,
  onClose,
}: {
  group?: DNSServerGroup;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const [groupType, setGroupType] = useState(group?.group_type ?? "internal");
  const [isRecursive, setIsRecursive] = useState(group?.is_recursive ?? true);
  // BIND9 catalog zones (RFC 9432). Off by default — only meaningful in
  // ≥2-server BIND9 groups, and BIND 9.18+ is required.
  const [catalogZonesEnabled, setCatalogZonesEnabled] = useState(
    group?.catalog_zones_enabled ?? false,
  );
  const [catalogZoneName, setCatalogZoneName] = useState(
    group?.catalog_zone_name ?? "catalog.spatium.invalid.",
  );
  // Issue #25 — flag this group as exposed to the public internet.
  // The IPAM safety guard returns ``requires_confirmation`` when an
  // operator binds a private IP into a zone in this group.
  const [isPublicFacing, setIsPublicFacing] = useState(
    group?.is_public_facing ?? false,
  );
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: (d: Partial<DNSServerGroup>) =>
      group ? dnsApi.updateGroup(group.id, d) : dnsApi.createGroup(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-groups"] });
      onClose();
    },
    onError: (e: ApiError) => setError(formatApiError(e)),
  });

  return (
    <Modal
      title={group ? "Edit Server Group" : "New Server Group"}
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError("");
          mut.mutate({
            name,
            description,
            group_type: groupType,
            is_recursive: isRecursive,
            catalog_zones_enabled: catalogZonesEnabled,
            catalog_zone_name: catalogZoneName.trim(),
            is_public_facing: isPublicFacing,
          });
        }}
        className="space-y-3"
      >
        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. internal-resolvers"
            required
            autoFocus
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional"
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Type">
            <select
              className={inputCls}
              value={groupType}
              onChange={(e) => setGroupType(e.target.value)}
            >
              <option value="internal">Internal</option>
              <option value="external">External</option>
              <option value="dmz">DMZ</option>
              <option value="custom">Custom</option>
            </select>
          </Field>
          <Field label="Recursion">
            <label className="flex items-center gap-2 mt-2 cursor-pointer">
              <input
                type="checkbox"
                checked={isRecursive}
                onChange={(e) => setIsRecursive(e.target.checked)}
                className="h-4 w-4"
              />
              <span className="text-sm">Allow recursion</span>
            </label>
          </Field>
        </div>

        <label className="flex items-start gap-2 text-xs cursor-pointer select-none rounded border bg-amber-500/5 px-3 py-2">
          <input
            type="checkbox"
            className="mt-0.5 h-4 w-4"
            checked={isPublicFacing}
            onChange={(e) => setIsPublicFacing(e.target.checked)}
          />
          <span>
            <span className="font-medium">Public-facing</span>
            <span className="ml-1 text-muted-foreground">
              — flag this group as exposed to the public internet. Publishing a
              private IP (RFC 1918 / CGNAT / ULA) into a zone in this group will
              require typed-CIDR confirmation on the IPAM side.
            </span>
          </span>
        </label>

        {/* BIND9 catalog zones (RFC 9432). The producer is the group's
            is_primary=True bind9 server; every other bind9 member joins
            as a consumer and pulls members from the catalog instead of
            getting per-zone config push. Pointless on a single-server
            group; the toggle is kept available so adding a second server
            later just works. */}
        <div className="rounded border bg-muted/20 p-3">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={catalogZonesEnabled}
              onChange={(e) => setCatalogZonesEnabled(e.target.checked)}
              className="h-4 w-4"
            />
            <span className="text-sm font-medium">Use BIND9 catalog zones</span>
          </label>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Distribute zones via one catalog instead of per-server config push.
            Requires BIND 9.18+. Skip on single-server groups.
          </p>
          {catalogZonesEnabled && (
            <div className="mt-2">
              <label className="mb-0.5 block text-xs font-medium">
                Catalog zone name
              </label>
              <input
                className={inputCls}
                value={catalogZoneName}
                onChange={(e) => setCatalogZoneName(e.target.value)}
                placeholder="catalog.spatium.invalid."
              />
              <p className="mt-0.5 text-[11px] text-muted-foreground">
                Synthetic FQDN — pick something inside an unroutable label (e.g.{" "}
                <code>.invalid.</code>) so it doesn't collide with a real zone.
              </p>
            </div>
          )}
        </div>

        {error && <p className="text-sm text-destructive">{error}</p>}
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label={group ? "Save" : "Create"}
        />
      </form>
    </Modal>
  );
}

// ── Server Modal (add / edit) ─────────────────────────────────────────────────

function ServerModal({
  groupId,
  server,
  onClose,
}: {
  groupId: string;
  server?: DNSServer;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const editing = !!server;
  const [name, setName] = useState(server?.name ?? "");
  const [driver, setDriver] = useState(server?.driver ?? "bind9");
  const [host, setHost] = useState(server?.host ?? "");
  const [port, setPort] = useState(String(server?.port ?? 53));
  const [apiPort, setApiPort] = useState(String(server?.api_port ?? ""));
  const [roles, setRoles] = useState((server?.roles ?? []).join(", "));
  const [notes, setNotes] = useState(server?.notes ?? "");
  const [apiKey, setApiKey] = useState("");
  const [isEnabled, setIsEnabled] = useState(server?.is_enabled ?? true);
  // #934 — move this server to another group, and designate the group's
  // primary. Edit-only: on create the group is the one you are creating it
  // in, and the primary flag is auto-elected when the group has none.
  const [targetGroupId, setTargetGroupId] = useState(
    server?.group_id ?? groupId,
  );
  const [isPrimary, setIsPrimary] = useState(server?.is_primary ?? false);
  const [error, setError] = useState("");

  // Only needed for the move picker, so don't fetch it on the create path.
  const { data: allGroups = [] } = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
    enabled: editing,
  });

  // Windows credential state — same contract as the DHCP modal:
  //   * On edit with creds: leave blank to keep, type to replace.
  //   * Always send the creds block on windows_dns so transport / port /
  //     TLS toggles reach the backend (backend merges with stored blob).
  const [winUsername, setWinUsername] = useState("");
  const [winPassword, setWinPassword] = useState("");
  const [winPort, setWinPort] = useState("5985");
  const [winTransport, setWinTransport] =
    useState<WindowsDNSCredentials["transport"]>("ntlm");
  const [winUseTLS, setWinUseTLS] = useState(false);
  const [winVerifyTLS, setWinVerifyTLS] = useState(false);
  const [winClearCreds, setWinClearCreds] = useState(false);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    message: string;
  } | null>(null);

  // Cloud DNS credential state (issue #37, Part B). Provider-specific dict
  // keyed by field. On edit, fields render blank ("leave blank to keep") and
  // we only send the cloud_credentials block when the operator types
  // something — or {} to clear.
  const [cloudCreds, setCloudCreds] = useState<Record<string, string>>({});
  const [cloudClearCreds, setCloudClearCreds] = useState(false);

  const hasExistingCreds = !!server?.has_credentials;

  const cloudDriver = isCloudDriver(driver) ? driver : null;
  // Any driver that takes a credential dict — the cloud providers plus
  // self-hosted technitium_api (#810). ``cloudDriver`` stays the narrower
  // test for the bits that are genuinely cloud-only: the hosted-provider
  // setup guide, the "no host/port" layout, and the hosted-zone import link.
  const credFields = CRED_FIELDS_BY_DRIVER[driver] ?? null;

  const testMut = useMutation({
    mutationFn: () => {
      const useStored =
        editing && hasExistingCreds && !winPassword && !winUsername;
      if (useStored) {
        return dnsApi.testWindowsCredentials({
          host,
          server_id: server!.id,
        });
      }
      return dnsApi.testWindowsCredentials({
        host,
        credentials: {
          username: winUsername,
          password: winPassword,
          winrm_port: parseInt(winPort, 10) || 5985,
          transport: winTransport,
          use_tls: winUseTLS,
          verify_tls: winVerifyTLS,
        },
      });
    },
    onSuccess: setTestResult,
    onError: (e: ApiError) =>
      setTestResult({ ok: false, message: formatApiError(e, "Test failed") }),
  });

  // Probe a saved credentialed agentless server with its STORED credentials
  // (#810). Separate from testMut, which is the Windows/WinRM pre-save probe:
  // this endpoint has no plaintext mode, so it needs a saved row — which is
  // why the button only appears when editing.
  const credTestMut = useMutation({
    mutationFn: () => dnsApi.testServerConnection(groupId, server!.id),
    onSuccess: setTestResult,
    onError: (e: ApiError) =>
      setTestResult({ ok: false, message: formatApiError(e, "Test failed") }),
  });

  const mut = useMutation({
    mutationFn: (d: Record<string, unknown>) =>
      server
        ? dnsApi.updateServer(groupId, server.id, d)
        : dnsApi.createServer(groupId, d),
    onSuccess: () => {
      // Prefix-invalidate EVERY group's server list, not just this one.
      // A #934 move writes rows in two groups (the server leaves one and
      // joins the other) and primary re-election touches a sibling in each,
      // so scoping this to `groupId` left the target group's cached list
      // wrong for the full 30 s `staleTime` — the moved server invisible in
      // both places if the operator navigated straight there.
      qc.invalidateQueries({ queryKey: ["dns-servers"] });
      // Also the group list: since #934 a group row carries `server_drivers`,
      // which a move changes on BOTH sides — and that field is what decides
      // which groups this picker offers, so a stale one would keep offering
      // a group the move now refuses (or hide one it would now accept).
      qc.invalidateQueries({ queryKey: ["dns-groups"] });
      onClose();
    },
    onError: (e: ApiError) => setError(formatApiError(e)),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const roleList = roles
      .split(/[,\s]+/)
      .map((r) => r.trim())
      .filter(Boolean);

    const cloud = isCloudDriver(driver);

    const payload: Record<string, unknown> = {
      name,
      driver,
      // Cloud drivers are agentless — there's no host/port/api_port to reach.
      // Send a stable sentinel host so the row is valid; the provider API is
      // addressed via the stored cloud credentials, not host:port.
      host: cloud ? driver : host,
      port: cloud ? 443 : parseInt(port, 10),
      api_port: cloud ? null : apiPort ? parseInt(apiPort, 10) : null,
      roles: roleList,
      notes,
      is_enabled: isEnabled,
      ...(apiKey && !cloud ? { api_key: apiKey } : {}),
      // #934 — only on edit, and only when actually changed. Sending an
      // unchanged group_id is a server-side no-op, but sending is_primary
      // unchanged would still take the demotion path on every save.
      ...(editing && targetGroupId !== server!.group_id
        ? { group_id: targetGroupId }
        : {}),
      ...(editing && isPrimary !== server!.is_primary
        ? { is_primary: isPrimary }
        : {}),
    };

    if (credFields) {
      const label = CRED_DRIVER_LABELS[driver] ?? driver;
      if (cloudClearCreds) {
        payload.cloud_credentials = {};
      } else {
        // Text fields and checkboxes are collected separately because
        // "did the operator change this?" means different things for each.
        // A text field is changed when it's non-empty; a checkbox always has
        // a value, so it counts as changed only when it has been TOUCHED —
        // `cloudCreds[key]` is undefined until the onChange fires. Treating
        // an untouched checkbox as a change would submit a credential blob
        // on every save; ignoring a touched one would make unticking
        // "Verify the TLS certificate" a silent no-op.
        const typed = credFields.filter((f) => !f.checkbox);
        const boxes = credFields.filter((f) => f.checkbox);
        const entered: Record<string, string | boolean> = {};
        for (const f of typed) {
          const v = (cloudCreds[f.key] ?? "").trim();
          if (v) entered[f.key] = v;
        }
        const touchedBoxes = boxes.filter(
          (f) => cloudCreds[f.key] !== undefined,
        );
        const anyTyped = Object.keys(entered).length > 0;

        if (anyTyped || touchedBoxes.length > 0) {
          // First-time create requires every typed field — a partial
          // credential set can't authenticate. On edit, the server merges the
          // submitted keys over the stored blob, so a partial set is fine and
          // untouched fields keep their stored values.
          const missing = typed.filter((f) => !entered[f.key]);
          if (!editing && missing.length > 0) {
            setError(
              `${label} requires all credential fields: ${typed
                .map((f) => f.label)
                .join(", ")}.`,
            );
            return;
          }
          // On create every checkbox is sent (its rendered state is what the
          // operator saw and accepted); on edit only the touched ones, so the
          // rest keep whatever is stored.
          for (const f of editing ? touchedBoxes : boxes) {
            const raw = cloudCreds[f.key];
            entered[f.key] =
              raw === undefined ? (f.checkboxDefault ?? true) : raw === "true";
          }
          payload.cloud_credentials = entered;
        } else if (!editing) {
          setError(`Enter ${label} credentials to enable this server.`);
          return;
        }
        // editing + nothing entered or touched → omit cloud_credentials
        // entirely (None = leave stored creds alone).
      }
    }

    if (driver === "windows_dns") {
      if (winClearCreds) {
        payload.windows_credentials = {};
      } else if (winUsername || winPassword || editing) {
        // Path B is opt-in: only send a creds block if the user entered
        // something, or if we're editing a server that may already have
        // creds (lets them flip transport / port without re-typing).
        const creds: Partial<WindowsDNSCredentials> = {
          winrm_port: parseInt(winPort, 10) || 5985,
          transport: winTransport,
          use_tls: winUseTLS,
          verify_tls: winVerifyTLS,
        };
        if (winUsername) creds.username = winUsername;
        if (winPassword) creds.password = winPassword;
        // First-time set requires both. Edit path is merge — backend
        // checks "have stored creds" before accepting partials.
        if (
          !editing &&
          (winUsername || winPassword) &&
          (!winUsername || !winPassword)
        ) {
          setError(
            "Windows DNS Path B requires both username and password to enable WinRM. Leave both blank for Path A only (RFC 2136).",
          );
          return;
        }
        if (winUsername || winPassword || (editing && hasExistingCreds)) {
          payload.windows_credentials = creds;
        }
      }
    }

    mut.mutate(payload);
  }

  return (
    <Modal
      title={server ? `Edit ${server.name}` : "Add Server"}
      onClose={onClose}
    >
      <form onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="ns1"
              required
              autoFocus
            />
          </Field>
          <Field label="Driver">
            <select
              className={inputCls}
              value={driver}
              onChange={(e) => setDriver(e.target.value)}
              // Provider/driver is immutable on edit — changing it would
              // strand the stored credentials + rendered config.
              disabled={editing}
            >
              <option value="bind9">BIND9 (agent-managed)</option>
              <option value="powerdns">PowerDNS (agent-managed)</option>
              <option value="technitium">Technitium (agent-managed)</option>
              <option value="technitium_api">
                Technitium (agentless, remote API)
              </option>
              <option value="windows_dns">
                Windows DNS (agentless, RFC 2136 + optional WinRM)
              </option>
              <optgroup label="Cloud DNS (agentless)">
                {CLOUD_DNS_DRIVERS.map((d) => (
                  <option key={d} value={d}>
                    {CLOUD_DNS_LABELS[d]}
                  </option>
                ))}
              </optgroup>
            </select>
          </Field>
        </div>
        {driver === "windows_dns" && (
          <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
            <strong>Windows DNS:</strong>{" "}
            <span className="font-medium">Path A</span> (always on): record CRUD
            via RFC 2136 — zones must exist in Windows DNS Manager with
            <em> Nonsecure and secure</em> dynamic updates enabled.{" "}
            <span className="font-medium">Path B</span> (optional, configure
            credentials below): adds WinRM-backed zone topology reads so you can
            import existing zones into SpatiumDDI. No agent container required
            either way.
          </div>
        )}
        {driver === "powerdns" && (
          <div className="rounded-md border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-xs text-violet-800 dark:text-violet-300">
            <strong>PowerDNS:</strong> agent-managed. Run the{" "}
            <code className="rounded bg-violet-500/20 px-1">
              ghcr.io/spatiumnorth/dns-powerdns
            </code>{" "}
            container alongside this server (it keeps zones in embedded LMDB
            storage; no external DB needed). Records apply via the local
            PowerDNS REST API on port 8081 (loopback only). The agent generates
            and rotates the API key automatically — leave the field below blank.
          </div>
        )}
        {driver === "technitium" && (
          <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-800 dark:text-emerald-300">
            <strong>Technitium:</strong> agent-managed. Run the{" "}
            <code className="rounded bg-emerald-500/20 px-1">
              ghcr.io/spatiumnorth/dns-technitium
            </code>{" "}
            container alongside this server. v1 supports primary zones +
            standard record types; DNSSEC, native DoT/DoH/DoQ listeners, and
            secondary zones are on the roadmap. The agent provisions and rotates
            its own API token automatically — leave the field below blank.
          </div>
        )}
        {driver === "technitium_api" && (
          <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-800 dark:text-emerald-300">
            <strong>Technitium (remote API):</strong> agentless. For a
            Technitium server <em>you already run</em> — nothing is deployed,
            and record CRUD runs from the SpatiumDDI control plane against its
            HTTP API. Enter the API URL and a permanent token below; they're
            stored Fernet-encrypted and never returned by the API. Use the
            agent-managed <code>technitium</code> driver instead if you want
            SpatiumDDI to run the daemon. DNSSEC, forwarders and the native
            blocklists are agent-managed only for now.
          </div>
        )}
        {cloudDriver && (
          <div className="rounded-md border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-xs text-sky-800 dark:text-sky-300">
            <strong>{CLOUD_DNS_LABELS[cloudDriver]}:</strong> agentless. Record
            CRUD runs from the SpatiumDDI control plane against the provider API
            — no agent container, host, or port to configure. Provide the
            provider credentials below; they're stored Fernet-encrypted and
            never returned by the API. Once registered you can pull existing
            hosted zones in via{" "}
            <span className="font-medium">DNS Import → Cloud</span>.
          </div>
        )}
        {!cloudDriver && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Host / IP">
                <input
                  className={inputCls}
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  placeholder="10.0.0.53"
                  required
                />
              </Field>
              <Field label="DNS Port">
                <input
                  className={inputCls}
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  placeholder="53"
                />
              </Field>
            </div>
            {/* technitium_api addresses the daemon's HTTP API through the
                credential block's api_url, not through api_port/api_key —
                those two exist for the agent-managed drivers. Host + DNS
                port above stay meaningful: they're the DNS service address
                shown in the UI and used by health checks. */}
            {driver !== "technitium_api" && (
              <div className="grid grid-cols-2 gap-3">
                <Field label="API Port (rndc / REST)">
                  <input
                    className={inputCls}
                    value={apiPort}
                    onChange={(e) => setApiPort(e.target.value)}
                    placeholder={
                      driver === "powerdns"
                        ? "8081 (PowerDNS REST, loopback)"
                        : driver === "technitium"
                          ? "5380 (Technitium API, loopback)"
                          : driver === "bind9"
                            ? "953 (rndc)"
                            : "953 / 8081"
                    }
                  />
                </Field>
                {driver === "powerdns" || driver === "technitium" ? (
                  <Field label="API Key">
                    <input
                      className={`${inputCls} bg-muted/50 cursor-not-allowed`}
                      value="(generated by agent on first boot)"
                      disabled
                      readOnly
                    />
                  </Field>
                ) : (
                  <Field
                    label={
                      server ? "New API Key (leave blank to keep)" : "API Key"
                    }
                  >
                    <input
                      type="password"
                      className={inputCls}
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      placeholder={server ? "unchanged" : "optional"}
                    />
                  </Field>
                )}
              </div>
            )}
          </>
        )}
        <Field label="Roles (comma-separated)">
          <input
            className={inputCls}
            value={roles}
            onChange={(e) => setRoles(e.target.value)}
            placeholder="authoritative, recursive"
          />
        </Field>
        <Field label="Notes">
          <input
            className={inputCls}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Optional notes"
          />
        </Field>
        {editing && (
          <>
            <Field label="Server group">
              <select
                className={inputCls}
                value={targetGroupId}
                onChange={(e) => setTargetGroupId(e.target.value)}
              >
                {allGroups.map((g) => {
                  // A group is single-driver, so the server can only move to
                  // one that is empty or already runs its driver. Incompatible
                  // groups are shown DISABLED with the reason rather than
                  // hidden: an operator looking for a group they can see in
                  // the sidebar should find out why it isn't available here,
                  // not conclude it has vanished. The server's current group
                  // always stays selectable, whatever it contains — otherwise
                  // an already-mixed group could not render its own value.
                  const drivers = g.server_drivers ?? [];
                  const foreign = drivers.filter((d) => d !== driver);
                  const isCurrent = g.id === server!.group_id;
                  const blocked = !isCurrent && foreign.length > 0;
                  return (
                    <option key={g.id} value={g.id} disabled={blocked}>
                      {g.name}
                      {blocked ? ` — runs ${foreign.join(", ")}` : ""}
                    </option>
                  );
                })}
              </select>
              {targetGroupId !== server!.group_id && (
                <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">
                  Moving this server re-renders both groups&rsquo; config. Its
                  per-zone sync state and any queued record updates for the old
                  group&rsquo;s zones are discarded, and the agent picks up the
                  new group&rsquo;s config on its next poll.
                </p>
              )}
            </Field>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={isPrimary}
                onChange={(e) => setIsPrimary(e.target.checked)}
              />
              <span>
                <span className="font-medium">Primary for this group</span>
                <span className="block text-xs text-muted-foreground">
                  The server DDNS and record writes are applied at. Exactly one
                  per group &mdash; ticking this demotes whichever server holds
                  it now. A group with no primary silently drops every record
                  write to its zones, so it can only be moved, not cleared.
                </span>
              </span>
            </label>
          </>
        )}
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={isEnabled}
            onChange={(e) => setIsEnabled(e.target.checked)}
          />
          <span>
            <span className="font-medium">Enabled</span>
            <span className="block text-xs text-muted-foreground">
              Uncheck to pause this server — SpatiumDDI will skip it in the
              health probe, the bi-directional sync task, and record-op writes.
              Useful during Windows DNS / DC maintenance. Status will read{" "}
              <code>disabled</code> until re-enabled.
            </span>
          </span>
        </label>

        {driver === "windows_dns" && (
          <div className="rounded-md border border-sky-500/40 bg-sky-500/5 p-3 space-y-3">
            <div className="text-xs">
              <div className="font-medium text-sky-600 dark:text-sky-400">
                Path B — WinRM / PowerShell (optional)
              </div>
              <p className="mt-1 text-muted-foreground">
                Fill the fields below to unlock zone-topology reads (import
                existing Windows DNS zones into SpatiumDDI). Credentials are
                stored Fernet-encrypted and never returned by the API. Leave
                blank to stay on Path A only (record CRUD via RFC 2136).
              </p>
            </div>

            <details className="rounded border bg-background/40 text-xs">
              <summary className="cursor-pointer px-3 py-2 font-medium select-none">
                Windows setup checklist — click to expand
              </summary>
              <div className="space-y-3 border-t px-3 py-2.5 text-muted-foreground">
                <div>
                  <div className="font-medium text-foreground">
                    1. Enable WinRM on the DNS server
                  </div>
                  <pre className="mt-1 rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">
                    Enable-PSRemoting -Force
                  </pre>
                </div>
                <div>
                  <div className="font-medium text-foreground">
                    2. Grant the service account access
                  </div>
                  <p>
                    Add the account to{" "}
                    <code className="font-mono">Remote Management Users</code>{" "}
                    (transport) and to{" "}
                    <code className="font-mono">DnsAdmins</code> for zone CRUD
                    (read-only needs only the first). DCs have the same domain
                    group quirks as Windows DHCP — see the DHCP server checklist
                    if you hit <code>0x80080005</code>.
                  </p>
                </div>
                <div>
                  <div className="font-medium text-foreground">
                    3. Verify from another host
                  </div>
                  <pre className="mt-1 rounded bg-muted p-2 font-mono text-[11px] whitespace-pre-wrap">
                    {
                      "Invoke-Command <host> { Get-DnsServerZone } -Credential (Get-Credential)"
                    }
                  </pre>
                </div>
              </div>
            </details>

            {hasExistingCreds && !winClearCreds && (
              <div className="flex items-center justify-between rounded border bg-background/50 px-3 py-2 text-xs">
                <span>
                  <span className="font-medium">Credentials set.</span> Leave
                  fields blank to keep them, or enter new values to replace.
                </span>
                <button
                  type="button"
                  onClick={() => setWinClearCreds(true)}
                  className="rounded border px-2 py-0.5 text-[11px] hover:bg-muted"
                >
                  Clear
                </button>
              </div>
            )}
            {winClearCreds && (
              <div className="flex items-center justify-between rounded border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs">
                <span className="text-destructive">
                  Credentials will be removed on save (Path A only afterward).
                </span>
                <button
                  type="button"
                  onClick={() => setWinClearCreds(false)}
                  className="rounded border px-2 py-0.5 text-[11px] hover:bg-muted"
                >
                  Undo
                </button>
              </div>
            )}

            <div
              className={`grid grid-cols-2 gap-3 ${winClearCreds ? "opacity-40 pointer-events-none" : ""}`}
            >
              <Field label="Username">
                <input
                  className={inputCls}
                  value={winUsername}
                  onChange={(e) => setWinUsername(e.target.value)}
                  placeholder={"CORP\\dnsreader"}
                  autoComplete="off"
                />
              </Field>
              <Field label="Password">
                <input
                  type="password"
                  className={inputCls}
                  value={winPassword}
                  onChange={(e) => setWinPassword(e.target.value)}
                  placeholder={hasExistingCreds ? "(unchanged)" : "optional"}
                  autoComplete="off"
                />
              </Field>
              <Field label="WinRM Port">
                <input
                  type="number"
                  className={inputCls}
                  value={winPort}
                  onChange={(e) => setWinPort(e.target.value)}
                />
              </Field>
              <Field label="Auth Transport">
                <select
                  className={inputCls}
                  value={winTransport}
                  onChange={(e) =>
                    setWinTransport(
                      e.target.value as WindowsDNSCredentials["transport"],
                    )
                  }
                >
                  <option value="ntlm">NTLM</option>
                  <option value="basic">Basic</option>
                  <option value="credssp">CredSSP</option>
                </select>
              </Field>
              <Field label="Use HTTPS (port 5986)">
                <input
                  type="checkbox"
                  checked={winUseTLS}
                  onChange={(e) => {
                    setWinUseTLS(e.target.checked);
                    if (e.target.checked && winPort === "5985")
                      setWinPort("5986");
                    if (!e.target.checked && winPort === "5986")
                      setWinPort("5985");
                  }}
                />
              </Field>
              <Field label="Verify TLS certificate">
                <input
                  type="checkbox"
                  checked={winVerifyTLS}
                  disabled={!winUseTLS}
                  onChange={(e) => setWinVerifyTLS(e.target.checked)}
                />
              </Field>
            </div>

            <div
              className={`flex items-center gap-3 ${winClearCreds ? "opacity-40 pointer-events-none" : ""}`}
            >
              <button
                type="button"
                onClick={() => {
                  setTestResult(null);
                  testMut.mutate();
                }}
                disabled={
                  testMut.isPending ||
                  !host ||
                  (!winUsername &&
                    !(editing && hasExistingCreds && !winPassword))
                }
                className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
              >
                {testMut.isPending ? "Testing…" : "Test Connection"}
              </button>
              {editing && hasExistingCreds && !winUsername && !winPassword && (
                <span className="text-[11px] text-muted-foreground">
                  will use stored credentials
                </span>
              )}
              {testResult && (
                <span
                  className={`text-xs ${testResult.ok ? "text-emerald-600 dark:text-emerald-400" : "text-destructive"}`}
                >
                  {testResult.ok ? "✓ " : "✗ "}
                  {testResult.message}
                </span>
              )}
            </div>
          </div>
        )}

        {credFields && (
          <div className="rounded-md border border-sky-500/40 bg-sky-500/5 p-3 space-y-3">
            <div className="text-xs">
              <div className="font-medium text-sky-600 dark:text-sky-400">
                {CRED_DRIVER_LABELS[driver] ?? driver} credentials
              </div>
              <p className="mt-1 text-muted-foreground">
                Stored Fernet-encrypted and never returned by the API.
                {editing && hasExistingCreds
                  ? " Leave fields blank to keep the stored credentials, or enter new values to replace them."
                  : ""}
              </p>
            </div>

            {cloudDriver && <CloudSetupGuide driver={cloudDriver} />}

            {editing && hasExistingCreds && !cloudClearCreds && (
              <div className="flex items-center justify-between rounded border bg-background/50 px-3 py-2 text-xs">
                <span>
                  <span className="font-medium">Credentials set.</span> Leave
                  fields blank to keep them, or enter new values to replace.
                </span>
                <button
                  type="button"
                  onClick={() => setCloudClearCreds(true)}
                  className="rounded border px-2 py-0.5 text-[11px] hover:bg-muted"
                >
                  Clear
                </button>
              </div>
            )}
            {cloudClearCreds && (
              <div className="flex items-center justify-between rounded border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs">
                <span className="text-destructive">
                  Credentials will be removed on save — this server won't be
                  able to reach its API until new credentials are set.
                </span>
                <button
                  type="button"
                  onClick={() => setCloudClearCreds(false)}
                  className="rounded border px-2 py-0.5 text-[11px] hover:bg-muted"
                >
                  Undo
                </button>
              </div>
            )}

            <div
              className={`space-y-3 ${cloudClearCreds ? "opacity-40 pointer-events-none" : ""}`}
            >
              {credFields.map((f) =>
                f.checkbox ? (
                  <label
                    key={f.key}
                    className="flex items-start gap-2 text-xs cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={
                        (cloudCreds[f.key] ??
                          String(f.checkboxDefault ?? true)) === "true"
                      }
                      onChange={(e) =>
                        setCloudCreds((c) => ({
                          ...c,
                          [f.key]: String(e.target.checked),
                        }))
                      }
                    />
                    <span>
                      <span className="font-medium">{f.label}</span>
                      {f.help && (
                        <span className="block text-muted-foreground">
                          {f.help}
                        </span>
                      )}
                    </span>
                  </label>
                ) : (
                  <Field key={f.key} label={f.label}>
                    {f.textarea ? (
                      <textarea
                        className={`${inputCls} font-mono text-xs`}
                        rows={6}
                        value={cloudCreds[f.key] ?? ""}
                        onChange={(e) =>
                          setCloudCreds((c) => ({
                            ...c,
                            [f.key]: e.target.value,
                          }))
                        }
                        placeholder={
                          editing && hasExistingCreds
                            ? "(unchanged)"
                            : (f.placeholder ?? "")
                        }
                        autoComplete="off"
                      />
                    ) : (
                      <input
                        type={f.secret ? "password" : "text"}
                        className={inputCls}
                        value={cloudCreds[f.key] ?? ""}
                        onChange={(e) =>
                          setCloudCreds((c) => ({
                            ...c,
                            [f.key]: e.target.value,
                          }))
                        }
                        placeholder={
                          editing && hasExistingCreds
                            ? "(unchanged)"
                            : (f.placeholder ?? "")
                        }
                        autoComplete="off"
                      />
                    )}
                    {f.help && (
                      <p className="mt-1 text-[11px] text-muted-foreground">
                        {f.help}
                      </p>
                    )}
                  </Field>
                ),
              )}
            </div>

            {cloudDriver && editing && server && (
              <button
                type="button"
                onClick={() =>
                  navigate("/admin/dns-import", {
                    state: { cloudServerId: server.id },
                  })
                }
                className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Sync from provider (DNS Import → Cloud)
              </button>
            )}

            {editing && server && hasExistingCreds && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setTestResult(null);
                    credTestMut.mutate();
                  }}
                  disabled={credTestMut.isPending}
                  className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
                >
                  {credTestMut.isPending ? "Testing…" : "Test Connection"}
                </button>
                <span className="text-[11px] text-muted-foreground">
                  Uses the stored credentials — save any changes first.
                </span>
              </div>
            )}
            {testResult && (
              <p
                className={`text-xs ${testResult.ok ? "text-emerald-600 dark:text-emerald-400" : "text-destructive"}`}
              >
                {testResult.ok ? "✓ " : "✗ "}
                {testResult.message}
              </p>
            )}
          </div>
        )}

        {server && !cloudDriver && (
          <p className="text-xs text-muted-foreground">
            Servers can also be auto-registered by the DNS agent container — see{" "}
            <code>DNS_AGENT_KEY</code> in deployment docs.
          </p>
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label={server ? "Save" : "Add Server"}
        />
      </form>
    </Modal>
  );
}

// ── DNSSEC card (Phase 3c.fe) ────────────────────────────────────────────

/**
 * Operator-facing DNSSEC management for a single zone. Renders the
 * current state (signed / unsigned + last sync timestamp), the
 * Sign / Unsign action buttons, and the DS rrset list with one-click
 * copy so operators can paste into their parent registrar.
 *
 * Driver gating happens server-side — clicking "Sign" against a
 * non-PowerDNS group returns 422 with a clear error which we surface
 * via the mutation's onError. Operators get the message inline rather
 * than the button being mysteriously absent.
 */
function DnssecCard({
  groupId,
  zoneId,
  zoneName,
  initiallyEnabled,
}: {
  groupId: string;
  zoneId: string;
  zoneName: string;
  initiallyEnabled: boolean;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null);
  const [policyId, setPolicyId] = useState<string>("");

  const info = useQuery({
    queryKey: ["dns-zone-dnssec-info", groupId, zoneId],
    queryFn: () => dnsApi.getZoneDnssecInfo(groupId, zoneId),
    refetchOnWindowFocus: true,
    refetchInterval: initiallyEnabled ? 10_000 : false,
  });
  // DNSSEC policies (issue #49) — operator picks one when signing a BIND9
  // zone; null/empty ⇒ BIND built-in "default".
  const policies = useQuery({
    queryKey: ["dns-dnssec-policies"],
    queryFn: () => dnsApi.listDnssecPolicies(),
  });
  // Seed the picker from the zone's stored policy so it reflects what's
  // actually applied (rather than always showing "default policy").
  useEffect(() => {
    if (info.data?.dnssec_policy_id) setPolicyId(info.data.dnssec_policy_id);
  }, [info.data?.dnssec_policy_id]);

  const invalidate = () => {
    qc.invalidateQueries({
      queryKey: ["dns-zone-dnssec-info", groupId, zoneId],
    });
    qc.invalidateQueries({ queryKey: ["dns-zones", groupId] });
  };

  // policy: a UUID / null sets-or-resets the policy (fresh sign);
  // ``undefined`` omits it so a re-sign keeps the zone's current policy.
  const signMut = useMutation({
    mutationFn: (policy: string | null | undefined) =>
      dnsApi.signZoneDnssec(groupId, zoneId, policy),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e: ApiError) => setError(formatApiError(e, "Sign failed")),
  });
  const unsignMut = useMutation({
    mutationFn: () => dnsApi.unsignZoneDnssec(groupId, zoneId),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e: ApiError) => setError(formatApiError(e, "Unsign failed")),
  });
  const rolloverMut = useMutation({
    mutationFn: (keyTag: number) =>
      dnsApi.rolloverZoneDnssecKey(groupId, zoneId, keyTag),
    onSuccess: () => {
      setError(null);
      invalidate();
    },
    onError: (e: ApiError) => setError(formatApiError(e, "Rollover failed")),
  });

  const enabled = info.data?.dnssec_enabled ?? initiallyEnabled;
  const dsRecords = info.data?.dnssec_ds_records ?? [];
  const syncedAt = info.data?.dnssec_synced_at ?? null;
  const keys = info.data?.keys ?? [];
  const busy =
    signMut.isPending || unsignMut.isPending || rolloverMut.isPending;

  function copyDs(idx: number, value: string) {
    navigator.clipboard.writeText(value).then(
      () => {
        setCopiedIdx(idx);
        setTimeout(() => setCopiedIdx((c) => (c === idx ? null : c)), 1500);
      },
      () => setError("Copy to clipboard failed"),
    );
  }

  return (
    <div className="rounded-md border bg-muted/30 p-3 space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <div className="text-sm font-medium">DNSSEC</div>
          <div className="text-xs text-muted-foreground">
            {enabled ? (
              <>
                Zone is{" "}
                <span className="font-medium text-emerald-600">signed</span>
                {syncedAt ? (
                  <>
                    {" — last sync "}
                    <time
                      className="font-mono"
                      title={new Date(syncedAt).toLocaleString()}
                    >
                      {new Date(syncedAt).toLocaleString()}
                    </time>
                  </>
                ) : (
                  " — agent has not yet reported DS records"
                )}
              </>
            ) : (
              <>
                Zone is <span className="font-medium">unsigned</span>. Sign to
                generate KSK + ZSK and publish DS records to the parent
                registrar. BIND9 (inline-signing) + PowerDNS.
              </>
            )}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {enabled ? (
            <>
              <button
                type="button"
                disabled={busy}
                onClick={() => signMut.mutate(undefined)}
                className="rounded border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
                title="Re-run sign (keeps the current policy)"
              >
                {signMut.isPending ? "Re-signing…" : "Re-sign"}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => unsignMut.mutate()}
                className="rounded border border-destructive/40 bg-destructive/10 px-2 py-1 text-xs text-destructive hover:bg-destructive/20 disabled:opacity-50"
              >
                {unsignMut.isPending ? "Unsigning…" : "Unsign"}
              </button>
            </>
          ) : (
            <>
              <select
                value={policyId}
                onChange={(e) => setPolicyId(e.target.value)}
                className="rounded border bg-background px-2 py-1 text-xs"
                title="DNSSEC signing policy (BIND9)"
              >
                <option value="">default policy</option>
                {(policies.data ?? [])
                  .filter((p) => p.name !== "default")
                  .map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.algorithm}
                      {p.nsec3 ? ", NSEC3" : ""})
                    </option>
                  ))}
              </select>
              <button
                type="button"
                disabled={busy}
                onClick={() => signMut.mutate(policyId || null)}
                className="rounded bg-emerald-600 px-3 py-1 text-xs font-medium text-white hover:bg-emerald-700 disabled:opacity-50"
              >
                {signMut.isPending ? "Signing…" : "Sign zone"}
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="rounded border border-destructive/40 bg-destructive/10 px-2 py-1.5 text-xs text-destructive">
          {error}
        </div>
      )}

      {enabled && keys.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            Keys
          </div>
          <table className="w-full text-[11px]">
            <thead className="text-left text-muted-foreground">
              <tr>
                <th className="py-0.5 pr-2">Tag</th>
                <th className="py-0.5 pr-2">Type</th>
                <th className="py-0.5 pr-2">Algo</th>
                <th className="py-0.5 pr-2">State</th>
                <th className="py-0.5" />
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={`${k.key_type}-${k.key_tag}`} className="border-t">
                  <td className="py-0.5 pr-2 font-mono">{k.key_tag}</td>
                  <td className="py-0.5 pr-2 uppercase">{k.key_type}</td>
                  <td className="py-0.5 pr-2">{k.algorithm}</td>
                  <td className="py-0.5 pr-2">{k.state}</td>
                  <td className="py-0.5 text-right">
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => rolloverMut.mutate(k.key_tag)}
                      className="rounded border px-1.5 py-0.5 text-[10px] hover:bg-accent disabled:opacity-50"
                      title="Force a key rollover (BIND9 rndc dnssec -rollover)"
                    >
                      Roll
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {enabled && (
        <div>
          <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
            DS records — paste these at the parent registrar for{" "}
            <code className="font-mono">{zoneName.replace(/\.$/, "")}</code>
          </div>
          {dsRecords.length === 0 ? (
            <div className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-700 dark:text-amber-300">
              Waiting for the agent to report DS records (typically &lt;30 s
              after signing).
            </div>
          ) : (
            <ul className="space-y-1">
              {dsRecords.map((ds, idx) => (
                <li
                  key={idx}
                  className="flex items-center gap-2 rounded border bg-background px-2 py-1.5"
                >
                  <code className="flex-1 break-all font-mono text-[11px]">
                    {ds}
                  </code>
                  <button
                    type="button"
                    onClick={() => copyDs(idx, ds)}
                    className="shrink-0 rounded border px-2 py-0.5 text-[10px] hover:bg-accent"
                  >
                    {copiedIdx === idx ? "Copied" : "Copy"}
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-2 text-[11px] text-muted-foreground">
            Multiple algorithms are normal — publish them all. Keys rotate
            automatically per the policy (BIND9) or pdns schedule; this list
            refreshes after each rollover.
          </div>
        </div>
      )}
    </div>
  );
}

// ── Zone Modal (add / edit) ───────────────────────────────────────────────────

function ZoneModal({
  groupId,
  views,
  zone,
  initialName,
  onClose,
}: {
  groupId: string;
  views: DNSView[];
  zone?: DNSZone;
  initialName?: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(
    zone?.name?.replace(/\.$/, "") ?? initialName ?? "",
  );
  const [zoneType, setZoneType] = useState(zone?.zone_type ?? "primary");
  const [kind, setKind] = useState(zone?.kind ?? "forward");
  const [viewId, setViewId] = useState(zone?.view_id ?? "");
  const [primaryNs, setPrimaryNs] = useState(zone?.primary_ns ?? "");
  const [adminEmail, setAdminEmail] = useState(zone?.admin_email ?? "");
  const [ttl, setTtl] = useState(String(zone?.ttl ?? 3600));
  const [dnssec, setDnssec] = useState(zone?.dnssec_enabled ?? false);
  const [color, setColor] = useState<string | null>(zone?.color ?? null);
  // Client-side FQDN check (create only — the name is locked on edit).
  const nameErr = !zone && name.trim() ? fqdnError(name) : null;
  // #986 — TLD scope hint under the name field. Classified server-side so
  // there is exactly one implementation of the rules (a TypeScript copy
  // would drift from the one that decides the pill in the zone table); on
  // edit the name is locked, so the zone's own stored detail is used and
  // no request is made. 250 ms debounce, same as GlobalSearch.
  const [debouncedName, setDebouncedName] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedName(name.trim()), 250);
    return () => clearTimeout(timer);
  }, [name]);
  const { data: liveScope } = useQuery({
    queryKey: ["dns-name-scope", debouncedName],
    queryFn: () => dnsApi.classifyZoneName(debouncedName),
    // Only while creating, only once the name has a dot — a bare label is
    // almost always mid-typing, and flashing "Undelegated" at someone who
    // has typed "exa" is noise, not a warning.
    enabled: !zone && debouncedName.includes(".") && !nameErr,
    staleTime: 5 * 60_000,
  });
  const scopeDetail = zone ? zone.name_scope_detail : liveScope;
  // Forward-zone config — only shown / submitted when zoneType === "forward".
  const [forwardersText, setForwardersText] = useState(
    (zone?.forwarders ?? []).join(", "),
  );
  const [forwardOnly, setForwardOnly] = useState(zone?.forward_only ?? true);
  // Secondary / stub primaries (issue #336) — the master IPs (ip or
  // ip@port) this zone transfers FROM. Only shown / submitted for
  // secondary + stub types.
  const [mastersText, setMastersText] = useState(
    (zone?.masters ?? []).join(", "),
  );
  const [domainId, setDomainId] = useState<string | null>(
    zone?.domain_id ?? null,
  );
  const [customerId, setCustomerId] = useState<string | null>(
    zone?.customer_id ?? null,
  );
  const { data: domainList } = useQuery({
    queryKey: ["domains-picker"],
    queryFn: () => domainsApi.list({ page_size: 500 }),
    staleTime: 60_000,
  });
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: (d: Record<string, unknown>) =>
      zone
        ? dnsApi.updateZone(groupId, zone.id, d)
        : dnsApi.createZone(groupId, d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-zones", groupId] });
      onClose();
    },
    onError: (e: ApiError) => setError(formatApiError(e)),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const payload: Record<string, unknown> = {
      name,
      zone_type: zoneType,
      kind,
      view_id: viewId || null,
      primary_ns: primaryNs,
      admin_email: adminEmail,
      ttl: parseInt(ttl, 10),
      dnssec_enabled: dnssec,
      color,
      domain_id: domainId,
      customer_id: customerId,
    };
    if (zoneType === "forward") {
      const fwds = forwardersText
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (fwds.length === 0) {
        setError("Forward zones need at least one forwarder IP");
        return;
      }
      payload.forwarders = fwds;
      payload.forward_only = forwardOnly;
    }
    if (zoneType === "secondary" || zoneType === "stub") {
      const masters = mastersText
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (masters.length === 0) {
        setError(
          `${zoneType === "stub" ? "Stub" : "Secondary"} zones need at least one master (primary server IP) to transfer from`,
        );
        return;
      }
      payload.masters = masters;
    }
    mut.mutate(payload);
  }

  return (
    <Modal title={zone ? `Edit ${zone.name}` : "Add Zone"} onClose={onClose}>
      <form onSubmit={submit} className="space-y-3">
        <Field label="Zone Name (FQDN)">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="example.com"
            required
            autoFocus
            disabled={!!zone}
          />
          {nameErr ? (
            <p className="text-xs text-destructive mt-0.5">{nameErr}</p>
          ) : (
            !zone && (
              <p className="text-xs text-muted-foreground mt-0.5">
                Trailing dot added automatically.
              </p>
            )
          )}
          {!nameErr && (
            <ZoneScopeHint
              scope={scopeDetail?.scope}
              detail={scopeDetail ?? null}
            />
          )}
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Type">
            <select
              className={inputCls}
              value={zoneType}
              onChange={(e) => setZoneType(e.target.value)}
            >
              <option value="primary">Primary</option>
              <option value="secondary">Secondary</option>
              <option value="stub">Stub</option>
              <option value="forward">Forward</option>
            </select>
          </Field>
          <Field label="Kind">
            <select
              className={inputCls}
              value={kind}
              onChange={(e) => setKind(e.target.value)}
            >
              <option value="forward">Forward lookup</option>
              <option value="reverse">Reverse lookup</option>
            </select>
          </Field>
        </div>
        {zoneType === "forward" && (
          <div className="space-y-3 rounded border border-dashed bg-muted/20 p-3">
            <p className="text-[11px] text-muted-foreground">
              <strong>Conditional forwarder.</strong> Queries for{" "}
              <span className="font-mono">{name || "this zone"}</span> are
              relayed to the upstream resolvers below — typical use is "forward{" "}
              <code>corp.local</code> to the AD DNS at 10.0.0.5". Records on the
              zone are ignored when the type is forward.
            </p>
            <Field label="Forwarder IPs (comma- or space-separated)">
              <input
                className={inputCls}
                value={forwardersText}
                onChange={(e) => setForwardersText(e.target.value)}
                placeholder="10.0.0.5, 10.0.0.6"
              />
            </Field>
            <Field label="Fallback policy">
              <select
                className={inputCls}
                value={forwardOnly ? "only" : "first"}
                onChange={(e) => setForwardOnly(e.target.value === "only")}
              >
                <option value="only">
                  forward only — never fall back to recursion
                </option>
                <option value="first">
                  forward first — fall back if all forwarders fail
                </option>
              </select>
            </Field>
          </div>
        )}
        {(zoneType === "secondary" || zoneType === "stub") && (
          <div className="space-y-3 rounded border border-dashed bg-muted/20 p-3">
            <p className="text-[11px] text-muted-foreground">
              <strong>
                {zoneType === "stub" ? "Stub zone." : "Secondary zone."}
              </strong>{" "}
              This server transfers{" "}
              <span className="font-mono">{name || "this zone"}</span> from the
              primary (master) server(s) below via AXFR/IXFR — no records are
              edited here. At least one master is required.
            </p>
            <Field label="Master IPs (comma- or space-separated; ip or ip@port)">
              <input
                className={inputCls}
                value={mastersText}
                onChange={(e) => setMastersText(e.target.value)}
                placeholder="192.0.2.10, 192.0.2.11@5353"
              />
            </Field>
          </div>
        )}
        {views.length > 0 && (
          <Field label="View (optional)">
            <select
              className={inputCls}
              value={viewId}
              onChange={(e) => setViewId(e.target.value)}
            >
              <option value="">— No view —</option>
              {views.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
            </select>
          </Field>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Primary NS">
            <input
              className={inputCls}
              value={primaryNs}
              onChange={(e) => setPrimaryNs(e.target.value)}
              placeholder="ns1.example.com."
            />
          </Field>
          <Field label="Admin Email">
            <input
              className={inputCls}
              value={adminEmail}
              onChange={(e) => setAdminEmail(e.target.value)}
              placeholder="hostmaster.example.com."
            />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Default TTL (seconds)">
            <input
              className={inputCls}
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              placeholder="3600"
            />
          </Field>
          <Field label="DNSSEC">
            {zone ? (
              <div className="mt-1 text-xs text-muted-foreground">
                Manage signing in the panel below.
              </div>
            ) : (
              <label className="flex items-center gap-2 mt-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={dnssec}
                  onChange={(e) => setDnssec(e.target.checked)}
                  className="h-4 w-4"
                />
                <span className="text-sm">Enable DNSSEC after creation</span>
              </label>
            )}
          </Field>
        </div>
        {zone && (
          <DnssecCard
            groupId={groupId}
            zoneId={zone.id}
            zoneName={zone.name}
            initiallyEnabled={zone.dnssec_enabled}
          />
        )}
        <Field label="Color">
          <SwatchPicker value={color} onChange={setColor} />
        </Field>
        <Field label="Linked Domain (optional)">
          <select
            className={inputCls}
            value={domainId ?? ""}
            onChange={(e) => setDomainId(e.target.value || null)}
          >
            <option value="">— Auto-match by zone name —</option>
            {(domainList?.items ?? []).map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
                {d.registrar ? ` — ${d.registrar}` : ""}
              </option>
            ))}
          </select>
          <p className="mt-1 text-[11px] text-muted-foreground">
            Pin to a tracked domain registration so the Domain detail page
            surfaces it under "Linked DNS Zones". Auto-matches by name when left
            blank.
          </p>
        </Field>
        <Field label="Customer (optional)">
          <CustomerPicker
            className={inputCls}
            value={customerId}
            onChange={setCustomerId}
          />
        </Field>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label={zone ? "Save" : "Add Zone"}
          disabled={!!nameErr}
        />
      </form>
    </Modal>
  );
}

// ── Record Modal (add / edit) ─────────────────────────────────────────────────

const RECORD_TYPES = [
  "A",
  "AAAA",
  "ALIAS",
  "CNAME",
  "MX",
  "TXT",
  "NS",
  "PTR",
  "SRV",
  "CAA",
  "TLSA",
  "SSHFP",
  "NAPTR",
  "LOC",
  "LUA",
  "SVCB",
  "HTTPS",
  "DNAME",
];

// Per-type placeholder for the Value field. For MX / SRV the Value is the
// *target host* only — priority/weight/port are entered in their own
// fields and stitched into the wire format by the driver. The
// packed-value types (CAA / NAPTR / SSHFP / TLSA / LOC / SVCB / HTTPS)
// carry their whole RDATA in Value, so the hint shows the wire format so
// operators know what to type (#424 — sweep of every record type).
const RECORD_VALUE_PLACEHOLDER: Record<string, string> = {
  A: "10.0.0.1",
  AAAA: "2001:db8::1",
  CNAME: "other.example.com.",
  ALIAS: "lb.elsewhere.example.net.",
  PTR: "host.example.com.",
  NS: "ns1.example.com.",
  MX: "mail.example.com.  (target host — set Priority below)",
  SRV: "target host, e.g. sipserver.example.com.",
  TXT: '"v=spf1 include:_spf.example.com ~all"',
  CAA: '0 issue "letsencrypt.org"',
  NAPTR: '100 10 "U" "E2U+sip" "!^.*$!sip:info@ex.com!" .',
  SSHFP: "2 1 123456789abcdef67890...",
  TLSA: "3 1 1 0123456789abcdef...",
  LOC: "37 23 30.900 N 121 59 19.000 W 7m",
  SVCB: '1 . alpn="h2,h3"',
  HTTPS: '1 . alpn="h2,h3"',
  DNAME: "target.example.net.",
};

function RecordModal({
  groupId,
  zoneId,
  zoneName,
  record,
  onClose,
}: {
  groupId: string;
  zoneId: string;
  zoneName?: string;
  record?: DNSRecord;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const isReverseZone =
    !!zoneName && /\.(in-addr|ip6)\.arpa\.?$/i.test(zoneName);
  const [name, setName] = useState(record?.name ?? "");
  const [type, setType] = useState(
    record?.record_type ?? (isReverseZone ? "PTR" : "A"),
  );
  const [value, setValue] = useState(record?.value ?? "");
  const [ttl, setTtl] = useState(String(record?.ttl ?? ""));
  const [priority, setPriority] = useState(String(record?.priority ?? ""));
  const [weight, setWeight] = useState(String(record?.weight ?? ""));
  const [port, setPort] = useState(String(record?.port ?? ""));
  const [viewId, setViewId] = useState<string>(record?.view_id ?? "");
  const [error, setError] = useState("");
  // Owner-name check — permits `_`, a leftmost `*`, and empty/`@` (apex).
  const nameErr = recordOwnerError(name);

  const { data: views = [] } = useQuery({
    queryKey: ["dns-views", groupId],
    queryFn: () => dnsApi.listViews(groupId),
  });

  // SRV carries priority + weight + port (RFC 2782); MX carries only a
  // priority (the preference). Everything else carries none. (#424)
  const isSrv = type === "SRV";
  const isAddress = type === "A" || type === "AAAA";
  const usesPriority = type === "MX" || isSrv;

  const mut = useMutation({
    mutationFn: (d: Record<string, unknown>) =>
      record
        ? dnsApi.updateRecord(groupId, zoneId, record.id, d)
        : dnsApi.createRecord(groupId, zoneId, d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-records", zoneId] });
      onClose();
    },
    onError: (e: ApiError) => setError(formatApiError(e)),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    // Client-side guard mirroring the API's per-type rules so the operator
    // gets an inline message instead of a round-trip 422 (#424).
    if (isSrv && (priority === "" || weight === "" || port === "")) {
      setError("SRV records require priority, weight, and port.");
      return;
    }
    mut.mutate({
      name,
      record_type: type,
      value,
      ttl: ttl ? parseInt(ttl, 10) : null,
      // Only send the structured fields the type actually uses, so the API
      // never sees a stray weight/port on a non-SRV record.
      priority: usesPriority && priority !== "" ? parseInt(priority, 10) : null,
      weight: isSrv && weight !== "" ? parseInt(weight, 10) : null,
      port: isSrv && port !== "" ? parseInt(port, 10) : null,
      view_id: viewId || null,
    });
  }

  return (
    <Modal title={record ? "Edit Record" : "Add Record"} onClose={onClose}>
      <form onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Name (relative to zone)">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder='@ for apex, "www", "mail"'
              required
              autoFocus
            />
            {nameErr && <p className="text-xs text-destructive">{nameErr}</p>}
          </Field>
          <Field label="Type">
            <select
              className={inputCls}
              value={type}
              onChange={(e) => setType(e.target.value)}
              // record_type is immutable on update (the API ignores it), so
              // lock it in edit mode rather than let the per-type fields
              // shift around a Type that won't actually change (#424).
              disabled={!!record}
            >
              {RECORD_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <Field label="Value">
          {type === "LUA" ? (
            <div className="space-y-1">
              <div className="flex items-center justify-between gap-2">
                <select
                  className="rounded-md border bg-background px-2 py-1 text-xs"
                  value=""
                  onChange={(e) => {
                    if (e.target.value) {
                      setValue(e.target.value);
                      e.target.value = "";
                    }
                  }}
                  aria-label="Insert LUA snippet template"
                >
                  <option value="">Insert snippet…</option>
                  <option
                    value={`A "pickrandom({'10.0.0.1','10.0.0.2','10.0.0.3'})"`}
                  >
                    pickrandom — round-robin A
                  </option>
                  <option value={`A "ifportup(443, {'10.0.0.1','10.0.0.2'})"`}>
                    ifportup — failover by TCP probe
                  </option>
                  <option
                    value={`A "ifurlup('https://example.com/health', {'10.0.0.1','10.0.0.2'})"`}
                  >
                    ifurlup — failover by HTTP(S) probe
                  </option>
                  <option
                    value={`CNAME "createReverse('%5%.%4%.%3%.%2%.in-addr.arpa.')"`}
                  >
                    createReverse — generated PTR
                  </option>
                  <option
                    value={`A "pickwhashed({{1, '10.0.0.1'}, {3, '10.0.0.2'}})"`}
                  >
                    pickwhashed — sticky weighted
                  </option>
                  <option value={`A "pickclosest({'10.0.0.1','192.168.1.1'})"`}>
                    pickclosest — geo / latency
                  </option>
                </select>
                <span className="text-[11px] text-muted-foreground">
                  Templates are starting points — edit to fit your zone.
                </span>
              </div>
              <textarea
                className={`${inputCls} font-mono text-xs`}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={`A 'pickrandom({"10.0.0.1","10.0.0.2"})'`}
                rows={4}
                required
              />
            </div>
          ) : (
            <input
              className={inputCls}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={RECORD_VALUE_PLACEHOLDER[type] ?? "record value"}
              required
            />
          )}
          {isSrv && (
            <p className="mt-1 text-[11px] text-muted-foreground">
              Value is the <strong>target host</strong> only — set priority,
              weight, and port in the fields below.
            </p>
          )}
          {isAddress && (
            <p className="mt-1 text-[11px] text-muted-foreground">
              One IP per record. To point this name at several IPs, add{" "}
              <strong>one {type} record per address</strong> — they render as
              separate lines (RFC 1035 round-robin). For health-checked
              failover, use a <strong>DNS Pool</strong> (Pools tab) instead.
            </p>
          )}
        </Field>
        {type === "ALIAS" && (
          <div className="rounded-md border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-xs text-violet-800 dark:text-violet-300">
            <strong>ALIAS:</strong> PowerDNS-only. The server resolves the
            target at query time and serves the resulting A / AAAA, so this is
            the canonical CNAME-at-apex (which RFC 1034 §3.6.2 forbids). The
            zone must live in a server group whose every server runs the
            PowerDNS driver; the API will return 422 otherwise.
          </div>
        )}
        {type === "LUA" && (
          <div className="rounded-md border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-xs text-violet-800 dark:text-violet-300">
            <strong>LUA:</strong> PowerDNS-only computed-record snippet. Format
            is{" "}
            <code className="rounded bg-violet-500/20 px-1">
              RTYPE 'lua-snippet'
            </code>
            {" — e.g. "}
            <code className="rounded bg-violet-500/20 px-1">
              A 'pickrandom(...)'
            </code>
            ,{" "}
            <code className="rounded bg-violet-500/20 px-1">
              AAAA 'ifportup(443, {"{...}"})'
            </code>
            , or{" "}
            <code className="rounded bg-violet-500/20 px-1">
              CNAME 'createReverse(...)'
            </code>
            . The snippet executes inside <em>pdns_server</em> at query time, so
            an untrusted snippet is a server-side code-execution risk — keep
            this surface admin-only. The agent automatically sets{" "}
            <code className="rounded bg-violet-500/20 px-1">
              ENABLE-LUA-RECORDS=1
            </code>{" "}
            metadata on the zone the first time you save a LUA record. Zone must
            live in a powerdns-only group; API returns 422 otherwise.
          </div>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="TTL (leave blank for zone default)">
            <input
              className={inputCls}
              value={ttl}
              onChange={(e) => setTtl(e.target.value)}
              placeholder="zone default"
            />
          </Field>
          {type === "MX" && (
            <Field label="Priority">
              <input
                type="number"
                min={0}
                max={65535}
                className={inputCls}
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                placeholder="10"
              />
            </Field>
          )}
        </div>
        {isSrv && (
          <div className="grid grid-cols-3 gap-3">
            <Field label="Priority">
              <input
                type="number"
                min={0}
                max={65535}
                className={inputCls}
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                placeholder="0"
                required
              />
            </Field>
            <Field label="Weight">
              <input
                type="number"
                min={0}
                max={65535}
                className={inputCls}
                value={weight}
                onChange={(e) => setWeight(e.target.value)}
                placeholder="0"
                required
              />
            </Field>
            <Field label="Port">
              <input
                type="number"
                min={0}
                max={65535}
                className={inputCls}
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="e.g. 5060"
                required
              />
            </Field>
          </div>
        )}
        <Field label="View (optional — scope record to a split-horizon view)">
          <select
            className={inputCls}
            value={viewId}
            onChange={(e) => setViewId(e.target.value)}
          >
            <option value="">All views (default)</option>
            {views.map((v) => (
              <option key={v.id} value={v.id}>
                {v.name}
              </option>
            ))}
          </select>
        </Field>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label={record ? "Save" : "Add Record"}
          disabled={!!nameErr}
        />
      </form>
    </Modal>
  );
}

// ── Zone Detail View (records panel) ─────────────────────────────────────────

/**
 * Per-server serial-drift pill. Three display states:
 *  - All servers on the target serial → emerald "N/N synced · serial X"
 *  - Some servers behind / ahead      → amber "1/3 drift · target X"
 *  - No server has reported yet       → muted "— not reported"
 *
 * Hover tooltip lists every server with its own serial for quick drift
 * diagnosis (e.g. "ns2: 41 (target 42, reported 3m ago)").
 */
function ZoneSyncPill({ state }: { state: ZoneServerState }) {
  const total = state.servers.length;
  if (total === 0) return null;
  const reported = state.servers.filter((s) => s.current_serial !== null);
  const inSync = state.servers.filter(
    (s) => s.current_serial === state.target_serial,
  );
  const tooltip = state.servers
    .map((s) =>
      s.current_serial === null
        ? `${s.server_name}: not reported`
        : `${s.server_name}: serial ${s.current_serial}` +
          (s.current_serial !== state.target_serial ? " (drift)" : ""),
    )
    .join("\n");

  let cls = "bg-muted/40 text-muted-foreground";
  let label = "not reported";
  if (reported.length === 0) {
    // noop — keep muted
  } else if (state.in_sync) {
    cls =
      "bg-emerald-500/15 text-emerald-600 dark:bg-emerald-500/20 dark:text-emerald-400";
    label = `${inSync.length}/${total} synced · serial ${state.target_serial}`;
  } else {
    cls =
      "bg-amber-500/15 text-amber-700 dark:bg-amber-500/20 dark:text-amber-400";
    label = `${total - inSync.length}/${total} drift · target ${state.target_serial}`;
  }
  return (
    <span
      className={cn(
        "ml-2 inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium",
        cls,
      )}
      title={tooltip}
    >
      {label}
    </span>
  );
}

// ── Move a zone to another server group (#935) ─────────────────────────────
//
// Preview → commit rather than a one-click action, because none of the
// consequences are visible from the zone page: which view scoping survives,
// which dynamic-update grants do, and that a signed zone changes groups by
// rolling its keys. Each consequence is its own checkbox — a single "I
// understand" would let the DNSSEC warning be accepted by someone who only
// read the view one.

const ACK_LABELS: Record<string, string> = {
  view_widening:
    "I understand these records will answer in EVERY view in the target group, not just the one they are scoped to today.",
  dnssec_rollover:
    "I understand this zone will be re-signed with new keys, and DNSSEC validation fails until I publish the new DS record at the registrar.",
  lost_update_grants:
    "I understand the listed dynamic-update grants will be deleted, and the clients using them can no longer update this zone.",
};

function MoveZoneModal({
  zone,
  onClose,
  onMoved,
}: {
  zone: DNSZone;
  onClose: () => void;
  onMoved: (targetGroupId: string) => void;
}) {
  const [targetGroupId, setTargetGroupId] = useState("");
  const [acks, setAcks] = useState<Record<string, boolean>>({});
  const [confirmName, setConfirmName] = useState("");
  const [error, setError] = useState("");

  const { data: groups = [] } = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });

  // Preview is a pure read, so it re-runs freely as the target changes.
  const { data: preview, isFetching: previewing } = useQuery({
    queryKey: ["zone-move-preview", zone.id, targetGroupId],
    queryFn: () =>
      dnsApi.previewZoneMove(zone.group_id, zone.id, targetGroupId),
    enabled: !!targetGroupId,
  });

  // Clear stale acknowledgements when the target changes — a box ticked
  // for one group's consequences must not carry over to another's.
  useEffect(() => {
    setAcks({});
  }, [targetGroupId]);

  const mut = useMutation({
    mutationFn: () =>
      dnsApi.commitZoneMove(zone.group_id, zone.id, {
        target_group_id: targetGroupId,
        confirmation_zone_name: confirmName,
        acknowledgements: Object.keys(acks).filter((k) => acks[k]),
      }),
    onSuccess: () => onMoved(targetGroupId),
    onError: (e: ApiError) => setError(formatApiError(e)),
  });

  const required = preview?.required_acknowledgements ?? [];
  const allAcked = required.every((k) => acks[k]);
  const nameOk =
    confirmName.trim().replace(/\.$/, "") === zone.name.replace(/\.$/, "");
  const blocked =
    !!preview &&
    (preview.name_collision ||
      preview.dnssec_unsupported_drivers.length > 0 ||
      preview.acl_names_lost.length > 0);
  const canSubmit =
    !!targetGroupId &&
    !!preview &&
    !blocked &&
    allAcked &&
    nameOk &&
    !mut.isPending;

  return (
    <Modal title={`Move ${zone.name}`} onClose={onClose} wide>
      <div className="space-y-4">
        <Field label="Destination server group">
          <select
            className={inputCls}
            value={targetGroupId}
            onChange={(e) => setTargetGroupId(e.target.value)}
          >
            <option value="">Select a group…</option>
            {groups
              .filter((g) => g.id !== zone.group_id)
              .map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
          </select>
        </Field>

        {previewing && (
          <p className="text-sm text-muted-foreground">
            Checking what this move would do…
          </p>
        )}

        {preview && (
          <>
            {preview.name_collision && (
              <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-300">
                <strong>{preview.target_group_name}</strong> already has a zone
                named <code>{preview.zone_name}</code> in the view this one
                would land in. Rename or delete it first.
              </div>
            )}
            {/* Two blockers no acknowledgement can waive — neither leaves a
                state the operator could inspect and fix afterwards. */}
            {preview.dnssec_unsupported_drivers.length > 0 && (
              <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-300">
                This zone is DNSSEC-signed and{" "}
                <strong>{preview.target_group_name}</strong> runs{" "}
                <code>{preview.dnssec_unsupported_drivers.join(", ")}</code>,
                which cannot sign. It would keep reporting as signed while being
                served unsigned. Unsign it first, or pick a BIND9 / PowerDNS
                group.
              </div>
            )}
            {preview.acl_names_lost.length > 0 && (
              <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-300">
                This zone names ACL(s){" "}
                <code>{preview.acl_names_lost.join(", ")}</code> that{" "}
                <strong>{preview.target_group_name}</strong> does not define.
                Moving it would leave an undefined symbol in that group&rsquo;s{" "}
                <code>named.conf</code>, which BIND rejects whole &mdash; the
                entire target group would stop converging, not just this zone.
                Create ACLs with those names there first.
              </div>
            )}

            <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
              <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                <span className="text-muted-foreground">Records moving</span>
                <span>{preview.records_total}</span>
                {preview.records_remapped > 0 && (
                  <>
                    <span className="text-muted-foreground">
                      View scoping preserved
                    </span>
                    <span>
                      {preview.records_remapped} record(s) remapped by view name
                    </span>
                  </>
                )}
                {preview.acl_rows_remapped > 0 && (
                  <>
                    <span className="text-muted-foreground">
                      Update grants preserved
                    </span>
                    <span>
                      {preview.acl_rows_remapped} remapped by key name
                    </span>
                  </>
                )}
                {preview.pools_repointed > 0 && (
                  <>
                    <span className="text-muted-foreground">
                      Pools following
                    </span>
                    <span>{preview.pools_repointed}</span>
                  </>
                )}
                {preview.pending_ops > 0 && (
                  <>
                    <span className="text-muted-foreground">
                      Queued updates discarded
                    </span>
                    <span>{preview.pending_ops}</span>
                  </>
                )}
              </div>
            </div>

            {preview.warnings.length > 0 && (
              <ul className="space-y-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
                {preview.warnings.map((w, i) => (
                  <li key={i}>• {w}</li>
                ))}
              </ul>
            )}

            {required.length > 0 && (
              <div className="space-y-2">
                {required.map((key) => (
                  <label key={key} className="flex items-start gap-2 text-xs">
                    <input
                      type="checkbox"
                      className="mt-0.5"
                      checked={!!acks[key]}
                      onChange={(e) =>
                        setAcks((prev) => ({
                          ...prev,
                          [key]: e.target.checked,
                        }))
                      }
                    />
                    <span>{ACK_LABELS[key] ?? key}</span>
                  </label>
                ))}
              </div>
            )}

            <Field label={`Type the zone name to confirm (${zone.name})`}>
              <input
                className={inputCls}
                value={confirmName}
                onChange={(e) => setConfirmName(e.target.value)}
                placeholder={zone.name}
              />
            </Field>
          </>
        )}

        {error && (
          <p className="text-sm text-rose-600 dark:text-rose-400">{error}</p>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <HeaderButton onClick={onClose}>Cancel</HeaderButton>
          <HeaderButton
            variant="destructive"
            disabled={!canSubmit}
            onClick={() => {
              setError("");
              mut.mutate();
            }}
          >
            {mut.isPending ? "Moving…" : "Move zone"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}

// Sub-tabs on the zone detail surface. Mirrored in the ``subtab`` URL param
// (``records`` is the default and is left out of the URL entirely).
type ZoneSubtab = "records" | "pools" | "certs" | "drift";

// Matches BULK_DELETE_RECORDS_MAX server-side. A selection larger than this
// is split, and each call is its own trash batch — the confirm copy says so.
const BULK_DELETE_CHUNK = 2000;

function ZoneDetailView({
  group,
  zone,
  highlightRecordId,
  onDeleted,
}: {
  group: DNSServerGroup;
  zone: DNSZone;
  highlightRecordId?: string | null;
  onDeleted: () => void;
}) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [showAddRecord, setShowAddRecord] = useState(false);
  const [editRecord, setEditRecord] = useState<DNSRecord | null>(null);
  const [propagationRecord, setPropagationRecord] = useState<DNSRecord | null>(
    null,
  );
  const [showEditZone, setShowEditZone] = useState(false);
  const [showAddSubzone, setShowAddSubzone] = useState(false);
  const [showDelegate, setShowDelegate] = useState(false);
  const [showUpdateAcl, setShowUpdateAcl] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [showMoveZone, setShowMoveZone] = useState(false);
  const [deleteNotice, setDeleteNotice] = useState<string | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [showRecFilters, setShowRecFilters] = useState(false);
  const [recFilter, setRecFilter] = useState({ name: "", type: "", value: "" });
  // Server-side pagination + search (#455): a large zone (20k+ records) no
  // longer ships its whole record set per poll. `recordSearch` matches
  // name / fqdn / value / type on the server; the per-column recFilter below
  // stays a client-side refinement over the current page.
  const [recordSearch, setRecordSearch] = useState("");
  const [recordPage, setRecordPage] = useState(1);
  const recordPageSize = 100;
  // Search-landing highlight — ``highlightRecordId`` is passed down
  // by DNSPage, which captured it from ``location.state`` before
  // ``setSelection`` fired its ``setSearchParams(..., { replace: true })``
  // that drops state.
  const { register: registerHighlightRow, isActive: isHighlightedRow } =
    useRowHighlight(highlightRecordId ?? null);

  const handleExport = async () => {
    const { data, filename } = await dnsApi.exportZone(group.id, zone.id);
    const name =
      filename ??
      `${zone.name.replace(/\.$/, "")}-${_utcTimestampSuffix()}.zone`;
    downloadBlob(data, name, "text/dns");
  };

  // Per-server zone-serial drift pill — agents POST their loaded serial
  // to /dns/agents/zone-state after each structural apply; this endpoint
  // joins those reports with the group's server list.
  const { data: serverState } = useQuery({
    queryKey: ["zone-server-state", group.id, zone.id],
    queryFn: () => dnsApi.getZoneServerState(group.id, zone.id),
    refetchInterval: 30_000,
  });

  // Delegation wizard surface only appears when this zone has an eligible
  // parent zone in the same group — preview the parent up front so the
  // header button can hide cleanly otherwise.
  const { data: delegationPreview } = useQuery({
    queryKey: ["dns-delegation-preview", group.id, zone.id],
    queryFn: () => dnsApi.getDelegationPreview(group.id, zone.id),
    // Forward zones don't host records, so no delegation work to do.
    enabled: zone.zone_type !== "forward" && !zone.tailscale_tenant_id,
  });
  const showDelegateButton =
    delegationPreview?.has_parent === true &&
    (delegationPreview.ns_records_to_create.length > 0 ||
      delegationPreview.glue_records_to_create.length > 0);

  // "Sync with server" — bi-directional additive sync against the zone's
  // primary authoritative server (today: Windows DNS). AXFR imports missing
  // records into our DB, then every DB record not already on the wire is
  // pushed back via RFC 2136. Never deletes. Result shown in <SyncResultModal/>.
  const [syncResult, setSyncResult] = useState<SyncResultPayload | null>(null);
  const syncMut = useMutation({
    mutationFn: () => dnsApi.syncZoneWithServer(group.id, zone.id, true),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["dns-records", zone.id] });
      setSyncResult({ ok: true, ...res });
    },
    onError: (err) => {
      setSyncResult({
        ok: false,
        error: formatApiError(err, "Sync with server failed"),
      });
    },
  });

  const { data: views = [] } = useQuery({
    queryKey: ["dns-views", group.id],
    queryFn: () => dnsApi.listViews(group.id),
  });
  const recordParams = useMemo(() => {
    const p: { page: number; page_size: number; search?: string } = {
      page: recordPage,
      page_size: recordPageSize,
    };
    if (recordSearch.trim()) p.search = recordSearch.trim();
    return p;
  }, [recordPage, recordSearch]);
  const { data: recordsPage, isFetching } = useQuery({
    queryKey: ["dns-records", zone.id, recordParams],
    queryFn: () => dnsApi.listRecords(group.id, zone.id, recordParams),
  });
  const records = recordsPage?.items ?? [];
  const recordsTotal = recordsPage?.total ?? 0;

  // TLS cert targets linked to this zone (#118). Powers the Certs
  // sub-tab + the per-record state pill on A/AAAA rows. Gated on the
  // feature module so disabling it stops the extra query entirely.
  const { enabled: moduleEnabled, ready: modulesReady } = useFeatureModules();
  const tlsCertsOn = moduleEnabled("security.tls_certs");
  const { data: tlsCerts, isLoading: tlsCertsLoading } = useQuery({
    queryKey: ["tls-certs", "dns-zone", zone.id],
    queryFn: () => tlsCertsApi.list({ dns_zone_id: zone.id, limit: 200 }),
    enabled: modulesReady && tlsCertsOn,
  });
  // #118 — toggle auto-discovery of cert probe targets for this zone's
  // A/AAAA records. The discovery reconciler picks the change up on its
  // next sweep (~5 min).
  const autoTlsProbeMutation = useMutation({
    mutationFn: (next: boolean) =>
      dnsApi.updateZone(group.id, zone.id, { auto_tls_probe: next }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-zones", group.id] });
      qc.invalidateQueries({ queryKey: ["tls-certs", "dns-zone", zone.id] });
    },
  });
  const certStateByRecord = new Map(
    (tlsCerts?.items ?? [])
      .filter((t) => t.dns_record_id)
      .map((t) => [t.dns_record_id as string, t.state]),
  );

  const deleteZone = useMutation({
    mutationFn: () => dnsApi.deleteZone(group.id, zone.id),
    onSuccess: (resp) => {
      // Two-person approval (#62): a covered delete returns 202 with a
      // queued change-request instead of deleting. Surface the message,
      // refresh the approval queue, and leave the zone in place.
      if (handleApprovalQueued(resp)) {
        setDeleteNotice(APPROVAL_QUEUED_MESSAGE);
        qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY });
        return;
      }
      qc.invalidateQueries({ queryKey: ["dns-zones", group.id] });
      onDeleted();
    },
  });

  const deleteRecord = useMutation({
    mutationFn: (r: DNSRecord) => dnsApi.deleteRecord(group.id, zone.id, r.id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["dns-records", zone.id] }),
  });
  const [confirmDeleteRecord, setConfirmDeleteRecord] =
    useState<DNSRecord | null>(null);
  const [selectedRecords, setSelectedRecords] = useState<Set<string>>(
    new Set(),
  );
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);
  // Superadmin-only permanent bulk delete (#963): the default moves the
  // selection to the trash under one batch id; before #963 the grid could
  // only hard-delete, so the option stays reachable for the one role that
  // may use it.
  const { isSuperadmin } = usePermissions();
  const [bulkPermanent, setBulkPermanent] = useState(false);
  // Outcome of the last bulk delete when some rows were skipped — the
  // selection persists across pages, so the count in the modal can differ
  // from what the server did (pool-managed or synthesised rows, wire
  // failures). Shown above the records table until dismissed.
  const [bulkDeleteNotice, setBulkDeleteNotice] = useState<string | null>(null);
  const bulkDeleteRecords = useMutation({
    // Server-side bulk endpoint: one WinRM round trip for agentless
    // drivers + a single zone-serial bump instead of N. Replaces the
    // old Promise.allSettled fan-out. The server caps a call at
    // BULK_DELETE_CHUNK ids and the selection can exceed that across
    // pages, so chunk — and each chunk is its own trash batch, which the
    // confirm copy says rather than promising one restore.
    mutationFn: async (ids: string[]) => {
      let deleted = 0;
      const skipped: { record_id: string; reason: string }[] = [];
      const batches: string[] = [];
      for (let i = 0; i < ids.length; i += BULK_DELETE_CHUNK) {
        const res = await dnsApi.bulkDeleteRecords(
          group.id,
          zone.id,
          ids.slice(i, i + BULK_DELETE_CHUNK),
          { permanent: bulkPermanent },
        );
        deleted += res.deleted;
        skipped.push(...res.skipped);
        if (res.deletion_batch_id) batches.push(res.deletion_batch_id);
      }
      return { deleted, skipped, batches };
    },
    onSuccess: ({ deleted, skipped, batches }) => {
      qc.invalidateQueries({ queryKey: ["dns-records", zone.id] });
      setSelectedRecords(new Set());
      setConfirmBulkDelete(false);
      const spread =
        batches.length > 1
          ? ` across ${batches.length} trash batches, each restored separately`
          : "";
      if (skipped.length > 0) {
        const reasons = Array.from(new Set(skipped.map((s) => s.reason)));
        setBulkDeleteNotice(
          `${deleted} record${deleted === 1 ? "" : "s"} ${bulkPermanent ? "deleted" : "moved to the trash"}${spread}; ${skipped.length} skipped — ${reasons.join("; ")}`,
        );
      } else if (spread) {
        setBulkDeleteNotice(
          `${deleted} record${deleted === 1 ? "" : "s"} ${bulkPermanent ? "deleted" : "moved to the trash"}${spread}.`,
        );
      } else {
        setBulkDeleteNotice(null);
      }
      setBulkPermanent(false);
    },
  });

  // Forward zones have no records — they just hand queries off to the
  // listed forwarders. The detail surface below swaps the records table
  // for a forwarders/policy panel and hides the record-management buttons.
  const isForward = zone.zone_type === "forward";

  // #996 — the Add Record keycap, rendered from lib/shortcuts.ts rather
  // than typed here, so retuning the binding moves the handler below,
  // this tooltip and the ``?`` overlay together.
  const addRecordHint = formatCombo(ADD_DNS_RECORD.combos[0]);

  // …and the handler it describes. Stands down inside form fields (the
  // same ``isTypingTarget`` guard ``?`` uses — a bare letter would
  // otherwise fire while the operator types a hostname), on a forward
  // zone (no records to add), on a Tailscale-owned zone (the reconciler
  // owns them), and while any modifier is held so browser bindings are
  // untouched. Also stands down while a dialog is open, or ``n`` on a
  // modal's own button would stack a second Add Record behind the first.
  //
  // ``[role="dialog"]`` is the signal because every modal in the app sets
  // it: the shared ``Modal`` primitive, and since #1156 every custom shape
  // through ``useModalDialog`` (the standing rule is that pages never
  // reintroduce a local one). The explicit ``showAddRecord`` check still
  // covers the case that actually matters whatever it is built on.
  useEffect(() => {
    if (isForward || zone.tailscale_tenant_id) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      if (isTypingTarget(e.target)) return;
      if (!matchesShortcut(e, ADD_DNS_RECORD)) return;
      if (showAddRecord || document.querySelector('[role="dialog"]')) return;
      e.preventDefault();
      setShowAddRecord(true);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [isForward, zone.tailscale_tenant_id, showAddRecord]);

  // Records / Pools sub-tab toggle. Pools live under the same zone but
  // need their own management surface — health-check config, member
  // states, manual enable toggles. Forward zones don't host records,
  // so the tab strip is hidden there. ``subtab=pools`` in the URL
  // (set by the global DNS Pools page when an operator clicks a row)
  // pre-selects the Pools tab so the deep-link lands on the right
  // surface; otherwise default to Records.
  const [zoneSearchParams, setZoneSearchParams] = useSearchParams();
  const subtabParam = zoneSearchParams.get("subtab");
  const initialSubtab: ZoneSubtab =
    subtabParam === "pools"
      ? "pools"
      : subtabParam === "certs"
        ? "certs"
        : subtabParam === "drift"
          ? "drift"
          : "records";
  const [zoneView, _setZoneView] = useState<ZoneSubtab>(initialSubtab);
  const setZoneView = (v: ZoneSubtab) => {
    _setZoneView(v);
    // Keep the URL in sync so a refresh / back-navigation lands on
    // the same tab. ``subtab=records`` is the default state — drop
    // the param entirely rather than ship every URL with it.
    setZoneSearchParams(
      (prev: URLSearchParams) => {
        const next = new URLSearchParams(prev);
        if (v === "records") next.delete("subtab");
        else next.set("subtab", v);
        return next;
      },
      { replace: true },
    );
  };
  const { data: poolsForCount = [] } = useQuery({
    queryKey: ["dns-pools", group.id, zone.id],
    queryFn: () => dnsApi.listPools(group.id, zone.id),
    enabled: !isForward && !zone.tailscale_tenant_id,
  });

  const recordTypes = [...new Set(records.map((r) => r.record_type))].sort();
  const hasRecFilter = Object.values(recFilter).some(Boolean);
  const filtered = records.filter((r) => {
    if (
      recFilter.name &&
      !r.name.toLowerCase().includes(recFilter.name.toLowerCase())
    )
      return false;
    if (recFilter.type && r.record_type !== recFilter.type) return false;
    if (
      recFilter.value &&
      !r.value.toLowerCase().includes(recFilter.value.toLowerCase())
    )
      return false;
    return true;
  });

  // Reuse the shared module-level RECORD_TYPE_BADGE map so the
  // server-group records view and this zone-level view colour
  // record types identically.

  return (
    <div className="flex flex-col h-full">
      {/* Zone header — #996: wraps rather than clips. ``flex-wrap`` on the
          row plus ``min-w-0 flex-1`` here and ``shrink-0`` on the action
          block is the Wave D admin-page rule; without it a narrow window
          squeezes the title line and pushes the primary action off the
          right edge instead of moving the actions to a second line. */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b px-5 py-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            {swatchCls(zone.color) ? (
              <span
                className={cn(
                  "h-3 w-3 rounded-full flex-shrink-0",
                  swatchCls(zone.color)!,
                )}
                title={`color: ${zone.color}`}
              />
            ) : (
              <FileText className="h-4 w-4 text-muted-foreground" />
            )}
            <h2 className="font-semibold text-base font-mono">
              {zone.name.replace(/\.$/, "")}
            </h2>
            <ZoneScopePill
              scope={zone.name_scope}
              detail={zone.name_scope_detail}
            />
            <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs">
              {zone.zone_type}
            </span>
            <span className="text-xs text-muted-foreground">{zone.kind}</span>
            {zone.dnssec_enabled && (
              <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-emerald-500/15 text-emerald-600">
                DNSSEC
              </span>
            )}
            {zone.dynamic_update_enabled && (
              <span
                className="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-sky-500/15 text-sky-600 dark:text-sky-300"
                title="This zone accepts external RFC 2136 dynamic updates from an operator-configured ACL."
              >
                Dynamic updates
              </span>
            )}
            {zone.tailscale_tenant_id && (
              <span
                className="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-cyan-500/15 text-cyan-700 dark:text-cyan-300"
                title="Synthesised by the Tailscale integration. Records are derived from the device list on every sync; manual edits are blocked."
              >
                Tailscale (read-only)
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            TTL {zone.ttl}s · serial {zone.last_serial || "—"}
            {zone.primary_ns && ` · ${zone.primary_ns}`}
            {serverState && <ZoneSyncPill state={serverState} />}
          </p>
        </div>
        {/* #996 — three visible actions, the rest folded into two menus.
            This row had ELEVEN peer buttons and did not wrap, so at
            ~1,460px with the sidebar open the primary action was clipped
            to a sliver. ``shrink-0`` here plus ``min-w-0`` on the title
            block above is the other half: with menus the row fits, but a
            narrow window must wrap the actions under the title rather
            than clip them again (the Wave D admin-page rule). */}
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
          <AskAIButton
            context={[
              `DNS zone ${zone.name}`,
              `type: ${zone.zone_type}`,
              `kind: ${zone.kind}`,
              group?.name ? `server group: ${group.name}` : null,
              `TTL: ${zone.ttl}`,
              zone.last_serial ? `last serial: ${zone.last_serial}` : null,
              zone.primary_ns ? `primary NS: ${zone.primary_ns}` : null,
              `zone_id: ${zone.id}`,
            ]
              .filter(Boolean)
              .join(", ")}
            tooltip="Ask AI about this zone"
            prompt="Summarise this zone — record count, recent changes, and any drift between configured and authoritative state."
          />
          {!isForward && (
            <HeaderButton
              icon={RefreshCw}
              iconClassName={isFetching ? "animate-spin" : ""}
              onClick={() => {
                // Refresh everything the zone view can show — records,
                // pools, and per-server convergence — so the button
                // works on whichever tab the operator is on. Each
                // invalidation only re-fetches if the corresponding
                // query is currently mounted, so this stays cheap.
                qc.invalidateQueries({ queryKey: ["dns-records", zone.id] });
                qc.invalidateQueries({
                  queryKey: ["dns-pools", group.id, zone.id],
                });
                qc.invalidateQueries({ queryKey: ["dns-pools"] });
                qc.invalidateQueries({
                  queryKey: ["dns-zone-server-state", zone.id],
                });
              }}
              disabled={isFetching}
              title="Reload the data shown in this view (records, pools, sync state) from SpatiumDDI — does not re-query the DNS server"
            >
              Refresh
            </HeaderButton>
          )}
          <ServicesUsingButton
            kind="dns_zone"
            resourceId={zone.id}
            label={zone.name}
          />
          {/* Data ▾ — everything that moves records in or out. A forward
              zone stores no records at all, so this collapses to nothing
              and HeaderMenu declines to render a trigger. */}
          <HeaderMenu
            label="Data"
            icon={Database}
            title="Import, export, or reconcile this zone's records with its authoritative server"
            items={
              isForward
                ? []
                : [
                    {
                      key: "sync",
                      label: syncMut.isPending
                        ? "Syncing…"
                        : "Sync with server",
                      icon: RefreshCw,
                      iconClassName: syncMut.isPending ? "animate-spin" : "",
                      disabled: syncMut.isPending,
                      onSelect: () => syncMut.mutate(),
                      title:
                        "Two-way additive sync with the zone's authoritative server: AXFR missing records into SpatiumDDI, then push anything in our DB that isn't on the wire. Never deletes.",
                    },
                    {
                      key: "import",
                      label: "Import",
                      icon: Upload,
                      onSelect: () => setShowImport(true),
                    },
                    {
                      key: "export",
                      label: "Export",
                      icon: Download,
                      onSelect: handleExport,
                    },
                  ]
            }
          />
          {/* Zone ▾ — the once-per-zone lifecycle actions, Delete last. */}
          <HeaderMenu
            label="Zone"
            icon={Settings2}
            title="Edit, move, delegate or delete this zone"
            badge={showDelegateButton}
            badgeTitle="The parent zone is missing NS / glue records for this zone."
            items={[
              ...(showDelegateButton
                ? [
                    {
                      key: "delegate",
                      label: "Delegate",
                      icon: Workflow,
                      onSelect: () => setShowDelegate(true),
                      title:
                        "The parent zone is missing NS / glue records for this zone. Review and create them.",
                    },
                  ]
                : []),
              {
                key: "edit",
                label: "Edit Zone",
                icon: Pencil,
                onSelect: () => setShowEditZone(true),
                disabled: !!zone.tailscale_tenant_id,
                title: zone.tailscale_tenant_id
                  ? "This zone is synthesised by the Tailscale integration; edits would be overwritten on the next sync."
                  : undefined,
              },
              ...((zone.zone_type === "primary" ||
                zone.zone_type === "master") &&
              moduleEnabled("dns.dynamic_update_acl")
                ? [
                    {
                      key: "dynamic-updates",
                      label: "Dynamic Updates",
                      icon: KeyRound,
                      onSelect: () => setShowUpdateAcl(true),
                      title:
                        "Manage which external clients (by TSIG key or source IP/CIDR) may send RFC 2136 dynamic updates to this zone.",
                    },
                  ]
                : []),
              ...(!isForward
                ? [
                    {
                      key: "subzone",
                      label: "Sub-zone",
                      icon: Plus,
                      onSelect: () => setShowAddSubzone(true),
                      title: `Create a sub-zone under ${zone.name.replace(/\.$/, "")}`,
                    },
                  ]
                : []),
              {
                key: "move",
                label: "Move",
                icon: ArrowRightLeft,
                onSelect: () => setShowMoveZone(true),
                disabled: !!zone.tailscale_tenant_id,
                title: zone.tailscale_tenant_id
                  ? "This zone is synthesised by the Tailscale integration; it is bound to that tenant's group."
                  : "Move this zone to another server group",
              },
              {
                key: "delete",
                label: "Delete Zone",
                icon: Trash2,
                destructive: true,
                separatorBefore: true,
                onSelect: () => setConfirmDelete(true),
                disabled: !!zone.tailscale_tenant_id,
                title: zone.tailscale_tenant_id
                  ? "Delete the Tailscale tenant or unbind its DNS group to release this zone."
                  : undefined,
              },
            ]}
          />
          {!isForward && (
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowAddRecord(true)}
              disabled={!!zone.tailscale_tenant_id}
              title={
                zone.tailscale_tenant_id
                  ? "Records are managed by the Tailscale reconciler."
                  : `Add a record to ${zone.name.replace(/\.$/, "")} (${addRecordHint})`
              }
            >
              Add Record
            </HeaderButton>
          )}
        </div>
      </div>

      {/* Forward-zone detail — no records, just forwarders + policy. */}
      {isForward && (
        <div className="flex-1 overflow-auto px-5 py-4">
          <div className="max-w-2xl space-y-4">
            <div className="rounded border bg-card p-4 text-sm">
              <p className="text-xs text-muted-foreground">
                <strong className="text-foreground">
                  Conditional forwarder.
                </strong>{" "}
                Queries for{" "}
                <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
                  {zone.name.replace(/\.$/, "")}
                </code>{" "}
                are sent to the upstream resolvers below — no records are stored
                in SpatiumDDI for this zone.
              </p>
            </div>

            <div className="rounded border bg-card">
              <div className="border-b px-4 py-2 text-xs font-medium text-muted-foreground">
                Forwarders
              </div>
              <div className="divide-y">
                {zone.forwarders.length === 0 ? (
                  <p className="px-4 py-3 text-sm italic text-muted-foreground">
                    No forwarders configured. Click <em>Edit Zone</em> to add
                    upstream resolvers.
                  </p>
                ) : (
                  zone.forwarders.map((ip, i) => (
                    <div
                      key={`${ip}-${i}`}
                      className="px-4 py-2 font-mono text-sm"
                    >
                      {ip}
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="rounded border bg-card px-4 py-3 text-sm">
              <div className="text-xs font-medium text-muted-foreground">
                Policy
              </div>
              <div className="mt-1">
                {zone.forward_only ? (
                  <span className="font-mono">forward only</span>
                ) : (
                  <span className="font-mono">forward first</span>
                )}
                <p className="mt-1 text-xs text-muted-foreground">
                  {zone.forward_only
                    ? "Queries are sent only to the forwarders. If they all fail, BIND returns SERVFAIL — it never falls back to recursion."
                    : "Queries are sent to the forwarders first. If they all fail, BIND falls back to normal recursion via the root servers."}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Records / Pools tab strip — primary zones only. */}
      {!isForward && !zone.tailscale_tenant_id && (
        <div className="flex gap-1 border-b px-5">
          <button
            type="button"
            onClick={() => setZoneView("records")}
            className={
              "border-b-2 px-3 py-2 text-xs font-medium transition-colors " +
              (zoneView === "records"
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground")
            }
          >
            Records ({recordsTotal.toLocaleString()})
          </button>
          <button
            type="button"
            onClick={() => setZoneView("pools")}
            className={
              "border-b-2 px-3 py-2 text-xs font-medium transition-colors " +
              (zoneView === "pools"
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground")
            }
          >
            Pools ({poolsForCount.length})
          </button>
          {(!modulesReady || tlsCertsOn) && (
            <button
              type="button"
              onClick={() => setZoneView("certs")}
              className={
                "border-b-2 px-3 py-2 text-xs font-medium transition-colors " +
                (zoneView === "certs"
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground")
              }
            >
              Certificates ({tlsCerts?.items.length ?? 0})
            </button>
          )}
          {/* No count — the drift report AXFRs every server in the group, so
              it's only fetched once the operator opens the tab (#61). */}
          <button
            type="button"
            onClick={() => setZoneView("drift")}
            title="Compare what each server is actually serving against the database"
            className={
              "border-b-2 px-3 py-2 text-xs font-medium transition-colors " +
              (zoneView === "drift"
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground")
            }
          >
            Drift
          </button>
        </div>
      )}

      {/* Pools sub-view */}
      {!isForward && !zone.tailscale_tenant_id && zoneView === "pools" && (
        <PoolsView group={group} zone={zone} />
      )}

      {/* Drift sub-view (#61) — mounted only while the tab is active so the
          expensive per-server AXFR fan-out isn't fired on every zone open. */}
      {!isForward && !zone.tailscale_tenant_id && zoneView === "drift" && (
        <DriftView group={group} zone={zone} />
      )}

      {/* Certificates sub-view */}
      {!isForward && !zone.tailscale_tenant_id && zoneView === "certs" && (
        <div className="flex-1 overflow-auto p-5">
          {modulesReady && !tlsCertsOn ? (
            <p className="text-sm text-muted-foreground">
              TLS certificate monitoring is disabled.
            </p>
          ) : (
            <>
              <label className="mb-4 flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={!!zone.auto_tls_probe}
                  disabled={autoTlsProbeMutation.isPending}
                  onChange={(e) =>
                    autoTlsProbeMutation.mutate(e.target.checked)
                  }
                />
                <span>
                  Auto-discover &amp; probe every A/AAAA record in this zone
                </span>
              </label>
              <CertsCompactTable
                targets={tlsCerts?.items ?? []}
                isLoading={tlsCertsLoading}
                emptyLabel="No TLS certificates linked to records in this zone."
              />
            </>
          )}
        </div>
      )}

      {bulkDeleteNotice && (
        <div className="flex items-center justify-between border-b bg-amber-50 px-5 py-1.5 text-xs dark:bg-amber-900/10">
          <span>{bulkDeleteNotice}</span>
          <button
            onClick={() => setBulkDeleteNotice(null)}
            className="rounded-md border px-2 py-1 hover:bg-muted"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Bulk actions — shown when any manual records are selected. */}
      {!isForward && zoneView === "records" && selectedRecords.size > 0 && (
        <div className="flex items-center justify-between border-b bg-amber-50 px-5 py-1.5 text-xs dark:bg-amber-900/10">
          <span>
            {selectedRecords.size} record
            {selectedRecords.size !== 1 ? "s" : ""} selected
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSelectedRecords(new Set())}
              className="rounded-md border px-2 py-1 hover:bg-muted"
            >
              Clear
            </button>
            <button
              onClick={() => setConfirmBulkDelete(true)}
              className="flex items-center gap-1 rounded-md border border-destructive/40 px-2 py-1 text-destructive hover:bg-destructive/10"
            >
              <Trash2 className="h-3 w-3" /> Delete selected
            </button>
          </div>
        </div>
      )}

      {/* Records table */}
      {!isForward && zoneView === "records" && (
        <div className="flex-1 overflow-auto">
          <div className="flex items-center gap-2 px-5 py-2">
            <input
              className="w-72 rounded-md border bg-background px-2 py-1 text-xs"
              placeholder="Search name / value / type…"
              value={recordSearch}
              onChange={(e) => {
                setRecordSearch(e.target.value);
                setRecordPage(1);
              }}
            />
            <span className="text-xs text-muted-foreground">
              {recordsTotal.toLocaleString()}{" "}
              {recordsTotal === 1 ? "record" : "records"}
              {hasRecFilter && " · page filtered"}
              {isFetching && " · loading…"}
            </span>
            <div className="ml-auto">
              <Pager
                page={recordPage}
                total={recordsTotal}
                pageSize={recordPageSize}
                onChange={setRecordPage}
              />
            </div>
          </div>
          {isFetching && records.length === 0 && (
            <p className="px-5 py-4 text-sm text-muted-foreground">Loading…</p>
          )}
          {filtered.length === 0 && !isFetching && (
            <div className="flex flex-col items-center justify-center h-40">
              <p className="text-sm text-muted-foreground italic">
                {hasRecFilter
                  ? "No records match the current filter."
                  : 'No records yet. Click "Add Record" to create one.'}
              </p>
            </div>
          )}
          {(filtered.length > 0 || showRecFilters) && (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead className="sticky top-0 bg-card">
                  <tr className="border-b text-xs text-muted-foreground">
                    <th className="w-8 py-2 pl-3">
                      {(() => {
                        const manualIds = filtered
                          .filter((r) => !r.auto_generated && !r.pool_member_id)
                          .map((r) => r.id);
                        const allSel =
                          manualIds.length > 0 &&
                          manualIds.every((id) => selectedRecords.has(id));
                        return (
                          <input
                            type="checkbox"
                            disabled={manualIds.length === 0}
                            checked={allSel}
                            onChange={() => {
                              setSelectedRecords((prev) => {
                                const next = new Set(prev);
                                if (allSel)
                                  manualIds.forEach((id) => next.delete(id));
                                else manualIds.forEach((id) => next.add(id));
                                return next;
                              });
                            }}
                            title="Select all manual records (IPAM-managed records are skipped)"
                          />
                        );
                      })()}
                    </th>
                    {(["Name", "Type", "Value", "TTL", "Pri"] as const).map(
                      (col) => {
                        const filterKey =
                          col === "Name"
                            ? "name"
                            : col === "Type"
                              ? "type"
                              : col === "Value"
                                ? "value"
                                : null;
                        const hasFilter = filterKey
                          ? !!recFilter[filterKey as keyof typeof recFilter]
                          : false;
                        return (
                          <th
                            key={col}
                            className={
                              col === "Name"
                                ? "py-2 pl-5 text-left font-medium"
                                : "py-2 text-left font-medium"
                            }
                          >
                            <span className="inline-flex items-center gap-1">
                              {col}
                              {filterKey && (
                                <button
                                  onClick={() => setShowRecFilters((v) => !v)}
                                  title={`Filter by ${col}`}
                                  className={`rounded p-0.5 hover:bg-accent ${hasFilter ? "text-primary" : showRecFilters || hasRecFilter ? "text-primary/50" : "text-muted-foreground/40 hover:text-muted-foreground"}`}
                                >
                                  <Filter className="h-2.5 w-2.5" />
                                </button>
                              )}
                            </span>
                          </th>
                        );
                      },
                    )}
                    <th className="py-2 pr-3 text-right">
                      {hasRecFilter && (
                        <button
                          onClick={() =>
                            setRecFilter({ name: "", type: "", value: "" })
                          }
                          title="Clear filters"
                          className="rounded p-0.5 text-primary hover:text-destructive"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      )}
                    </th>
                  </tr>
                  {showRecFilters && (
                    <tr className="border-b bg-muted/10 text-xs">
                      <td />
                      <td className="px-2 py-1 pl-5">
                        <input
                          type="text"
                          value={recFilter.name}
                          onChange={(e) =>
                            setRecFilter((f) => ({
                              ...f,
                              name: e.target.value,
                            }))
                          }
                          placeholder="Filter…"
                          className="w-full rounded border border-border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                        />
                      </td>
                      <td className="px-2 py-1">
                        <select
                          value={recFilter.type}
                          onChange={(e) =>
                            setRecFilter((f) => ({
                              ...f,
                              type: e.target.value,
                            }))
                          }
                          className="w-full rounded border border-border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                        >
                          <option value="">All</option>
                          {recordTypes.map((t) => (
                            <option key={t} value={t}>
                              {t}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="px-2 py-1">
                        <input
                          type="text"
                          value={recFilter.value}
                          onChange={(e) =>
                            setRecFilter((f) => ({
                              ...f,
                              value: e.target.value,
                            }))
                          }
                          placeholder="Filter…"
                          className="w-full rounded border border-border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
                        />
                      </td>
                      <td />
                      <td />
                      <td />
                    </tr>
                  )}
                </thead>
                <tbody className={zebraBodyCls}>
                  {filtered.map((r) => (
                    <ContextMenu key={r.id}>
                      <ContextMenuTrigger asChild>
                        <tr
                          ref={registerHighlightRow(r.id)}
                          className={cn(
                            "border-b last:border-0 hover:bg-muted/40 group",
                            isHighlightedRow(r.id) && "spatium-row-highlight",
                          )}
                        >
                          <td className="w-8 py-1.5 pl-3">
                            {!r.auto_generated && !r.pool_member_id && (
                              <input
                                type="checkbox"
                                checked={selectedRecords.has(r.id)}
                                onChange={() =>
                                  setSelectedRecords((prev) => {
                                    const next = new Set(prev);
                                    if (next.has(r.id)) next.delete(r.id);
                                    else next.add(r.id);
                                    return next;
                                  })
                                }
                              />
                            )}
                          </td>
                          <td className="py-1.5 pl-5 font-mono text-xs font-medium">
                            {r.auto_generated || r.pool_member_id ? (
                              r.name
                            ) : (
                              <button
                                onClick={() => setEditRecord(r)}
                                className="hover:text-primary hover:underline"
                                title="Edit record"
                              >
                                {r.name}
                              </button>
                            )}
                          </td>
                          <td className="py-1.5">
                            <span className="inline-flex items-center gap-1.5">
                              <span
                                className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${RECORD_TYPE_BADGE[r.record_type] ?? RECORD_TYPE_BADGE_FALLBACK}`}
                              >
                                {r.record_type}
                              </span>
                              {(r.record_type === "A" ||
                                r.record_type === "AAAA") &&
                                certStateByRecord.has(r.id) && (
                                  <TLSStatePill
                                    state={certStateByRecord.get(r.id)!}
                                  />
                                )}
                            </span>
                          </td>
                          <td className="py-1.5 font-mono text-xs text-muted-foreground max-w-xs truncate">
                            {r.value}
                          </td>
                          <td className="py-1.5 text-xs text-muted-foreground">
                            {r.ttl ?? "—"}
                          </td>
                          <td className="py-1.5 text-xs text-muted-foreground">
                            {r.priority ?? "—"}
                          </td>
                          <td className="py-1.5 pr-3">
                            {r.pool_member_id ? (
                              <div className="flex items-center justify-end gap-1">
                                <span
                                  title="This record is rendered by a DNS pool's health-check pipeline. Manage it from the Pools tab — direct edits are blocked."
                                  className="flex items-center gap-1 rounded border border-violet-300/60 bg-violet-50 px-1.5 py-0.5 text-xs text-violet-700 dark:border-violet-700/40 dark:bg-violet-900/20 dark:text-violet-300"
                                >
                                  <Lock className="h-2.5 w-2.5" />
                                  Pool
                                </span>
                                <button
                                  className="h-6 w-6 flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                                  onClick={() => setZoneView("pools")}
                                  title="Manage in Pools tab"
                                >
                                  <Info className="h-3 w-3" />
                                </button>
                              </div>
                            ) : r.auto_generated ? (
                              <div className="flex items-center justify-end gap-1">
                                {r.tailscale_tenant_id ? (
                                  <span
                                    title="Synthesised by the Tailscale integration. Records are derived from the device list on every sync; manual edits are blocked."
                                    className="flex items-center gap-1 rounded border border-cyan-300/60 bg-cyan-50 px-1.5 py-0.5 text-xs text-cyan-700 dark:border-cyan-700/40 dark:bg-cyan-900/20 dark:text-cyan-300"
                                  >
                                    <Lock className="h-2.5 w-2.5" />
                                    Tailscale
                                  </span>
                                ) : (
                                  <span
                                    title="This record was created automatically by IPAM. Edit the IP address in IPAM to change it."
                                    className="flex items-center gap-1 rounded border border-amber-300/60 bg-amber-50 px-1.5 py-0.5 text-xs text-amber-700 dark:border-amber-700/40 dark:bg-amber-900/20 dark:text-amber-400"
                                  >
                                    <Lock className="h-2.5 w-2.5" />
                                    IPAM
                                  </span>
                                )}
                                <span
                                  title="Managed externally — changes made here will be overwritten on the next sync."
                                  className="flex h-5 w-5 cursor-help items-center justify-center rounded text-muted-foreground/60 hover:text-muted-foreground"
                                >
                                  <Info className="h-3 w-3" />
                                </span>
                              </div>
                            ) : (
                              <div className="flex items-center justify-end gap-1">
                                <AskAIButton
                                  context={[
                                    `DNS record ${r.name} ${r.record_type} ${r.value}`,
                                    r.ttl != null ? `TTL: ${r.ttl}` : null,
                                    r.priority != null
                                      ? `priority: ${r.priority}`
                                      : null,
                                    `zone: ${zone.name}`,
                                    `record_id: ${r.id}`,
                                  ]
                                    .filter(Boolean)
                                    .join(", ")}
                                  tooltip="Ask AI about this record"
                                  prompt="What does this record point to, and is anything else using the same target?"
                                  iconOnly
                                  className="h-6 px-1 py-0"
                                />
                                <button
                                  className="h-6 w-6 flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                                  onClick={() => setPropagationRecord(r)}
                                  title="Check propagation across public resolvers"
                                >
                                  <Radar className="h-3 w-3" />
                                </button>
                                <button
                                  className="h-6 w-6 flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                                  onClick={() => setEditRecord(r)}
                                  title="Edit record"
                                >
                                  <Pencil className="h-3 w-3" />
                                </button>
                                <button
                                  className="h-6 w-6 flex items-center justify-center rounded text-muted-foreground hover:text-destructive"
                                  onClick={() => setConfirmDeleteRecord(r)}
                                  title="Delete record"
                                >
                                  <Trash2 className="h-3 w-3" />
                                </button>
                              </div>
                            )}
                          </td>
                        </tr>
                      </ContextMenuTrigger>
                      <ContextMenuContent>
                        <ContextMenuLabel>
                          {r.name} {r.record_type}
                        </ContextMenuLabel>
                        <ContextMenuSeparator />
                        <ContextMenuItem
                          onSelect={() => copyToClipboard(r.name)}
                        >
                          Copy Name
                        </ContextMenuItem>
                        <ContextMenuItem
                          onSelect={() => copyToClipboard(r.value)}
                        >
                          Copy Value
                        </ContextMenuItem>
                        {r.auto_generated ? (
                          <>
                            <ContextMenuSeparator />
                            <ContextMenuItem disabled>
                              Managed by IPAM — read-only
                            </ContextMenuItem>
                          </>
                        ) : (
                          <>
                            <ContextMenuSeparator />
                            <ContextMenuItem onSelect={() => setEditRecord(r)}>
                              Edit…
                            </ContextMenuItem>
                            <ContextMenuItem
                              destructive
                              onSelect={() => setConfirmDeleteRecord(r)}
                            >
                              Delete…
                            </ContextMenuItem>
                          </>
                        )}
                      </ContextMenuContent>
                    </ContextMenu>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="px-5 py-2">
            <Pager
              page={recordPage}
              total={recordsTotal}
              pageSize={recordPageSize}
              onChange={setRecordPage}
            />
          </div>
        </div>
      )}

      {showAddRecord && (
        <RecordModal
          groupId={group.id}
          zoneId={zone.id}
          zoneName={zone.name}
          onClose={() => setShowAddRecord(false)}
        />
      )}
      {editRecord && (
        <RecordModal
          groupId={group.id}
          zoneId={zone.id}
          zoneName={zone.name}
          record={editRecord}
          onClose={() => setEditRecord(null)}
        />
      )}
      {propagationRecord && (
        <PropagationCheckModal
          fqdn={propagationRecord.fqdn}
          recordType={propagationRecord.record_type}
          onClose={() => setPropagationRecord(null)}
        />
      )}
      {confirmDeleteRecord && (
        <ConfirmSingleModal
          title="Delete Record"
          description={
            <>
              Delete{" "}
              <span className="font-mono">
                {confirmDeleteRecord.name} {confirmDeleteRecord.record_type}
              </span>
              ? This will remove the record from the zone and fire an RFC 2136
              update.
            </>
          }
          isPending={deleteRecord.isPending}
          onConfirm={() =>
            deleteRecord.mutate(confirmDeleteRecord, {
              onSuccess: () => setConfirmDeleteRecord(null),
            })
          }
          onClose={() => setConfirmDeleteRecord(null)}
        />
      )}
      {confirmBulkDelete && (
        <ConfirmSingleModal
          title={
            bulkPermanent
              ? `Permanently delete ${selectedRecords.size} records`
              : `Move ${selectedRecords.size} records to the trash`
          }
          description={
            <div className="space-y-2">
              <p>
                {bulkPermanent ? "Permanently delete the " : "Move the "}
                <span className="font-medium">{selectedRecords.size}</span>{" "}
                selected records
                {bulkPermanent
                  ? "? This cannot be undone."
                  : selectedRecords.size > BULK_DELETE_CHUNK
                    ? ` to the trash? They are split into ${Math.ceil(selectedRecords.size / BULK_DELETE_CHUNK)} batches in Admin → Trash, each restored separately.`
                    : " to the trash? They can be restored together from Admin → Trash."}{" "}
                IPAM-managed records are excluded automatically.
              </p>
              {isSuperadmin && (
                <label className="flex items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={bulkPermanent}
                    onChange={(e) => setBulkPermanent(e.target.checked)}
                  />
                  Delete permanently (skip the trash)
                </label>
              )}
            </div>
          }
          confirmLabel={bulkPermanent ? "Delete permanently" : "Move to trash"}
          isPending={bulkDeleteRecords.isPending}
          onConfirm={() =>
            bulkDeleteRecords.mutate(Array.from(selectedRecords))
          }
          onClose={() => {
            setConfirmBulkDelete(false);
            setBulkPermanent(false);
          }}
        />
      )}
      {showMoveZone && (
        <MoveZoneModal
          zone={zone}
          onClose={() => setShowMoveZone(false)}
          onMoved={(targetGroupId) => {
            setShowMoveZone(false);
            // Both groups' zone lists changed, and the zone's own URL is
            // keyed on the group it is in — so navigate to it under the new
            // group rather than leaving the page on a 404.
            qc.invalidateQueries({ queryKey: ["dns-zones"] });
            qc.invalidateQueries({ queryKey: ["dns-groups"] });
            navigate(`/dns?group=${targetGroupId}&zone=${zone.id}`, {
              replace: true,
            });
          }}
        />
      )}
      {showEditZone && (
        <ZoneModal
          groupId={group.id}
          views={views}
          zone={zone}
          onClose={() => setShowEditZone(false)}
        />
      )}
      {showAddSubzone && (
        <ZoneModal
          groupId={group.id}
          views={views}
          // Pre-fill with the parent suffix so the operator just types
          // the leading label at the cursor: "sub" + ".example.com".
          initialName={"." + zone.name.replace(/\.$/, "")}
          onClose={() => setShowAddSubzone(false)}
        />
      )}
      {showUpdateAcl && (
        <DynamicUpdateAclModal
          groupId={group.id}
          zoneId={zone.id}
          zoneName={zone.name}
          onClose={() => setShowUpdateAcl(false)}
        />
      )}
      {showDelegate && (
        <DelegationModal
          groupId={group.id}
          zoneId={zone.id}
          zoneName={zone.name}
          onClose={() => setShowDelegate(false)}
        />
      )}
      {showImport && (
        <ImportZoneModal
          groupId={group.id}
          zone={zone}
          onClose={() => setShowImport(false)}
        />
      )}
      {confirmDelete && (
        <ConfirmDestroyModal
          title="Delete DNS Zone"
          description={`Permanently delete zone "${zone.name}" and all its records from SpatiumDDI?`}
          checkLabel={`I understand all records in "${zone.name}" will be permanently deleted.`}
          onConfirm={() => deleteZone.mutate()}
          onClose={() => {
            setConfirmDelete(false);
            setDeleteNotice(null);
            deleteZone.reset();
          }}
          isPending={deleteZone.isPending}
          notice={deleteNotice}
        />
      )}
      {syncResult && (
        <SyncResultModal
          zoneName={zone.name}
          result={syncResult}
          onClose={() => setSyncResult(null)}
        />
      )}
    </div>
  );
}

// ── Sync-with-server result modal ─────────────────────────────────────────────
//
// Surfaces the per-run summary from POST /dns/groups/{id}/zones/{id}/sync-with-server
// — counts for both directions (pulled from server → DB, pushed from DB → server)
// plus per-record lists and any push errors that came back.

type SyncRecord = {
  name: string;
  fqdn: string;
  record_type: string;
  value: string;
  ttl: number | null;
};

type SyncResultPayload =
  | {
      ok: true;
      // pull direction
      server_records: number;
      existing_in_db: number;
      imported: number;
      skipped_unsupported: number;
      imported_records: SyncRecord[];
      // push direction
      push_candidates: number;
      pushed: number;
      pushed_records: SyncRecord[];
      push_errors: string[];
    }
  | { ok: false; error: string };

function SyncResultModal({
  zoneName,
  result,
  onClose,
}: {
  zoneName: string;
  result: SyncResultPayload;
  onClose: () => void;
}) {
  if (!result.ok) {
    return (
      <Modal title="Sync with server — failed" onClose={onClose}>
        <div className="space-y-3">
          <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-xs text-destructive">
            {result.error}
          </div>
          <p className="text-xs text-muted-foreground">
            Common causes: zone transfers not allowed from this host (DNS
            Manager → zone → Properties → Zone Transfers), dynamic updates not
            permitted, primary server unreachable, or the driver does not
            support AXFR pull (only Windows DNS does today).
          </p>
          <div className="flex justify-end pt-1">
            <button
              onClick={onClose}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
            >
              Close
            </button>
          </div>
        </div>
      </Modal>
    );
  }

  const {
    server_records,
    existing_in_db,
    imported,
    skipped_unsupported,
    imported_records,
    pushed,
    pushed_records,
    push_errors,
  } = result;
  const somethingHappened =
    imported > 0 || pushed > 0 || push_errors.length > 0;
  const wide = imported_records.length > 0 || pushed_records.length > 0;

  return (
    <Modal
      title={`Sync with server — ${zoneName.replace(/\.$/, "")}`}
      onClose={onClose}
      wide={wide}
    >
      <div className="space-y-4">
        {/* Pull direction */}
        <div>
          <div className="mb-2 text-xs font-medium text-muted-foreground">
            ⬇ Server → SpatiumDDI (pull)
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label="On server" value={server_records} />
            <Stat label="Already in DB" value={existing_in_db} />
            <Stat
              label="Imported"
              value={imported}
              highlight={imported > 0 ? "good" : undefined}
            />
            <Stat
              label="Skipped"
              value={skipped_unsupported}
              hint="unsupported record type"
            />
          </div>
          {imported > 0 && (
            <RecordTable
              records={imported_records}
              heading="New records added to SpatiumDDI"
            />
          )}
        </div>

        {/* Push direction */}
        <div>
          <div className="mb-2 text-xs font-medium text-muted-foreground">
            ⬆ SpatiumDDI → Server (push)
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            <Stat
              label="Pushed"
              value={pushed}
              highlight={
                pushed > 0 && push_errors.length === 0 ? "good" : undefined
              }
            />
            <Stat
              label="Errors"
              value={push_errors.length}
              highlight={push_errors.length > 0 ? "bad" : undefined}
            />
            <Stat label="Skipped" value={0} hint="DB already matches server" />
          </div>
          {pushed > 0 && (
            <RecordTable
              records={pushed_records}
              heading="Records applied to the server"
            />
          )}
          {push_errors.length > 0 && (
            <div className="mt-2 rounded-md border border-destructive/30 bg-destructive/10 p-3">
              <div className="mb-1 text-xs font-medium text-destructive">
                Push errors ({push_errors.length})
              </div>
              <ul className="list-disc space-y-0.5 pl-4 text-xs text-destructive">
                {push_errors.map((e, i) => (
                  <li key={i} className="font-mono break-all">
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {!somethingHappened && (
          <p className="text-xs text-muted-foreground">
            Already in sync — the DB and the authoritative server hold the same
            records.
          </p>
        )}

        <div className="flex justify-end pt-1">
          <button
            onClick={onClose}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
          >
            Done
          </button>
        </div>
      </div>
    </Modal>
  );
}

function RecordTable({
  records,
  heading,
}: {
  records: SyncRecord[];
  heading: string;
}) {
  return (
    <div className="mt-2 rounded-md border">
      <div className="border-b px-3 py-2 text-xs font-medium text-muted-foreground">
        {heading}
      </div>
      <div className="max-h-60 overflow-auto">
        <table className="w-full text-xs">
          <thead className="bg-muted/40">
            <tr className="text-left">
              <th className="px-3 py-1.5 font-medium">Name</th>
              <th className="px-3 py-1.5 font-medium">Type</th>
              <th className="px-3 py-1.5 font-medium">Value</th>
              <th className="px-3 py-1.5 font-medium">TTL</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {records.map((r, i) => (
              <tr key={i} className="border-t">
                <td className="px-3 py-1 font-mono">{r.name}</td>
                <td className="px-3 py-1">
                  <span className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium">
                    {r.record_type}
                  </span>
                </td>
                <td className="px-3 py-1 font-mono break-all">{r.value}</td>
                <td className="px-3 py-1 text-muted-foreground">
                  {r.ttl ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  highlight,
  hint,
}: {
  label: string;
  value: number;
  highlight?: "good" | "bad";
  hint?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-md border p-3",
        highlight === "good" &&
          "border-emerald-500/30 bg-emerald-500/5 dark:bg-emerald-500/10",
        highlight === "bad" &&
          "border-destructive/30 bg-destructive/5 dark:bg-destructive/10",
      )}
    >
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-xl font-semibold tabular-nums">{value}</div>
      {hint && (
        <div className="mt-0.5 text-[10px] text-muted-foreground/70">
          {hint}
        </div>
      )}
    </div>
  );
}

// ── Servers Tab ────────────────────────────────────────────────────────────────

function ServersTab({ group }: { group: DNSServerGroup }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [showAdd, setShowAdd] = useState(false);
  const [editServer, setEditServer] = useState<DNSServer | null>(null);
  const [detailServer, setDetailServer] = useState<DNSServer | null>(null);
  const [confirmDeleteServer, setConfirmDeleteServer] =
    useState<DNSServer | null>(null);
  // Issue #182 — per-row Pause/Resume affordance. The Pause click
  // opens a small modal that captures an optional reason; Resume
  // fires immediately. ``pauseInFlightFor`` tracks which row is
  // mid-mutation so we don't disable every Pause/Resume button at
  // once when one of them is busy.
  const [pausePrompt, setPausePrompt] = useState<DNSServer | null>(null);
  const pauseInFlightFor = useRef<string | null>(null);
  const pauseMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      dnsApi.pauseServer(group.id, id, reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-servers"] }),
    onSettled: () => {
      pauseInFlightFor.current = null;
    },
  });
  const resumeMut = useMutation({
    mutationFn: (id: string) => dnsApi.resumeServer(group.id, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-servers"] }),
    onSettled: () => {
      pauseInFlightFor.current = null;
    },
  });

  const { data: servers = [], isFetching } = useQuery({
    queryKey: ["dns-servers", group.id],
    queryFn: () => dnsApi.listServers(group.id),
    // Refetch frequently so the health dot stays fresh as the Celery
    // Beat-scheduled dns-health-sweep task updates server rows.
    refetchInterval: 30_000,
  });
  const { data: zones = [] } = useQuery({
    queryKey: ["dns-zones", group.id],
    queryFn: () => dnsApi.listZones(group.id),
  });

  const healthCounts = servers.reduce(
    (acc, s) => {
      acc[s.status] = (acc[s.status] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  const del = useMutation({
    mutationFn: (s: DNSServer) => dnsApi.deleteServer(group.id, s.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-servers", group.id] });
      setConfirmDeleteServer(null);
    },
  });

  const statusCls: Record<string, string> = {
    active: "bg-emerald-500/15 text-emerald-600",
    unreachable: "bg-red-500/15 text-red-600",
    syncing: "bg-blue-500/15 text-blue-600",
    error: "bg-red-500/15 text-red-600",
    disabled: "bg-muted text-muted-foreground",
  };
  const dotCls: Record<string, string> = {
    active: "bg-emerald-500",
    unreachable: "bg-red-500",
    syncing: "bg-blue-500",
    error: "bg-red-500",
    disabled: "bg-muted-foreground/40",
  };

  return (
    <div>
      {servers.length > 0 && (
        <div className="mb-4 rounded-md border bg-card p-3">
          <div className="flex items-center gap-4 flex-wrap text-xs">
            <span className="font-medium text-muted-foreground uppercase tracking-wider">
              Health
            </span>
            {(["active", "unreachable", "syncing", "error"] as const).map(
              (s) =>
                healthCounts[s] ? (
                  <span key={s} className="flex items-center gap-1.5">
                    <span
                      className={`inline-block h-2 w-2 rounded-full ${dotCls[s]}`}
                    />
                    {healthCounts[s]} {s}
                  </span>
                ) : null,
            )}
            <span className="ml-auto text-muted-foreground">
              Zone serials:{" "}
              {zones.length === 0
                ? "no zones"
                : `${zones.length} zone${zones.length === 1 ? "" : "s"} · all servers assumed consistent (per-server serials arrive in Wave 3)`}
            </span>
          </div>
        </div>
      )}
      <div className="flex items-center justify-between mb-4">
        <div>
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
            DNS Servers
          </span>
          <p className="text-xs text-muted-foreground mt-0.5">
            Servers can also be auto-registered by BIND9 agent containers using
            the <code className="font-mono">DNS_AGENT_KEY</code> env var.
          </p>
        </div>
        <button
          className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
          onClick={() => setShowAdd(true)}
        >
          <Plus className="h-3 w-3" /> Add Server
        </button>
      </div>
      {isFetching && servers.length === 0 && (
        <p className="text-sm text-muted-foreground">Loading…</p>
      )}
      {servers.length === 0 && !isFetching && (
        <p className="text-sm text-muted-foreground italic">
          No servers. Add one manually or start a DNS agent container.
        </p>
      )}
      <div className="space-y-2">
        {servers.map((s) => (
          <div
            key={s.id}
            className="flex items-center justify-between rounded-md border bg-card px-3 py-2.5 group cursor-pointer hover:bg-accent/40"
            onClick={() => setDetailServer(s)}
            title="Click to view details"
          >
            <div className="flex items-center gap-3">
              <Cpu className="h-4 w-4 text-muted-foreground flex-shrink-0" />
              <div>
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-block h-2 w-2 rounded-full ${dotCls[s.status] ?? "bg-muted"}`}
                    title={`status: ${s.status}${s.last_health_check_at ? ` · last check: ${new Date(s.last_health_check_at).toLocaleString()}` : " · never checked"}`}
                  />
                  <span className="text-sm font-medium">{s.name}</span>
                  <span
                    className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${statusCls[s.status] ?? "bg-muted text-muted-foreground"}`}
                  >
                    {s.status}
                  </span>
                  <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs">
                    {s.driver}
                  </span>
                  {s.maintenance_mode && (
                    <span
                      className="inline-flex items-center rounded bg-amber-500/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-400"
                      title={
                        s.maintenance_reason
                          ? `Paused: ${s.maintenance_reason}`
                          : "In operator-set maintenance mode"
                      }
                    >
                      Maintenance
                    </span>
                  )}
                  <ConfigApplyChip server={s} />
                  <SpoolChip server={s} />
                  <DaemonStateChip server={s} />
                </div>
                <p className="text-xs text-muted-foreground">
                  {s.host}:{s.port}
                  {s.last_seen_ip && (
                    <span
                      className="ml-1.5 font-mono"
                      title="Source IP of the most recent agent heartbeat"
                    >
                      ({s.last_seen_ip})
                    </span>
                  )}
                  {s.roles.length > 0 && ` · ${s.roles.join(", ")}`}
                  {s.last_sync_at &&
                    ` · synced ${new Date(s.last_sync_at).toLocaleDateString()}`}
                  {s.last_health_check_at &&
                    ` · health ${new Date(s.last_health_check_at).toLocaleTimeString()}`}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-1">
              {isCloudDriver(s.driver) && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    navigate("/admin/dns-import", {
                      state: { cloudServerId: s.id },
                    });
                  }}
                  className="inline-flex items-center gap-1 rounded border border-sky-600/40 bg-sky-500/10 px-1.5 py-1 text-[11px] font-medium text-sky-700 hover:bg-sky-500/20 dark:text-sky-400"
                  title="Sync existing hosted zones in from the provider"
                >
                  <Cloud className="h-3 w-3" />
                  Sync
                </button>
              )}
              {s.maintenance_mode ? (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    pauseInFlightFor.current = s.id;
                    resumeMut.mutate(s.id);
                  }}
                  disabled={
                    (pauseMut.isPending || resumeMut.isPending) &&
                    pauseInFlightFor.current === s.id
                  }
                  className="inline-flex items-center gap-1 rounded border border-emerald-600/40 bg-emerald-500/10 px-1.5 py-1 text-[11px] font-medium text-emerald-700 hover:bg-emerald-500/20 disabled:opacity-50 dark:text-emerald-400"
                  title="Resume — exit maintenance mode"
                >
                  <Play className="h-3 w-3" />
                  {(pauseMut.isPending || resumeMut.isPending) &&
                  pauseInFlightFor.current === s.id
                    ? "…"
                    : "Resume"}
                </button>
              ) : (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    setPausePrompt(s);
                  }}
                  className="inline-flex items-center gap-1 rounded border border-amber-600/40 bg-amber-500/10 px-1.5 py-1 text-[11px] font-medium text-amber-700 hover:bg-amber-500/20 dark:text-amber-400"
                  title="Pause — enter maintenance mode"
                >
                  <Pause className="h-3 w-3" />
                  Pause
                </button>
              )}
              <button
                className="h-7 w-7 flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                onClick={(e) => {
                  e.stopPropagation();
                  setEditServer(s);
                }}
              >
                <Pencil className="h-3.5 w-3.5" />
              </button>
              <button
                className="h-7 w-7 flex items-center justify-center rounded text-muted-foreground hover:text-destructive"
                onClick={(e) => {
                  e.stopPropagation();
                  setConfirmDeleteServer(s);
                }}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
      {showAdd && (
        <ServerModal groupId={group.id} onClose={() => setShowAdd(false)} />
      )}
      {editServer && (
        <ServerModal
          groupId={group.id}
          server={editServer}
          onClose={() => setEditServer(null)}
        />
      )}
      {detailServer && (
        <ServerDetailModal
          server={detailServer}
          onClose={() => setDetailServer(null)}
        />
      )}
      {pausePrompt && (
        <PauseServerModal
          serverName={pausePrompt.name}
          serverKind="DNS"
          isPending={pauseMut.isPending}
          onConfirm={(reason) => {
            pauseInFlightFor.current = pausePrompt.id;
            pauseMut.mutate(
              { id: pausePrompt.id, reason },
              { onSuccess: () => setPausePrompt(null) },
            );
          }}
          onCancel={() => setPausePrompt(null)}
        />
      )}
      {confirmDeleteServer && (
        <ConfirmDestroyModal
          title="Delete DNS Server"
          description={`Remove "${confirmDeleteServer.name}" (${confirmDeleteServer.host}:${confirmDeleteServer.port}) from this group?`}
          checkLabel="I understand this server will be removed from SpatiumDDI management."
          onConfirm={() => del.mutate(confirmDeleteServer)}
          onClose={() => setConfirmDeleteServer(null)}
          isPending={del.isPending}
        />
      )}
    </div>
  );
}

function SyncStat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number | string;
  accent?: "good" | "bad";
}) {
  const color =
    accent === "good"
      ? "text-emerald-600 dark:text-emerald-400"
      : accent === "bad"
        ? "text-destructive"
        : "text-foreground";
  return (
    <div className="rounded-md border bg-card px-2.5 py-1.5">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className={`text-lg font-semibold tabular-nums ${color}`}>
        {value}
      </div>
    </div>
  );
}

// ── Views Tab ─────────────────────────────────────────────────────────────────

/**
 * Views tab (#876) — full CRUD.
 *
 * View storage, per-view zone rendering and per-view RPZ all shipped with
 * #24, but the only way to define a view was the REST API, which meant
 * split-horizon DNS and per-subnet blocklist scoping were both
 * unreachable from the product. This tab is that missing surface.
 *
 * `match_clients` is the whole point: it is the address-match-list BIND
 * tests a query's source address against, so "the adult lists on the
 * guest VLAN only" is a view whose match_clients is the guest CIDRs plus
 * a blocklist scoped to that view.
 */
function ViewsTab({ group }: { group: DNSServerGroup }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<DNSView | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<DNSView | null>(null);
  const [error, setError] = useState("");

  const { data: views = [] } = useQuery({
    queryKey: ["dns-views", group.id],
    queryFn: () => dnsApi.listViews(group.id),
  });
  const { data: servers = [] } = useQuery({
    queryKey: ["dns-servers", group.id],
    queryFn: () => dnsApi.listServers(group.id),
  });
  const { data: blocklists = [] } = useQuery({
    queryKey: ["dns-blocklists"],
    queryFn: () => dnsBlocklistApi.list(),
  });

  // Per-view RPZ is rendered by the BIND9 driver only — render_rpz_zone is
  // a no-op on Windows / PowerDNS / cloud, and Technitium blocks natively
  // with no per-view concept. Saying so here beats an operator scoping a
  // list to a view and waiting for filtering that will never arrive.
  const nonBindDrivers = Array.from(
    new Set(servers.filter((s) => s.driver !== "bind9").map((s) => s.driver)),
  );
  const hasBind = servers.some((s) => s.driver === "bind9");

  const delMut = useMutation({
    mutationFn: (id: string) => dnsApi.deleteView(group.id, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-views", group.id] });
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      setConfirmDelete(null);
    },
    // Close the dialog on failure too — the error renders on the page
    // behind it, so leaving the modal up hides the only explanation and
    // reads as "Delete does nothing".
    onError: (e: ApiError) => {
      setError(formatApiError(e, "Delete failed"));
      setConfirmDelete(null);
    },
  });

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          Views
        </span>
        <button
          className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
          onClick={() => {
            setError("");
            setCreating(true);
          }}
        >
          <Plus className="h-3 w-3" /> New View
        </button>
      </div>

      {servers.length > 0 && !hasBind && (
        <div className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/5 p-2 text-xs text-amber-700 dark:text-amber-400">
          <strong>This group runs no BIND9 server.</strong> Views and
          view-scoped blocking lists are rendered by the BIND9 driver only — on{" "}
          {nonBindDrivers.join(" / ")} they are stored but never applied.
        </div>
      )}

      {views.length === 0 ? (
        <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
          <p className="font-medium text-foreground">No views defined.</p>
          <p className="mt-1">
            A view serves different answers to different clients, matched on the
            query's source address. Use one to run split-horizon DNS, or to
            apply a blocking list to just one VLAN.
          </p>
          <p className="mt-1">
            Note that once any view exists, <em>every</em> zone in this group is
            served from inside a view — zones with no view of their own are
            rendered into all of them.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {views.map((v) => {
            const scoped = blocklists.filter((b) =>
              b.applied_view_ids?.includes(v.id),
            );
            return (
              <div
                key={v.id}
                className="rounded-md border bg-card px-3 py-2.5 group"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <span className="text-sm font-medium font-mono">
                      {v.name}
                    </span>
                    <span className="ml-2 text-xs text-muted-foreground">
                      order {v.order}
                    </span>
                    {!v.recursion && (
                      <span className="ml-2 rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium">
                        no recursion
                      </span>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-1 opacity-0 group-hover:opacity-100">
                    <button
                      className="h-7 w-7 flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                      title="Edit view"
                      onClick={() => {
                        setError("");
                        setEditing(v);
                      }}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      className="h-7 w-7 flex items-center justify-center rounded text-muted-foreground hover:text-destructive"
                      title="Delete view"
                      onClick={() => {
                        setError("");
                        setConfirmDelete(v);
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
                {v.description && (
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {v.description}
                  </p>
                )}
                <div className="mt-1.5 flex flex-wrap items-center gap-1">
                  <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70">
                    clients
                  </span>
                  {v.match_clients.map((c) => (
                    <span
                      key={c}
                      className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-xs font-mono"
                    >
                      {c}
                    </span>
                  ))}
                </div>
                {scoped.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap items-center gap-1">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground/70">
                      blocking
                    </span>
                    {scoped.map((b) => (
                      <span
                        key={b.id}
                        className="inline-flex items-center rounded bg-rose-500/10 px-1.5 py-0.5 text-xs text-rose-600 dark:text-rose-400"
                        title={`${b.entry_count.toLocaleString()} entries`}
                      >
                        {b.name}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {error && <p className="mt-2 text-xs text-destructive">{error}</p>}

      {(creating || editing) && (
        <ViewModal
          groupId={group.id}
          view={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
        />
      )}

      {confirmDelete && (
        <ConfirmModal
          open
          title={`Delete view "${confirmDelete.name}"?`}
          confirmLabel="Delete view"
          tone="destructive"
          loading={delMut.isPending}
          onClose={() => setConfirmDelete(null)}
          onConfirm={() => delMut.mutate(confirmDelete.id)}
          message={
            <div className="space-y-2 text-sm">
              <p>
                Zones assigned to this view are not deleted — they fall back to
                being served from every remaining view.
              </p>
              <p>
                Any blocking list scoped only to this view stops being applied
                anywhere.
              </p>
              {views.length === 1 && (
                <p className="text-amber-700 dark:text-amber-400">
                  This is the last view in the group. Removing it returns the
                  group to serving one flat set of zones to every client.
                </p>
              )}
            </div>
          }
        />
      )}
    </div>
  );
}

/** Create / edit a DNS view.
 *
 * `match_clients` is entered as one element per line, mirroring the ACL
 * editor next door — an operator who has typed one has typed both. The
 * "Add subnets…" picker exists because what people actually mean by
 * "scope this to the guest VLAN" is the guest VLAN's CIDR, and retyping a
 * prefix they already modelled in IPAM is how typos get in.
 *
 * Validation is server-side (`app/services/dns/named_conf_validation.py`): these
 * strings are interpolated verbatim into named.conf, so the client checks
 * nothing it could be wrong about and simply renders the 422.
 */
function ViewModal({
  groupId,
  view,
  onClose,
}: {
  groupId: string;
  view: DNSView | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(view?.name ?? "");
  const [description, setDescription] = useState(view?.description ?? "");
  const [order, setOrder] = useState(String(view?.order ?? 0));
  const [recursion, setRecursion] = useState(view?.recursion ?? true);
  const [matchClients, setMatchClients] = useState(
    (view?.match_clients ?? ["any"]).join("\n"),
  );
  const [matchDestinations, setMatchDestinations] = useState(
    (view?.match_destinations ?? []).join("\n"),
  );
  const [showSubnets, setShowSubnets] = useState(false);
  const [error, setError] = useState("");

  const lines = (s: string) =>
    s
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

  const saveMut = useMutation({
    mutationFn: (payload: Partial<DNSView>) =>
      view
        ? dnsApi.updateView(groupId, view.id, payload)
        : dnsApi.createView(groupId, payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-views", groupId] });
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      onClose();
    },
    onError: (e: ApiError) => setError(formatApiError(e, "Save failed")),
  });

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const clients = lines(matchClients);
    if (clients.length === 0) {
      // BIND treats an empty match-clients as "match nothing", so a view
      // saved this way silently answers no one. Refuse rather than let an
      // operator ship a view that looks configured and serves nobody.
      setError(
        "Add at least one client match — an address, a CIDR prefix, an ACL name, or 'any'.",
      );
      return;
    }
    saveMut.mutate({
      name: name.trim(),
      description: description.trim(),
      order: Number(order) || 0,
      recursion,
      match_clients: clients,
      match_destinations: lines(matchDestinations),
    });
  }

  return (
    <Modal
      title={view ? `Edit view "${view.name}"` : "New view"}
      onClose={onClose}
      wide
    >
      <form onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="guest"
              required
            />
          </Field>
          <Field label="Order">
            <input
              className={inputCls}
              type="number"
              value={order}
              onChange={(e) => setOrder(e.target.value)}
            />
          </Field>
          <Field label="Recursion">
            <label className="flex h-[30px] items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={recursion}
                onChange={(e) => setRecursion(e.target.checked)}
              />
              Answer recursive queries
            </label>
          </Field>
        </div>
        <p className="-mt-1 text-[11px] text-muted-foreground">
          Views are evaluated low order first, and a client is served by the
          first view it matches — so put the most specific view above the
          catch-all.
        </p>

        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Optional"
          />
        </Field>

        <div>
          <div className="mb-1 flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">
              Match clients (one per line; prefix ! to negate)
            </span>
            <button
              type="button"
              className="flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent"
              onClick={() => setShowSubnets(true)}
            >
              <Plus className="h-3 w-3" /> Add subnets…
            </button>
          </div>
          <textarea
            value={matchClients}
            onChange={(e) => setMatchClients(e.target.value)}
            className="w-full rounded border bg-background px-2 py-1 font-mono text-xs resize-none h-24 focus:outline-none focus:ring-1 focus:ring-ring"
            placeholder={"10.20.0.0/16\n192.168.50.0/24\nany"}
          />
          <p className="mt-1 text-[11px] text-muted-foreground">
            An address, a CIDR prefix, a named ACL from the ACLs tab, or one of{" "}
            <span className="font-mono">any</span> /{" "}
            <span className="font-mono">none</span> /{" "}
            <span className="font-mono">localhost</span> /{" "}
            <span className="font-mono">localnets</span>.
          </p>
        </div>

        <details className="rounded border bg-muted/20 px-2 py-1.5">
          <summary className="cursor-pointer text-xs text-muted-foreground">
            Match destinations (advanced)
          </summary>
          <div className="mt-2">
            <textarea
              value={matchDestinations}
              onChange={(e) => setMatchDestinations(e.target.value)}
              className="w-full rounded border bg-background px-2 py-1 font-mono text-xs resize-none h-16 focus:outline-none focus:ring-1 focus:ring-ring"
              placeholder="Leave empty unless the server listens on several addresses"
            />
            <p className="mt-1 text-[11px] text-muted-foreground">
              Matches the address the query arrived <em>on</em>, not the client
              it came from. Only useful on a multi-homed server.
            </p>
          </div>
        </details>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex justify-end gap-2 border-t pt-3">
          <button
            type="button"
            className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saveMut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : view ? "Save changes" : "Create"}
          </button>
        </div>
      </form>

      {showSubnets && (
        <SubnetPickerModal
          onClose={() => setShowSubnets(false)}
          onPick={(cidrs) => {
            setMatchClients((prev) => {
              const existing = lines(prev);
              const merged = [...existing];
              for (const c of cidrs) if (!merged.includes(c)) merged.push(c);
              return merged.join("\n");
            });
            setShowSubnets(false);
          }}
        />
      )}
    </Modal>
  );
}

/** Pick IPAM subnets and return their CIDRs.
 *
 * Views are the mechanism, but subnets are what operators think in — this
 * turns "the guest VLAN" into the prefix without a copy-paste round trip
 * through the IPAM page.
 */
function SubnetPickerModal({
  onClose,
  onPick,
}: {
  onClose: () => void;
  onPick: (cidrs: string[]) => void;
}) {
  const [filter, setFilter] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const { data: subnets = [], isLoading } = useQuery({
    queryKey: ["ipam-subnets", "view-picker"],
    queryFn: () => ipamApi.listSubnets(),
  });

  const q = filter.trim().toLowerCase();
  const shown = q
    ? subnets.filter(
        (s) =>
          s.network.toLowerCase().includes(q) ||
          (s.name ?? "").toLowerCase().includes(q),
      )
    : subnets;

  return (
    <Modal title="Add subnets" onClose={onClose}>
      <div className="space-y-3">
        <input
          className={inputCls}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter by name or CIDR…"
          autoFocus
        />
        <div className="max-h-72 overflow-y-auto rounded border">
          {isLoading && (
            <p className="p-3 text-xs text-muted-foreground">Loading…</p>
          )}
          {!isLoading && shown.length === 0 && (
            <p className="p-3 text-xs text-muted-foreground italic">
              No subnets match.
            </p>
          )}
          {shown.map((s) => (
            <label
              key={s.id}
              className="flex cursor-pointer items-center gap-2 border-b px-2 py-1.5 text-xs last:border-0 hover:bg-accent/50"
            >
              <input
                type="checkbox"
                checked={picked.has(s.network)}
                onChange={() =>
                  setPicked((prev) => {
                    const next = new Set(prev);
                    if (next.has(s.network)) next.delete(s.network);
                    else next.add(s.network);
                    return next;
                  })
                }
              />
              <span className="font-mono">{s.network}</span>
              {s.name && (
                <span className="truncate text-muted-foreground">{s.name}</span>
              )}
            </label>
          ))}
        </div>
        <div className="flex items-center justify-between border-t pt-3">
          <span className="text-xs text-muted-foreground">
            {picked.size} selected
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={picked.size === 0}
              className="rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground disabled:opacity-50"
              onClick={() => onPick(Array.from(picked))}
            >
              Add {picked.size > 0 ? picked.size : ""}
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
}

// ── ACLs Tab ──────────────────────────────────────────────────────────────────

function AclsTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  // ConfirmModal rather than window.confirm — a native dialog can't be
  // styled, can't explain the blast radius, and is blocked outright in
  // some embedded browsers. (Project convention; this was the last
  // window.confirm on the DNS page.)
  const [confirmDelete, setConfirmDelete] = useState<DNSAcl | null>(null);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newEntries, setNewEntries] = useState("");
  const [error, setError] = useState("");

  const { data: acls = [] } = useQuery({
    queryKey: ["dns-acls", groupId],
    queryFn: () => dnsApi.listAcls(groupId),
  });

  const createMut = useMutation({
    mutationFn: (d: Record<string, unknown>) => dnsApi.createAcl(groupId, d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-acls", groupId] });
      setShowCreate(false);
      setNewName("");
      setNewDesc("");
      setNewEntries("");
    },
    onError: (e: ApiError) => setError(formatApiError(e)),
  });
  const delMut = useMutation({
    mutationFn: (id: string) => dnsApi.deleteAcl(groupId, id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-acls", groupId] }),
  });

  function createAcl(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    const entries = newEntries
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((val, i) => ({
        value: val.startsWith("!") ? val.slice(1) : val,
        negate: val.startsWith("!"),
        order: i,
      }));
    createMut.mutate({ name: newName, description: newDesc, entries });
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          Named ACLs
        </span>
        <button
          className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
          onClick={() => setShowCreate(true)}
        >
          <Plus className="h-3 w-3" /> New ACL
        </button>
      </div>
      {showCreate && (
        <form
          onSubmit={createAcl}
          className="mb-4 rounded-md border bg-muted/30 p-3 space-y-3"
        >
          <div className="grid grid-cols-2 gap-3">
            <Field label="ACL Name">
              <input
                className={inputCls}
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="internal-clients"
                required
              />
            </Field>
            <Field label="Description">
              <input
                className={inputCls}
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                placeholder="Optional"
              />
            </Field>
          </div>
          <Field label="Entries (one per line; prefix ! to negate)">
            <textarea
              value={newEntries}
              onChange={(e) => setNewEntries(e.target.value)}
              className="w-full rounded border bg-background px-2 py-1 font-mono text-xs resize-none h-20 focus:outline-none focus:ring-1 focus:ring-ring"
              placeholder={"10.0.0.0/8\n192.168.0.0/16\n!198.51.100.0/24"}
            />
          </Field>
          {error && <p className="text-xs text-destructive">{error}</p>}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
              onClick={() => setShowCreate(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMut.isPending}
              className="rounded-md bg-primary px-2 py-1 text-xs text-primary-foreground disabled:opacity-50"
            >
              Create
            </button>
          </div>
        </form>
      )}
      {acls.length === 0 && !showCreate && (
        <p className="text-sm text-muted-foreground italic">
          No named ACLs defined.
        </p>
      )}
      <div className="space-y-2">
        {acls.map((acl) => (
          <div
            key={acl.id}
            className="rounded-md border bg-card px-3 py-2.5 group"
          >
            <div className="flex items-center justify-between">
              <div>
                <span className="text-sm font-medium font-mono">
                  {acl.name}
                </span>
                {acl.description && (
                  <span className="ml-2 text-xs text-muted-foreground">
                    {acl.description}
                  </span>
                )}
              </div>
              <button
                className="h-7 w-7 flex items-center justify-center rounded opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive"
                onClick={() => setConfirmDelete(acl)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
            {acl.entries.length > 0 && (
              <div className="mt-1.5 flex flex-wrap gap-1">
                {acl.entries.map((entry) => (
                  <span
                    key={entry.id}
                    className={`inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-xs font-mono ${entry.negate ? "line-through opacity-60" : ""}`}
                  >
                    {entry.negate ? "!" : ""}
                    {entry.value}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
      {confirmDelete && (
        <ConfirmModal
          open
          title={`Delete ACL "${confirmDelete.name}"?`}
          confirmLabel="Delete ACL"
          tone="destructive"
          onClose={() => setConfirmDelete(null)}
          onConfirm={() => {
            delMut.mutate(confirmDelete.id);
            setConfirmDelete(null);
          }}
          message={
            <p className="text-sm">
              Any view or zone referencing{" "}
              <span className="font-mono">{confirmDelete.name}</span> by name
              will stop resolving it — check the Views tab before removing an
              ACL that is in use.
            </p>
          }
        />
      )}
    </div>
  );
}

// ── TSIG Keys Tab ─────────────────────────────────────────────────────────────

function TSIGKeysTab({ group }: { group: DNSServerGroup }) {
  const qc = useQueryClient();
  const { data: keys = [], isFetching } = useQuery({
    queryKey: ["dns-tsig-keys", group.id],
    queryFn: () => dnsApi.listTSIGKeys(group.id),
  });
  const [showAdd, setShowAdd] = useState(false);
  const [editKey, setEditKey] = useState<DNSTSIGKey | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<DNSTSIGKey | null>(null);
  const [confirmRotate, setConfirmRotate] = useState<DNSTSIGKey | null>(null);
  // Lives across modals — surfaces the freshly-issued plaintext secret one
  // last time after create / rotate so the operator can copy it.
  const [revealedSecret, setRevealedSecret] = useState<{
    name: string;
    algorithm: string;
    secret: string;
    action: "created" | "rotated";
  } | null>(null);

  const deleteMut = useMutation({
    mutationFn: (id: string) => dnsApi.deleteTSIGKey(group.id, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-tsig-keys", group.id] });
      setConfirmDelete(null);
    },
  });
  const rotateMut = useMutation({
    mutationFn: (id: string) => dnsApi.rotateTSIGKey(group.id, id),
    onSuccess: (key) => {
      qc.invalidateQueries({ queryKey: ["dns-tsig-keys", group.id] });
      setConfirmRotate(null);
      if (key.secret) {
        setRevealedSecret({
          name: key.name,
          algorithm: key.algorithm,
          secret: key.secret,
          action: "rotated",
        });
      }
    },
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          {keys.length} TSIG key{keys.length !== 1 ? "s" : ""}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() =>
              qc.invalidateQueries({ queryKey: ["dns-tsig-keys", group.id] })
            }
            className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted/50"
            disabled={isFetching}
          >
            <RefreshCw
              className={cn("h-3 w-3", isFetching && "animate-spin")}
            />
            Refresh
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-1 rounded-md bg-primary px-2 py-1 text-xs text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-3 w-3" /> New TSIG Key
          </button>
        </div>
      </div>

      <p className="rounded border bg-muted/20 px-3 py-2 text-xs text-muted-foreground">
        Named TSIG keys distributed to every BIND9 agent in this group. Use them
        to authenticate external <code>nsupdate</code> clients (allow-update) or
        downstream secondaries pulling AXFR (allow-transfer). Reference a key
        from a zone's allow-update / allow-transfer field as{" "}
        <code>key {"<name>;"}</code>.
      </p>

      {keys.length === 0 && (
        <p className="text-xs italic text-muted-foreground">
          No TSIG keys yet. Click <em>New TSIG Key</em> to add one.
        </p>
      )}

      <div className="overflow-x-auto rounded border">
        <table className="w-full min-w-[640px] text-sm">
          <thead className="bg-muted/30 text-xs text-muted-foreground">
            <tr className="border-b">
              <th className="px-3 py-1.5 text-left font-medium">Name</th>
              <th className="px-2 py-1.5 text-left font-medium">Algorithm</th>
              <th className="px-2 py-1.5 text-left font-medium">Purpose</th>
              <th className="px-2 py-1.5 text-left font-medium">
                Last rotated
              </th>
              <th className="px-3 py-1.5 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr
                key={k.id}
                className="border-b last:border-0 hover:bg-muted/20"
              >
                <td className="px-3 py-1.5 font-mono text-xs">{k.name}</td>
                <td className="px-2 py-1.5 font-mono text-xs">{k.algorithm}</td>
                <td className="px-2 py-1.5 text-xs text-muted-foreground">
                  {k.purpose ?? "—"}
                </td>
                <td className="px-2 py-1.5 text-xs text-muted-foreground">
                  {k.last_rotated_at
                    ? new Date(k.last_rotated_at).toLocaleString()
                    : "never"}
                </td>
                <td className="px-3 py-1.5 text-right">
                  <div className="inline-flex items-center gap-1">
                    <button
                      onClick={() => setConfirmRotate(k)}
                      className="rounded border px-2 py-0.5 text-xs hover:bg-muted/50"
                      title="Generate a fresh secret of the same algorithm and replace the stored one"
                    >
                      Rotate
                    </button>
                    <button
                      onClick={() => setEditKey(k)}
                      className="h-6 w-6 inline-flex items-center justify-center rounded hover:bg-muted/50"
                      title="Edit metadata"
                    >
                      <Pencil className="h-3 w-3" />
                    </button>
                    <button
                      onClick={() => setConfirmDelete(k)}
                      className="h-6 w-6 inline-flex items-center justify-center rounded text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                      title="Delete key"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showAdd && (
        <TSIGKeyModal
          groupId={group.id}
          onClose={() => setShowAdd(false)}
          onCreated={(secret) => {
            setShowAdd(false);
            setRevealedSecret({ ...secret, action: "created" });
          }}
        />
      )}
      {editKey && (
        <TSIGKeyModal
          groupId={group.id}
          existing={editKey}
          onClose={() => setEditKey(null)}
        />
      )}
      {confirmDelete && (
        <ConfirmDestroyModal
          title="Delete TSIG Key"
          description={`Permanently delete "${confirmDelete.name}"? Any zones referencing this key in their allow-update / allow-transfer fields will start failing auth on the next BIND reload.`}
          checkLabel={`I understand "${confirmDelete.name}" will be deleted from every BIND9 server in this group on the next config push.`}
          onConfirm={() => deleteMut.mutate(confirmDelete.id)}
          onClose={() => setConfirmDelete(null)}
          isPending={deleteMut.isPending}
        />
      )}
      {confirmRotate && (
        <ConfirmDestroyModal
          title="Rotate TSIG Key"
          description={`Generate a new secret for "${confirmRotate.name}"? The old secret stops working immediately on the next BIND9 push — every consuming client must be updated with the new value.`}
          checkLabel={`I understand consumers of "${confirmRotate.name}" will break until reconfigured.`}
          onConfirm={() => rotateMut.mutate(confirmRotate.id)}
          onClose={() => setConfirmRotate(null)}
          isPending={rotateMut.isPending}
        />
      )}
      {revealedSecret && (
        <RevealedSecretModal
          name={revealedSecret.name}
          algorithm={revealedSecret.algorithm}
          secret={revealedSecret.secret}
          action={revealedSecret.action}
          onClose={() => setRevealedSecret(null)}
        />
      )}
    </div>
  );
}

function TSIGKeyModal({
  groupId,
  existing,
  onClose,
  onCreated,
}: {
  groupId: string;
  existing?: DNSTSIGKey;
  onClose: () => void;
  onCreated?: (s: { name: string; algorithm: string; secret: string }) => void;
}) {
  const qc = useQueryClient();
  const isEdit = !!existing;
  const [name, setName] = useState(existing?.name ?? "");
  const [algorithm, setAlgorithm] = useState(
    existing?.algorithm ?? "hmac-sha256",
  );
  const [purpose, setPurpose] = useState<string>(existing?.purpose ?? "");
  const [notes, setNotes] = useState<string>(existing?.notes ?? "");
  // Optional operator-supplied secret — empty string means "let the server
  // generate one." Only used on the create path.
  const [secret, setSecret] = useState<string>("");

  const generateMut = useMutation({
    mutationFn: () => dnsApi.generateTSIGSecret(groupId, algorithm),
    onSuccess: (r) => setSecret(r.secret),
  });

  const saveMut = useMutation({
    mutationFn: () => {
      if (isEdit && existing) {
        return dnsApi.updateTSIGKey(groupId, existing.id, {
          name,
          algorithm,
          purpose: purpose || null,
          notes,
        });
      }
      return dnsApi.createTSIGKey(groupId, {
        name,
        algorithm,
        secret: secret.trim() || null,
        purpose: purpose || null,
        notes,
      });
    },
    onSuccess: (key) => {
      qc.invalidateQueries({ queryKey: ["dns-tsig-keys", groupId] });
      if (!isEdit && key.secret && onCreated) {
        onCreated({
          name: key.name,
          algorithm: key.algorithm,
          secret: key.secret,
        });
      } else {
        onClose();
      }
    },
  });

  return (
    <Modal
      title={isEdit ? `Edit ${existing!.name}` : "New TSIG Key"}
      onClose={onClose}
    >
      <div className="space-y-3 text-sm">
        <div>
          <label className="mb-0.5 block text-xs font-medium">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. tsig-update.spatium.local."
            className="w-full rounded border bg-background px-2 py-1 text-xs font-mono"
          />
          <p className="mt-0.5 text-[11px] text-muted-foreground">
            RFC 1035 dotted ASCII label. Lower-case letters, digits, dots,
            dashes. The convention is to end with a trailing dot (FQDN).
          </p>
        </div>
        <div>
          <label className="mb-0.5 block text-xs font-medium">Algorithm</label>
          <select
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
            className="w-full rounded border bg-background px-2 py-1 text-xs"
          >
            {[
              "hmac-sha1",
              "hmac-sha224",
              "hmac-sha256",
              "hmac-sha384",
              "hmac-sha512",
            ].map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <p className="mt-0.5 text-[11px] text-muted-foreground">
            BIND9 + dnspython both default to <code>hmac-sha256</code>. Older
            clients may still need <code>hmac-sha1</code>.
          </p>
        </div>
        {!isEdit && (
          <div>
            <label className="mb-0.5 block text-xs font-medium">
              Secret (optional)
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder="Leave blank to generate"
                className="flex-1 rounded border bg-background px-2 py-1 text-xs font-mono"
              />
              <button
                type="button"
                onClick={() => generateMut.mutate()}
                disabled={generateMut.isPending}
                className="rounded border px-2 py-1 text-xs hover:bg-muted/50 disabled:opacity-50"
              >
                Generate
              </button>
            </div>
            <p className="mt-0.5 text-[11px] text-muted-foreground">
              Base64-encoded random bytes. Leave blank to have the server
              generate one of the right size for the chosen algorithm.
            </p>
          </div>
        )}
        <div>
          <label className="mb-0.5 block text-xs font-medium">
            Purpose (optional)
          </label>
          <input
            type="text"
            value={purpose}
            onChange={(e) => setPurpose(e.target.value)}
            placeholder="e.g. nsupdate, axfr-pull"
            className="w-full rounded border bg-background px-2 py-1 text-xs"
          />
        </div>
        <div>
          <label className="mb-0.5 block text-xs font-medium">Notes</label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={2}
            className="w-full rounded border bg-background px-2 py-1 text-xs"
            placeholder="What is this key for?"
          />
        </div>
        {saveMut.isError && (
          <p className="text-xs text-destructive">
            {formatApiError(saveMut.error, "Save failed")}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded border px-3 py-1.5 text-xs hover:bg-muted/50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => saveMut.mutate()}
            disabled={saveMut.isPending || !name.trim()}
            className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saveMut.isPending ? "Saving…" : isEdit ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function RevealedSecretModal({
  name,
  algorithm,
  secret,
  action,
  onClose,
}: {
  name: string;
  algorithm: string;
  secret: string;
  action: "created" | "rotated";
  onClose: () => void;
}) {
  return (
    <Modal title="Copy this secret now" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p className="text-xs text-muted-foreground">
          This is the only time the plaintext secret for{" "}
          <code className="font-mono">{name}</code> will be shown. Copy it into
          your <code>nsupdate</code> client / secondary-server config before
          closing — it is hashed at rest and can't be recovered.
        </p>
        <div className="rounded border bg-muted/30 p-3 font-mono text-xs">
          <div className="mb-1 text-muted-foreground">{algorithm}</div>
          <div className="break-all">{secret}</div>
        </div>
        <button
          type="button"
          onClick={() => {
            void navigator.clipboard.writeText(secret);
          }}
          className="inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs hover:bg-muted/50"
        >
          <Copy className="h-3 w-3" /> Copy secret
        </button>
        <p className="text-[11px] text-muted-foreground">
          Key {action} • The new value will reach BIND9 servers on the next
          ConfigBundle long-poll (typically within seconds).
        </p>
        <div className="flex justify-end pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
          >
            I have copied it
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Options Tab ───────────────────────────────────────────────────────────────

function OptionsTab({ groupId }: { groupId: string }) {
  const qc = useQueryClient();
  const { data: opts, isLoading } = useQuery({
    queryKey: ["dns-options", groupId],
    queryFn: () => dnsApi.getOptions(groupId),
  });
  // Certificate picker for the DoT/DoH listeners (issue #50). Shares the
  // appliance cert store with the web UI cert + the ACME client, so the
  // operator issues once and points both at it. Non-admins get a 403 here;
  // the select just falls back to "— none —" rather than erroring the page.
  const { data: certs } = useQuery({
    queryKey: ["appliance-tls-certs"],
    queryFn: () => applianceTlsApi.list(),
    retry: false,
  });

  const [forwardersEnabled, setForwardersEnabled] = useState(false);
  const [forwarders, setForwarders] = useState("");
  const [forwardPolicy, setForwardPolicy] = useState("first");
  const [recursionEnabled, setRecursionEnabled] = useState(true);
  const [allowRecursion, setAllowRecursion] = useState("any");
  const [dnssecValidation, setDnssecValidation] = useState("auto");
  const [notifyEnabled, setNotifyEnabled] = useState("yes");
  const [allowQuery, setAllowQuery] = useState("any");
  const [allowTransfer, setAllowTransfer] = useState("none");
  const [queryLogEnabled, setQueryLogEnabled] = useState(false);
  const [responseLogEnabled, setResponseLogEnabled] = useState(false);
  const [queryLogChannel, setQueryLogChannel] = useState("file");
  const [queryLogFile, setQueryLogFile] = useState(
    "/var/log/named/queries.log",
  );
  const [queryLogSeverity, setQueryLogSeverity] = useState("info");
  // RRL + amplification (issue #146). Optional numerics held as strings so
  // "" round-trips to null.
  const [rrlEnabled, setRrlEnabled] = useState(false);
  const [rrlRps, setRrlRps] = useState(15);
  const [rrlWindow, setRrlWindow] = useState(15);
  const [rrlSlip, setRrlSlip] = useState(2);
  const [rrlQpsScale, setRrlQpsScale] = useState("");
  const [rrlExempt, setRrlExempt] = useState("");
  const [rrlLogOnly, setRrlLogOnly] = useState(false);
  const [minimalResponses, setMinimalResponses] = useState(false);
  const [tcpClients, setTcpClients] = useState("");
  const [clientsPerQuery, setClientsPerQuery] = useState("");
  const [maxClientsPerQuery, setMaxClientsPerQuery] = useState("");
  // dnsdist front for PowerDNS (#146 Phase 2).
  const [dnsdistEnabled, setDnsdistEnabled] = useState(false);
  const [dnsdistMaxQps, setDnsdistMaxQps] = useState("");
  const [dnsdistAction, setDnsdistAction] = useState("truncate");
  const [dnsdistDynblockQps, setDnsdistDynblockQps] = useState("");
  const [dnsdistDynblockSeconds, setDnsdistDynblockSeconds] = useState(60);
  // Encrypted transports (issue #50).
  const [dotEnabled, setDotEnabled] = useState(false);
  const [dotPort, setDotPort] = useState(853);
  const [dohEnabled, setDohEnabled] = useState(false);
  const [dohPort, setDohPort] = useState(443);
  const [dohPath, setDohPath] = useState("/dns-query");
  // DoQ (#741) — Technitium only. UDP, so it may share dot_port's number.
  const [doqEnabled, setDoqEnabled] = useState(false);
  const [doqPort, setDoqPort] = useState(853);
  const [tlsCertificateId, setTlsCertificateId] = useState("");
  const [forwardTransport, setForwardTransport] = useState("do53");
  const [forwardTlsHostname, setForwardTlsHostname] = useState("");
  const [forwardTlsVerify, setForwardTlsVerify] = useState(true);
  const [dirty, setDirty] = useState(false);
  const [saved, setSaved] = useState(false);
  const [initialized, setInitialized] = useState(false);

  if (opts && !initialized) {
    setForwardersEnabled(opts.forwarders.length > 0);
    setForwarders(opts.forwarders.join("\n"));
    setForwardPolicy(opts.forward_policy);
    setRecursionEnabled(opts.recursion_enabled);
    setAllowRecursion(opts.allow_recursion.join(", "));
    setDnssecValidation(opts.dnssec_validation);
    setNotifyEnabled(opts.notify_enabled);
    setAllowQuery(opts.allow_query.join(", "));
    setAllowTransfer(opts.allow_transfer.join(", "));
    setQueryLogEnabled(opts.query_log_enabled);
    setResponseLogEnabled(opts.response_log_enabled);
    setQueryLogChannel(opts.query_log_channel);
    setQueryLogFile(opts.query_log_file);
    setQueryLogSeverity(opts.query_log_severity);
    setRrlEnabled(opts.rrl_enabled);
    setRrlRps(opts.rrl_responses_per_second);
    setRrlWindow(opts.rrl_window);
    setRrlSlip(opts.rrl_slip);
    setRrlQpsScale(opts.rrl_qps_scale?.toString() ?? "");
    setRrlExempt(opts.rrl_exempt_clients.join(", "));
    setRrlLogOnly(opts.rrl_log_only);
    setMinimalResponses(opts.minimal_responses);
    setTcpClients(opts.tcp_clients?.toString() ?? "");
    setClientsPerQuery(opts.clients_per_query?.toString() ?? "");
    setMaxClientsPerQuery(opts.max_clients_per_query?.toString() ?? "");
    setDnsdistEnabled(opts.dnsdist_enabled);
    setDnsdistMaxQps(opts.dnsdist_max_qps_per_client?.toString() ?? "");
    setDnsdistAction(opts.dnsdist_action);
    setDnsdistDynblockQps(opts.dnsdist_dynblock_qps?.toString() ?? "");
    setDnsdistDynblockSeconds(opts.dnsdist_dynblock_seconds);
    setDotEnabled(opts.dot_enabled);
    setDotPort(opts.dot_port);
    setDohEnabled(opts.doh_enabled);
    setDohPort(opts.doh_port);
    setDoqEnabled(opts.doq_enabled ?? false);
    setDoqPort(opts.doq_port ?? 853);
    setDohPath(opts.doh_path);
    setTlsCertificateId(opts.tls_certificate_id ?? "");
    setForwardTransport(opts.forward_transport);
    setForwardTlsHostname(opts.forward_tls_hostname ?? "");
    setForwardTlsVerify(opts.forward_tls_verify);
    setInitialized(true);
  }

  const saveMut = useMutation({
    mutationFn: (d: Record<string, unknown>) =>
      dnsApi.updateOptions(groupId, d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-options", groupId] });
      setDirty(false);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    },
  });

  function list(s: string) {
    return s
      .split(/[,\n]+/)
      .map((x) => x.trim())
      .filter(Boolean);
  }

  // "" → null (clear), else the parsed number. Used for the optional RRL /
  // amplification numerics.
  function numOrNull(s: string): number | null {
    const t = s.trim();
    return t === "" ? null : Number(t);
  }

  // For the REQUIRED RRL numerics: a blank/invalid input must not silently
  // coerce to 0 (Number("") === 0). slip=0 is a valid-but-different BIND
  // behavior; rps/window=0 fail server validation. Fall back to the BIND
  // default instead.
  function numOrDefault(raw: string, dflt: number): number {
    const n = Number(raw);
    return raw.trim() === "" || Number.isNaN(n) ? dflt : n;
  }

  // ── Resolver presets (issue #877) ──────────────────────────────────
  const { data: presetCatalog } = useQuery({
    queryKey: ["dns", "forwarder-presets"],
    queryFn: () => dnsApi.forwarderPresets(),
    // Static catalogue shipped with the release — refetching it is pointless.
    staleTime: Infinity,
  });

  const presetsByProvider = useMemo(() => {
    const grouped = new Map<string, ResolverPreset[]>();
    for (const p of presetCatalog?.presets ?? []) {
      const bucket = grouped.get(p.provider);
      if (bucket) bucket.push(p);
      else grouped.set(p.provider, [p]);
    }
    return [...grouped.entries()];
  }, [presetCatalog]);

  /** Which catalogued upstream the current forwarder list resolves to, or
   *  null when it is empty, custom, or mixed. Drives both the DoT nudge and
   *  the hostname advisory below. */
  const appliedPreset = useMemo(() => {
    const presets = presetCatalog?.presets ?? [];
    if (!presets.length) return null;
    const addresses = list(forwarders).map((f) =>
      f.split("@")[0].trim().toLowerCase(),
    );
    if (!addresses.length) return null;
    const matched = new Set<string>();
    for (const addr of addresses) {
      const hit = presets.find((p) =>
        [...p.ipv4, ...p.ipv6].some((a) => a.toLowerCase() === addr),
      );
      if (hit) matched.add(hit.id);
    }
    if (matched.size !== 1) return null;
    return presets.find((p) => p.id === [...matched][0]) ?? null;
  }, [presetCatalog, forwarders]);

  /** Advisory, not a block: providers put several names in one certificate
   *  (Cloudflare's covers one.one.one.one as well as cloudflare-dns.com) and
   *  the catalogue records only the canonical one, so a mismatch is worth
   *  flagging but not worth refusing. The API separately hard-refuses the
   *  unambiguous case — forwarders spanning two certificate names. */
  const forwarderHostnameHint = useMemo(() => {
    // Applies to every encrypted transport, not just tls: https and quic
    // address the upstream BY NAME and the API requires a hostname for
    // them unconditionally, so a wrong one there is at least as
    // fail-closed as it is on DoT. Only opportunistic DoT (verify off)
    // and plaintext do53 authenticate nothing and need no opinion.
    if (forwardTransport === "do53") return null;
    if (forwardTransport === "tls" && !forwardTlsVerify) return null;
    if (!appliedPreset) return null;
    const typed = forwardTlsHostname.trim().toLowerCase();
    if (!typed || typed === appliedPreset.tls_hostname.toLowerCase())
      return null;
    return `These forwarders are ${appliedPreset.name}, which documents its encrypted-DNS hostname as ${appliedPreset.tls_hostname} — not ${forwardTlsHostname.trim()}. If that name is not on the upstream's certificate, every query will fail closed with SERVFAIL.`;
  }, [forwardTransport, forwardTlsVerify, forwardTlsHostname, appliedPreset]);

  /** Caveats worth showing about the selected upstream — its own documented
   *  quirks, plus the one interaction the operator cannot see coming. */
  const presetAdvisories = useMemo(() => {
    if (!appliedPreset) return [];
    const out: string[] = [];
    // An upstream that answers a forged address for a blocked name produces
    // bogus data for a SIGNED name, so validating downstream turns the
    // block into SERVFAIL. That is the same fail-closed symptom this
    // feature exists to prevent, arriving from the opposite direction —
    // and nothing in either setting hints at the interaction.
    if (
      appliedPreset.blocking_method === "forged_address" &&
      dnssecValidation !== "no"
    ) {
      out.push(
        `${appliedPreset.name} answers blocked names with a forged address rather than NXDOMAIN. With DNSSEC validation on, a blocked name that is signed validates as bogus and returns SERVFAIL instead of the block. Quad9 avoids this by answering NXDOMAIN.`,
      );
    }
    if (appliedPreset.notes) out.push(appliedPreset.notes);
    return out;
  }, [appliedPreset, dnssecValidation]);

  const [presetIncludeV6, setPresetIncludeV6] = useState(false);

  function applyResolverPreset(id: string) {
    const preset = (presetCatalog?.presets ?? []).find((p) => p.id === id);
    if (!preset) return;
    const addresses = presetIncludeV6
      ? [...preset.ipv4, ...preset.ipv6]
      : [...preset.ipv4];
    setForwarders(addresses.join("\n"));
    // Always fill the hostname, even on do53: it costs nothing, and it means
    // switching to DoT later is one click rather than a lookup.
    setForwardTlsHostname(preset.tls_hostname);
    // Upstreams that refuse plaintext 53 get switched over rather than left
    // in a state the API will reject on save — do53 here is not a weaker
    // choice, it is a broken one.
    if (preset.requires_encrypted && forwardTransport === "do53") {
      setForwardTransport("tls");
      setForwardTlsVerify(true);
    }
    setDirty(true);
  }

  function save() {
    saveMut.mutate({
      forwarders: forwardersEnabled ? list(forwarders) : [],
      forward_policy: forwardPolicy,
      recursion_enabled: recursionEnabled,
      allow_recursion: list(allowRecursion),
      dnssec_validation: dnssecValidation,
      notify_enabled: notifyEnabled,
      allow_query: list(allowQuery),
      allow_transfer: list(allowTransfer),
      query_log_enabled: queryLogEnabled,
      // Only meaningful with query logging on; the API 422s the other
      // combination, so never send it (#914).
      response_log_enabled: queryLogEnabled && responseLogEnabled,
      query_log_channel: queryLogChannel,
      query_log_file: queryLogFile,
      query_log_severity: queryLogSeverity,
      rrl_enabled: rrlEnabled,
      rrl_responses_per_second: rrlRps,
      rrl_window: rrlWindow,
      rrl_slip: rrlSlip,
      rrl_qps_scale: numOrNull(rrlQpsScale),
      rrl_exempt_clients: list(rrlExempt),
      rrl_log_only: rrlLogOnly,
      minimal_responses: minimalResponses,
      tcp_clients: numOrNull(tcpClients),
      clients_per_query: numOrNull(clientsPerQuery),
      max_clients_per_query: numOrNull(maxClientsPerQuery),
      dnsdist_enabled: dnsdistEnabled,
      dnsdist_max_qps_per_client: numOrNull(dnsdistMaxQps),
      dnsdist_action: dnsdistAction,
      dnsdist_dynblock_qps: numOrNull(dnsdistDynblockQps),
      dnsdist_dynblock_seconds: dnsdistDynblockSeconds,
      dot_enabled: dotEnabled,
      dot_port: dotPort,
      doh_enabled: dohEnabled,
      doh_port: dohPort,
      doh_path: dohPath.trim() || "/dns-query",
      doq_enabled: doqEnabled,
      doq_port: doqPort,
      // "" is the "no cert linked" shape; send explicit null so the server's
      // exclude_none re-injection clears the column instead of dropping it.
      tls_certificate_id: tlsCertificateId || null,
      forward_transport: forwardTransport,
      forward_tls_hostname: forwardTlsHostname.trim() || null,
      forward_tls_verify: forwardTlsVerify,
    });
  }

  if (isLoading)
    return <p className="text-sm text-muted-foreground">Loading…</p>;

  // Full-width select to prevent text/arrow overlap
  const selCls =
    "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring appearance-none";

  const card = "rounded-md border p-4 space-y-3";
  const cardTitle = "text-sm font-medium flex items-center gap-2";

  return (
    <div className="space-y-5 max-w-xl">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Zone/view overrides take precedence over server defaults.
        </p>
        <button
          disabled={!dirty || saveMut.isPending}
          onClick={save}
          className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm disabled:opacity-50 ${saved ? "border text-emerald-600" : "bg-primary text-primary-foreground hover:bg-primary/90"}`}
        >
          {saved ? (
            <>
              <RefreshCw className="h-3.5 w-3.5" /> Saved
            </>
          ) : saveMut.isPending ? (
            "Saving…"
          ) : (
            "Save Changes"
          )}
        </button>
      </div>

      {/* Server-side validation (e.g. the issue-#50 encrypted-transport
          rules) returns 422 with an explanatory message. Without this the
          button just flips back to "Save Changes" and the operator has no
          idea why nothing happened. */}
      {saveMut.isError && (
        <p className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          {formatApiError(saveMut.error, "Save failed")}
        </p>
      )}

      <div className={card}>
        <div className="flex items-center justify-between">
          <h4 className={cardTitle}>
            <Layers className="h-4 w-4 text-muted-foreground" /> Forwarders
          </h4>
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={forwardersEnabled}
              onChange={(e) => {
                setForwardersEnabled(e.target.checked);
                setDirty(true);
              }}
              className="h-4 w-4"
            />
            Enable
          </label>
        </div>
        {!forwardersEnabled && (
          <p className="text-xs text-muted-foreground">
            Forwarders disabled — suitable for authoritative-only or air-gapped
            servers.
          </p>
        )}
        {forwardersEnabled && (
          <>
            <Field label="Use a well-known resolver">
              <div className="space-y-2">
                <select
                  className={selCls}
                  value=""
                  onChange={(e) => applyResolverPreset(e.target.value)}
                >
                  <option value="">Choose a preset…</option>
                  {presetsByProvider.map(([provider, items]) => (
                    <optgroup key={provider} label={provider}>
                      {items.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} — {p.filtering}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={presetIncludeV6}
                    onChange={(e) => setPresetIncludeV6(e.target.checked)}
                    className="h-3.5 w-3.5"
                  />
                  Include IPv6 addresses
                </label>
                <p className="text-xs text-muted-foreground">
                  Fills the resolvers below and the matching DoT hostname
                  together — with verification on they have to agree, and a
                  mismatch fails closed rather than falling back to plaintext.
                </p>
              </div>
            </Field>
            <Field label="Upstream resolvers (one per line)">
              <div className="space-y-1">
                <textarea
                  value={forwarders}
                  onChange={(e) => {
                    setForwarders(e.target.value);
                    setDirty(true);
                  }}
                  className="w-full rounded border bg-background px-2 py-1 font-mono text-xs resize-none h-16 focus:outline-none focus:ring-1 focus:ring-ring"
                  placeholder={"1.1.1.1\n8.8.8.8"}
                />
                {/* The presets fill this box; they never police it. Say so,
                    so nobody reads the picker above as a required choice. */}
                <p className="text-xs text-muted-foreground">
                  {appliedPreset
                    ? `Recognised as ${appliedPreset.name}. Edit freely — any resolver address works, including your own.`
                    : "Type any resolver address, or pick a preset above to fill this in. Addresses may pin a port as ip@port."}
                </p>
              </div>
            </Field>
            {presetAdvisories.map((advisory) => (
              <p
                key={advisory}
                className="rounded-md border border-dashed px-3 py-2 text-xs text-muted-foreground"
              >
                {advisory}
              </p>
            ))}
            {/* Only do53 is plaintext — https and quic are already encrypted,
                so nudging there would claim a plaintext leak that isn't
                happening AND downgrade a working DoH/DoQ config to DoT. The
                requires_encrypted case gets the same button with a harder
                message: on do53 that upstream does not merely leak, it
                answers nothing, and the API refuses the save. */}
            {appliedPreset && forwardTransport === "do53" && (
              <p
                className={cn(
                  "flex flex-wrap items-center gap-2 rounded-md border border-dashed px-3 py-2 text-xs",
                  appliedPreset.requires_encrypted
                    ? "border-amber-500/40 bg-amber-500/5 text-amber-700 dark:text-amber-400"
                    : "text-muted-foreground",
                )}
              >
                <span>
                  {appliedPreset.requires_encrypted
                    ? `${appliedPreset.name} answers only over an encrypted transport and returns REFUSED on plaintext port 53, so forwarding to it over do53 fails every query. Saving this combination is rejected.`
                    : `${appliedPreset.name} supports DNS-over-TLS. Queries currently leave in plaintext on port 53.`}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setForwardTransport("tls");
                    setForwardTlsVerify(true);
                    setForwardTlsHostname(appliedPreset.tls_hostname);
                    setDirty(true);
                  }}
                  className="rounded-md border px-2 py-1 font-medium hover:bg-accent"
                >
                  Switch to DoT
                </button>
              </p>
            )}
            {forwarderHostnameHint && (
              <p className="rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
                {forwarderHostnameHint}
              </p>
            )}
            <Field label="Forward policy">
              <select
                className={selCls}
                value={forwardPolicy}
                onChange={(e) => {
                  setForwardPolicy(e.target.value);
                  setDirty(true);
                }}
              >
                <option value="first">
                  first — try forwarders first, fall back to recursion
                </option>
                <option value="only">
                  only — always send to forwarders, never recurse
                </option>
              </select>
            </Field>
          </>
        )}
      </div>

      <div className={card}>
        <h4 className={cardTitle}>Recursion</h4>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={recursionEnabled}
            onChange={(e) => {
              setRecursionEnabled(e.target.checked);
              setDirty(true);
            }}
            className="h-4 w-4"
          />
          <span className="text-sm">Enable recursion</span>
        </label>
        <Field label="allow-recursion (comma-separated CIDRs / ACL names)">
          <input
            className={inputCls}
            value={allowRecursion}
            onChange={(e) => {
              setAllowRecursion(e.target.value);
              setDirty(true);
            }}
            placeholder="any"
          />
        </Field>
      </div>

      <div className={card}>
        <h4 className={cardTitle}>
          <Shield className="h-4 w-4 text-muted-foreground" /> DNSSEC Validation
        </h4>
        <Field label="Validation mode">
          <select
            className={selCls}
            value={dnssecValidation}
            onChange={(e) => {
              setDnssecValidation(e.target.value);
              setDirty(true);
            }}
          >
            <option value="auto">
              auto — validate using built-in managed keys (recommended)
            </option>
            <option value="yes">
              yes — validate; trust anchors must be configured manually
            </option>
            <option value="no">no — do not validate DNSSEC signatures</option>
          </select>
        </Field>
      </div>

      <div className={card}>
        <div className="flex items-center justify-between">
          <h4 className={cardTitle}>
            <Shield className="h-4 w-4 text-muted-foreground" /> Rate limiting
            (RRL) &amp; amplification
          </h4>
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={rrlEnabled}
              onChange={(e) => {
                setRrlEnabled(e.target.checked);
                setDirty(true);
              }}
              className="h-4 w-4"
            />
            Enable RRL
          </label>
        </div>
        <p className="text-xs text-muted-foreground">
          BIND9 Response Rate Limiting drops/truncates duplicate responses to
          the same client /24 — the primary defense against DNS amplification.
          Applies to every view on this server group.
        </p>
        {rrlEnabled && (
          <>
            <div className="grid grid-cols-3 gap-3">
              <Field label="responses/sec (1–1000)">
                <input
                  type="number"
                  min={1}
                  max={1000}
                  className={inputCls}
                  value={rrlRps}
                  onChange={(e) => {
                    setRrlRps(numOrDefault(e.target.value, 15));
                    setDirty(true);
                  }}
                />
              </Field>
              <Field label="window sec (1–3600)">
                <input
                  type="number"
                  min={1}
                  max={3600}
                  className={inputCls}
                  value={rrlWindow}
                  onChange={(e) => {
                    setRrlWindow(numOrDefault(e.target.value, 15));
                    setDirty(true);
                  }}
                />
              </Field>
              <Field label="slip (0–10)">
                <input
                  type="number"
                  min={0}
                  max={10}
                  className={inputCls}
                  value={rrlSlip}
                  onChange={(e) => {
                    setRrlSlip(numOrDefault(e.target.value, 2));
                    setDirty(true);
                  }}
                />
              </Field>
            </div>
            <Field label="qps-scale (optional — tighten limit under load)">
              <input
                type="number"
                min={1}
                className={inputCls}
                value={rrlQpsScale}
                onChange={(e) => {
                  setRrlQpsScale(e.target.value);
                  setDirty(true);
                }}
                placeholder="unset"
              />
            </Field>
            <Field label="exempt-clients (comma/newline CIDRs or ACL names)">
              <input
                className={inputCls}
                value={rrlExempt}
                onChange={(e) => {
                  setRrlExempt(e.target.value);
                  setDirty(true);
                }}
                placeholder="10.0.0.0/8, 192.168.0.0/16"
              />
            </Field>
            <label className="flex items-center gap-2 cursor-pointer text-sm">
              <input
                type="checkbox"
                checked={rrlLogOnly}
                onChange={(e) => {
                  setRrlLogOnly(e.target.checked);
                  setDirty(true);
                }}
                className="h-4 w-4"
              />
              log-only (dry run — count would-be drops without dropping)
            </label>
          </>
        )}
        <div className="border-t pt-3 space-y-3">
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={minimalResponses}
              onChange={(e) => {
                setMinimalResponses(e.target.checked);
                setDirty(true);
              }}
              className="h-4 w-4"
            />
            minimal-responses (shrink amplification payload)
          </label>
          <div className="grid grid-cols-3 gap-3">
            <Field label="tcp-clients">
              <input
                type="number"
                min={1}
                className={inputCls}
                value={tcpClients}
                onChange={(e) => {
                  setTcpClients(e.target.value);
                  setDirty(true);
                }}
                placeholder="default"
              />
            </Field>
            <Field label="clients-per-query">
              <input
                type="number"
                min={1}
                className={inputCls}
                value={clientsPerQuery}
                onChange={(e) => {
                  setClientsPerQuery(e.target.value);
                  setDirty(true);
                }}
                placeholder="default"
              />
            </Field>
            <Field label="max-clients-per-query">
              <input
                type="number"
                min={1}
                className={inputCls}
                value={maxClientsPerQuery}
                onChange={(e) => {
                  setMaxClientsPerQuery(e.target.value);
                  setDirty(true);
                }}
                placeholder="default"
              />
            </Field>
          </div>
        </div>
      </div>

      <div className={card}>
        <h4 className={cardTitle}>
          <Shield className="h-4 w-4 text-muted-foreground" /> Encrypted
          transports (DoT / DoH)
        </h4>
        <p className="text-xs text-muted-foreground">
          Serve DNS-over-TLS and DNS-over-HTTPS to clients, and forward to
          upstream resolvers over TLS instead of plaintext port 53. Listeners
          are <strong>additive</strong> — plain DNS on :53 keeps working.
        </p>

        <Field label="TLS certificate (served by both listeners)">
          <select
            className={selCls}
            value={tlsCertificateId}
            onChange={(e) => {
              setTlsCertificateId(e.target.value);
              setDirty(true);
            }}
          >
            <option value="">— none —</option>
            {/* CSR-pending rows (pending === true, i.e. cert_pem IS NULL)
                are shown but disabled: the server 422s them with "CSR
                pending", so offering them as a live choice would be an
                option that can only ever fail. Rendering them greyed-out
                explains WHY the cert they just generated isn't usable
                yet. */}
            {(certs ?? []).map((c) => (
              <option key={c.id} value={c.id} disabled={c.pending}>
                {c.name} ({c.subject_cn})
                {c.pending ? " — awaiting signed certificate" : ""}
              </option>
            ))}
          </select>
        </Field>
        <p className="text-xs text-muted-foreground">
          Managed under Appliance → Web UI Certificate — upload one, or issue it
          from Let's Encrypt with the built-in ACME client. Renewals are picked
          up automatically. A listener with no usable certificate is skipped and
          the server stays Do53-only rather than failing to start.
        </p>

        <div className="flex items-center justify-between border-t pt-3">
          <span className="text-sm">DNS-over-TLS (DoT)</span>
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={dotEnabled}
              onChange={(e) => {
                setDotEnabled(e.target.checked);
                setDirty(true);
              }}
              className="h-4 w-4"
            />
            Enable
          </label>
        </div>
        {dotEnabled && (
          <Field label="DoT port">
            <input
              type="number"
              min={1}
              max={65535}
              className={inputCls}
              value={dotPort}
              onChange={(e) => {
                setDotPort(numOrDefault(e.target.value, 853));
                setDirty(true);
              }}
            />
          </Field>
        )}

        <div className="flex items-center justify-between border-t pt-3">
          <span className="text-sm">DNS-over-HTTPS (DoH)</span>
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={dohEnabled}
              onChange={(e) => {
                setDohEnabled(e.target.checked);
                setDirty(true);
              }}
              className="h-4 w-4"
            />
            Enable
          </label>
        </div>
        {dohEnabled && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <Field label="DoH port">
                <input
                  type="number"
                  min={1}
                  max={65535}
                  className={inputCls}
                  value={dohPort}
                  onChange={(e) => {
                    setDohPort(numOrDefault(e.target.value, 443));
                    setDirty(true);
                  }}
                />
              </Field>
              <Field label="URL path">
                <input
                  className={inputCls}
                  value={dohPath}
                  placeholder="/dns-query"
                  onChange={(e) => {
                    setDohPath(e.target.value);
                    setDirty(true);
                  }}
                />
              </Field>
            </div>
            {dohPort === 443 && (
              <p className="text-xs text-amber-600">
                Port 443 is the RFC 8484 default but collides with the web UI on
                an appliance install, where it will be rejected. Use 8443 and
                publish it to clients in their DoH URL.
              </p>
            )}
          </>
        )}
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">DNS-over-QUIC (DoQ)</div>
            <div className="text-xs text-muted-foreground">
              RFC 9250. Technitium groups only — BIND9 has no DoQ listener and
              PowerDNS speaks none of the encrypted transports.
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={doqEnabled}
              onChange={(e) => {
                setDoqEnabled(e.target.checked);
                setDirty(true);
              }}
              className="h-4 w-4"
            />
            Enable
          </label>
        </div>
        {doqEnabled && (
          <>
            <Field label="DoQ port">
              <input
                type="number"
                min={1}
                max={65535}
                className={inputCls}
                value={doqPort}
                onChange={(e) => {
                  setDoqPort(numOrDefault(e.target.value, 853));
                  setDirty(true);
                }}
              />
            </Field>
            <p className="text-xs text-muted-foreground">
              DoQ is UDP where DoT is TCP, so sharing port 853 with DoT is
              expected and does not collide.
            </p>
          </>
        )}
        <p className="text-xs text-muted-foreground">
          On PowerDNS groups the listeners run on the dnsdist front below (pdns
          speaks neither protocol), so DoT/DoH there needs that front deployed.
          BIND9 serves both natively.
        </p>

        <div className="border-t pt-3 space-y-3">
          <Field label="Upstream forwarding transport">
            <select
              className={selCls}
              value={forwardTransport}
              onChange={(e) => {
                setForwardTransport(e.target.value);
                setDirty(true);
              }}
            >
              <option value="do53">
                do53 — plaintext UDP/TCP port 53 (default)
              </option>
              <option value="tls">
                tls — DNS-over-TLS to the forwarders above
              </option>
              <option value="https">
                https — DNS-over-HTTPS (Technitium groups only)
              </option>
              <option value="quic">
                quic — DNS-over-QUIC (Technitium groups only)
              </option>
            </select>
          </Field>
          {forwardTransport === "tls" && (
            <>
              <p className="text-xs text-muted-foreground">
                Applies to the forwarders configured above, and to per-zone
                forwarders. Forwarders default to port 853 unless one pins its
                own. BIND has no client-side HTTP or QUIC transport, so the
                https and quic options are rejected for a group containing a
                BIND9 server — use a Technitium-only group for those.
              </p>
              <label className="flex items-center gap-2 cursor-pointer text-sm">
                <input
                  type="checkbox"
                  checked={forwardTlsVerify}
                  onChange={(e) => {
                    setForwardTlsVerify(e.target.checked);
                    setDirty(true);
                  }}
                  className="h-4 w-4"
                />
                Verify the upstream certificate
              </label>
              {forwardTlsVerify ? (
                <Field label="Upstream TLS hostname (required)">
                  <input
                    className={inputCls}
                    value={forwardTlsHostname}
                    placeholder="cloudflare-dns.com"
                    onChange={(e) => {
                      setForwardTlsHostname(e.target.value);
                      setDirty(true);
                    }}
                  />
                </Field>
              ) : (
                <p className="text-xs text-amber-600">
                  Opportunistic DoT: traffic is encrypted but the upstream isn't
                  authenticated, so an active on-path attacker can still
                  impersonate it. Prefer verification wherever the provider
                  publishes a DoT hostname.
                </p>
              )}
              <p className="text-xs text-muted-foreground">
                One hostname applies to every forwarder, so all of them must
                present it (e.g. 1.1.1.1 + 1.0.0.1 both serve
                cloudflare-dns.com). Mixing providers needs one group per
                provider.
              </p>
            </>
          )}
        </div>
      </div>

      <div className={card}>
        <div className="flex items-center justify-between">
          <h4 className={cardTitle}>
            <Shield className="h-4 w-4 text-muted-foreground" /> dnsdist front
            (PowerDNS)
          </h4>
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={dnsdistEnabled}
              onChange={(e) => {
                setDnsdistEnabled(e.target.checked);
                setDirty(true);
              }}
              className="h-4 w-4"
            />
            Enable
          </label>
        </div>
        <p className="text-xs text-muted-foreground">
          PowerDNS Authoritative has no built-in rate limiting, so a dnsdist
          front (a separate container) forwards to pdns and applies these rules.
          Applies to PowerDNS server groups, and requires the dnsdist front
          deployed (compose <code>dns-powerdns-with-dnsdist</code> profile —
          docker-compose only for now). pdns is unaffected; with the front off
          it's a plain pass-through. Point DNS clients at the front.
        </p>
        {dnsdistEnabled && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Max QPS per client IP (blank = none)">
                <input
                  type="number"
                  min={1}
                  className={inputCls}
                  value={dnsdistMaxQps}
                  onChange={(e) => {
                    setDnsdistMaxQps(e.target.value);
                    setDirty(true);
                  }}
                  placeholder="e.g. 50"
                />
              </Field>
              <Field label="Over-limit action">
                <select
                  className={selCls}
                  value={dnsdistAction}
                  onChange={(e) => {
                    setDnsdistAction(e.target.value);
                    setDirty(true);
                  }}
                >
                  <option value="truncate">
                    truncate (TC=1 — client retries over TCP)
                  </option>
                  <option value="drop">drop (no response)</option>
                </select>
              </Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Dynamic-block QPS (blank = off)">
                <input
                  type="number"
                  min={1}
                  className={inputCls}
                  value={dnsdistDynblockQps}
                  onChange={(e) => {
                    setDnsdistDynblockQps(e.target.value);
                    setDirty(true);
                  }}
                  placeholder="e.g. 200"
                />
              </Field>
              <Field label="Dynamic-block duration (s)">
                <input
                  type="number"
                  min={1}
                  max={86400}
                  className={inputCls}
                  value={dnsdistDynblockSeconds}
                  onChange={(e) => {
                    setDnsdistDynblockSeconds(numOrDefault(e.target.value, 60));
                    setDirty(true);
                  }}
                />
              </Field>
            </div>
          </>
        )}
      </div>

      <div className={card}>
        <h4 className={cardTitle}>Notify</h4>
        <Field label="Notify mode">
          <select
            className={selCls}
            value={notifyEnabled}
            onChange={(e) => {
              setNotifyEnabled(e.target.value);
              setDirty(true);
            }}
          >
            <option value="yes">
              yes — notify all servers listed in NS records
            </option>
            <option value="explicit">
              explicit — only notify servers in also-notify list
            </option>
            <option value="master-only">
              master-only — only send notifies from primary
            </option>
            <option value="no">no — disable zone change notifications</option>
          </select>
        </Field>
      </div>

      <div className={card}>
        <h4 className={cardTitle}>Query &amp; Transfer ACLs</h4>
        <Field label="allow-query (comma-separated CIDRs / ACL names)">
          <input
            className={inputCls}
            value={allowQuery}
            onChange={(e) => {
              setAllowQuery(e.target.value);
              setDirty(true);
            }}
            placeholder="any"
          />
        </Field>
        <Field label="allow-transfer (comma-separated CIDRs / ACL names)">
          <input
            className={inputCls}
            value={allowTransfer}
            onChange={(e) => {
              setAllowTransfer(e.target.value);
              setDirty(true);
            }}
            placeholder="none"
          />
        </Field>
      </div>

      <div className={card}>
        <div className="flex items-center justify-between">
          <h4 className={cardTitle}>
            <FileText className="h-4 w-4 text-muted-foreground" /> Query Logging
          </h4>
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={queryLogEnabled}
              onChange={(e) => {
                setQueryLogEnabled(e.target.checked);
                setDirty(true);
              }}
              className="h-4 w-4"
            />
            Enable
          </label>
        </div>
        {!queryLogEnabled && (
          <p className="text-xs text-muted-foreground">
            DNS query logs are disabled. Enable to record every query received
            by BIND for debugging or audit purposes (high volume — large file
            growth).
          </p>
        )}
        {queryLogEnabled && (
          <>
            {/* Response logging (#914). Nested inside the query-log gate
                because the response lines are written to the same
                channel — the API refuses the other combination rather
                than accepting a toggle that produces nothing. */}
            <label className="flex cursor-pointer items-start gap-2 rounded border bg-muted/20 p-2 text-sm">
              <input
                type="checkbox"
                checked={responseLogEnabled}
                onChange={(e) => {
                  setResponseLogEnabled(e.target.checked);
                  setDirty(true);
                }}
                className="mt-0.5 h-4 w-4"
              />
              <span>
                Record the outcome of each query
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  Adds the RCODE (NOERROR / NXDOMAIN / REFUSED / SERVFAIL) and
                  answer count to every row in the Logs page, which is what
                  separates &ldquo;it is not DNS&rdquo; from &ldquo;an ACL is
                  rejecting this client&rdquo;. BIND9 only, and it roughly
                  doubles query-log volume — named writes a second line per
                  query.
                </span>
              </span>
            </label>
            <Field label="Log channel">
              <select
                className={selCls}
                value={queryLogChannel}
                onChange={(e) => {
                  setQueryLogChannel(e.target.value);
                  setDirty(true);
                }}
              >
                <option value="file">
                  file — write to a log file (rotated by BIND)
                </option>
                <option value="syslog">
                  syslog — send to local syslog (daemon facility)
                </option>
                <option value="stderr">
                  stderr — write to container stderr (visible via docker logs)
                </option>
              </select>
            </Field>
            {queryLogChannel === "file" && (
              <Field label="Log file path (inside container)">
                <input
                  className={inputCls}
                  value={queryLogFile}
                  onChange={(e) => {
                    setQueryLogFile(e.target.value);
                    setDirty(true);
                  }}
                  placeholder="/var/log/named/queries.log"
                />
              </Field>
            )}
            <Field label="Severity">
              <select
                className={selCls}
                value={queryLogSeverity}
                onChange={(e) => {
                  setQueryLogSeverity(e.target.value);
                  setDirty(true);
                }}
              >
                <option value="info">
                  info — normal queries (recommended)
                </option>
                <option value="debug">
                  debug — very verbose; for troubleshooting only
                </option>
                <option value="notice">notice — only notable events</option>
                <option value="warning">warning — warnings and above</option>
                <option value="error">error — errors only</option>
              </select>
            </Field>
            <p className="text-xs text-muted-foreground">
              Logs the <code>queries</code> and <code>query-errors</code>{" "}
              categories. View with{" "}
              <code className="font-mono">docker logs</code> (stderr) or{" "}
              <code className="font-mono">
                docker exec &lt;dns-container&gt; tail -f {queryLogFile}
              </code>{" "}
              (file).
            </p>
          </>
        )}
      </div>
    </div>
  );
}

// ── Records Tab ───────────────────────────────────────────────────────────────
// Group-wide view of every record across every zone. Mirrors the IPAM subnet
// address-table filter pattern: per-column inputs with a contains/begins/ends
// /regex mode picker for text columns, dropdowns for Type / Zone / View /
// Source, click-to-sort on every header.

type RecordFilterMode = "contains" | "begins" | "ends" | "regex";

function applyTextFilter(
  value: string | null | undefined,
  filter: string,
  mode: RecordFilterMode,
): boolean {
  if (!filter) return true;
  const v = (value ?? "").toLowerCase();
  const f = filter.toLowerCase();
  if (mode === "begins") return v.startsWith(f);
  if (mode === "ends") return v.endsWith(f);
  if (mode === "regex") {
    try {
      return new RegExp(filter, "i").test(value ?? "");
    } catch {
      return true;
    }
  }
  return v.includes(f);
}

function RecordsTab({
  group,
  onSelectZone,
}: {
  group: DNSServerGroup;
  onSelectZone: (z: DNSZone) => void;
}) {
  const qc = useQueryClient();
  // Server-side pagination + search (#455). `groupRecordSearch` matches
  // name / fqdn / value / type / zone on the server; the per-column filters
  // below stay client-side refinements over the current page.
  const [groupRecordSearch, setGroupRecordSearch] = useState("");
  const [groupRecordPage, setGroupRecordPage] = useState(1);
  const groupRecordPageSize = 100;
  const groupRecordParams = useMemo(() => {
    const p: { page: number; page_size: number; search?: string } = {
      page: groupRecordPage,
      page_size: groupRecordPageSize,
    };
    if (groupRecordSearch.trim()) p.search = groupRecordSearch.trim();
    return p;
  }, [groupRecordPage, groupRecordSearch]);
  const { data: groupRecordsPage, isLoading } = useQuery({
    queryKey: ["dns-group-records", group.id, groupRecordParams],
    queryFn: () => dnsApi.listGroupRecords(group.id, groupRecordParams),
  });
  const records = groupRecordsPage?.items ?? [];
  const recordsTotal = groupRecordsPage?.total ?? 0;
  const { data: zones = [] } = useQuery({
    queryKey: ["dns-zones", group.id],
    queryFn: () => dnsApi.listZones(group.id),
  });
  const { data: views = [] } = useQuery({
    queryKey: ["dns-views", group.id],
    queryFn: () => dnsApi.listViews(group.id),
  });

  type ColKey = "name" | "type" | "zone" | "value" | "ttl" | "view" | "source";

  const [colFilters, setColFilters] = useState<Record<ColKey, string>>({
    name: "",
    type: "",
    zone: "",
    value: "",
    ttl: "",
    view: "",
    source: "",
  });
  const [filterModes, setFilterModes] = useState<
    Partial<Record<ColKey, RecordFilterMode>>
  >({});
  const [openFilterMenu, setOpenFilterMenu] = useState<ColKey | null>(null);
  const [editing, setEditing] = useState<DNSGroupRecord | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<DNSGroupRecord | null>(
    null,
  );

  const uniqueTypes = Array.from(
    new Set(records.map((r) => r.record_type)),
  ).sort();

  const filtered = records.filter((r) => {
    if (
      !applyTextFilter(
        r.name || "@",
        colFilters.name,
        filterModes.name ?? "contains",
      )
    )
      return false;
    if (colFilters.type && r.record_type !== colFilters.type) return false;
    if (
      !applyTextFilter(
        r.zone_name,
        colFilters.zone,
        filterModes.zone ?? "contains",
      )
    )
      return false;
    if (
      !applyTextFilter(
        r.value,
        colFilters.value,
        filterModes.value ?? "contains",
      )
    )
      return false;
    if (colFilters.ttl) {
      const ttlStr = r.ttl === null ? "" : String(r.ttl);
      if (!ttlStr.includes(colFilters.ttl)) return false;
    }
    if (colFilters.view) {
      if (colFilters.view === "__none__") {
        if (r.view_id) return false;
      } else if (r.view_id !== colFilters.view) {
        return false;
      }
    }
    if (colFilters.source) {
      const src = r.auto_generated ? "auto" : "user";
      if (src !== colFilters.source) return false;
    }
    return true;
  });

  const { sorted, sort, toggle } = useTableSort<DNSGroupRecord, ColKey>(
    filtered,
    { key: "name", dir: "asc" },
    (row, key) => {
      if (key === "name") return row.fqdn;
      if (key === "type") return row.record_type;
      if (key === "zone") return row.zone_name;
      if (key === "value") return row.value;
      if (key === "ttl") return row.ttl ?? -1;
      if (key === "view") return row.view_name ?? "";
      if (key === "source") return row.auto_generated ? "auto" : "user";
      return "";
    },
  );

  const deleteMut = useMutation({
    mutationFn: (rec: DNSGroupRecord) =>
      dnsApi.deleteRecord(group.id, rec.zone_id, rec.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-group-records", group.id] });
      qc.invalidateQueries({ queryKey: ["dns-records"] });
      setConfirmDelete(null);
    },
  });

  const hasActiveFilter = Object.values(colFilters).some(Boolean);
  function clearFilters() {
    setColFilters({
      name: "",
      type: "",
      zone: "",
      value: "",
      ttl: "",
      view: "",
      source: "",
    });
    setFilterModes({});
  }

  const TEXT_COLS: ColKey[] = ["name", "zone", "value", "ttl"];

  function renderFilterCell(col: ColKey) {
    if (col === "type") {
      return (
        <select
          value={colFilters.type}
          onChange={(e) =>
            setColFilters((p) => ({ ...p, type: e.target.value }))
          }
          className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
        >
          <option value="">All</option>
          {uniqueTypes.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      );
    }
    if (col === "view") {
      return (
        <select
          value={colFilters.view}
          onChange={(e) =>
            setColFilters((p) => ({ ...p, view: e.target.value }))
          }
          className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
        >
          <option value="">All</option>
          <option value="__none__">— none —</option>
          {views.map((v) => (
            <option key={v.id} value={v.id}>
              {v.name}
            </option>
          ))}
        </select>
      );
    }
    if (col === "source") {
      return (
        <select
          value={colFilters.source}
          onChange={(e) =>
            setColFilters((p) => ({ ...p, source: e.target.value }))
          }
          className="w-full rounded border bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
        >
          <option value="">All</option>
          <option value="user">User</option>
          <option value="auto">Auto (IPAM/DHCP)</option>
        </select>
      );
    }
    if (!TEXT_COLS.includes(col)) return null;
    const mode = filterModes[col] ?? "contains";
    return (
      <div className="flex items-center">
        <input
          type="text"
          value={colFilters[col]}
          onChange={(e) =>
            setColFilters((p) => ({ ...p, [col]: e.target.value }))
          }
          placeholder="Filter…"
          className="w-full min-w-0 rounded-l border border-r-0 bg-background px-1.5 py-0.5 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
        />
        <div className="relative">
          <button
            type="button"
            onClick={() =>
              setOpenFilterMenu(openFilterMenu === col ? null : col)
            }
            className="rounded-r border bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground hover:bg-accent"
            title="Filter mode"
          >
            {mode === "begins"
              ? "^"
              : mode === "ends"
                ? "$"
                : mode === "regex"
                  ? ".*"
                  : "⊂"}
          </button>
          {openFilterMenu === col && (
            <div className="absolute left-0 top-full z-30 mt-0.5 w-32 rounded-md border bg-popover shadow-md">
              {(
                [
                  ["contains", "⊂ Contains"],
                  ["begins", "^ Begins"],
                  ["ends", "$ Ends"],
                  ["regex", ".* Regex"],
                ] as const
              ).map(([m, label]) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => {
                    setFilterModes((p) => ({ ...p, [col]: m }));
                    setOpenFilterMenu(null);
                  }}
                  className={cn(
                    "w-full px-3 py-1.5 text-left text-xs hover:bg-accent",
                    mode === m && "font-semibold text-primary",
                  )}
                >
                  {label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  if (isLoading) {
    return <p className="text-sm text-muted-foreground">Loading records…</p>;
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <input
            className="w-72 rounded-md border bg-background px-2 py-1 text-xs"
            placeholder="Search name / value / type / zone…"
            value={groupRecordSearch}
            onChange={(e) => {
              setGroupRecordSearch(e.target.value);
              setGroupRecordPage(1);
            }}
          />
          <p className="text-xs text-muted-foreground">
            {filtered.length.toLocaleString()} of{" "}
            {recordsTotal.toLocaleString()}{" "}
            {recordsTotal === 1 ? "record" : "records"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Pager
            page={groupRecordPage}
            total={recordsTotal}
            pageSize={groupRecordPageSize}
            onChange={setGroupRecordPage}
          />
          {hasActiveFilter && (
            <button
              onClick={clearFilters}
              className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs text-muted-foreground hover:bg-accent"
            >
              <X className="h-3 w-3" />
              Clear filters
            </button>
          )}
        </div>
      </div>

      <div className="overflow-hidden rounded-lg border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/40 text-xs">
              <SortableTh sortKey="name" sort={sort} onSort={toggle}>
                Name
              </SortableTh>
              <SortableTh sortKey="type" sort={sort} onSort={toggle}>
                Type
              </SortableTh>
              <SortableTh sortKey="zone" sort={sort} onSort={toggle}>
                Zone
              </SortableTh>
              <SortableTh sortKey="value" sort={sort} onSort={toggle}>
                Value
              </SortableTh>
              <SortableTh
                sortKey="ttl"
                sort={sort}
                onSort={toggle}
                align="right"
              >
                TTL
              </SortableTh>
              <SortableTh sortKey="view" sort={sort} onSort={toggle}>
                View
              </SortableTh>
              <SortableTh sortKey="source" sort={sort} onSort={toggle}>
                Source
              </SortableTh>
              <th className="px-2 py-2 text-right" />
            </tr>
            <tr className="border-b bg-muted/10 text-xs">
              {(
                [
                  "name",
                  "type",
                  "zone",
                  "value",
                  "ttl",
                  "view",
                  "source",
                ] as ColKey[]
              ).map((col) => (
                <td key={col} className="px-2 py-1">
                  {renderFilterCell(col)}
                </td>
              ))}
              <td />
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {sorted.length === 0 ? (
              <tr>
                <td
                  colSpan={8}
                  className="px-4 py-8 text-center text-sm text-muted-foreground"
                >
                  {recordsTotal === 0
                    ? "No records in this group yet."
                    : "No records match the active filters."}
                </td>
              </tr>
            ) : (
              sorted.map((rec) => {
                const zone = zones.find((z) => z.id === rec.zone_id);
                return (
                  <tr
                    key={rec.id}
                    className="border-b last:border-0 hover:bg-muted/20"
                  >
                    <td className="px-4 py-2 font-mono text-xs">
                      <button
                        onClick={() => zone && onSelectZone(zone)}
                        className="hover:underline"
                        title="Open zone"
                      >
                        {rec.fqdn}
                      </button>
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${RECORD_TYPE_BADGE[rec.record_type] ?? RECORD_TYPE_BADGE_FALLBACK}`}
                      >
                        {rec.record_type}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                      {rec.zone_name}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                      {rec.value}
                    </td>
                    <td className="px-4 py-2 text-right text-xs tabular-nums text-muted-foreground">
                      {rec.ttl ?? (
                        <span className="text-muted-foreground/40">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {rec.view_name ?? (
                        <span className="text-muted-foreground/40">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      {rec.auto_generated ? (
                        <span
                          className="inline-flex items-center rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-700 dark:bg-amber-900/30 dark:text-amber-400"
                          title="Auto-managed by IPAM or DHCP"
                        >
                          auto
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                          user
                        </span>
                      )}
                    </td>
                    <td className="px-2 py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setEditing(rec)}
                          disabled={rec.auto_generated}
                          className="rounded p-1 text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:pointer-events-none"
                          title={
                            rec.auto_generated
                              ? "Auto-managed — edit the source IP/lease"
                              : "Edit"
                          }
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          onClick={() => setConfirmDelete(rec)}
                          disabled={rec.auto_generated}
                          className="rounded p-1 text-muted-foreground hover:text-destructive disabled:opacity-30 disabled:pointer-events-none"
                          title={
                            rec.auto_generated
                              ? "Auto-managed — delete the source IP/lease"
                              : "Delete"
                          }
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
      <Pager
        page={groupRecordPage}
        total={recordsTotal}
        pageSize={groupRecordPageSize}
        onChange={setGroupRecordPage}
      />

      {editing && (
        <RecordModal
          groupId={group.id}
          zoneId={editing.zone_id}
          zoneName={editing.zone_name}
          record={{
            id: editing.id,
            zone_id: editing.zone_id,
            view_id: editing.view_id,
            name: editing.name,
            fqdn: editing.fqdn,
            record_type: editing.record_type,
            value: editing.value,
            ttl: editing.ttl,
            priority: editing.priority,
            weight: editing.weight,
            port: editing.port,
            auto_generated: editing.auto_generated,
            tailscale_tenant_id: editing.tailscale_tenant_id ?? null,
            pool_member_id: editing.pool_member_id ?? null,
            created_at: editing.created_at,
            modified_at: editing.modified_at,
          }}
          onClose={() => {
            setEditing(null);
            qc.invalidateQueries({
              queryKey: ["dns-group-records", group.id],
            });
          }}
        />
      )}

      {confirmDelete && (
        <Modal title="Delete DNS record" onClose={() => setConfirmDelete(null)}>
          <div className="space-y-3">
            <p className="text-sm">
              Delete{" "}
              <span className="font-mono font-medium">
                {confirmDelete.fqdn}
              </span>{" "}
              <span className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium">
                {confirmDelete.record_type}
              </span>
              ? This cannot be undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setConfirmDelete(null)}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={() => deleteMut.mutate(confirmDelete)}
                disabled={deleteMut.isPending}
                className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
              >
                {deleteMut.isPending ? "Deleting…" : "Delete"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

// ── Zones Tab ─────────────────────────────────────────────────────────────────

function ZonesTab({
  group,
  onSelectZone,
}: {
  group: DNSServerGroup;
  onSelectZone: (z: DNSZone) => void;
}) {
  const qc = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [showFromTemplate, setShowFromTemplate] = useState(false);
  const [showZoneFilters, setShowZoneFilters] = useState(false);
  const [zoneNameFilter, setZoneNameFilter] = useState("");
  const [zoneTypeFilter, setZoneTypeFilter] = useState("");
  // #986 — "" is all scopes.
  const [zoneScopeFilter, setZoneScopeFilter] = useState<"" | ZoneNameScope>(
    "",
  );
  const [tagFilters, setTagFilters] = useState<string[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);

  const { data: zones = [], isFetching } = useQuery({
    queryKey: ["dns-zones", group.id, tagFilters],
    queryFn: () =>
      dnsApi.listZones(
        group.id,
        tagFilters.length > 0 ? { tag: tagFilters } : undefined,
      ),
  });

  const { data: views = [] } = useQuery({
    queryKey: ["dns-views", group.id],
    queryFn: () => dnsApi.listViews(group.id),
  });

  const hasZoneFilter = !!(zoneNameFilter || zoneTypeFilter || zoneScopeFilter);
  const filteredZones = hasZoneFilter
    ? zones.filter((z) => {
        if (
          zoneNameFilter &&
          !z.name.toLowerCase().includes(zoneNameFilter.toLowerCase())
        )
          return false;
        if (zoneTypeFilter && z.zone_type !== zoneTypeFilter) return false;
        if (zoneScopeFilter && z.name_scope !== zoneScopeFilter) return false;
        return true;
      })
    : zones;
  const tree = buildDnsTree(filteredZones);

  const typeBadge: Record<string, string> = {
    primary: "bg-blue-500/15 text-blue-600",
    secondary: "bg-violet-500/15 text-violet-600",
    stub: "bg-amber-500/15 text-amber-600",
    forward: "bg-muted text-muted-foreground",
  };

  const filteredIds = filteredZones.map((z) => z.id);
  const allFilteredSelected =
    filteredIds.length > 0 && filteredIds.every((id) => selected.has(id));
  const someFilteredSelected =
    !allFilteredSelected && filteredIds.some((id) => selected.has(id));

  function toggleAll() {
    if (allFilteredSelected) {
      setSelected((prev) => {
        const next = new Set(prev);
        for (const id of filteredIds) next.delete(id);
        return next;
      });
    } else {
      setSelected((prev) => {
        const next = new Set(prev);
        for (const id of filteredIds) next.add(id);
        return next;
      });
    }
  }
  function toggleOne(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const bulkDeleteZones = useMutation({
    mutationFn: async (ids: string[]) => {
      await Promise.allSettled(
        ids.map((id) => dnsApi.deleteZone(group.id, id)),
      );
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-zones", group.id] });
      setSelected(new Set());
      setConfirmBulkDelete(false);
    },
  });

  function renderZoneRows(node: DnsTreeNode, depth: number): React.ReactNode[] {
    const rows: React.ReactNode[] = [];
    const indent = depth * 14;
    if (node.zone) {
      const z = node.zone;
      const sel = selected.has(z.id);
      rows.push(
        <ContextMenu key={z.id}>
          <ContextMenuTrigger asChild>
            <tr
              className={cn(
                "border-b last:border-0 hover:bg-muted/30",
                sel && "bg-primary/5",
              )}
            >
              <td className="w-8 px-2 py-1">
                <input
                  type="checkbox"
                  checked={sel}
                  onChange={() => toggleOne(z.id)}
                  onClick={(e) => e.stopPropagation()}
                />
              </td>
              <td
                className="py-1 pr-2 cursor-pointer"
                onClick={() => onSelectZone(z)}
              >
                <span
                  className="inline-flex items-center gap-1.5"
                  style={{ paddingLeft: indent }}
                >
                  {swatchCls(z.color) ? (
                    <span
                      className={cn(
                        "h-2 w-2 rounded-full flex-shrink-0",
                        swatchCls(z.color)!,
                      )}
                    />
                  ) : (
                    <FileText className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                  )}
                  <span className="font-mono text-xs">
                    {z.name.replace(/\.$/, "")}
                  </span>
                  <CustomerChip customerId={z.customer_id} />
                </span>
              </td>
              <td className="py-1 pr-2">
                <ZoneScopePill
                  scope={z.name_scope}
                  detail={z.name_scope_detail}
                />
              </td>
              <td className="py-1">
                <span
                  className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium ${typeBadge[z.zone_type] ?? "bg-muted text-muted-foreground"}`}
                >
                  {z.zone_type}
                </span>
              </td>
              <td className="py-1 tabular-nums text-xs text-muted-foreground">
                {z.ttl}
              </td>
              <td className="py-1 text-xs">
                {z.dnssec_enabled ? (
                  <span className="inline-flex items-center gap-1 text-emerald-600">
                    <Shield className="h-3 w-3" /> on
                  </span>
                ) : (
                  <span className="text-muted-foreground/50">—</span>
                )}
              </td>
              <td className="py-1 text-xs text-muted-foreground">
                {z.last_pushed_at
                  ? new Date(z.last_pushed_at).toLocaleString()
                  : "—"}
              </td>
              <td className="py-1 pr-2 text-right">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectZone(z);
                  }}
                  className="inline-flex h-5 w-5 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground"
                  title="Open zone"
                >
                  <Pencil className="h-3 w-3" />
                </button>
              </td>
            </tr>
          </ContextMenuTrigger>
          <ContextMenuContent>
            <ContextMenuLabel>{z.name.replace(/\.$/, "")}</ContextMenuLabel>
            <ContextMenuSeparator />
            <ContextMenuItem onSelect={() => onSelectZone(z)}>
              Open Zone
            </ContextMenuItem>
            <ContextMenuItem
              onSelect={() => copyToClipboard(z.name.replace(/\.$/, ""))}
            >
              Copy Name
            </ContextMenuItem>
            <ContextMenuItem
              onSelect={async () => {
                const { data, filename } = await dnsApi.exportZone(
                  group.id,
                  z.id,
                );
                const name =
                  filename ??
                  `${z.name.replace(/\.$/, "")}-${_utcTimestampSuffix()}.zone`;
                downloadBlob(data, name, "text/dns");
              }}
            >
              Export Zone File
            </ContextMenuItem>
          </ContextMenuContent>
        </ContextMenu>,
      );
    } else {
      rows.push(
        <tr
          key={`folder:${node.domain}`}
          className="bg-muted/10 border-b last:border-0"
        >
          <td />
          <td colSpan={7} className="py-0.5">
            <span
              className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground/70"
              style={{ paddingLeft: indent }}
            >
              <Folder className="h-3 w-3" />.{node.domain}
            </span>
          </td>
        </tr>,
      );
    }
    for (const child of node.children) {
      rows.push(...renderZoneRows(child, depth + 1));
    }
    return rows;
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          {hasZoneFilter
            ? `${filteredZones.length} / ${zones.length}`
            : zones.length}{" "}
          zone{zones.length !== 1 ? "s" : ""}
          {selected.size > 0 && (
            <span className="ml-2 text-primary normal-case tracking-normal">
              {selected.size} selected
            </span>
          )}
        </span>
        <div className="flex items-center gap-2 flex-wrap">
          {selected.size > 0 && (
            <>
              <button
                onClick={() => setConfirmBulkDelete(true)}
                className="flex items-center gap-1 rounded-md bg-destructive px-2 py-1 text-xs text-destructive-foreground hover:bg-destructive/90"
              >
                <Trash2 className="h-3 w-3" /> Delete {selected.size}
              </button>
              <button
                onClick={() => setSelected(new Set())}
                className="rounded-md border px-2 py-1 text-xs hover:bg-accent"
              >
                Clear
              </button>
              <span className="h-4 w-px bg-border" />
            </>
          )}
          <button
            onClick={() => setShowZoneFilters((v) => !v)}
            title="Toggle filters"
            className={`flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent ${showZoneFilters ? "bg-muted" : ""}`}
          >
            <Filter className="h-3 w-3" />
            {hasZoneFilter && (
              <span className="h-1.5 w-1.5 rounded-full bg-primary" />
            )}
          </button>
          <button
            className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted disabled:opacity-50"
            disabled={zones.length === 0}
            onClick={async () => {
              const { data, filename } = await dnsApi.exportAllZones(group.id);
              const name =
                filename ??
                `dns-zones-${group.id}-${_utcTimestampSuffix()}.zip`;
              downloadBlob(data, name, "application/zip");
            }}
          >
            <Download className="h-3.5 w-3.5" /> Export All
          </button>
          <button
            className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted/50"
            onClick={() => setShowFromTemplate(true)}
            title="Stamp a starter zone from a curated template (mail, AD, web, k8s)"
          >
            <Sparkles className="h-3 w-3" /> From Template
          </button>
          <button
            className="flex items-center gap-1 rounded-md bg-primary px-2 py-1 text-xs text-primary-foreground hover:bg-primary/90"
            onClick={() => setShowAdd(true)}
          >
            <Plus className="h-3 w-3" /> Add Zone
          </button>
        </div>
      </div>

      <div className="mb-3">
        <TagFilterChips
          value={tagFilters}
          onChange={setTagFilters}
          placeholder="Filter zones by tag — try env or env:prod…"
        />
      </div>

      {showZoneFilters && (
        <div className="mb-3 flex items-center gap-2 rounded-md border bg-muted/10 px-3 py-2">
          <input
            type="text"
            value={zoneNameFilter}
            onChange={(e) => setZoneNameFilter(e.target.value)}
            placeholder="Filter by name…"
            className="flex-1 rounded border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
          />
          <select
            value={zoneTypeFilter}
            onChange={(e) => setZoneTypeFilter(e.target.value)}
            className="rounded border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option value="">All types</option>
            {["primary", "secondary", "stub", "forward"].map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <select
            value={zoneScopeFilter}
            onChange={(e) =>
              setZoneScopeFilter(e.target.value as "" | ZoneNameScope)
            }
            title="Filter by the TLD scope of the zone name (#986)"
            className="rounded border border-border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option value="">All scopes</option>
            <option value="public">Public</option>
            <option value="reserved">Private (reserved)</option>
            <option value="undelegated">Undelegated</option>
            <option value="reverse">Reverse</option>
          </select>
          {hasZoneFilter && (
            <button
              onClick={() => {
                setZoneNameFilter("");
                setZoneTypeFilter("");
                setZoneScopeFilter("");
              }}
              className="text-xs text-muted-foreground hover:text-foreground"
              title="Clear filters"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      )}

      {isFetching && zones.length === 0 && (
        <p className="text-sm text-muted-foreground">Loading…</p>
      )}
      {zones.length === 0 && !isFetching && (
        <p className="text-sm text-muted-foreground italic">
          No zones yet. Click "Add Zone" to create one.
        </p>
      )}
      {hasZoneFilter && filteredZones.length === 0 && zones.length > 0 && (
        <p className="text-sm text-muted-foreground italic">
          No zones match the current filter.
        </p>
      )}

      {zones.length > 0 && (
        <div className="rounded-md border overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/30 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                <th className="w-8 px-2 py-1.5">
                  <input
                    type="checkbox"
                    checked={allFilteredSelected}
                    ref={(el) => {
                      if (el) el.indeterminate = someFilteredSelected;
                    }}
                    onChange={toggleAll}
                    aria-label="Select all filtered zones"
                  />
                </th>
                <th className="py-1.5 font-medium">Name</th>
                <th className="py-1.5 font-medium">Scope</th>
                <th className="py-1.5 font-medium">Type</th>
                <th className="py-1.5 font-medium">TTL</th>
                <th className="py-1.5 font-medium">DNSSEC</th>
                <th className="py-1.5 font-medium">Last Push</th>
                <th className="py-1.5" />
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {tree.flatMap((root) => renderZoneRows(root, 0))}
            </tbody>
          </table>
        </div>
      )}

      {showAdd && (
        <ZoneModal
          groupId={group.id}
          views={views}
          onClose={() => setShowAdd(false)}
        />
      )}
      {showFromTemplate && (
        <ZoneTemplateModal
          groupId={group.id}
          onClose={() => setShowFromTemplate(false)}
          onCreated={(zone) => {
            setShowFromTemplate(false);
            // Navigate the operator straight into the freshly-created zone.
            onSelectZone(zone);
          }}
        />
      )}

      {confirmBulkDelete && (
        <ConfirmDestroyModal
          title={`Delete ${selected.size} zone${selected.size === 1 ? "" : "s"}`}
          description={
            <>
              Permanently delete the{" "}
              <span className="font-medium">{selected.size}</span> selected zone
              {selected.size === 1 ? "" : "s"} and all their records from
              SpatiumDDI? This cannot be undone.
            </>
          }
          checkLabel={`I understand ${selected.size} zone${selected.size === 1 ? "" : "s"} and all their records will be permanently deleted.`}
          isPending={bulkDeleteZones.isPending}
          onClose={() => setConfirmBulkDelete(false)}
          onConfirm={() => bulkDeleteZones.mutate(Array.from(selected))}
        />
      )}
    </div>
  );
}

// ── Blocklists Tab ────────────────────────────────────────────────────────────

/**
 * Choose where a blocking list applies (#876).
 *
 * The backend has carried two independent relationships since #24 —
 * ``server_groups`` (every client of the group) and ``views`` (only
 * clients matching that view's address list) — but the UI only ever wrote
 * the first, so per-subnet filtering was unreachable from the product
 * despite being fully rendered by the agent.
 *
 * Both are written in one PUT so the two halves can't diverge, and so the
 * de-assigned groups get woken too (the endpoint unions old and new
 * affected groups before publishing the config wake).
 */
function BlocklistScopeModal({
  list,
  group,
  views,
  onClose,
}: {
  list: DNSBlockList;
  group: DNSServerGroup;
  views: DNSView[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [wholeGroup, setWholeGroup] = useState(
    list.applied_group_ids.includes(group.id),
  );
  // Only THIS group's views — the checkbox list below renders no others, so
  // seeding from the raw ``applied_view_ids`` would park an un-unpickable
  // id in the state that the footer then counts ("Applies to 1 view" about a
  // view of some other group) and that ships duplicated in the PUT alongside
  // ``otherViews``.
  const [picked, setPicked] = useState<Set<string>>(() => {
    const thisGroups = new Set(views.map((v) => v.id));
    return new Set(
      (list.applied_view_ids ?? []).filter((v) => thisGroups.has(v)),
    );
  });
  const [error, setError] = useState("");

  const { data: servers = [] } = useQuery({
    queryKey: ["dns-servers", group.id],
    queryFn: () => dnsApi.listServers(group.id),
  });
  const nonBind = Array.from(
    new Set(servers.filter((s) => s.driver !== "bind9").map((s) => s.driver)),
  );

  const saveMut = useMutation({
    mutationFn: () => {
      // Preserve assignments to OTHER groups and to views of other groups —
      // this modal only speaks for the group it was opened from, and the
      // endpoint replaces each list wholesale.
      const otherGroups = list.applied_group_ids.filter((g) => g !== group.id);
      const thisGroupsViews = new Set(views.map((v) => v.id));
      const otherViews = (list.applied_view_ids ?? []).filter(
        (v) => !thisGroupsViews.has(v),
      );
      return dnsBlocklistApi.updateAssignments(list.id, {
        server_group_ids: wholeGroup ? [...otherGroups, group.id] : otherGroups,
        view_ids: [...otherViews, ...Array.from(picked)],
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      onClose();
    },
    onError: (e: ApiError) => setError(formatApiError(e, "Save failed")),
  });

  const nothingSelected = !wholeGroup && picked.size === 0;

  return (
    <Modal title={`Scope "${list.name}"`} onClose={onClose} wide>
      <div className="space-y-3">
        {nonBind.length > 0 && (
          <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-2 text-xs text-amber-700 dark:text-amber-400">
            This group also runs {nonBind.join(" / ")}, which
            {nonBind.length === 1 ? " does" : " do"} not render RPZ blocking.
            Scoping affects the BIND9 servers only.
          </div>
        )}

        <label className="flex cursor-pointer items-start gap-2 rounded-md border p-2.5 hover:bg-accent/30">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={wholeGroup}
            onChange={(e) => setWholeGroup(e.target.checked)}
          />
          <span className="text-sm">
            <span className="font-medium">Whole group</span>
            <span className="block text-xs text-muted-foreground">
              Every client {group.name} answers, including clients of every
              view.
            </span>
          </span>
        </label>

        <div>
          <p className="mb-1 text-xs font-medium text-muted-foreground">
            Specific views
          </p>
          {views.length === 0 ? (
            <p className="rounded-md border border-dashed p-3 text-xs text-muted-foreground">
              No views defined in this group. Create one on the Views tab to
              apply a list to a subset of clients — that is how "adult lists on
              the guest VLAN only" is expressed.
            </p>
          ) : (
            <div className="space-y-1">
              {views.map((v) => (
                <label
                  key={v.id}
                  className={cn(
                    "flex cursor-pointer items-start gap-2 rounded-md border p-2 hover:bg-accent/30",
                    wholeGroup && "opacity-50",
                  )}
                >
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={picked.has(v.id)}
                    onChange={() =>
                      setPicked((prev) => {
                        const next = new Set(prev);
                        if (next.has(v.id)) next.delete(v.id);
                        else next.add(v.id);
                        return next;
                      })
                    }
                  />
                  <span className="min-w-0 text-sm">
                    <span className="font-mono">{v.name}</span>
                    <span className="mt-0.5 flex flex-wrap gap-1">
                      {v.match_clients.map((c) => (
                        <span
                          key={c}
                          className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[11px] font-mono"
                        >
                          {c}
                        </span>
                      ))}
                    </span>
                  </span>
                </label>
              ))}
            </div>
          )}
          {wholeGroup && picked.size > 0 && (
            <p className="mt-1 text-[11px] text-muted-foreground">
              The group-wide assignment already covers every view, so these
              per-view selections add nothing while it is on. They are kept so
              unchecking "Whole group" narrows the list rather than removing it
              everywhere.
            </p>
          )}
        </div>

        {error && <p className="text-xs text-destructive">{error}</p>}

        <div className="flex items-center justify-between border-t pt-3">
          <span className="text-xs text-muted-foreground">
            {nothingSelected
              ? "Not applied anywhere in this group."
              : wholeGroup
                ? "Applies to every client of this group."
                : `Applies to ${picked.size} view${picked.size === 1 ? "" : "s"}.`}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              className="rounded-md border px-3 py-1.5 text-xs hover:bg-accent"
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={saveMut.isPending}
              className="rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground disabled:opacity-50"
              onClick={() => saveMut.mutate()}
            >
              {saveMut.isPending ? "Saving…" : "Save scope"}
            </button>
          </div>
        </div>
      </div>
    </Modal>
  );
}

function BlocklistsTab({ group }: { group: DNSServerGroup }) {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<DNSBlockList | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showCatalog, setShowCatalog] = useState(false);
  const [editList, setEditList] = useState<DNSBlockList | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<DNSBlockList | null>(null);
  // #876 — per-view scoping. Editing which views a list applies to is a
  // separate action from the group-wide Apply/Detach toggle, because they
  // write two different relationships.
  const [scopeList, setScopeList] = useState<DNSBlockList | null>(null);
  // Bulk-select state. Keyed by blocklist id; spans both sections so the
  // operator can apply / detach / refresh / delete a mixed selection.
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false);

  // Track baselines so we can detect when an in-flight refresh has actually
  // finished writing rows. Stamping `last_synced_at` is the proxy.
  const refreshBaselineRef = useRef<Map<string, string | null>>(new Map());
  // Per-row in-flight set; the refresh task takes 10–60s, far longer than
  // the API call to enqueue it. Driven by onMutate / onError plus an
  // effect that clears entries once the row's last_synced_at advances.
  const [refreshing, setRefreshing] = useState<Set<string>>(new Set());

  const { data: lists = [], isFetching } = useQuery({
    queryKey: ["dns-blocklists"],
    queryFn: () => dnsBlocklistApi.list(),
    // While any row is mid-refresh, poll every 3s so the entry_count
    // updates without the operator having to refresh the page. The
    // task itself takes 10–60s; the refetch interval clears once
    // every pending row's last_synced_at has advanced past its baseline.
    refetchInterval: refreshing.size > 0 ? 3000 : false,
  });

  // Clear the per-row pending flag as soon as the row's last_synced_at
  // advances past the value it had when the refresh was kicked off.
  useEffect(() => {
    if (refreshing.size === 0) return;
    setRefreshing((prev) => {
      const next = new Set(prev);
      for (const id of prev) {
        const baseline = refreshBaselineRef.current.get(id) ?? null;
        const row = lists.find((l) => l.id === id);
        if (row && row.last_synced_at && row.last_synced_at !== baseline) {
          next.delete(id);
          refreshBaselineRef.current.delete(id);
        }
      }
      return next.size === prev.size ? prev : next;
    });
  }, [lists, refreshing]);

  const { data: views = [] } = useQuery({
    queryKey: ["dns-views", group.id],
    queryFn: () => dnsApi.listViews(group.id),
  });
  const viewIds = useMemo(() => new Set(views.map((v) => v.id)), [views]);
  const viewName = useMemo(
    () => new Map(views.map((v) => [v.id, v.name])),
    [views],
  );

  /** Views of THIS group that ``l`` is scoped to. */
  const scopedViews = (l: DNSBlockList) =>
    (l.applied_view_ids ?? []).filter((id) => viewIds.has(id));

  // A list scoped to a view of this group IS applied here — the bundle
  // renders it inside that view's ``response-policy``. Classifying purely
  // on ``applied_group_ids`` (as this did before #876 surfaced view
  // scoping) filed those lists under "Available (not applied)", which
  // reads as "this list is doing nothing" about a list that is actively
  // filtering a VLAN.
  const groupAssigned = (l: DNSBlockList) =>
    l.applied_group_ids.includes(group.id);
  const appliesHere = (l: DNSBlockList) =>
    l.applied_group_ids.includes(group.id) || scopedViews(l).length > 0;
  const applied = lists.filter(appliesHere);
  const other = lists.filter((l) => !appliesHere(l));

  // Selection helpers — both per-row and per-section.
  function toggleOne(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }
  function toggleSection(rows: DNSBlockList[]) {
    const ids = rows.map((r) => r.id);
    const allSel = ids.length > 0 && ids.every((id) => selectedIds.has(id));
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allSel) ids.forEach((id) => next.delete(id));
      else ids.forEach((id) => next.add(id));
      return next;
    });
  }
  const selectedRows = lists.filter((l) => selectedIds.has(l.id));
  const selCount = selectedRows.length;
  const selAppliedCount = selectedRows.filter((l) =>
    l.applied_group_ids.includes(group.id),
  ).length;
  const selDetachedCount = selCount - selAppliedCount;
  const selRefreshableCount = selectedRows.filter(
    (l) => l.source_type === "url" && l.feed_url,
  ).length;

  const deleteMut = useMutation({
    mutationFn: (id: string) => dnsBlocklistApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      setConfirmDelete(null);
      if (selected && confirmDelete && selected.id === confirmDelete.id)
        setSelected(null);
    },
  });

  const toggleAssignment = useMutation({
    mutationFn: async ({
      list,
      assign,
    }: {
      list: DNSBlockList;
      assign: boolean;
    }) => {
      const ids = new Set(list.applied_group_ids);
      if (assign) ids.add(group.id);
      else ids.delete(group.id);
      return dnsBlocklistApi.updateAssignments(list.id, {
        server_group_ids: Array.from(ids),
      });
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-blocklists"] }),
  });

  const refreshMut = useMutation({
    mutationFn: (id: string) => dnsBlocklistApi.refresh(id),
    onMutate: (id) => {
      const row = lists.find((l) => l.id === id);
      refreshBaselineRef.current.set(id, row?.last_synced_at ?? null);
      setRefreshing((prev) => new Set(prev).add(id));
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-blocklists"] }),
    onError: (_e, id) => {
      setRefreshing((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
      refreshBaselineRef.current.delete(id);
    },
  });

  // Bulk mutations — fan out via Promise.allSettled. Per-list scale is
  // small (a few dozen at most), so client-side fan-out beats adding a
  // bulk endpoint for now.
  const bulkApply = useMutation({
    mutationFn: async (ids: string[]) => {
      const targets = lists.filter(
        (l) => ids.includes(l.id) && !l.applied_group_ids.includes(group.id),
      );
      await Promise.allSettled(
        targets.map((l) =>
          dnsBlocklistApi.updateAssignments(l.id, {
            server_group_ids: [...l.applied_group_ids, group.id],
          }),
        ),
      );
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      setSelectedIds(new Set());
    },
  });
  const bulkDetach = useMutation({
    mutationFn: async (ids: string[]) => {
      const targets = lists.filter(
        (l) => ids.includes(l.id) && l.applied_group_ids.includes(group.id),
      );
      await Promise.allSettled(
        targets.map((l) =>
          dnsBlocklistApi.updateAssignments(l.id, {
            server_group_ids: l.applied_group_ids.filter((g) => g !== group.id),
          }),
        ),
      );
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      setSelectedIds(new Set());
    },
  });
  const bulkRefresh = useMutation({
    mutationFn: async (ids: string[]) => {
      const targets = lists.filter(
        (l) => ids.includes(l.id) && l.source_type === "url" && l.feed_url,
      );
      // Stamp baselines + flip per-row spinners up-front so the existing
      // single-row polling logic clears them once last_synced_at advances.
      for (const l of targets) {
        refreshBaselineRef.current.set(l.id, l.last_synced_at ?? null);
      }
      setRefreshing((prev) => {
        const next = new Set(prev);
        for (const l of targets) next.add(l.id);
        return next;
      });
      const results = await Promise.allSettled(
        targets.map((l) => dnsBlocklistApi.refresh(l.id)),
      );
      // Roll back spinners for any failed enqueue. Successes stay spinning
      // until last_synced_at moves.
      const failedIds = targets
        .filter((_, i) => results[i].status === "rejected")
        .map((l) => l.id);
      if (failedIds.length > 0) {
        setRefreshing((prev) => {
          const next = new Set(prev);
          for (const id of failedIds) next.delete(id);
          return next;
        });
        for (const id of failedIds) refreshBaselineRef.current.delete(id);
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      setSelectedIds(new Set());
    },
  });
  const bulkDelete = useMutation({
    mutationFn: async (ids: string[]) => {
      await Promise.allSettled(ids.map((id) => dnsBlocklistApi.delete(id)));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      setSelectedIds(new Set());
      setConfirmBulkDelete(false);
    },
  });

  if (selected) {
    return (
      <BlocklistDetail
        list={selected}
        onBack={() => {
          setSelected(null);
          qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          {lists.length} blocking list{lists.length !== 1 ? "s" : ""}
        </span>
        <div className="flex items-center gap-2">
          <button
            className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-muted/50"
            onClick={() => setShowCatalog(true)}
            title="Subscribe to a curated public blocklist (StevenBlack / Hagezi / OISD / AdGuard / …)"
          >
            <Sparkles className="h-3 w-3" /> Browse Catalog
          </button>
          <button
            className="flex items-center gap-1 rounded-md bg-primary px-2 py-1 text-xs text-primary-foreground hover:bg-primary/90"
            onClick={() => setShowCreate(true)}
          >
            <Plus className="h-3 w-3" /> New Blocking List
          </button>
        </div>
      </div>
      {showCatalog && (
        <BlocklistCatalogModal onClose={() => setShowCatalog(false)} />
      )}

      {/* Bulk-action toolbar — only visible when at least one row is
          selected. Each button operates on the subset of selected rows
          where it's meaningful (Apply skips already-applied; Detach
          skips not-applied; Refresh skips manual / file_upload lists). */}
      {selCount > 0 && (
        <div className="flex items-center justify-between rounded-md border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs dark:border-amber-900 dark:bg-amber-900/20">
          <span>
            {selCount} list{selCount !== 1 ? "s" : ""} selected
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSelectedIds(new Set())}
              className="rounded border px-2 py-1 hover:bg-muted/30"
            >
              Clear
            </button>
            <button
              onClick={() => bulkApply.mutate(Array.from(selectedIds))}
              disabled={bulkApply.isPending || selDetachedCount === 0}
              className="inline-flex items-center gap-1 rounded border border-emerald-400 px-2 py-1 text-emerald-600 hover:bg-emerald-500/10 disabled:opacity-40"
              title={
                selDetachedCount === 0
                  ? "Every selected list is already applied to this group"
                  : `Apply ${selDetachedCount} list${selDetachedCount !== 1 ? "s" : ""} to ${group.name}`
              }
            >
              Apply ({selDetachedCount})
            </button>
            <button
              onClick={() => bulkDetach.mutate(Array.from(selectedIds))}
              disabled={bulkDetach.isPending || selAppliedCount === 0}
              className="inline-flex items-center gap-1 rounded border border-amber-400 px-2 py-1 text-amber-600 hover:bg-amber-500/10 disabled:opacity-40"
              title={
                selAppliedCount === 0
                  ? "None of the selected lists are applied to this group"
                  : `Detach ${selAppliedCount} list${selAppliedCount !== 1 ? "s" : ""} from ${group.name}`
              }
            >
              Detach ({selAppliedCount})
            </button>
            <button
              onClick={() => bulkRefresh.mutate(Array.from(selectedIds))}
              disabled={bulkRefresh.isPending || selRefreshableCount === 0}
              className="inline-flex items-center gap-1 rounded border px-2 py-1 hover:bg-muted/30 disabled:opacity-40"
              title={
                selRefreshableCount === 0
                  ? "Only URL-sourced lists can be refreshed"
                  : `Refresh ${selRefreshableCount} URL-sourced list${selRefreshableCount !== 1 ? "s" : ""}`
              }
            >
              <RefreshCw className="h-3 w-3" /> Refresh ({selRefreshableCount})
            </button>
            <button
              onClick={() => setConfirmBulkDelete(true)}
              disabled={bulkDelete.isPending}
              className="inline-flex items-center gap-1 rounded border border-destructive/40 px-2 py-1 text-destructive hover:bg-destructive/10 disabled:opacity-40"
            >
              <Trash2 className="h-3 w-3" /> Delete ({selCount})
            </button>
          </div>
        </div>
      )}

      {isFetching && lists.length === 0 && (
        <p className="text-sm text-muted-foreground">Loading…</p>
      )}

      {/* No ``assigned`` flag on the section any more: since #876 a row can
          sit in the applied section purely because a VIEW of this group
          scopes it, so per-row controls key off ``groupAssigned(l)``. */}
      {[
        { label: "Applied to this group or one of its views", rows: applied },
        { label: "Available (not applied)", rows: other },
      ].map((section) => {
        const sectionIds = section.rows.map((r) => r.id);
        const sectionAllSel =
          sectionIds.length > 0 &&
          sectionIds.every((id) => selectedIds.has(id));
        const sectionSomeSel =
          !sectionAllSel && sectionIds.some((id) => selectedIds.has(id));
        return (
          <div key={section.label}>
            <div className="mb-2 flex items-center gap-2">
              {section.rows.length > 0 && (
                <input
                  type="checkbox"
                  checked={sectionAllSel}
                  ref={(el) => {
                    if (el) el.indeterminate = sectionSomeSel;
                  }}
                  onChange={() => toggleSection(section.rows)}
                  title={`Select all in "${section.label}"`}
                />
              )}
              <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                {section.label}
              </h4>
            </div>
            {section.rows.length === 0 && (
              <p className="text-xs text-muted-foreground italic">None.</p>
            )}
            <div className="space-y-1">
              {section.rows.map((l) => {
                const isSel = selectedIds.has(l.id);
                return (
                  <div
                    key={l.id}
                    className={cn(
                      "flex items-center gap-2 rounded-md border bg-card px-3 py-2 group hover:bg-accent/30 cursor-pointer",
                      isSel && "ring-1 ring-primary/40 bg-primary/5",
                    )}
                    onClick={() => setSelected(l)}
                  >
                    <input
                      type="checkbox"
                      checked={isSel}
                      onChange={() => toggleOne(l.id)}
                      onClick={(e) => e.stopPropagation()}
                      className="flex-shrink-0"
                    />
                    <Ban className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                    <span className="font-mono text-sm truncate">{l.name}</span>
                    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-muted text-muted-foreground">
                      {l.category}
                    </span>
                    <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-muted text-muted-foreground">
                      {l.block_mode}
                    </span>
                    {l.source_type === "url" && l.feed_url && (
                      <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-blue-500/15 text-blue-600">
                        feed
                      </span>
                    )}
                    {!l.enabled && (
                      <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-amber-500/15 text-amber-600">
                        disabled
                      </span>
                    )}
                    {scopedViews(l).map((id) => (
                      <span
                        key={id}
                        className="inline-flex items-center rounded bg-violet-500/15 px-1.5 py-0.5 text-xs text-violet-600 dark:text-violet-400"
                        title="Applied to this view only"
                      >
                        view: {viewName.get(id)}
                      </span>
                    ))}
                    <span className="ml-auto text-xs text-muted-foreground">
                      {l.entry_count} entries
                    </span>
                    <div
                      className="flex items-center gap-1"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {/* Group-wide toggle. Keyed off the actual group
                          relationship rather than the section, because a
                          list can sit in the "applied" section purely
                          because a VIEW of this group scopes it — and
                          "Detach" would then rewrite a group list it was
                          never in, doing nothing while looking broken. */}
                      {groupAssigned(l) ? (
                        <button
                          title="Detach from this group"
                          className="rounded border border-amber-400 px-2 py-0.5 text-xs text-amber-600"
                          onClick={() =>
                            toggleAssignment.mutate({ list: l, assign: false })
                          }
                        >
                          Detach
                        </button>
                      ) : (
                        <button
                          title="Apply to every client of this group"
                          className="rounded border border-emerald-400 px-2 py-0.5 text-xs text-emerald-600"
                          onClick={() =>
                            toggleAssignment.mutate({ list: l, assign: true })
                          }
                        >
                          Apply
                        </button>
                      )}
                      {views.length > 0 && (
                        <button
                          title="Scope to specific views"
                          className="h-6 w-6 flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                          onClick={() => setScopeList(l)}
                        >
                          <Filter className="h-3 w-3" />
                        </button>
                      )}
                      {l.source_type === "url" && l.feed_url && (
                        <button
                          title={
                            refreshing.has(l.id)
                              ? "Refresh in progress…"
                              : "Refresh from feed"
                          }
                          disabled={refreshing.has(l.id)}
                          className="h-6 w-6 flex items-center justify-center rounded text-muted-foreground hover:text-foreground disabled:opacity-50"
                          onClick={() => refreshMut.mutate(l.id)}
                        >
                          <RefreshCw
                            className={cn(
                              "h-3 w-3",
                              refreshing.has(l.id) && "animate-spin",
                            )}
                          />
                        </button>
                      )}
                      <button
                        className="h-6 w-6 flex items-center justify-center rounded text-muted-foreground hover:text-foreground"
                        onClick={() => setEditList(l)}
                      >
                        <Pencil className="h-3 w-3" />
                      </button>
                      <button
                        className="h-6 w-6 flex items-center justify-center rounded text-muted-foreground hover:text-destructive"
                        onClick={() => setConfirmDelete(l)}
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {scopeList && (
        <BlocklistScopeModal
          list={scopeList}
          group={group}
          views={views}
          onClose={() => setScopeList(null)}
        />
      )}

      {showCreate && <BlocklistModal onClose={() => setShowCreate(false)} />}
      {editList && (
        <BlocklistModal list={editList} onClose={() => setEditList(null)} />
      )}
      {confirmDelete && (
        <ConfirmDestroyModal
          title="Delete Blocking List"
          description={`Permanently delete "${confirmDelete.name}" and all its entries/exceptions?`}
          checkLabel={`I understand all entries in "${confirmDelete.name}" will be permanently deleted.`}
          onConfirm={() => deleteMut.mutate(confirmDelete.id)}
          onClose={() => setConfirmDelete(null)}
          isPending={deleteMut.isPending}
        />
      )}
      {confirmBulkDelete && (
        <ConfirmDestroyModal
          title={`Delete ${selCount} blocklist${selCount === 1 ? "" : "s"}`}
          description={`Permanently delete the ${selCount} selected blocking list${selCount === 1 ? "" : "s"} and all their entries / exceptions? This cannot be undone.`}
          checkLabel={`I understand the ${selCount} selected blocking list${selCount === 1 ? " will be" : "s will be"} permanently deleted.`}
          onConfirm={() => bulkDelete.mutate(Array.from(selectedIds))}
          onClose={() => setConfirmBulkDelete(false)}
          isPending={bulkDelete.isPending}
        />
      )}
    </div>
  );
}

function BlocklistModal({
  list,
  onClose,
}: {
  list?: DNSBlockList;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(list?.name ?? "");
  const [description, setDescription] = useState(list?.description ?? "");
  const [category, setCategory] = useState(list?.category ?? "custom");
  const [sourceType, setSourceType] = useState(list?.source_type ?? "manual");
  const [feedUrl, setFeedUrl] = useState(list?.feed_url ?? "");
  const [feedFormat, setFeedFormat] = useState(list?.feed_format ?? "hosts");
  const [blockMode, setBlockMode] = useState(list?.block_mode ?? "nxdomain");
  const [sinkholeIp, setSinkholeIp] = useState(list?.sinkhole_ip ?? "");
  const [updateHours, setUpdateHours] = useState(
    list?.update_interval_hours ?? 24,
  );
  const [feedWildcard, setFeedWildcard] = useState(
    list?.feed_entries_are_wildcard ?? true,
  );
  const [enabled, setEnabled] = useState(list?.enabled ?? true);
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: (d: Partial<DNSBlockList>) =>
      list ? dnsBlocklistApi.update(list.id, d) : dnsBlocklistApi.create(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      onClose();
    },
    onError: (e: ApiError) => setError(formatApiError(e, "Failed")),
  });

  return (
    <Modal
      title={list ? "Edit Blocking List" : "New Blocking List"}
      onClose={onClose}
      wide
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate({
            name,
            description,
            category,
            source_type: sourceType,
            feed_url: sourceType === "url" ? feedUrl || null : null,
            feed_format: feedFormat,
            block_mode: blockMode,
            sinkhole_ip: blockMode === "sinkhole" ? sinkholeIp || null : null,
            update_interval_hours: updateHours,
            feed_entries_are_wildcard: feedWildcard,
            enabled,
          });
        }}
      >
        <Field label="Name">
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </Field>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Category">
            <input
              className={inputCls}
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              placeholder="ads | malware | tracking | ..."
            />
          </Field>
          <Field label="Block mode">
            <select
              className={inputCls}
              value={blockMode}
              onChange={(e) => setBlockMode(e.target.value)}
            >
              <option value="nxdomain">nxdomain</option>
              <option value="sinkhole">sinkhole</option>
              <option value="refused">refused</option>
            </select>
          </Field>
        </div>
        {blockMode === "sinkhole" && (
          <Field label="Sinkhole IP">
            <input
              className={inputCls}
              value={sinkholeIp}
              onChange={(e) => setSinkholeIp(e.target.value)}
              placeholder="0.0.0.0"
            />
          </Field>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Source type">
            <select
              className={inputCls}
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value)}
            >
              <option value="manual">manual</option>
              <option value="url">url (feed)</option>
              <option value="file_upload">file_upload</option>
            </select>
          </Field>
          <Field label="Feed format">
            <select
              className={inputCls}
              value={feedFormat}
              onChange={(e) => setFeedFormat(e.target.value)}
            >
              <option value="hosts">hosts</option>
              <option value="domains">domains</option>
              <option value="adblock">adblock</option>
            </select>
          </Field>
        </div>
        {sourceType === "url" && (
          <>
            <Field label="Feed URL">
              <input
                className={inputCls}
                value={feedUrl}
                onChange={(e) => setFeedUrl(e.target.value)}
                placeholder="https://example.com/list.txt"
              />
            </Field>
            <Field label="Update interval (hours, 0 = manual)">
              <input
                type="number"
                min={0}
                className={inputCls}
                value={updateHours}
                onChange={(e) => setUpdateHours(Number(e.target.value))}
              />
            </Field>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={feedWildcard}
                onChange={(e) => setFeedWildcard(e.target.checked)}
              />
              <span>
                Block subdomains of feed entries
                <span className="block text-xs text-muted-foreground">
                  On (recommended): a feed naming <code>tracker.example</code>{" "}
                  also blocks <code>cdn.tracker.example</code> — what these
                  lists mean. Turn off only for a feed listing specific hosts,
                  where blocking the parent domain would be too broad.
                  {list &&
                    list.feed_entries_are_wildcard !== feedWildcard &&
                    " Saving restamps the entries already imported, which" +
                      " takes a few seconds on a large list."}
                </span>
              </span>
            </label>
          </>
        )}
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Enabled
        </label>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <Btns onClose={onClose} pending={mut.isPending} />
      </form>
    </Modal>
  );
}

function BlocklistDetail({
  list,
  onBack,
}: {
  list: DNSBlockList;
  onBack: () => void;
}) {
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [limit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [newDomain, setNewDomain] = useState("");
  const [newReason, setNewReason] = useState("");
  const [bulkText, setBulkText] = useState("");
  const [showBulk, setShowBulk] = useState(false);
  const [excDomain, setExcDomain] = useState("");
  const [excReason, setExcReason] = useState("");

  const { data: page } = useQuery({
    queryKey: ["dns-blocklist-entries", list.id, q, limit, offset],
    queryFn: () =>
      dnsBlocklistApi.listEntries(list.id, {
        q: q || undefined,
        limit,
        offset,
      }),
  });
  const { data: exceptions = [] } = useQuery({
    queryKey: ["dns-blocklist-exceptions", list.id],
    queryFn: () => dnsBlocklistApi.listExceptions(list.id),
  });

  const addEntry = useMutation({
    // is_wildcard defaults to true server-side (Pi-hole semantics); toggle
    // per-entry via the Subdomains column after adding.
    mutationFn: () =>
      dnsBlocklistApi.addEntry(list.id, {
        domain: newDomain,
        reason: newReason || undefined,
      }),
    onSuccess: () => {
      setNewDomain("");
      setNewReason("");
      qc.invalidateQueries({ queryKey: ["dns-blocklist-entries", list.id] });
    },
  });
  const bulkAdd = useMutation({
    mutationFn: () =>
      dnsBlocklistApi.bulkAddEntries(
        list.id,
        bulkText
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter(Boolean),
      ),
    onSuccess: () => {
      setBulkText("");
      setShowBulk(false);
      qc.invalidateQueries({ queryKey: ["dns-blocklist-entries", list.id] });
    },
  });
  const deleteEntry = useMutation({
    mutationFn: (id: string) => dnsBlocklistApi.deleteEntry(list.id, id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["dns-blocklist-entries", list.id] }),
  });
  const [editEntry, setEditEntry] = useState<DNSBlockListEntry | null>(null);
  const [editDomain, setEditDomain] = useState("");
  const [editEntryReason, setEditEntryReason] = useState("");
  const [editEntryWildcard, setEditEntryWildcard] = useState(true);
  // Inline toggle — fires immediately from the row checkbox, no Save button.
  const toggleEntryWildcard = useMutation({
    mutationFn: ({ id, value }: { id: string; value: boolean }) =>
      dnsBlocklistApi.updateEntry(list.id, id, { is_wildcard: value }),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["dns-blocklist-entries", list.id] }),
  });
  const updateEntry = useMutation({
    mutationFn: () =>
      dnsBlocklistApi.updateEntry(list.id, editEntry!.id, {
        domain: editDomain,
        reason: editEntryReason,
        is_wildcard: editEntryWildcard,
      }),
    onSuccess: () => {
      setEditEntry(null);
      qc.invalidateQueries({ queryKey: ["dns-blocklist-entries", list.id] });
    },
  });
  const addException = useMutation({
    mutationFn: () =>
      dnsBlocklistApi.addException(list.id, {
        domain: excDomain,
        reason: excReason,
      }),
    onSuccess: () => {
      setExcDomain("");
      setExcReason("");
      qc.invalidateQueries({ queryKey: ["dns-blocklist-exceptions", list.id] });
    },
  });
  const deleteException = useMutation({
    mutationFn: (id: string) => dnsBlocklistApi.deleteException(list.id, id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["dns-blocklist-exceptions", list.id] }),
  });
  const [editException, setEditException] =
    useState<DNSBlockListException | null>(null);
  const [editExcDomain, setEditExcDomain] = useState("");
  const [editExcReason, setEditExcReason] = useState("");
  const updateException = useMutation({
    mutationFn: () =>
      dnsBlocklistApi.updateException(list.id, editException!.id, {
        domain: editExcDomain,
        reason: editExcReason,
      }),
    onSuccess: () => {
      setEditException(null);
      qc.invalidateQueries({ queryKey: ["dns-blocklist-exceptions", list.id] });
    },
  });
  const refresh = useMutation({
    mutationFn: () => dnsBlocklistApi.refresh(list.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["dns-blocklists"] }),
  });

  const total = page?.total ?? 0;
  const items = page?.items ?? [];

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <button
          className="text-xs text-muted-foreground hover:text-foreground"
          onClick={onBack}
        >
          <ChevronRight className="h-3 w-3 rotate-180 inline mr-1" />
          Back
        </button>
        <h3 className="font-semibold text-sm">{list.name}</h3>
        <span className="text-xs text-muted-foreground">
          {total} entries · {exceptions.length} exceptions
        </span>
        {list.feed_url && (
          <button
            className="ml-auto flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
            onClick={() => refresh.mutate()}
            disabled={refresh.isPending}
          >
            <RefreshCw className="h-3 w-3" />
            {refresh.isPending ? "Queuing…" : "Refresh from feed"}
          </button>
        )}
      </div>

      {list.last_synced_at && (
        <p className="text-xs text-muted-foreground">
          Last synced: {new Date(list.last_synced_at).toLocaleString()}
          {list.last_sync_status && <> — {list.last_sync_status}</>}
          {list.last_sync_error && (
            <span className="text-destructive"> ({list.last_sync_error})</span>
          )}
        </p>
      )}

      {/* Blocked domains (the list itself) */}
      <div className="rounded-md border-2 border-destructive/30">
        <div className="flex items-center justify-between border-b border-destructive/30 bg-destructive/5 px-3 py-1.5">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase text-destructive">
            <Ban className="h-3.5 w-3.5" /> Blocked Domains
          </div>
          <span className="text-xs text-muted-foreground">
            Domains added here are blocked by the DNS server.
          </span>
        </div>
        <div className="space-y-2 border-b p-2">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              className={`${inputCls} w-full pl-8`}
              placeholder="Search entries…"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setOffset(0);
              }}
            />
          </div>
          <div className="flex items-center gap-2">
            <input
              className={`${inputCls} flex-1 min-w-0`}
              placeholder="Domain to block"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && newDomain) {
                  e.preventDefault();
                  addEntry.mutate();
                }
              }}
            />
            <input
              className={`${inputCls} flex-1 min-w-0`}
              placeholder="Reason (optional)"
              value={newReason}
              onChange={(e) => setNewReason(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && newDomain) {
                  e.preventDefault();
                  addEntry.mutate();
                }
              }}
            />
            <button
              className="flex-shrink-0 rounded-md border px-2 py-1 text-xs hover:bg-accent"
              onClick={() => addEntry.mutate()}
              disabled={!newDomain}
            >
              Add
            </button>
            <button
              className="flex-shrink-0 rounded-md border px-2 py-1 text-xs hover:bg-accent"
              onClick={() => setShowBulk(true)}
            >
              Bulk add
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th className="px-3 py-1.5">Domain</th>
                <th className="px-3 py-1.5">Type</th>
                <th className="px-3 py-1.5">Subdomains</th>
                <th className="px-3 py-1.5">Reason</th>
                <th className="px-3 py-1.5">Source</th>
                <th className="px-3 py-1.5 w-8"></th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {items.length === 0 && (
                <tr>
                  <td
                    colSpan={6}
                    className="px-3 py-4 text-center text-xs text-muted-foreground italic"
                  >
                    No entries
                  </td>
                </tr>
              )}
              {items.map((e: DNSBlockListEntry) => (
                <tr key={e.id} className="border-t hover:bg-accent/30">
                  <td className="px-3 py-1 font-mono text-xs">{e.domain}</td>
                  <td className="px-3 py-1 text-xs">{e.entry_type}</td>
                  <td className="px-3 py-1">
                    <input
                      type="checkbox"
                      checked={e.is_wildcard}
                      disabled={
                        e.source !== "manual" ||
                        (toggleEntryWildcard.isPending &&
                          toggleEntryWildcard.variables?.id === e.id)
                      }
                      onChange={(ev) =>
                        toggleEntryWildcard.mutate({
                          id: e.id,
                          value: ev.target.checked,
                        })
                      }
                      title={
                        e.source === "manual"
                          ? "Also block *.<domain>. Saves immediately."
                          : "Feed-sourced entries can't be toggled."
                      }
                    />
                  </td>
                  <td className="px-3 py-1 text-xs text-muted-foreground">
                    {e.reason || (
                      <span className="text-muted-foreground/40">—</span>
                    )}
                  </td>
                  <td className="px-3 py-1 text-xs">{e.source}</td>
                  <td className="px-3 py-1 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {e.source === "manual" && (
                        <button
                          className="text-muted-foreground hover:text-foreground"
                          onClick={() => {
                            setEditEntry(e);
                            setEditDomain(e.domain);
                            setEditEntryReason(e.reason ?? "");
                            setEditEntryWildcard(e.is_wildcard);
                          }}
                          title="Edit domain"
                        >
                          <Pencil className="h-3 w-3" />
                        </button>
                      )}
                      <button
                        className="text-muted-foreground hover:text-destructive"
                        onClick={() => deleteEntry.mutate(e.id)}
                        title={
                          e.source === "manual"
                            ? "Remove entry"
                            : "Remove (will return on next feed refresh)"
                        }
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {total > limit && (
          <div className="flex items-center justify-between border-t px-3 py-1.5 text-xs">
            <span className="text-muted-foreground">
              {offset + 1}–{Math.min(offset + limit, total)} of {total}
            </span>
            <div className="flex gap-1">
              <button
                className="rounded border px-2 py-0.5 disabled:opacity-40"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - limit))}
              >
                Prev
              </button>
              <button
                className="rounded border px-2 py-0.5 disabled:opacity-40"
                disabled={offset + limit >= total}
                onClick={() => setOffset(offset + limit)}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Exceptions (allow-list) */}
      <div className="rounded-md border-2 border-emerald-500/30">
        <div className="flex items-center justify-between border-b border-emerald-500/30 bg-emerald-500/5 px-3 py-1.5">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase text-emerald-700 dark:text-emerald-400">
            <Shield className="h-3.5 w-3.5" /> Allow-list (Exceptions)
          </div>
          <span className="text-xs text-muted-foreground">
            Domains added here are never blocked, even if they match a blocked
            entry.
          </span>
        </div>
        <div className="flex items-center gap-2 border-b p-2">
          <input
            className={`${inputCls} flex-1 min-w-0`}
            placeholder="Domain to allow"
            value={excDomain}
            onChange={(e) => setExcDomain(e.target.value)}
          />
          <input
            className={`${inputCls} flex-1 min-w-0`}
            placeholder="Reason (optional)"
            value={excReason}
            onChange={(e) => setExcReason(e.target.value)}
          />
          <button
            className="flex-shrink-0 rounded-md border px-2 py-1 text-xs hover:bg-accent"
            onClick={() => addException.mutate()}
            disabled={!excDomain}
          >
            Add
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[480px] text-sm">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th className="px-3 py-1.5">Domain</th>
                <th className="px-3 py-1.5">Reason</th>
                <th className="px-3 py-1.5 w-8"></th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {exceptions.length === 0 && (
                <tr>
                  <td
                    colSpan={3}
                    className="px-3 py-4 text-center text-xs text-muted-foreground italic"
                  >
                    No exceptions
                  </td>
                </tr>
              )}
              {exceptions.map((ex: DNSBlockListException) => (
                <tr key={ex.id} className="border-t hover:bg-accent/30">
                  <td className="px-3 py-1 font-mono text-xs">{ex.domain}</td>
                  <td className="px-3 py-1 text-xs">{ex.reason}</td>
                  <td className="px-3 py-1 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        className="text-muted-foreground hover:text-foreground"
                        onClick={() => {
                          setEditException(ex);
                          setEditExcDomain(ex.domain);
                          setEditExcReason(ex.reason ?? "");
                        }}
                        title="Edit exception"
                      >
                        <Pencil className="h-3 w-3" />
                      </button>
                      <button
                        className="text-muted-foreground hover:text-destructive"
                        onClick={() => deleteException.mutate(ex.id)}
                        title="Remove exception"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {editException && (
        <Modal title="Edit Exception" onClose={() => setEditException(null)}>
          <div className="space-y-3">
            <Field label="Domain">
              <input
                className={inputCls}
                value={editExcDomain}
                onChange={(ev) => setEditExcDomain(ev.target.value)}
                autoFocus
              />
            </Field>
            <Field label="Reason">
              <input
                className={inputCls}
                value={editExcReason}
                onChange={(ev) => setEditExcReason(ev.target.value)}
                placeholder="Optional"
              />
            </Field>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setEditException(null)}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={() => updateException.mutate()}
                disabled={!editExcDomain.trim() || updateException.isPending}
                className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {updateException.isPending ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </Modal>
      )}
      {editEntry && (
        <Modal title="Edit Blocked Domain" onClose={() => setEditEntry(null)}>
          <div className="space-y-3">
            <Field label="Domain">
              <input
                className={inputCls}
                value={editDomain}
                onChange={(ev) => setEditDomain(ev.target.value)}
                autoFocus
              />
            </Field>
            <Field label="Reason">
              <input
                className={inputCls}
                value={editEntryReason}
                onChange={(ev) => setEditEntryReason(ev.target.value)}
                placeholder="Optional"
              />
            </Field>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={editEntryWildcard}
                onChange={(ev) => setEditEntryWildcard(ev.target.checked)}
              />
              Block subdomains too (
              <code className="font-mono text-xs">
                *.{editDomain || "domain"}
              </code>
              )
            </label>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setEditEntry(null)}
                className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
              >
                Cancel
              </button>
              <button
                onClick={() => updateEntry.mutate()}
                disabled={!editDomain.trim() || updateEntry.isPending}
                className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {updateEntry.isPending ? "Saving…" : "Save"}
              </button>
            </div>
          </div>
        </Modal>
      )}
      {showBulk && (
        <Modal title="Bulk Add Domains" onClose={() => setShowBulk(false)} wide>
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              bulkAdd.mutate();
            }}
          >
            <p className="text-xs text-muted-foreground">
              One domain per line. Duplicates and invalid entries are skipped.
            </p>
            <textarea
              className={`${inputCls} font-mono text-xs`}
              rows={12}
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
            />
            <Btns
              onClose={() => setShowBulk(false)}
              pending={bulkAdd.isPending}
              label="Add Domains"
            />
          </form>
        </Modal>
      )}
    </div>
  );
}

// ── Group Detail View ─────────────────────────────────────────────────────────

type GroupTab =
  | "zones"
  | "records"
  | "servers"
  | "views"
  | "acls"
  | "blocklists"
  | "tsig"
  | "options";

function GroupDetailView({
  group,
  onSelectZone,
  onEdit,
  onDelete,
}: {
  group: DNSServerGroup;
  onSelectZone: (z: DNSZone) => void;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const qc = useQueryClient();
  const [syncing, setSyncing] = useState(false);
  const [groupSyncResult, setGroupSyncResult] = useState<{
    result: DNSGroupSyncResult | null;
    error: string | null;
  } | null>(null);

  async function runGroupSync() {
    setSyncing(true);
    setGroupSyncResult({ result: null, error: null });
    try {
      const result = await dnsApi.syncGroupWithServers(group.id);
      setGroupSyncResult({ result, error: null });
      qc.invalidateQueries({ queryKey: ["dns-zones", group.id] });
      qc.invalidateQueries({ queryKey: ["dns-group-records", group.id] });
      qc.invalidateQueries({ queryKey: ["dns-servers", group.id] });
    } catch (e) {
      setGroupSyncResult({
        result: null,
        error: formatApiError(e as ApiError, "Sync with servers failed"),
      });
    } finally {
      setSyncing(false);
    }
  }

  const [searchParams, setSearchParams] = useSearchParams();
  const tab = (searchParams.get("tab") as GroupTab) || "servers";
  const setTab = (t: GroupTab) =>
    setSearchParams(
      (prev: URLSearchParams) => {
        const next = new URLSearchParams(prev);
        next.set("tab", t);
        return next;
      },
      { replace: true },
    );

  // Tab order mirrors DHCP — Servers first (the agents driving the
  // group), then content (zones / records), then ancillary surfaces.
  const tabs: { id: GroupTab; label: string; icon: React.ElementType }[] = [
    { id: "servers", label: "Servers", icon: Cpu },
    { id: "zones", label: "Zones", icon: FileText },
    { id: "records", label: "Records", icon: ListTree },
    { id: "views", label: "Views", icon: Eye },
    { id: "acls", label: "ACLs", icon: Shield },
    { id: "blocklists", label: "Blocking Lists", icon: Ban },
    { id: "tsig", label: "TSIG Keys", icon: KeyRound },
    { id: "options", label: "Options", icon: Settings2 },
  ];

  const typeBadge: Record<string, string> = {
    internal: "bg-blue-500/15 text-blue-600",
    external: "bg-violet-500/15 text-violet-600",
    dmz: "bg-amber-500/15 text-amber-600",
    custom: "bg-muted text-muted-foreground",
  };

  return (
    <div className="flex flex-col h-full">
      <div className="border-b px-5 py-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <Globe className="h-4 w-4 text-muted-foreground flex-shrink-0" />
            <h2 className="font-semibold text-base truncate">{group.name}</h2>
            <span
              className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium flex-shrink-0 ${typeBadge[group.group_type] ?? "bg-muted text-muted-foreground"}`}
            >
              {group.group_type}
            </span>
            {group.is_recursive && (
              <span className="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-emerald-500/15 text-emerald-600 flex-shrink-0">
                recursive
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            <button
              className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
              onClick={() => {
                qc.invalidateQueries({ queryKey: ["dns-zones", group.id] });
                qc.invalidateQueries({
                  queryKey: ["dns-group-records", group.id],
                });
                qc.invalidateQueries({
                  queryKey: ["dns-servers", group.id],
                });
                qc.invalidateQueries({ queryKey: ["dns-views", group.id] });
                qc.invalidateQueries({ queryKey: ["dns-acls", group.id] });
                qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
                qc.invalidateQueries({ queryKey: ["dns-options", group.id] });
              }}
              title="Reload all data for this group (zones, records, servers, views, ACLs, blocklists, options) from the control plane."
            >
              <RefreshCw className="h-3 w-3" />
              Refresh
            </button>
            <button
              className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
              onClick={runGroupSync}
              disabled={syncing}
              title="Bi-directional additive sync against every enabled server in this group. Pulls missing zones and records from the servers (imports into SpatiumDDI), and pushes any SpatiumDDI zones / records not yet on the servers."
            >
              <RefreshCw className={cn("h-3 w-3", syncing && "animate-spin")} />
              {syncing ? "Syncing…" : "Sync with Servers"}
            </button>
            <button
              className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
              onClick={onEdit}
            >
              <Pencil className="h-3 w-3" /> Edit Group
            </button>
            <button
              className="flex items-center gap-1 rounded-md border border-destructive/40 px-2 py-1 text-xs text-destructive hover:bg-destructive/10"
              onClick={onDelete}
            >
              <Trash2 className="h-3 w-3" /> Delete Group
            </button>
          </div>
        </div>
        {group.description && (
          <p className="text-xs text-muted-foreground mt-0.5">
            {group.description}
          </p>
        )}
      </div>

      <div className="flex border-b">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${tab === t.id ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
          >
            <t.icon className="h-3.5 w-3.5" />
            {t.label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-5">
        {tab === "zones" && (
          <ZonesTab group={group} onSelectZone={onSelectZone} />
        )}
        {tab === "records" && (
          <RecordsTab group={group} onSelectZone={onSelectZone} />
        )}
        {tab === "servers" && <ServersTab group={group} />}
        {tab === "views" && <ViewsTab group={group} />}
        {tab === "acls" && <AclsTab groupId={group.id} />}
        {tab === "blocklists" && <BlocklistsTab group={group} />}
        {tab === "tsig" && <TSIGKeysTab group={group} />}
        {tab === "options" && <OptionsTab groupId={group.id} />}
      </div>

      {groupSyncResult && (
        <SyncWithServersResultModal
          group={group}
          result={groupSyncResult.result}
          error={groupSyncResult.error}
          onClose={() => setGroupSyncResult(null)}
        />
      )}
    </div>
  );
}

function SyncWithServersResultModal({
  group,
  result,
  error,
  onClose,
}: {
  group: DNSServerGroup;
  result: DNSGroupSyncResult | null;
  error: string | null;
  onClose: () => void;
}) {
  return (
    <Modal title={`Sync result — ${group.name}`} onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </div>
        )}
        {result && (
          <>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 text-xs">
              <SyncStat
                label="Servers"
                value={`${result.servers_succeeded}/${result.servers_attempted}`}
              />
              <SyncStat
                label="Zones imported"
                value={result.total_zones_imported}
                accent={result.total_zones_imported ? "good" : undefined}
              />
              <SyncStat
                label="Zones pushed"
                value={result.total_zones_pushed_to_server}
                accent={
                  result.total_zones_pushed_to_server ? "good" : undefined
                }
              />
              <SyncStat
                label="Records imported"
                value={result.total_imported}
                accent={result.total_imported ? "good" : undefined}
              />
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-2 text-xs">
              <SyncStat
                label="Records pushed"
                value={result.total_pushed}
                accent={result.total_pushed ? "good" : undefined}
              />
              <SyncStat
                label="Push errors"
                value={result.total_push_errors}
                accent={result.total_push_errors ? "bad" : undefined}
              />
            </div>

            {result.items.length === 0 && (
              <p className="text-sm text-muted-foreground italic">
                No enabled servers in this group.
              </p>
            )}

            {result.items.map((srv) => (
              <details
                key={srv.server_id}
                className="rounded-md border"
                open={
                  !!srv.error ||
                  (srv.result?.zones_pushed_to_server?.length ?? 0) > 0 ||
                  (srv.result?.zones_imported?.length ?? 0) > 0 ||
                  (srv.result?.zones_push_to_server_errors?.length ?? 0) > 0
                }
              >
                <summary className="cursor-pointer select-none border-b bg-muted/20 px-3 py-1.5 text-xs font-medium flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <Cpu className="h-3 w-3" />
                    {srv.server_name}
                    <span className="rounded bg-muted px-1 py-0 text-[10px] text-muted-foreground">
                      {srv.driver}
                    </span>
                  </span>
                  <span
                    className={
                      srv.error ? "text-destructive" : "text-muted-foreground"
                    }
                  >
                    {srv.error
                      ? "failed"
                      : srv.result
                        ? `${srv.result.zones_attempted} zone${srv.result.zones_attempted === 1 ? "" : "s"}`
                        : "—"}
                  </span>
                </summary>
                <div className="px-3 py-2 space-y-2">
                  {srv.error && (
                    <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive">
                      {srv.error}
                    </div>
                  )}
                  {srv.result && (
                    <>
                      {srv.result.zones_pushed_to_server.length > 0 && (
                        <div className="rounded-md border border-sky-500/40 bg-sky-500/5 px-3 py-2 text-xs">
                          <div className="font-medium text-sky-700 dark:text-sky-300">
                            Pushed {srv.result.zones_pushed_to_server.length}{" "}
                            zone
                            {srv.result.zones_pushed_to_server.length === 1
                              ? ""
                              : "s"}{" "}
                            to the server
                          </div>
                          <ul className="mt-1 ml-4 list-disc text-muted-foreground">
                            {srv.result.zones_pushed_to_server.map((z) => (
                              <li key={z} className="font-mono">
                                {z}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {srv.result.zones_imported.length > 0 && (
                        <div className="rounded-md border border-emerald-500/40 bg-emerald-500/5 px-3 py-2 text-xs">
                          <div className="font-medium text-emerald-700 dark:text-emerald-400">
                            Imported {srv.result.zones_imported.length} new zone
                            {srv.result.zones_imported.length === 1 ? "" : "s"}
                          </div>
                          <ul className="mt-1 ml-4 list-disc text-muted-foreground">
                            {srv.result.zones_imported.map((z) => (
                              <li key={z} className="font-mono">
                                {z}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {srv.result.zones_push_to_server_errors.length > 0 && (
                        <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs">
                          <div className="font-medium text-destructive">
                            Zone push errors
                          </div>
                          <ul className="mt-1 ml-4 list-disc text-muted-foreground">
                            {srv.result.zones_push_to_server_errors.map(
                              (e, i) => (
                                <li key={i} className="font-mono text-[11px]">
                                  {e}
                                </li>
                              ),
                            )}
                          </ul>
                        </div>
                      )}
                      {srv.result.zones_skipped_system.length > 0 && (
                        <div className="text-[11px] text-muted-foreground">
                          Skipped Windows system zones:{" "}
                          <span className="font-mono">
                            {srv.result.zones_skipped_system.join(", ")}
                          </span>
                        </div>
                      )}
                      {srv.result.items.length > 0 && (
                        <div className="rounded border">
                          <table className="w-full text-xs">
                            <thead>
                              <tr className="border-b bg-muted/10 text-left">
                                <th className="px-3 py-1 font-medium">Zone</th>
                                <th className="px-3 py-1 font-medium tabular-nums">
                                  On server
                                </th>
                                <th className="px-3 py-1 font-medium tabular-nums">
                                  Imported
                                </th>
                                <th className="px-3 py-1 font-medium tabular-nums">
                                  Pushed
                                </th>
                                <th className="px-3 py-1 font-medium">
                                  Status
                                </th>
                              </tr>
                            </thead>
                            <tbody className={zebraBodyCls}>
                              {srv.result.items.map((item) => (
                                <tr
                                  key={item.zone}
                                  className="border-b last:border-0"
                                >
                                  <td className="px-3 py-1 font-mono">
                                    {item.zone}
                                  </td>
                                  <td className="px-3 py-1 tabular-nums">
                                    {item.server_records}
                                  </td>
                                  <td className="px-3 py-1 tabular-nums text-emerald-600">
                                    {item.imported || "—"}
                                  </td>
                                  <td className="px-3 py-1 tabular-nums text-emerald-600">
                                    {item.pushed || "—"}
                                  </td>
                                  <td className="px-3 py-1">
                                    {item.error ? (
                                      <span className="text-destructive">
                                        {item.error}
                                      </span>
                                    ) : item.push_errors.length > 0 ? (
                                      <span className="text-amber-600">
                                        {item.push_errors.length} push err
                                      </span>
                                    ) : (
                                      <span className="text-muted-foreground">
                                        ok
                                      </span>
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </details>
            ))}
          </>
        )}
        <div className="flex justify-end">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Sidebar zone tree rows ────────────────────────────────────────────────────

function ZoneTreeRows({
  groupId,
  selectedZoneId,
  onSelectZone,
}: {
  groupId: string;
  selectedZoneId: string | null;
  onSelectZone: (z: DNSZone) => void;
}) {
  const [expandedNodes, setExpandedNodes] = useSessionState<Set<string>>(
    `spatium.dns.expandedZones.${groupId}`,
    new Set(),
  );
  const [createZoneName, setCreateZoneName] = useState<string | null>(null);

  const { data: zones = [] } = useQuery({
    queryKey: ["dns-zones", groupId],
    queryFn: () => dnsApi.listZones(groupId),
  });
  const { data: views = [] } = useQuery({
    queryKey: ["dns-views", groupId],
    queryFn: () => dnsApi.listViews(groupId),
    staleTime: 30_000,
  });

  const tree = buildDnsTree(zones);

  if (tree.length === 0)
    return (
      <p className="px-3 py-1.5 text-xs text-muted-foreground italic">
        No zones
      </p>
    );

  function toggleNode(domain: string) {
    setExpandedNodes((prev: Set<string>) => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain);
      else next.add(domain);
      return next;
    });
  }

  function renderNode(node: DnsTreeNode, depth: number): React.ReactNode {
    const paddingLeft = 12 + depth * 14;
    const hasChildren = node.children.length > 0;
    const expanded = expandedNodes.has(node.domain);

    return (
      <div key={node.domain}>
        {hasChildren ? (
          /* Node with children — split expand toggle from zone select */
          <div className="flex items-center" style={{ paddingLeft }}>
            <button
              className="flex items-center justify-center w-5 h-6 flex-shrink-0 text-muted-foreground hover:text-foreground"
              onClick={() => toggleNode(node.domain)}
              title={expanded ? "Collapse" : "Expand"}
            >
              {expanded ? (
                <FolderOpen className="h-3 w-3" />
              ) : (
                <Folder className="h-3 w-3" />
              )}
            </button>
            {node.zone ? (
              /* This node is also a registered zone — make label clickable */
              <button
                className={`flex flex-1 items-center gap-1.5 rounded py-1 pr-2 text-xs ${
                  selectedZoneId === node.zone.id
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground"
                }`}
                onClick={() => onSelectZone(node.zone!)}
              >
                {swatchCls(node.zone.color) ? (
                  <span
                    className={cn(
                      "h-2 w-2 rounded-full flex-shrink-0",
                      swatchCls(node.zone.color)!,
                    )}
                  />
                ) : (
                  <FileText className="h-3 w-3 flex-shrink-0" />
                )}
                <span className="font-mono truncate">
                  {node.zone.name.replace(/\.$/, "")}
                </span>
                {node.zone.dnssec_enabled && (
                  <Shield className="h-2.5 w-2.5 ml-auto flex-shrink-0 text-emerald-500" />
                )}
              </button>
            ) : (
              /* Intermediate folder with no zone. TLD-level nodes (no dot,
                 like "org" or "com") just toggle; you never create a zone
                 literally at the TLD. Deeper folders (e.g. "example.com")
                 open the Create Zone modal on click. */
              <button
                className="flex flex-1 items-center gap-1 rounded py-1 pr-2 text-xs font-medium font-mono text-muted-foreground hover:bg-accent hover:text-foreground"
                onClick={() =>
                  node.domain.includes(".")
                    ? setCreateZoneName(node.domain)
                    : toggleNode(node.domain)
                }
                title={
                  node.domain.includes(".")
                    ? `Create zone "${node.domain}" here`
                    : "Expand / collapse"
                }
              >
                {node.domain}
              </button>
            )}
          </div>
        ) : node.zone ? (
          /* Leaf zone node */
          <button
            className={`flex w-full items-center gap-1.5 rounded py-1 pr-2 text-xs ${
              selectedZoneId === node.zone.id
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-accent hover:text-foreground"
            }`}
            style={{ paddingLeft }}
            onClick={() => onSelectZone(node.zone!)}
          >
            {swatchCls(node.zone.color) ? (
              <span
                className={cn(
                  "h-2 w-2 rounded-full flex-shrink-0",
                  swatchCls(node.zone.color)!,
                )}
              />
            ) : (
              <FileText className="h-3 w-3 flex-shrink-0" />
            )}
            <span className="font-mono truncate">
              {node.zone.name.replace(/\.$/, "")}
            </span>
            {node.zone.dnssec_enabled && (
              <Shield className="h-2.5 w-2.5 ml-auto flex-shrink-0 text-emerald-500" />
            )}
          </button>
        ) : (
          /* Intermediate domain with no zone */
          <div
            className="flex w-full items-center gap-1.5 rounded px-3 py-1 text-xs text-muted-foreground"
            style={{ paddingLeft }}
          >
            <Folder className="h-3 w-3 flex-shrink-0" />
            <span className="font-medium font-mono">{node.domain}</span>
          </div>
        )}
        {/* Children */}
        {hasChildren && expanded && (
          <div>
            {node.children.map((child) => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  }

  return (
    <>
      <div>{tree.map((root) => renderNode(root, 0))}</div>
      {createZoneName && (
        <ZoneModal
          groupId={groupId}
          views={views}
          initialName={createZoneName}
          onClose={() => setCreateZoneName(null)}
        />
      )}
    </>
  );
}

// ── Main DNS Page ─────────────────────────────────────────────────────────────

type Selection =
  | { type: "group"; group: DNSServerGroup }
  | { type: "zone"; group: DNSServerGroup; zone: DNSZone };

export function DNSPage() {
  useStickyLocation("spatium.lastUrl.dns");
  const qc = useQueryClient();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selection, setSelectionState] = useState<Selection | null>(null);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [editGroup, setEditGroup] = useState<DNSServerGroup | null>(null);
  const [confirmDeleteGroup, setConfirmDeleteGroup] =
    useState<DNSServerGroup | null>(null);
  const [deleteGroupNotice, setDeleteGroupNotice] = useState<string | null>(
    null,
  );
  const [expandedGroups, setExpandedGroups] = useSessionState<Set<string>>(
    "spatium.dns.expandedGroups",
    new Set(),
  );
  const urlRestored = useRef(false);
  // Captured from ``location.state.highlightRecord`` before
  // ``setSelection`` fires its ``setSearchParams(..., { replace: true })``
  // — that replace drops ``location.state`` so we can't lazy-read it
  // inside ``ZoneDetailView``.
  const [pendingHighlightRecord, setPendingHighlightRecord] = useState<
    string | null
  >(null);
  // Zone the deep-link targeted — used below to clear the highlight as
  // soon as the operator switches to a different zone (one-shot).
  const highlightTargetZoneRef = useRef<string | null>(null);

  // Update selection state + URL search params together. Preserves `tab`
  // when staying within the same group; clears it when switching groups.
  function setSelection(sel: Selection | null) {
    setSelectionState(sel);
    setSearchParams(
      (prev: URLSearchParams) => {
        const next = new URLSearchParams(prev);
        const prevGroupId = next.get("group");
        if (!sel) {
          next.delete("group");
          next.delete("zone");
          next.delete("tab");
        } else if (sel.type === "group") {
          next.set("group", sel.group.id);
          next.delete("zone");
          if (prevGroupId !== sel.group.id) next.delete("tab");
        } else {
          next.set("group", sel.group.id);
          next.set("zone", sel.zone.id);
          if (prevGroupId !== sel.group.id) next.delete("tab");
        }
        return next;
      },
      { replace: true },
    );
  }

  const { data: groups = [], isLoading } = useQuery({
    queryKey: ["dns-groups"],
    queryFn: () => dnsApi.listGroups(),
  });

  // Deep-link from global search: navigate("/dns", { state: { selectGroup, selectZone, highlightRecord? } })
  useEffect(() => {
    const state = location.state as {
      selectGroup?: string;
      selectZone?: string;
      highlightRecord?: string;
    } | null;
    if (!state?.selectGroup || groups.length === 0) return;
    const group = groups.find(
      (g: DNSServerGroup) => g.id === state.selectGroup,
    );
    if (!group) return;
    setExpandedGroups((prev) => new Set([...prev, group.id]));
    // Capture the highlight BEFORE setSelection fires — the setter
    // calls setSearchParams(..., { replace: true }) which drops
    // location.state, so ZoneDetailView can't read it later.
    if (state.highlightRecord && state.selectZone) {
      setPendingHighlightRecord(state.highlightRecord);
      highlightTargetZoneRef.current = state.selectZone;
    }
    if (state.selectZone) {
      // Zone selection: load zones for the group, then select
      dnsApi.listZones(group.id).then((zones: DNSZone[]) => {
        const zone = zones.find((z: DNSZone) => z.id === state.selectZone);
        if (zone) setSelection({ type: "zone", group, zone });
        else setSelection({ type: "group", group });
      });
    } else {
      setSelection({ type: "group", group });
    }
    // Clear state so re-renders don't re-trigger
    window.history.replaceState({}, "");
    urlRestored.current = true;
  }, [location.state, groups]);

  // One-shot: clear the pending record highlight as soon as the
  // operator switches to a different zone (or back to group view).
  useEffect(() => {
    if (!pendingHighlightRecord) return;
    const currentZoneId = selection?.type === "zone" ? selection.zone.id : null;
    if (currentZoneId !== highlightTargetZoneRef.current) {
      setPendingHighlightRecord(null);
    }
  }, [selection, pendingHighlightRecord]);

  // URL-state restore: reopen last-visited group/zone on back-navigation.
  // Depends on searchParams so that when `useStickyLocation` navigates from
  // bare `/dns` → `/dns?group=…` after mount, this effect re-runs and picks
  // up the now-populated params. The `urlRestored` guard is only set once
  // we've actually matched a param, so an early run with empty searchParams
  // doesn't latch us into "nothing to restore".
  useEffect(() => {
    if (urlRestored.current) return;
    if (groups.length === 0) return;
    const groupId = searchParams.get("group");
    const zoneId = searchParams.get("zone");
    if (!groupId) return;
    urlRestored.current = true;
    const group = groups.find((g: DNSServerGroup) => g.id === groupId);
    if (!group) return;
    setExpandedGroups((prev) => new Set([...prev, group.id]));
    if (zoneId) {
      dnsApi.listZones(group.id).then((zones: DNSZone[]) => {
        const zone = zones.find((z: DNSZone) => z.id === zoneId);
        setSelectionState(
          zone ? { type: "zone", group, zone } : { type: "group", group },
        );
      });
    } else {
      setSelectionState({ type: "group", group });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups, searchParams]);

  const deleteGroup = useMutation({
    mutationFn: (id: string) => dnsApi.deleteGroup(id),
    onSuccess: (resp, id) => {
      // Two-person approval (#62): a covered delete returns 202 with a
      // queued change-request instead of deleting. Surface the message,
      // refresh the approval queue, and leave the group in place.
      if (handleApprovalQueued(resp)) {
        setDeleteGroupNotice(APPROVAL_QUEUED_MESSAGE);
        qc.invalidateQueries({ queryKey: CHANGE_REQUEST_QUERY_KEY });
        return;
      }
      qc.invalidateQueries({ queryKey: ["dns-groups"] });
      if (selection && "group" in selection && selection.group.id === id)
        setSelection(null);
      setConfirmDeleteGroup(null);
    },
  });
  const deleteGroupError =
    deleteGroup.error &&
    (((deleteGroup.error as { response?: { data?: { detail?: string } } })
      ?.response?.data?.detail as string | undefined) ??
      formatApiError(deleteGroup.error));

  function toggleGroup(id: string) {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const groupTypeDot: Record<string, string> = {
    internal: "bg-blue-500",
    external: "bg-violet-500",
    dmz: "bg-amber-500",
    custom: "bg-muted-foreground",
  };

  return (
    <div className="flex h-full overflow-hidden">
      {/* ── Sidebar ── */}
      <div className="w-72 flex-shrink-0 flex flex-col border-r bg-card">
        <div className="flex items-center justify-between px-4 py-3 border-b">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            DNS Server Groups
          </span>
          <div className="flex gap-1">
            <button
              className="flex h-6 w-6 items-center justify-center rounded text-muted-foreground hover:bg-accent hover:text-foreground"
              onClick={() => {
                // Force refetch — bare invalidate only marks queries
                // stale, which isn't enough when the user pressed
                // Refresh after external changes (API, another tab).
                qc.refetchQueries({ queryKey: ["dns-groups"] });
                qc.refetchQueries({ queryKey: ["dns-servers"] });
                qc.refetchQueries({ queryKey: ["dns-zones"] });
              }}
              title="Refresh"
            >
              <RefreshCw className="h-3.5 w-3.5" />
            </button>
            <button
              className="flex h-6 w-6 items-center justify-center rounded hover:bg-accent"
              onClick={() => setShowCreateGroup(true)}
              title="New server group"
            >
              <Plus className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto py-1">
          {isLoading && (
            <p className="px-4 py-2 text-xs text-muted-foreground">Loading…</p>
          )}
          {groups.length === 0 && !isLoading && (
            <div className="px-4 pt-6 text-center">
              <Globe className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
              <p className="text-xs text-muted-foreground mb-3">
                No server groups yet.
              </p>
              <button
                className="flex items-center gap-1 rounded-md border px-2 py-1 text-xs mx-auto hover:bg-accent"
                onClick={() => setShowCreateGroup(true)}
              >
                <Plus className="h-3 w-3" /> Create Group
              </button>
            </div>
          )}

          {groups.map((g) => {
            const expanded = expandedGroups.has(g.id);
            const groupSelected =
              selection?.type === "group" && selection.group.id === g.id;

            return (
              <div key={g.id}>
                {/* Group row */}
                <div
                  className={`flex items-center rounded-md mx-1 ${groupSelected ? "bg-primary text-primary-foreground" : ""}`}
                >
                  {/* Expand toggle */}
                  <button
                    className={`ml-1 flex h-4 w-4 flex-shrink-0 items-center justify-center rounded-sm border text-[10px] font-bold ${
                      groupSelected
                        ? "border-primary-foreground/60 bg-primary text-primary-foreground"
                        : "border-border bg-background text-muted-foreground hover:border-primary hover:text-primary"
                    }`}
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleGroup(g.id);
                    }}
                    title={expanded ? "Collapse" : "Expand"}
                  >
                    {expanded ? "−" : "+"}
                  </button>
                  {/* Group name — click to select. Auto-expand on first
                      click but NEVER auto-collapse: clicking the name to
                      navigate back to the group view from a child zone
                      shouldn't lose the tree context. The chevron is the
                      dedicated way to collapse. */}
                  <button
                    className="flex flex-1 items-center gap-2 py-1.5 pl-2 pr-1 min-w-0"
                    onClick={() => {
                      setSelection({ type: "group", group: g });
                      if (!expanded) toggleGroup(g.id);
                    }}
                  >
                    <span
                      className={`h-2 w-2 rounded-full flex-shrink-0 ${groupTypeDot[g.group_type] ?? "bg-muted-foreground"}`}
                    />
                    <span className="text-sm font-medium truncate">
                      {g.name}
                    </span>
                  </button>
                </div>

                {/* Zone tree (when group expanded). `expandedGroups` is the
                    sole source of truth — URL/location restore effects add
                    the group to the set when navigating to a zone, so a
                    zone can't be "selected inside a collapsed group" in
                    practice. Overriding with a zone-in-group check made
                    the [+]/[−] toggle appear broken when a zone was selected:
                    the state flipped but the tree stayed visible. */}
                {expanded && (
                  <div className="ml-4 mb-1">
                    <ZoneTreeRows
                      groupId={g.id}
                      selectedZoneId={
                        selection?.type === "zone" ? selection.zone.id : null
                      }
                      onSelectZone={(z) =>
                        setSelection({ type: "zone", group: g, zone: z })
                      }
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Main panel ── */}
      <div className="flex-1 overflow-hidden">
        {!selection && (
          <div className="flex h-full items-center justify-center">
            <div className="text-center">
              <Globe className="h-12 w-12 text-muted-foreground/20 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">
                {groups.length === 0
                  ? "Create a server group to start managing DNS."
                  : "Select a server group or zone from the tree."}
              </p>
            </div>
          </div>
        )}
        {selection?.type === "group" && (
          <GroupDetailView
            group={selection.group}
            onSelectZone={(z) =>
              setSelection({ type: "zone", group: selection.group, zone: z })
            }
            onEdit={() => setEditGroup(selection.group)}
            onDelete={() => setConfirmDeleteGroup(selection.group)}
          />
        )}
        {selection?.type === "zone" && (
          <ZoneDetailView
            group={selection.group}
            zone={selection.zone}
            highlightRecordId={pendingHighlightRecord}
            onDeleted={() =>
              setSelection({ type: "group", group: selection.group })
            }
          />
        )}
      </div>

      {showCreateGroup && (
        <GroupModal onClose={() => setShowCreateGroup(false)} />
      )}
      {editGroup && (
        <GroupModal group={editGroup} onClose={() => setEditGroup(null)} />
      )}
      {confirmDeleteGroup && (
        <ConfirmDestroyModal
          title="Delete Server Group"
          description={`Permanently delete group "${confirmDeleteGroup.name}"? The group must be empty — move or delete its servers and zones first.`}
          checkLabel={`I understand the group "${confirmDeleteGroup.name}" will be deleted.`}
          onConfirm={() => deleteGroup.mutate(confirmDeleteGroup.id)}
          onClose={() => {
            setConfirmDeleteGroup(null);
            setDeleteGroupNotice(null);
            deleteGroup.reset();
          }}
          isPending={deleteGroup.isPending}
          error={deleteGroupError || null}
          notice={deleteGroupNotice}
        />
      )}
    </div>
  );
}
