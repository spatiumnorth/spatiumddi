import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Building2,
  Copy,
  ExternalLink,
  Factory,
  Loader2,
  Pencil,
  Phone,
  Power,
  Radar,
  Radio,
  RefreshCw,
  Route as RouteIcon,
  Scan,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";

import {
  bacnetApi,
  dicomApi,
  dnsblApi,
  ipamApi,
  lookingGlassApi,
  multicastApi,
  nmapApi,
  otApi,
  tlsCertsApi,
  type DHCPFingerprintResponse,
  type IPAddress,
  type MulticastMembershipReadWithGroup,
  type NmapScanRead,
  type Subnet,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { OT_PROTOCOL_LABELS, OT_ROLE_LABELS } from "@/lib/otLabels";
import { CertsCompactTable } from "@/pages/network/CertificatesPage";
import {
  MODAL_BACKDROP_CLS,
  useModalDialog,
} from "@/components/ui/use-draggable-modal";
import { AskAIButton } from "@/components/copilot/AskAIButton";
import { IPNetworkTab } from "./IPNetworkTab";
import { SeenDot } from "./SeenDot";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { RpkiPill } from "@/components/network/bgp-route-table";

// ── Helpers ──────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  active:
    "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
  reserved: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  deprecated:
    "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  quarantine: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  allocated:
    "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400",
  available:
    "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
  dhcp: "bg-cyan-100 text-cyan-800 dark:bg-cyan-900/30 dark:text-cyan-400",
  static_dhcp:
    "bg-teal-100 text-teal-800 dark:bg-teal-900/30 dark:text-teal-400",
  network: "bg-zinc-100 text-zinc-500 dark:bg-zinc-800/50 dark:text-zinc-400",
  broadcast: "bg-zinc-100 text-zinc-500 dark:bg-zinc-800/50 dark:text-zinc-400",
  orphan:
    "bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400",
  // ``discovered`` — passive observation only, no operator intent yet.
  // Sky tone keeps it visually distinct from ``available`` (green) and
  // ``allocated`` (purple); the orthogonal alive dot in the IPAM table
  // tells the operator whether the discovered row is currently up.
  discovered: "bg-sky-100 text-sky-800 dark:bg-sky-900/30 dark:text-sky-400",
};

function copy(text: string) {
  void navigator.clipboard.writeText(text);
}

function fmtTs(ts?: string | null): string {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function Field({
  label,
  children,
  mono,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div>
      <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className={cn("mt-0.5 text-sm", mono && "font-mono", "break-words")}>
        {children}
      </div>
    </div>
  );
}

function dash(v: unknown) {
  if (v === null || v === undefined || v === "") {
    return <span className="text-muted-foreground/50">—</span>;
  }
  return v as React.ReactNode;
}

// ── Modal ────────────────────────────────────────────────────────────

export interface IPDetailModalProps {
  address: IPAddress;
  subnet?: Subnet | null;
  zoneNameById?: Record<string, string>;
  canEdit: boolean;
  onClose: () => void;
  onEdit: () => void;
  onScan: () => void;
  onDelete?: () => void;
  /** Click-to-filter affordance from the issue #104 spec. When the
   *  operator clicks a tag pill, the modal closes and the parent
   *  pushes the chip onto its own ``addressTagFilters`` so the
   *  underlying address list filters to matching rows. The chip
   *  string is the wire form (``key`` for key-only, ``key:value``
   *  for exact match) — same shape ``<TagFilterChips>`` accepts. */
  onTagClick?: (chip: string) => void;
}

/**
 * Read-only detail surface for an IP. Opens on row-click; from here the
 * operator can launch a scan or hop into the editor. Tries hard to keep
 * useful details visible at a glance — the form is one click away via
 * the Edit button if anything needs changing.
 */
export function IPDetailModal({
  address: addr,
  subnet,
  zoneNameById,
  canEdit,
  onClose,
  onEdit,
  onScan,
  onDelete,
  onTagClick,
}: IPDetailModalProps) {
  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);
  const zoneNames = zoneNameById ?? {};

  // Wake-on-LAN (#533) — self-contained like the "Re-profile now" action.
  // Fire-and-forget: no data changes, so no query invalidation; we just
  // surface a transient result line under the header.
  const [wakeMsg, setWakeMsg] = useState<{ ok: boolean; text: string } | null>(
    null,
  );
  // Opt in to the post-wake liveness check (#596). Off by default: a bare Wake
  // stays the one-click fire-and-forget it has always been.
  const [verifyAfterWake, setVerifyAfterWake] = useState(false);
  const wake = useMutation({
    mutationFn: (verify: boolean) => ipamApi.wakeAddress(addr.id, { verify }),
    onSuccess: (data, verify) => {
      const via =
        data.ran_from === "server"
          ? "the server"
          : data.ran_from.replace(":", " ");
      setWakeMsg({
        ok: true,
        text:
          `Magic packet sent to ${data.mac} via ${via}.` +
          (verify
            ? " Checking in 60s whether it came up — the result appears in Wake Schedules → History."
            : ""),
      });
    },
    onError: (err: unknown) => {
      // detail is a string for our HTTPExceptions but a list of objects for a
      // Pydantic 422 — only render it when it's actually a string.
      const detail = (err as { response?: { data?: { detail?: unknown } } })
        ?.response?.data?.detail;
      setWakeMsg({
        ok: false,
        text:
          typeof detail === "string"
            ? detail
            : "Failed to send the magic packet.",
      });
    },
  });

  const tagEntries = Object.entries(addr.tags ?? {});
  const cfEntries = Object.entries(addr.custom_fields ?? {});

  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        className="w-full rounded-lg border bg-card shadow-lg max-h-[90vh] overflow-y-auto max-w-[95vw] sm:max-w-3xl focus:outline-none"
        style={dialogStyle}
      >
        {/* Header */}
        <div
          {...dragHandleProps}
          className={cn(
            "flex items-start justify-between gap-3 border-b p-4 sm:p-5",
            dragHandleProps.className,
          )}
        >
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 {...titleProps} className="font-mono text-xl font-semibold">
                {addr.address}
              </h2>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  copy(addr.address);
                }}
                className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                title="Copy IP"
              >
                <Copy className="h-3.5 w-3.5" />
              </button>
              <span
                className={cn(
                  "rounded-full px-2 py-0.5 text-xs font-medium",
                  STATUS_COLORS[addr.status] ??
                    "bg-muted text-muted-foreground",
                )}
              >
                {addr.status}
              </span>
              <SeenDot
                lastSeenAt={addr.last_seen_at}
                lastSeenMethod={addr.last_seen_method}
                size="md"
              />
              {addr.role && (
                <span className="inline-flex items-center rounded bg-indigo-100 px-1.5 py-0.5 text-[11px] font-medium text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400">
                  {addr.role}
                </span>
              )}
              {addr.auto_from_lease && (
                <span className="inline-flex items-center rounded bg-cyan-100 px-1.5 py-0.5 text-[11px] font-medium text-cyan-800 dark:bg-cyan-900/30 dark:text-cyan-400">
                  DHCP-mirror
                </span>
              )}
            </div>
            {addr.fqdn ? (
              <div className="mt-1 font-mono text-xs text-muted-foreground">
                {addr.fqdn}
              </div>
            ) : addr.hostname ? (
              <div className="mt-1 text-xs text-muted-foreground">
                {addr.hostname}
              </div>
            ) : null}
          </div>
          <div
            className="flex flex-shrink-0 items-center gap-2"
            onClick={(e) => e.stopPropagation()}
          >
            <AskAIButton
              context={[
                `IP address ${addr.address}`,
                addr.hostname ? `hostname: ${addr.hostname}` : null,
                addr.fqdn ? `FQDN: ${addr.fqdn}` : null,
                addr.mac_address ? `MAC: ${addr.mac_address}` : null,
                `status: ${addr.status}`,
                addr.role ? `role: ${addr.role}` : null,
                addr.description ? `description: ${addr.description}` : null,
                addr.last_seen_at
                  ? `last seen: ${addr.last_seen_at}` +
                    (addr.last_seen_method ? ` (${addr.last_seen_method})` : "")
                  : null,
                `subnet_id: ${addr.subnet_id}`,
                `ip_address_id: ${addr.id}`,
              ]
                .filter(Boolean)
                .join(", ")}
              tooltip="Ask AI about this IP"
              prompt="Summarise this IP — owner, last-seen, services, vendor, and anything flagged."
            />
            <button
              type="button"
              onClick={onScan}
              className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs hover:bg-accent"
              title="Run an nmap scan against this IP"
            >
              <Radar className="h-3.5 w-3.5" /> Scan with Nmap
            </button>
            {addr.mac_address && (
              <div className="inline-flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setWakeMsg(null);
                    wake.mutate(verifyAfterWake);
                  }}
                  disabled={wake.isPending}
                  className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
                  title="Send a Wake-on-LAN magic packet to this MAC"
                >
                  {wake.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Power className="h-3.5 w-3.5" />
                  )}{" "}
                  Wake
                </button>
                <label
                  className="inline-flex cursor-pointer items-center gap-1 text-[11px] text-muted-foreground"
                  title="After 60s, check whether the host came up (ping, then TCP, then a network sighting) and re-wake it once if it didn't. The outcome is recorded in Wake Schedules → History."
                >
                  <input
                    type="checkbox"
                    checked={verifyAfterWake}
                    onChange={(e) => setVerifyAfterWake(e.target.checked)}
                    disabled={wake.isPending}
                  />
                  verify
                </label>
              </div>
            )}
            {canEdit && (
              <button
                type="button"
                onClick={onEdit}
                className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs hover:bg-accent"
              >
                <Pencil className="h-3.5 w-3.5" /> Edit
              </button>
            )}
            {canEdit && onDelete && (
              <button
                type="button"
                onClick={onDelete}
                className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs text-destructive hover:bg-destructive/10"
              >
                <Trash2 className="h-3.5 w-3.5" /> Delete
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="rounded p-1 text-muted-foreground hover:text-foreground"
              title="Close"
              aria-label="Close dialog"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="space-y-5 p-4 sm:p-5">
          {wakeMsg && (
            <div
              className={
                "flex items-center gap-2 rounded-md border px-3 py-2 text-xs " +
                (wakeMsg.ok
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                  : "border-destructive/40 bg-destructive/5 text-destructive")
              }
            >
              <Power className="h-3.5 w-3.5 shrink-0" />
              {wakeMsg.text}
            </div>
          )}
          {/* Identity grid */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="Hostname">{dash(addr.hostname)}</Field>
            <Field label="FQDN" mono>
              {dash(addr.fqdn)}
            </Field>
            <Field label="MAC address" mono>
              {addr.mac_address ? (
                <span className="inline-flex items-center gap-1.5">
                  {addr.mac_address}
                  {addr.is_voip_phone && (
                    <span
                      className="inline-flex items-center"
                      title={`VoIP phone${addr.vendor ? ` — ${addr.vendor}` : ""}`}
                    >
                      <Phone className="h-3 w-3 text-sky-600 dark:text-sky-400" />
                    </span>
                  )}
                  {addr.vendor && (
                    <span className="font-sans text-[11px] text-muted-foreground">
                      {addr.vendor}
                    </span>
                  )}
                </span>
              ) : (
                dash(null)
              )}
            </Field>
            <Field label="Subnet" mono>
              {subnet ? (
                <span>
                  {subnet.network}
                  {subnet.name && (
                    <span className="ml-2 font-sans text-xs text-muted-foreground">
                      {subnet.name}
                    </span>
                  )}
                </span>
              ) : (
                dash(null)
              )}
            </Field>
            <Field label="Description">{dash(addr.description)}</Field>
            <Field label="Reserved until">
              {addr.reserved_until ? fmtTs(addr.reserved_until) : dash(null)}
            </Field>
            <Field label="Last seen">
              <span title={addr.last_seen_at ?? ""}>
                {addr.last_seen_at ? (
                  <>
                    {fmtTs(addr.last_seen_at)}
                    {addr.last_seen_method && (
                      <span className="ml-2 text-[11px] text-muted-foreground">
                        via {addr.last_seen_method}
                      </span>
                    )}
                  </>
                ) : (
                  dash(null)
                )}
              </span>
            </Field>
            <Field label="Forward DNS zone">
              {addr.forward_zone_id ? (
                <span className="font-mono text-xs">
                  {/* #516 — zoneNameById is now supplied by the caller (it was
                      previously never passed, so this always rendered "—").
                      Fall back to the raw id if the map lacks the zone. */}
                  {zoneNames[addr.forward_zone_id] ?? addr.forward_zone_id}
                </span>
              ) : (
                dash(null)
              )}
            </Field>
            <Field label="Reverse DNS zone">
              {addr.reverse_zone_id ? (
                <span className="font-mono text-xs">
                  {zoneNames[addr.reverse_zone_id] ?? addr.reverse_zone_id}
                </span>
              ) : (
                dash(null)
              )}
            </Field>
            <Field label="DNS / DHCP linkage">
              <span className="space-x-2 text-[11px] text-muted-foreground">
                {addr.dns_record_id && <span>A-record</span>}
                {addr.dhcp_lease_id && <span>· DHCP lease</span>}
                {addr.static_assignment_id && <span>· DHCP static</span>}
                {!addr.dns_record_id &&
                  !addr.dhcp_lease_id &&
                  !addr.static_assignment_id &&
                  dash(null)}
              </span>
            </Field>
          </div>

          {/* Counters row */}
          {((addr.alias_count ?? 0) > 0 ||
            (addr.nat_mapping_count ?? 0) > 0) && (
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
              {(addr.alias_count ?? 0) > 0 && (
                <span className="inline-flex items-center rounded bg-indigo-100 px-1.5 py-0.5 font-medium text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-400">
                  +{addr.alias_count} alias
                  {addr.alias_count === 1 ? "" : "es"}
                </span>
              )}
              {(addr.nat_mapping_count ?? 0) > 0 && (
                <span className="inline-flex items-center rounded bg-amber-100 px-1.5 py-0.5 font-medium text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">
                  NAT {addr.nat_mapping_count}
                </span>
              )}
            </div>
          )}

          {/* Tags */}
          {tagEntries.length > 0 && (
            <div>
              <div className="mb-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                Tags
              </div>
              <div className="flex flex-wrap gap-1">
                {tagEntries.map(([k, v]) => {
                  // Wire shape matches ``<TagFilterChips>`` exactly —
                  // ``key:value`` when there's a printable value,
                  // bare ``key`` when the stored value is the
                  // sentinel ``true`` / empty string.
                  const chip = v !== true && v !== "" ? `${k}:${String(v)}` : k;
                  const content = (
                    <>
                      <span className="font-medium">{k}</span>
                      {v !== true && v !== "" && (
                        <span className="ml-1 text-muted-foreground">
                          {String(v)}
                        </span>
                      )}
                    </>
                  );
                  if (onTagClick) {
                    return (
                      <button
                        key={k}
                        type="button"
                        onClick={() => onTagClick(chip)}
                        title={`Filter the address list by ${chip}`}
                        className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[11px] hover:bg-primary/15 hover:ring-1 hover:ring-primary/30"
                      >
                        {content}
                      </button>
                    );
                  }
                  return (
                    <span
                      key={k}
                      className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[11px]"
                    >
                      {content}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {/* Custom fields */}
          {cfEntries.length > 0 && (
            <div>
              <div className="mb-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                Custom fields
              </div>
              <div className="rounded-md border">
                <table className="w-full text-xs">
                  <tbody>
                    {cfEntries.map(([k, v]) => (
                      <tr key={k} className="border-b last:border-0 align-top">
                        <td className="w-1/3 px-2 py-1 text-muted-foreground">
                          {k}
                        </td>
                        <td className="px-2 py-1 break-words">
                          {v === null || v === undefined || v === ""
                            ? dash(null)
                            : typeof v === "object"
                              ? JSON.stringify(v)
                              : String(v)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Network discovery (FDB) */}
          <div>
            <div className="mb-1 flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
              <ExternalLink className="h-3 w-3" /> Network discovery
            </div>
            <IPNetworkTab addressId={addr.id} />
          </div>

          {/* Device profile (active layer — Phase 1 nmap auto-profile) */}
          <DeviceProfileSection addr={addr} canEdit={canEdit} />

          {/* Multicast memberships (issue #126 Wave 4). Hidden when
              the network.multicast feature module is disabled. */}
          <MulticastMembershipsSection addressId={addr.id} />

          {/* BACnet/IP device (issue #541), OT descriptor (issue #542)
              and DICOM AE (issue #723). Each self-hides when its module
              is off or the address carries no such sidecar. */}
          <BACnetDeviceSection addressId={addr.id} />
          <OTDeviceSection addressId={addr.id} />
          <DICOMAESection addressId={addr.id} />

          {/* Covering BGP route (issue #566 Phase 3). Hidden when the
              network.looking_glass module is off or nothing in the
              active RIB covers this address. */}
          <BgpRouteLookupSection address={addr.address} />

          <CertsSection addressId={addr.id} />

          {/* Reputation — DNSBL / RBL listing status (issue #528). Hidden
              when the security.dnsbl module is off or the IP isn't IPv4. */}
          <ReputationSection address={addr.address} canEdit={canEdit} />
        </div>
      </div>
    </div>
  );
}

// ── Reputation (DNSBL / RBL) ──────────────────────────────────────
//
// Per-IP DNS blocklist status across every enabled list, with a manual
// "Check now" action. IPv4-only (v1). Hidden when the security.dnsbl
// feature module is disabled.

function ReputationSection({
  address,
  canEdit,
}: {
  address: string;
  canEdit: boolean;
}) {
  const qc = useQueryClient();
  const { enabled } = useFeatureModules();
  const dnsblEnabled = enabled("security.dnsbl");
  const bareIp = (address || "").split("/")[0];
  const isIPv4 = bareIp.includes(".") && !bareIp.includes(":");

  const q = useQuery({
    queryKey: ["dnsbl", "by-ip", bareIp],
    queryFn: () => dnsblApi.byIp(bareIp),
    enabled: dnsblEnabled && isIPv4,
    staleTime: 30_000,
  });

  const check = useMutation({
    mutationFn: () => dnsblApi.checkNow(bareIp),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dnsbl", "by-ip", bareIp] });
      qc.invalidateQueries({ queryKey: ["dnsbl-listings"] });
    },
  });

  if (!dnsblEnabled || !isIPv4) return null;

  const data = q.data;
  const entries = data?.entries ?? [];

  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <div className="flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
          {data && data.listed_count > 0 ? (
            <ShieldAlert className="h-3 w-3 text-rose-500" />
          ) : (
            <ShieldCheck className="h-3 w-3" />
          )}{" "}
          Reputation
        </div>
        {canEdit && (
          <button
            type="button"
            onClick={() => check.mutate()}
            disabled={check.isPending}
            className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:opacity-60"
          >
            {check.isPending ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <RefreshCw className="h-3 w-3" />
            )}
            Check now
          </button>
        )}
      </div>

      {entries.length === 0 ? (
        <div className="rounded border border-dashed px-2 py-1.5 text-[11px] text-muted-foreground">
          No blocklists are enabled. Enable lists in Administration → DNS
          Blocklists to check this IP.
        </div>
      ) : (
        <div className="space-y-1">
          {data && data.listed_count > 0 && (
            <div className="text-[11px] font-medium text-rose-600">
              Listed on {data.listed_count} of {entries.length} blocklist(s).
            </div>
          )}
          <ul className="divide-y rounded border text-[11px]">
            {entries.map((e) => (
              <li
                key={e.list_id}
                className="flex items-start justify-between gap-2 px-2 py-1"
              >
                <div className="min-w-0">
                  <div className="font-medium">{e.list_name}</div>
                  {e.txt_reason && (
                    <div className="truncate text-muted-foreground">
                      {e.txt_reason}
                    </div>
                  )}
                  {e.check_error && (
                    <div className="truncate text-amber-600">
                      {e.check_error}
                    </div>
                  )}
                </div>
                <span
                  className={cn(
                    "shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium",
                    e.listed
                      ? "bg-rose-500/15 text-rose-600"
                      : e.checked
                        ? "bg-emerald-500/15 text-emerald-600"
                        : "bg-muted text-muted-foreground",
                  )}
                >
                  {e.listed
                    ? e.return_codes.length
                      ? `Listed (${e.return_codes.join(", ")})`
                      : "Listed"
                    : e.checked
                      ? "Clean"
                      : "Not checked"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ── Multicast memberships ─────────────────────────────────────────
//
// Surfaces the multicast groups this IP is a member of (producer /
// consumer / RP). Hidden when the network.multicast feature module
// is off, so non-multicast deployments don't see chrome they don't
// need.

function CertsSection({ addressId }: { addressId: string }) {
  const { enabled } = useFeatureModules();
  const certsEnabled = enabled("security.tls_certs");

  const q = useQuery({
    queryKey: ["tls-certs", "by-ip", addressId],
    queryFn: () => tlsCertsApi.list({ ip_address_id: addressId, limit: 50 }),
    enabled: certsEnabled,
    staleTime: 30_000,
  });

  if (!certsEnabled) return null;
  const targets = q.data?.items ?? [];
  // Most IPs serve no monitored cert — hide the section entirely then.
  if (targets.length === 0) return null;

  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        <ShieldCheck className="h-3 w-3" /> TLS certificates
      </div>
      <CertsCompactTable targets={targets} />
    </div>
  );
}

function MulticastMembershipsSection({ addressId }: { addressId: string }) {
  const { enabled } = useFeatureModules();
  const multicastEnabled = enabled("network.multicast");

  const q = useQuery({
    queryKey: ["multicast-memberships-by-ip", addressId],
    queryFn: () => multicastApi.listMembershipsByIP(addressId),
    enabled: multicastEnabled,
    staleTime: 30_000,
  });

  if (!multicastEnabled) return null;
  // Hide the section entirely when the IP isn't in any multicast
  // group. The fanout for a typical IP is zero so most callers
  // won't render anything; only stream-bearing endpoints carry
  // memberships.
  const memberships = q.data ?? [];
  if (q.isFetching && memberships.length === 0) return null;
  if (memberships.length === 0) return null;

  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        <Radio className="h-3 w-3" /> Multicast memberships
      </div>
      <div className="rounded-md border">
        <table className="w-full text-xs">
          <thead className="text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            <tr className="border-b bg-muted/30">
              <th className="px-3 py-1.5">Group</th>
              <th className="px-3 py-1.5">Application</th>
              <th className="px-3 py-1.5">Role</th>
              <th className="px-3 py-1.5">Source</th>
            </tr>
          </thead>
          <tbody>
            {memberships.map((m) => (
              <MulticastMembershipRow key={m.id} row={m} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── BACnet/IP device (issue #541) ─────────────────────────────────
//
// The BACnet identity of this address, if it has one. Most IPs are not
// building-automation controllers, so the section renders nothing at
// all rather than empty chrome — and the endpoint answers 404 for
// "not a BACnet device", which is a normal answer here, not a failure.

function BACnetDeviceSection({ addressId }: { addressId: string }) {
  // Gate on `ready &&`: enabled() answers optimistically true while the
  // module list is still loading, so without it a hard page load fires
  // one request that 404s when the module is off.
  const { enabled, ready } = useFeatureModules();
  const bacnetEnabled = ready && enabled("network.bacnet");

  const q = useQuery({
    queryKey: ["bacnet-device-by-ip", addressId],
    queryFn: () => bacnetApi.byAddress(addressId),
    enabled: bacnetEnabled,
    staleTime: 30_000,
    // A 404 is the expected answer for most addresses; retrying it just
    // burns three round-trips to learn the same thing.
    retry: false,
  });

  if (!bacnetEnabled) return null;
  const device = q.data;
  if (!device) return null;

  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        <Building2 className="h-3 w-3" /> BACnet/IP device
      </div>
      <div className="space-y-1 rounded-md border px-3 py-2 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[13px] font-semibold tabular-nums">
            {device.device_instance}
          </span>
          <span>{device.device_name || "unnamed device"}</span>
          {device.is_bbmd && (
            <span
              className="inline-flex rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400"
              title="Broadcast Distribution Device — forwards BACnet broadcasts between subnets"
            >
              BBMD
            </span>
          )}
          {device.is_foreign_device && (
            <span className="inline-flex rounded bg-sky-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-sky-700 dark:bg-sky-950/30 dark:text-sky-400">
              foreign
            </span>
          )}
        </div>
        <div className="text-muted-foreground">
          {[
            device.vendor_label || device.vendor_name,
            device.model_name,
            device.location,
          ]
            .filter(Boolean)
            .join(" · ") || "No vendor / model recorded"}
        </div>
        <div className="text-muted-foreground">
          UDP {device.udp_port}
          {device.network_number !== null &&
            ` · BACnet network ${device.network_number}`}
        </div>
      </div>
    </div>
  );
}

// ── DICOM application entity (issue #723) ─────────────────────────
//
// The DICOM identity of this address, if it has one. A PACS host can
// front several AE Titles; this shows the lowest-titled one, which is
// enough to answer "is this an imaging node" — the full set is on the
// DICOM page. 404 means "not a DICOM node", a normal answer here.
//
// Network identity only: nothing rendered here is patient data, because
// the registry stores none.

function DICOMAESection({ addressId }: { addressId: string }) {
  const { enabled, ready } = useFeatureModules();
  const dicomEnabled = ready && enabled("network.dicom");

  const q = useQuery({
    queryKey: ["dicom-ae-by-ip", addressId],
    queryFn: () => dicomApi.byAddress(addressId),
    enabled: dicomEnabled,
    staleTime: 30_000,
    // 404 = "this address has no DICOM AE", the common case.
    retry: false,
  });

  if (!dicomEnabled) return null;
  const ae = q.data;
  if (!ae) return null;

  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        <Scan className="h-3 w-3" /> DICOM application entity
      </div>
      <div className="space-y-1 rounded-md border px-3 py-2 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[13px] font-semibold">
            {ae.ae_title}
          </span>
          {ae.is_vendor_default && (
            <span
              className="inline-flex rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-amber-700 dark:bg-amber-950/30 dark:text-amber-400"
              title="Still a vendor default — the most common cause of institution-wide AE Title collisions"
            >
              default
            </span>
          )}
          {!ae.tls_enabled && (
            <span
              className="inline-flex rounded bg-rose-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-rose-700 dark:bg-rose-950/30 dark:text-rose-400"
              title="Not recorded as TLS-enabled — plaintext DICOM carries ePHI in the clear"
            >
              plaintext
            </span>
          )}
        </div>
        <div className="text-muted-foreground">
          {[ae.vendor, ae.model_name, ae.department, ae.location]
            .filter(Boolean)
            .join(" · ") || "No vendor / department recorded"}
        </div>
        <div className="text-muted-foreground">
          Port {ae.port} · {ae.role} · {ae.device_class}
        </div>
      </div>
    </div>
  );
}

// ── OT / industrial descriptor (issue #542) ───────────────────────
//
// The industrial identity of this address plus the Purdue verdict from
// its subnet's zone. ``purdue_mismatch`` is tri-state: null means one
// side has no declared level, which is an unknown rather than a
// violation, so only an explicit ``true`` is flagged.

function OTDeviceSection({ addressId }: { addressId: string }) {
  const { enabled, ready } = useFeatureModules();
  const otEnabled = ready && enabled("network.ot");

  const q = useQuery({
    queryKey: ["ot-device-by-ip", addressId],
    queryFn: () => otApi.byAddress(addressId),
    enabled: otEnabled,
    staleTime: 30_000,
    // 404 = "this address has no OT descriptor", the common case.
    retry: false,
  });

  if (!otEnabled) return null;
  const device = q.data;
  if (!device) return null;

  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        <Factory className="h-3 w-3" /> OT device
      </div>
      <div className="space-y-1 rounded-md border px-3 py-2 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium">
            {device.profinet_device_name || "unnamed device"}
          </span>
          <span className="text-muted-foreground">
            {OT_PROTOCOL_LABELS[device.ot_protocol] ?? device.ot_protocol}
          </span>
          {device.ot_role && (
            <span className="inline-flex rounded bg-zinc-100 px-1.5 py-0.5 text-[10px] font-medium text-zinc-700 dark:bg-zinc-800/50 dark:text-zinc-300">
              {OT_ROLE_LABELS[device.ot_role] ?? device.ot_role}
            </span>
          )}
          {device.purdue_level !== null && (
            <span className="inline-flex rounded bg-indigo-100 px-1.5 py-0.5 text-[10px] font-medium tabular-nums text-indigo-700 dark:bg-indigo-950/30 dark:text-indigo-400">
              Purdue L{device.purdue_level}
            </span>
          )}
          {device.purdue_mismatch === true && (
            <span
              className="inline-flex rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-amber-700 dark:bg-amber-950/30 dark:text-amber-400"
              title={`The subnet's zone declares Purdue ${device.zone_purdue_level}`}
            >
              zone mismatch
            </span>
          )}
        </div>
        <div className="text-muted-foreground">
          {[device.ot_vendor, device.ot_product, device.ot_serial]
            .filter(Boolean)
            .join(" · ") || "No vendor / product recorded"}
        </div>
        <div className="text-muted-foreground">
          {device.zone_id
            ? `Zone: ${device.zone_name || device.zone_cell_area || "unnamed"} (Purdue L${device.zone_purdue_level})`
            : "Subnet has no Purdue zone declared"}
          {device.cell_area && ` · Cell ${device.cell_area}`}
        </div>
      </div>
    </div>
  );
}

/** Reverse LPM-by-address lookup — "what BGP route covers this exact
 *  IP?" (issue #566 Phase 3). Self-hides when the network.looking_glass
 *  module is off or nothing in the active RIB covers the address. */
function BgpRouteLookupSection({ address }: { address: string }) {
  const { enabled } = useFeatureModules();
  const lgEnabled = enabled("network.looking_glass");

  const q = useQuery({
    queryKey: ["bgp-lg-route-for-ip", address],
    queryFn: () => lookingGlassApi.routeForIp(address),
    enabled: lgEnabled,
    staleTime: 30_000,
  });

  if (!lgEnabled) return null;
  if (!q.data?.found || !q.data.route) return null;
  const r = q.data.route;

  return (
    <div>
      <div className="mb-1 flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        <RouteIcon className="h-3 w-3" /> BGP route
      </div>
      <div className="space-y-1 rounded-md border px-3 py-2 text-xs">
        <div className="flex items-center justify-between">
          <span className="font-mono">{r.prefix}</span>
          <RpkiPill status={r.rpki_status} />
        </div>
        <div className="text-muted-foreground">
          Origin {r.origin_asn == null ? "—" : `AS${r.origin_asn}`} via{" "}
          {r.next_hop}
          {q.data.alternate_paths_count > 0 &&
            ` · +${q.data.alternate_paths_count} more path${
              q.data.alternate_paths_count === 1 ? "" : "s"
            }`}
        </div>
      </div>
    </div>
  );
}

function MulticastMembershipRow({
  row,
}: {
  row: MulticastMembershipReadWithGroup;
}) {
  const roleStyles: Record<string, string> = {
    producer:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    consumer: "bg-sky-100 text-sky-700 dark:bg-sky-950/30 dark:text-sky-400",
    rendezvous_point:
      "bg-violet-100 text-violet-700 dark:bg-violet-950/30 dark:text-violet-400",
  };
  return (
    <tr className="border-b last:border-b-0">
      <td className="px-3 py-1.5">
        <div className="flex flex-col">
          <span className="font-mono text-[12px]">{row.group_address}</span>
          <span className="text-[11px] text-muted-foreground">
            {row.group_name}
          </span>
        </div>
      </td>
      <td className="px-3 py-1.5 text-muted-foreground">
        {row.group_application || "—"}
      </td>
      <td className="px-3 py-1.5">
        <span
          className={cn(
            "inline-flex items-center rounded px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider",
            roleStyles[row.role] ?? "bg-zinc-200 text-zinc-700",
          )}
        >
          {row.role.replace("_", " ")}
        </span>
      </td>
      <td className="px-3 py-1.5 text-muted-foreground">
        {row.seen_via.replace("_", " ")}
      </td>
    </tr>
  );
}

// ── Device profile ─────────────────────────────────────────────────────
//
// Shows the most recent successful nmap profile scan (OS guess + top
// open services) and surfaces a "Re-profile now" button. The button
// dispatches an ad-hoc scan via /ipam/addresses/{id}/profile — same
// pipeline as the lease-driven auto-profile, but with the refresh-window
// dedupe bypassed so the operator can force a fresh result on demand.
// Per-subnet concurrency cap still applies (returns 429 when full).
//
// Phase 2 (passive DHCP fingerprinting) will surface a sibling
// "Passive fingerprint" panel inside this section once shipped — the
// passive layer reads option-55/option-60 from incoming DHCP traffic
// and looks up the device class via fingerbank. For now Phase 1 owns
// the whole block.

function DeviceProfileSection({
  addr,
  canEdit,
}: {
  addr: IPAddress;
  canEdit: boolean;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const [showRawSig, setShowRawSig] = useState(false);
  // Track the scan dispatched by clicking "Re-profile now" so we can
  // keep the button in a "Scanning…" state until the worker finishes.
  // The mutation's own ``isPending`` only covers the dispatch HTTP
  // call (~ms), but the actual nmap run takes 30 s–2 min server-side.
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  // The most recent scan completed in *this* modal session. The parent
  // (IPAMPage) holds ``viewingAddress`` as a snapshot, so even after we
  // invalidate the addresses query the ``addr`` prop here doesn't see
  // the new ``last_profile_scan_id`` until the operator reopens the
  // modal. Caching the completed scan locally lets the panel refresh
  // immediately on terminal status without that round-trip.
  const [sessionScan, setSessionScan] = useState<NmapScanRead | null>(null);

  const scanQuery = useQuery({
    enabled: !!addr.last_profile_scan_id,
    queryKey: ["nmap-scan", addr.last_profile_scan_id],
    queryFn: () => nmapApi.getScan(addr.last_profile_scan_id as string),
    staleTime: 30_000,
  });

  // Poll the freshly-dispatched scan until it reaches a terminal
  // state. ``refetchInterval`` returns ``false`` to stop the poll
  // automatically; the effect below clears local state + invalidates
  // the parent queries so the device-profile panel refreshes.
  const activeScanQuery = useQuery({
    enabled: !!activeScanId,
    queryKey: ["nmap-scan-active", activeScanId],
    queryFn: () => nmapApi.getScan(activeScanId as string),
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      return s === "queued" || s === "running" ? 2000 : false;
    },
    refetchIntervalInBackground: false,
  });

  useEffect(() => {
    if (!activeScanId) return;
    const data = activeScanQuery.data;
    const status = data?.status;
    if (
      status === "completed" ||
      status === "failed" ||
      status === "cancelled"
    ) {
      // Cache the completed scan so the panel re-renders immediately
      // (the ``addr`` prop is parent-held + lags the DB).
      setSessionScan(data ?? null);
      qc.invalidateQueries({ queryKey: ["addresses", addr.subnet_id] });
      qc.invalidateQueries({
        queryKey: ["nmap-scan", addr.last_profile_scan_id],
      });
      qc.invalidateQueries({ queryKey: ["dhcp-fingerprint", addr.id] });
      if (status === "failed") {
        const msg = data?.error_message;
        setError(typeof msg === "string" && msg ? msg : "Scan failed");
      }
      setActiveScanId(null);
    }
  }, [
    activeScanId,
    activeScanQuery.data,
    addr.id,
    addr.subnet_id,
    addr.last_profile_scan_id,
    qc,
  ]);

  // Passive fingerprint — Phase 2. The endpoint 404s when no MAC or
  // no fingerprint has been observed; treat 404 as "no data" rather
  // than a hard error.
  const fingerprintQuery = useQuery({
    enabled: !!addr.mac_address,
    queryKey: ["dhcp-fingerprint", addr.id],
    queryFn: async () => {
      try {
        return await ipamApi.getDhcpFingerprint(addr.id);
      } catch (err) {
        const status = (err as { response?: { status?: number } })?.response
          ?.status;
        if (status === 404) return null;
        throw err;
      }
    },
    staleTime: 30_000,
  });

  const reprofile = useMutation({
    mutationFn: () => ipamApi.profileAddress(addr.id),
    onSuccess: (data) => {
      setError(null);
      // Hand the dispatched scan to the polling query so the spinner
      // tracks the actual worker run, not just the dispatch ack.
      setActiveScanId(data.scan_id);
      qc.invalidateQueries({ queryKey: ["nmap-scans"] });
    },
    onError: (err: unknown) => {
      const detail = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      setError(typeof detail === "string" ? detail : "Failed to dispatch scan");
    },
  });

  // Effective "scan in flight" state: covers the dispatch HTTP call
  // (mutation pending) AND the worker-side scan window (active scan
  // status is queued or running). ``activeScanLabel`` reflects what
  // the user sees alongside the spinner.
  const activeStatus = activeScanQuery.data?.status;
  const isScanning =
    reprofile.isPending ||
    (!!activeScanId &&
      (activeStatus === "queued" ||
        activeStatus === "running" ||
        activeStatus === undefined));
  const scanLabel = reprofile.isPending
    ? "Dispatching…"
    : activeStatus === "running"
      ? "Scanning…"
      : activeStatus === "queued"
        ? "Queued…"
        : isScanning
          ? "Scanning…"
          : "Re-profile now";

  const passiveType =
    addr.device_type ?? fingerprintQuery.data?.fingerbank_device_name ?? null;
  const passiveClass =
    addr.device_class ?? fingerprintQuery.data?.fingerbank_device_class ?? null;
  const passiveManufacturer =
    addr.device_manufacturer ??
    fingerprintQuery.data?.fingerbank_manufacturer ??
    null;
  const hasPassive =
    !!passiveType ||
    !!passiveClass ||
    !!passiveManufacturer ||
    !!fingerprintQuery.data;

  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <div className="flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
          <Radar className="h-3 w-3" /> Device profile
        </div>
        {canEdit && (
          <button
            type="button"
            onClick={() => reprofile.mutate()}
            disabled={isScanning}
            className="inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:opacity-60"
            title={
              isScanning
                ? "A profile scan is currently running for this IP"
                : "Run a fresh nmap profile scan now"
            }
          >
            {isScanning ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <RefreshCw className="h-3 w-3" />
            )}
            {scanLabel}
          </button>
        )}
      </div>

      {error && (
        <div className="mb-2 rounded-md border border-destructive/40 bg-destructive/5 px-2 py-1 text-[11px] text-destructive">
          {error}
        </div>
      )}

      {/* Passive layer — DHCP fingerprint via fingerbank. */}
      {hasPassive && (
        <div className="mb-2 rounded-md border bg-muted/30 p-2.5">
          <div className="mb-1 flex items-center justify-between text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            <span>Passive fingerprint</span>
            {fingerprintQuery.data && (
              <button
                type="button"
                onClick={() => setShowRawSig((v) => !v)}
                className="text-[10px] font-normal normal-case tracking-normal text-muted-foreground/80 hover:text-foreground"
              >
                {showRawSig ? "hide" : "show"} raw signature
              </button>
            )}
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Type
              </div>
              <div className="mt-0.5 text-sm">
                {passiveType ?? (
                  <span className="text-muted-foreground/50">—</span>
                )}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Class
              </div>
              <div className="mt-0.5 text-sm">
                {passiveClass ?? (
                  <span className="text-muted-foreground/50">—</span>
                )}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
                Manufacturer
              </div>
              <div className="mt-0.5 text-sm">
                {passiveManufacturer ?? (
                  <span className="text-muted-foreground/50">—</span>
                )}
              </div>
            </div>
          </div>
          {fingerprintQuery.data?.fingerbank_score != null && (
            <div className="mt-1 text-[11px] text-muted-foreground">
              fingerbank score {fingerprintQuery.data.fingerbank_score}/100
              {fingerprintQuery.data.fingerbank_last_lookup_at && (
                <>
                  {" · "}
                  looked up{" "}
                  {new Date(
                    fingerprintQuery.data.fingerbank_last_lookup_at,
                  ).toLocaleString()}
                </>
              )}
            </div>
          )}
          {fingerprintQuery.data?.fingerbank_last_error && (
            <div className="mt-1 text-[11px] text-destructive">
              fingerbank: {fingerprintQuery.data.fingerbank_last_error}
            </div>
          )}
          {showRawSig && fingerprintQuery.data && (
            <RawSignaturePanel fp={fingerprintQuery.data} />
          )}
        </div>
      )}

      {/* Active layer — nmap profile scan. ``sessionScan`` (the
          just-completed scan from this modal session) wins over the
          parent-held ``addr.last_profile_scan_id`` snapshot so the
          panel refreshes immediately on terminal status. */}
      {(() => {
        const displayScan = sessionScan ?? scanQuery.data ?? null;
        const displayProfiledAt =
          sessionScan?.finished_at ?? addr.last_profiled_at ?? null;
        const havePrior = !!addr.last_profile_scan_id || !!sessionScan;
        if (!havePrior && !isScanning) {
          return (
            <p className="text-xs text-muted-foreground italic">
              No active profile yet. Auto-profiling triggers on a fresh DHCP
              lease when the subnet's "Device profiling" toggle is enabled, or
              run one ad-hoc via the button above.
            </p>
          );
        }
        if (!havePrior) return null;
        return (
          <DeviceProfileScanPanel
            lastProfiledAt={displayProfiledAt}
            scan={displayScan}
            loading={scanQuery.isLoading && !sessionScan}
          />
        );
      })()}
    </div>
  );
}

function RawSignaturePanel({ fp }: { fp: DHCPFingerprintResponse }) {
  return (
    <div className="mt-2 space-y-1 border-t pt-2 font-mono text-[11px] text-muted-foreground">
      <div>
        <span className="text-muted-foreground/70">option-55</span>{" "}
        {fp.option_55 ?? "—"}
      </div>
      <div>
        <span className="text-muted-foreground/70">option-60</span>{" "}
        {fp.option_60 ?? "—"}
      </div>
      <div>
        <span className="text-muted-foreground/70">option-77</span>{" "}
        {fp.option_77 ?? "—"}
      </div>
      <div>
        <span className="text-muted-foreground/70">client-id</span>{" "}
        {fp.client_id ?? "—"}
      </div>
      <div>
        <span className="text-muted-foreground/70">first seen</span>{" "}
        {new Date(fp.first_seen_at).toLocaleString()}
      </div>
      <div>
        <span className="text-muted-foreground/70">last seen</span>{" "}
        {new Date(fp.last_seen_at).toLocaleString()}
      </div>
    </div>
  );
}

function DeviceProfileScanPanel({
  lastProfiledAt,
  scan,
  loading,
}: {
  lastProfiledAt: string | null;
  scan: NmapScanRead | null;
  loading: boolean;
}) {
  if (loading) {
    return (
      <p className="text-xs text-muted-foreground">
        <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />
        Loading profile…
      </p>
    );
  }
  if (!scan) {
    return (
      <p className="text-xs text-muted-foreground italic">
        Profile scan unavailable (deleted or not yet readable).
      </p>
    );
  }

  // Cap services at 8 to keep the modal readable. Operators who need
  // the full list can deep-link into the nmap surface from the row id.
  const openPorts = (scan.summary?.ports ?? [])
    .filter((p) => p.state === "open")
    .slice(0, 8);
  const os = scan.summary?.os ?? null;

  return (
    <div className="space-y-2 rounded-md border bg-muted/30 p-2.5">
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        <span>
          Last scanned{" "}
          {lastProfiledAt
            ? new Date(lastProfiledAt).toLocaleString()
            : new Date(scan.finished_at ?? scan.created_at).toLocaleString()}
        </span>
        <span>·</span>
        <span>preset {scan.preset}</span>
        <span>·</span>
        <span
          className={cn(
            "rounded px-1.5 py-0.5 font-medium",
            scan.status === "completed"
              ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400"
              : scan.status === "running" || scan.status === "queued"
                ? "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400"
                : "bg-zinc-100 text-zinc-700 dark:bg-zinc-800/50 dark:text-zinc-400",
          )}
        >
          {scan.status}
        </span>
      </div>

      <div>
        <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
          OS guess
        </div>
        <div className="mt-0.5 text-sm">
          {os?.name ? (
            <>
              {os.name}
              {os.accuracy != null && (
                <span className="ml-2 text-[11px] text-muted-foreground">
                  {os.accuracy}% confidence
                </span>
              )}
            </>
          ) : (
            <span className="text-muted-foreground/50">—</span>
          )}
        </div>
      </div>

      <div>
        <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
          Open services
        </div>
        {openPorts.length === 0 ? (
          <div className="mt-0.5 text-sm text-muted-foreground/50">—</div>
        ) : (
          <ul className="mt-0.5 space-y-0.5 text-xs">
            {openPorts.map((p) => (
              <li key={`${p.proto}-${p.port}`} className="font-mono">
                <span>
                  {p.port}/{p.proto}
                </span>
                {p.service && (
                  <span className="ml-2 text-muted-foreground">
                    {p.service}
                  </span>
                )}
                {(p.product || p.version) && (
                  <span className="ml-2 text-[11px] text-muted-foreground/80">
                    {[p.product, p.version].filter(Boolean).join(" ")}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
