/**
 * BulkAllocateModal — stamp a contiguous IP range with name templating.
 *
 * Two-phase flow mirrors ResizeModals + SubnetOpsModals:
 * - Phase "form"      → operator types range + template + options.
 * - Phase "previewed" → server returned blast-radius counts + sample.
 *                       Operator confirms or backs out.
 * - Phase "committed" → server returned commit results; modal shows
 *                       the summary + a "Done" button.
 *
 * Template tokens (mirrors backend `_BULK_TEMPLATE_RE`):
 *   {n}, {n:03d}, {n:x}, {oct1}-{oct4}
 * Anything else is literal. Live preview renders client-side as the
 * operator types so they see the rendered hostnames before posting.
 */

import { useEffect, useMemo, useState } from "react";
import {
  useMutation,
  useQueries,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Sparkles,
  X,
} from "lucide-react";
import {
  MODAL_BACKDROP_CLS,
  useModalDialog,
} from "@/components/ui/use-draggable-modal";
import { cn } from "@/lib/utils";
import {
  type BulkAllocateCommitResponse,
  type BulkAllocateItem,
  type BulkAllocatePreviewResponse,
  type BulkAllocateRequest,
  type DNSZone,
  dnsApi,
  formatApiError,
  ipamApi,
  type Subnet,
} from "@/lib/api";

const BULK_TEMPLATE_RE = /\{(n|oct[1-4])(?::([^}]+))?\}/g;
const HOSTNAME_LABEL_RE = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$/;

function expandTemplate(
  template: string,
  ip: string,
  n: number,
  v6: boolean,
): string {
  const octets = v6 ? [] : ip.split(".");
  return template.replace(
    BULK_TEMPLATE_RE,
    (_match, token: string, fmt: string | undefined) => {
      if (token === "n") {
        if (!fmt) return String(n);
        // Support {n:03d} (zero-pad), {n:x} (hex), {n:X} (upper hex).
        const padMatch = /^0?(\d+)d$/.exec(fmt);
        if (padMatch) return String(n).padStart(Number(padMatch[1]), "0");
        if (fmt === "x") return n.toString(16);
        if (fmt === "X") return n.toString(16).toUpperCase();
        return String(n);
      }
      const idx = Number(token[3]) - 1;
      return octets[idx] ?? "";
    },
  );
}

function ipToBigInt(ip: string): bigint | null {
  if (ip.includes(":")) {
    // IPv6 — best-effort parsing for live preview
    try {
      const expanded = expandIpv6(ip);
      if (!expanded) return null;
      return BigInt(`0x${expanded.replace(/:/g, "")}`);
    } catch {
      return null;
    }
  }
  const parts = ip.split(".").map((p) => Number(p));
  if (
    parts.length !== 4 ||
    parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)
  ) {
    return null;
  }
  return (
    (BigInt(parts[0]) << 24n) |
    (BigInt(parts[1]) << 16n) |
    (BigInt(parts[2]) << 8n) |
    BigInt(parts[3])
  );
}

function expandIpv6(ip: string): string | null {
  const dblIdx = ip.indexOf("::");
  let hextets: string[];
  if (dblIdx === -1) {
    hextets = ip.split(":");
  } else {
    const left = ip.slice(0, dblIdx).split(":").filter(Boolean);
    const right = ip
      .slice(dblIdx + 2)
      .split(":")
      .filter(Boolean);
    const fill = 8 - left.length - right.length;
    if (fill < 0) return null;
    hextets = [...left, ...Array(fill).fill("0"), ...right];
  }
  if (hextets.length !== 8) return null;
  return hextets.map((h) => h.padStart(4, "0")).join(":");
}

function bigIntToIp(n: bigint, v6: boolean): string {
  if (v6) {
    const hex = n.toString(16).padStart(32, "0");
    return hex.match(/.{4}/g)!.join(":");
  }
  return [
    Number((n >> 24n) & 0xffn),
    Number((n >> 16n) & 0xffn),
    Number((n >> 8n) & 0xffn),
    Number(n & 0xffn),
  ].join(".");
}

function ModalShell({
  title,
  onClose,
  children,
  footer,
  width = "780px",
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer: React.ReactNode;
  width?: string;
}) {
  const { dialogProps, titleProps, dialogStyle, dragHandleProps } =
    useModalDialog(onClose);
  return (
    <div className={MODAL_BACKDROP_CLS}>
      <div
        {...dialogProps}
        className="flex max-h-[90vh] w-full max-w-[95vw] flex-col rounded-lg bg-background shadow-xl focus:outline-none"
        style={{ ...dialogStyle, maxWidth: `min(95vw, ${width})` }}
      >
        <div
          {...dragHandleProps}
          className={cn(
            "flex items-center justify-between border-b p-4",
            dragHandleProps.className,
          )}
        >
          <h2 {...titleProps} className="text-base font-semibold">
            {title}
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">{children}</div>
        <div className="flex flex-wrap justify-end gap-2 border-t p-3">
          {footer}
        </div>
      </div>
    </div>
  );
}

const inputCls =
  "block w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring";

export function BulkAllocateModal({
  subnet,
  onClose,
  onCommitted,
}: {
  subnet: Subnet;
  onClose: () => void;
  onCommitted?: () => void;
}) {
  const qc = useQueryClient();
  const v6 = subnet.network.includes(":");

  // Sensible default range: skip the network address (IPv4) and broadcast,
  // start two in. For /24 192.168.0.0/24 that's 192.168.0.10 → 192.168.0.20.
  const defaultStart = useMemo(() => {
    const networkOnly = subnet.network.split("/")[0];
    const base = ipToBigInt(networkOnly);
    if (base === null) return networkOnly;
    return bigIntToIp(base + (v6 ? 1n : 10n), v6);
  }, [subnet.network, v6]);
  const defaultEnd = useMemo(() => {
    const networkOnly = subnet.network.split("/")[0];
    const base = ipToBigInt(networkOnly);
    if (base === null) return networkOnly;
    return bigIntToIp(base + (v6 ? 16n : 20n), v6);
  }, [subnet.network, v6]);

  const [phase, setPhase] = useState<"form" | "previewed" | "committed">(
    "form",
  );
  const [rangeStart, setRangeStart] = useState(defaultStart);
  const [rangeEnd, setRangeEnd] = useState(defaultEnd);
  const [hostnameTemplate, setHostnameTemplate] = useState("host-{n}");
  const [templateStart, setTemplateStart] = useState(1);
  const [statusValue, setStatusValue] = useState("allocated");
  const [description, setDescription] = useState("");
  const [dnsZoneId, setDnsZoneId] = useState<string>("");
  const [createDnsRecords, setCreateDnsRecords] = useState(true);
  const [onCollision, setOnCollision] = useState<"skip" | "abort">("skip");

  const [serverError, setServerError] = useState<string | null>(null);
  const [previewData, setPreviewData] =
    useState<BulkAllocatePreviewResponse | null>(null);
  const [commitData, setCommitData] =
    useState<BulkAllocateCommitResponse | null>(null);

  // Pull effective DNS so we can populate the zone dropdown with just the
  // zones that actually apply to this subnet (mirrors AddAddressModal).
  const { data: effectiveDns } = useQuery({
    queryKey: ["effective-dns-subnet", subnet.id],
    queryFn: () => ipamApi.getEffectiveSubnetDns(subnet.id),
    staleTime: 30_000,
  });

  const zoneGroupIds: string[] = effectiveDns?.dns_group_ids ?? [];
  const zoneQueries = useQueries({
    queries: zoneGroupIds.map((gId) => ({
      queryKey: ["dns-zones", gId],
      queryFn: () => dnsApi.listZones(gId),
      staleTime: 60_000,
    })),
  });
  const allGroupZones: DNSZone[] = zoneQueries
    .flatMap((q) => (q.data as DNSZone[] | undefined) ?? [])
    .filter((z) => !z.name.toLowerCase().includes("arpa"));
  const explicitZoneIds = [
    ...(effectiveDns?.dns_zone_id ? [effectiveDns.dns_zone_id] : []),
    ...(effectiveDns?.dns_additional_zone_ids ?? []),
  ];
  const availableZones: DNSZone[] =
    explicitZoneIds.length > 0
      ? allGroupZones.filter((z) => explicitZoneIds.includes(z.id))
      : allGroupZones;

  useEffect(() => {
    if (!dnsZoneId && availableZones.length > 0) {
      const primary = effectiveDns?.dns_zone_id;
      setDnsZoneId(
        primary && availableZones.some((z) => z.id === primary)
          ? primary
          : availableZones[0].id,
      );
    }
  }, [availableZones.length, effectiveDns?.dns_zone_id]); // eslint-disable-line react-hooks/exhaustive-deps

  // Client-side live preview: shows the first few rendered hostnames as
  // the operator types so they see the template effect before posting.
  // Errors are silent — the real validation happens server-side.
  const livePreview = useMemo(() => {
    const startInt = ipToBigInt(rangeStart);
    const endInt = ipToBigInt(rangeEnd);
    if (startInt === null || endInt === null || endInt < startInt) return null;
    const total = Number(endInt - startInt + 1n);
    if (total <= 0 || total > 1024) return null;
    const limit = Math.min(total, 5);
    const samples: { ip: string; hostname: string }[] = [];
    for (let i = 0; i < limit; i++) {
      const ipStr = bigIntToIp(startInt + BigInt(i), v6);
      samples.push({
        ip: ipStr,
        hostname: expandTemplate(
          hostnameTemplate,
          ipStr,
          templateStart + i,
          v6,
        ),
      });
    }
    if (total > limit) {
      const lastIp = bigIntToIp(endInt, v6);
      samples.push({
        ip: "…",
        hostname: "…",
      });
      samples.push({
        ip: lastIp,
        hostname: expandTemplate(
          hostnameTemplate,
          lastIp,
          templateStart + total - 1,
          v6,
        ),
      });
    }
    return { total, samples };
  }, [rangeStart, rangeEnd, hostnameTemplate, templateStart, v6]);

  // Quick local validation: does the rendered hostname match RFC 1035?
  // Server enforces the same rule; this just gives instant feedback.
  const hostnameError = useMemo(() => {
    const startInt = ipToBigInt(rangeStart);
    if (startInt === null) return null;
    const probe = expandTemplate(
      hostnameTemplate,
      rangeStart,
      templateStart,
      v6,
    );
    if (!probe) return "Template is empty";
    if (!HOSTNAME_LABEL_RE.test(probe)) {
      return `Renders to '${probe}' — must match ^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$`;
    }
    return null;
  }, [rangeStart, hostnameTemplate, templateStart, v6]);

  const buildBody = (): BulkAllocateRequest => ({
    range_start: rangeStart.trim(),
    range_end: rangeEnd.trim(),
    hostname_template: hostnameTemplate.trim(),
    template_start: templateStart,
    status: statusValue,
    description: description.trim() || null,
    dns_zone_id: createDnsRecords ? dnsZoneId || null : null,
    create_dns_records: createDnsRecords,
    on_collision: onCollision,
  });

  const previewMut = useMutation({
    mutationFn: () => ipamApi.bulkAllocatePreview(subnet.id, buildBody()),
    onSuccess: (data) => {
      setPreviewData(data);
      setPhase("previewed");
      setServerError(null);
    },
    onError: (err) => setServerError(formatApiError(err)),
  });

  const commitMut = useMutation({
    mutationFn: () => ipamApi.bulkAllocateCommit(subnet.id, buildBody()),
    onSuccess: (data) => {
      setCommitData(data);
      setPhase("committed");
      setServerError(null);
      qc.invalidateQueries({ queryKey: ["addresses", subnet.id] });
      qc.invalidateQueries({ queryKey: ["subnets"] });
      qc.invalidateQueries({ queryKey: ["dns-records"] });
      qc.invalidateQueries({ queryKey: ["dns-zones"] });
      onCommitted?.();
    },
    onError: (err) => setServerError(formatApiError(err)),
  });

  const formInvalid =
    !rangeStart.trim() ||
    !rangeEnd.trim() ||
    !hostnameTemplate.trim() ||
    !!hostnameError;

  // ── Footer buttons per phase ─────────────────────────────────────────
  const footer =
    phase === "form" ? (
      <>
        <button
          type="button"
          onClick={onClose}
          className="rounded border px-3 py-1.5 text-sm hover:bg-accent"
        >
          Cancel
        </button>
        <button
          type="button"
          disabled={formInvalid || previewMut.isPending}
          onClick={() => previewMut.mutate()}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {previewMut.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Sparkles className="h-4 w-4" />
          )}
          Preview
        </button>
      </>
    ) : phase === "previewed" ? (
      <>
        <button
          type="button"
          onClick={() => {
            setPhase("form");
            setPreviewData(null);
          }}
          className="rounded border px-3 py-1.5 text-sm hover:bg-accent"
        >
          Back to edit
        </button>
        <button
          type="button"
          disabled={
            commitMut.isPending ||
            !previewData ||
            previewData.will_create === 0 ||
            (onCollision === "abort" &&
              previewData &&
              previewData.conflicts_in_use +
                previewData.conflicts_in_pool +
                previewData.conflicts_fqdn >
                0)
          }
          onClick={() => commitMut.mutate()}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {commitMut.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <CheckCircle2 className="h-4 w-4" />
          )}
          {previewData ? `Allocate ${previewData.will_create} IPs` : "Allocate"}
        </button>
      </>
    ) : (
      <button
        type="button"
        onClick={onClose}
        className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90"
      >
        Done
      </button>
    );

  return (
    <ModalShell
      title={`Bulk allocate — ${subnet.network}${subnet.name ? ` (${subnet.name})` : ""}`}
      onClose={onClose}
      footer={footer}
    >
      {phase === "form" && (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Range start
              </label>
              <input
                className={cn(inputCls, "font-mono")}
                value={rangeStart}
                onChange={(e) => setRangeStart(e.target.value)}
                placeholder={defaultStart}
                autoFocus
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Range end
              </label>
              <input
                className={cn(inputCls, "font-mono")}
                value={rangeEnd}
                onChange={(e) => setRangeEnd(e.target.value)}
                placeholder={defaultEnd}
              />
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Hostname template
            </label>
            <input
              className={cn(inputCls, "font-mono")}
              value={hostnameTemplate}
              onChange={(e) => setHostnameTemplate(e.target.value)}
              placeholder="e.g. dhcp-{n} or host-{oct3}-{oct4} or web-{n:03d}"
            />
            <p className="mt-1 text-[11px] text-muted-foreground/80">
              Tokens: <span className="font-mono">{"{n}"}</span> iterator •{" "}
              <span className="font-mono">{"{n:03d}"}</span> zero-pad •{" "}
              <span className="font-mono">{"{n:x}"}</span> hex •{" "}
              <span className="font-mono">{"{oct1}"}</span>–
              <span className="font-mono">{"{oct4}"}</span> IP octets
            </p>
            {hostnameError && (
              <p className="mt-1 text-xs text-destructive">{hostnameError}</p>
            )}
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Iterator start
              </label>
              <input
                type="number"
                className={cn(inputCls, "font-mono")}
                value={templateStart}
                onChange={(e) => setTemplateStart(Number(e.target.value) || 0)}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Status
              </label>
              <select
                className={inputCls}
                value={statusValue}
                onChange={(e) => setStatusValue(e.target.value)}
              >
                <option value="allocated">allocated</option>
                <option value="reserved">reserved</option>
                <option value="deprecated">deprecated</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                On collision
              </label>
              <select
                className={inputCls}
                value={onCollision}
                onChange={(e) =>
                  setOnCollision(e.target.value as "skip" | "abort")
                }
              >
                <option value="skip">Skip conflicting IPs</option>
                <option value="abort">Abort if any conflict</option>
              </select>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Description (optional)
            </label>
            <input
              className={inputCls}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Applied to every created row"
            />
          </div>

          <div className="rounded-md border bg-muted/30 p-3">
            <label className="flex cursor-pointer items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={createDnsRecords}
                onChange={(e) => setCreateDnsRecords(e.target.checked)}
              />
              <span>Create DNS records (forward A/AAAA + reverse PTR)</span>
            </label>
            {createDnsRecords && availableZones.length > 0 && (
              <div className="mt-2">
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Forward zone
                </label>
                <select
                  className={inputCls}
                  value={dnsZoneId}
                  onChange={(e) => setDnsZoneId(e.target.value)}
                >
                  {availableZones.map((z) => (
                    <option key={z.id} value={z.id}>
                      {z.name}
                    </option>
                  ))}
                </select>
              </div>
            )}
            {createDnsRecords && availableZones.length === 0 && (
              <p className="mt-1 text-xs text-muted-foreground">
                No DNS zones are pinned to this subnet — A records will fall
                through to the effective default zone if one exists.
              </p>
            )}
          </div>

          {livePreview && (
            <div className="rounded-md border bg-muted/20 p-3">
              <div className="mb-1 text-xs font-medium text-muted-foreground">
                Preview ({livePreview.total} IPs total)
              </div>
              <table className="w-full text-xs font-mono">
                <tbody>
                  {livePreview.samples.map((s, i) => (
                    <tr key={i}>
                      <td className="py-0.5 pr-3 text-muted-foreground">
                        {s.ip}
                      </td>
                      <td className="py-0.5">{s.hostname}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {serverError && (
            <div className="flex items-start gap-2 rounded border border-red-300 bg-red-50 p-3 text-xs text-red-900 dark:border-red-900 dark:bg-red-900/20 dark:text-red-200">
              <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
              <span>{serverError}</span>
            </div>
          )}
        </>
      )}

      {phase === "previewed" && previewData && (
        <PreviewResults data={previewData} onCollision={onCollision} />
      )}

      {phase === "committed" && commitData && (
        <CommitResults data={commitData} />
      )}
    </ModalShell>
  );
}

function PreviewResults({
  data,
  onCollision,
}: {
  data: BulkAllocatePreviewResponse;
  onCollision: "skip" | "abort";
}) {
  const totalConflicts =
    data.conflicts_in_use + data.conflicts_in_pool + data.conflicts_fqdn;
  const blockedByAbort = onCollision === "abort" && totalConflicts > 0;

  return (
    <>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <Stat label="Total" value={data.total} />
        <Stat
          label="Will create"
          value={data.will_create}
          tone={data.will_create > 0 ? "good" : "muted"}
        />
        <Stat
          label="Conflicts"
          value={totalConflicts}
          tone={totalConflicts > 0 ? "warn" : "muted"}
        />
        <Stat
          label="On collision"
          value={onCollision}
          tone={blockedByAbort ? "bad" : "muted"}
        />
      </div>

      {totalConflicts > 0 && (
        <div className="rounded border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-900/20 dark:text-amber-200">
          <div className="mb-1 flex items-center gap-2 font-medium">
            <AlertTriangle className="h-4 w-4" />
            {totalConflicts} conflict{totalConflicts === 1 ? "" : "s"}
          </div>
          <ul className="list-disc pl-5">
            {data.conflicts_in_use > 0 && (
              <li>
                {data.conflicts_in_use} IP(s) already allocated in this subnet
              </li>
            )}
            {data.conflicts_in_pool > 0 && (
              <li>
                {data.conflicts_in_pool} IP(s) inside a dynamic DHCP pool —
                cannot allocate
              </li>
            )}
            {data.conflicts_fqdn > 0 && (
              <li>
                {data.conflicts_fqdn} IP(s) collide on hostname+zone with
                existing rows
              </li>
            )}
          </ul>
          {blockedByAbort && (
            <p className="mt-2 font-medium">
              Mode is <span className="font-mono">abort</span> — back out and
              switch to <span className="font-mono">skip</span> to allocate the{" "}
              {data.will_create} clean IP(s).
            </p>
          )}
        </div>
      )}

      {data.warnings.length > 0 && (
        <div className="rounded border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-900 dark:bg-amber-900/20 dark:text-amber-200">
          <ul className="list-disc pl-5">
            {data.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="overflow-hidden rounded border">
        <table className="w-full text-xs">
          <thead className="bg-muted/40">
            <tr>
              <th className="px-2 py-1.5 text-left">Address</th>
              <th className="px-2 py-1.5 text-left">Hostname</th>
              <th className="px-2 py-1.5 text-left">FQDN</th>
              <th className="px-2 py-1.5 text-left">Outcome</th>
            </tr>
          </thead>
          <tbody>
            {data.sample.map((it: BulkAllocateItem, i) => {
              let outcome: { label: string; tone: string };
              if (it.in_use) {
                outcome = {
                  label: "in use",
                  tone: "text-amber-700 dark:text-amber-300",
                };
              } else if (it.in_dynamic_pool) {
                outcome = {
                  label: "dynamic pool",
                  tone: "text-rose-700 dark:text-rose-300",
                };
              } else if (it.fqdn_collision) {
                outcome = {
                  label: "FQDN collision",
                  tone: "text-rose-700 dark:text-rose-300",
                };
              } else {
                outcome = {
                  label: "create",
                  tone: "text-emerald-700 dark:text-emerald-300",
                };
              }
              return (
                <tr key={i} className="border-t">
                  <td className="px-2 py-1 font-mono">{it.address}</td>
                  <td className="px-2 py-1 font-mono">{it.hostname}</td>
                  <td className="px-2 py-1 font-mono text-muted-foreground">
                    {it.fqdn ?? "—"}
                  </td>
                  <td className={cn("px-2 py-1", outcome.tone)}>
                    {outcome.label}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {data.total > data.sample.length && (
          <p className="px-2 py-1.5 text-[11px] text-muted-foreground">
            Showing {data.sample.length} of {data.total} — first 5 + last 2.
          </p>
        )}
      </div>
    </>
  );
}

function CommitResults({ data }: { data: BulkAllocateCommitResponse }) {
  return (
    <>
      <div className="flex items-center gap-2 rounded border border-emerald-300 bg-emerald-50 p-3 text-sm text-emerald-900 dark:border-emerald-900 dark:bg-emerald-900/20 dark:text-emerald-200">
        <CheckCircle2 className="h-5 w-5" />
        <span className="font-medium">
          Created {data.created} IP{data.created === 1 ? "" : "s"}.
        </span>
      </div>
      {data.summary.length > 0 && (
        <ul className="list-disc pl-5 text-xs text-muted-foreground">
          {data.summary.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ul>
      )}
      {data.sample_created.length > 0 && (
        <div className="rounded-md border bg-muted/20 p-3">
          <div className="mb-1 text-xs font-medium text-muted-foreground">
            Created (sample)
          </div>
          <div className="font-mono text-xs">
            {data.sample_created.join(", ")}
          </div>
        </div>
      )}
    </>
  );
}

function Stat({
  label,
  value,
  tone = "muted",
}: {
  label: string;
  value: string | number;
  tone?: "muted" | "good" | "warn" | "bad";
}) {
  const toneCls = {
    muted: "text-foreground",
    good: "text-emerald-700 dark:text-emerald-300",
    warn: "text-amber-700 dark:text-amber-300",
    bad: "text-rose-700 dark:text-rose-300",
  }[tone];
  return (
    <div className="rounded border bg-muted/30 p-2">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className={cn("text-base font-semibold", toneCls)}>{value}</div>
    </div>
  );
}
