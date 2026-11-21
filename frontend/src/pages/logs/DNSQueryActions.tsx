import { useId, useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Ban, Search, ShieldCheck, ShieldOff } from "lucide-react";
import {
  dhcpApi,
  dnsApi,
  dnsBlocklistApi,
  formatApiError,
  ipamApi,
  type BlocklistMatch,
  type DNSBlockList,
  type DNSQueryLogRow,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { HeaderMenu, type HeaderMenuItem } from "@/components/ui/header-menu";
import { AskAIButton } from "@/components/copilot/AskAIButton";
import { useFeatureModules } from "@/hooks/useFeatureModules";
import { usePermissions } from "@/hooks/usePermissions";
import { copyToClipboard } from "@/lib/clipboard";
import { cn } from "@/lib/utils";
import {
  allowGate,
  blockGate,
  longestZoneMatch,
  nameChoices,
  type Triage,
  type TriageDone,
} from "./dnsQueryTriage";

/**
 * Actions for the DNS query details modal (#4250): block or allow the name,
 * a "Blocked by" line, who the client is, and the next triage step (open the
 * zone, dig / whois the name, copy).
 *
 * Every control is gated on the grant its API route asks for, and a control
 * the caller cannot use says which grant is missing rather than vanishing —
 * except where showing it would itself leak (no read on blocking lists hides
 * the Block action and the "Blocked by" line).
 */

const BLOCK_CLIENT_REASON =
  "SpatiumDDI cannot block one client's DNS yet. A superadmin can drop its queries with the server group's blackhole option (BIND9 only, applies to the whole group).";

const inputCls =
  "w-full rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// ── Result: "Blocked by" ──────────────────────────────────────────────

export function BlockedByLine({ triage }: { triage: Triage }) {
  const { match, perms, matchQ } = triage;
  if (!perms.can("read", "dns_blocklist") || !triage.qname || !triage.groupId) {
    return null;
  }
  if (matchQ.isError) {
    return (
      <span className="mt-0.5 block text-xs text-muted-foreground">
        Blocking-list check unavailable
      </span>
    );
  }
  if (!match) return null;
  const live = match.matches.filter((m) => m.applies_here);
  const hit = live.find((m) => !m.excepted);
  if (match.effective === "blocked" && hit) {
    return (
      <span
        data-testid="blocked-by"
        className="mt-0.5 block text-xs text-amber-700 dark:text-amber-400"
      >
        Blocked by <strong>{hit.list_name}</strong> (entry{" "}
        <span className="font-mono">{hit.entry_domain}</span>,{" "}
        {hit.is_wildcard ? "wildcard" : "exact"})
      </span>
    );
  }
  if (match.effective === "allowed" && live[0]) {
    return (
      <span
        data-testid="blocked-by"
        className="mt-0.5 block text-xs text-muted-foreground"
      >
        On <strong>{live[0].list_name}</strong>, allowed by an exception.
      </span>
    );
  }
  return null;
}

/** The note under an NXDOMAIN that no blocking list explains. */
export function NotFromListNote({
  triage,
  rcode,
}: {
  triage: Triage;
  rcode: string | null;
}) {
  if (rcode !== "NXDOMAIN" || triage.match?.effective !== "none") return null;
  return (
    <span className="mt-0.5 block text-xs text-muted-foreground">
      NXDOMAIN came from DNS, not from a blocking list.
    </span>
  );
}

// ── Client panel ──────────────────────────────────────────────────────

export function ClientPanel({ ip }: { ip: string | null }) {
  const perms = usePermissions();
  const { enabled: moduleOn } = useFeatureModules();
  const canIpam = perms.can("read", "ip_address");
  const canLease = perms.can("read", "dhcp_server") && moduleOn("core.dhcp");

  const ipamQ = useQuery({
    queryKey: ["dns-client-ipam", ip],
    queryFn: () => ipamApi.searchAddresses({ q: ip!, limit: 10 }),
    enabled: !!ip && canIpam,
    staleTime: 60_000,
    retry: false,
  });
  const leaseQ = useQuery({
    queryKey: ["dns-client-lease", ip],
    queryFn: () =>
      dhcpApi.findLeases({ ip: ip!, state: "active", page_size: 1 }),
    enabled: !!ip && canLease,
    staleTime: 60_000,
    retry: false,
  });
  if (!ip) return null;

  const addr = ipamQ.data?.items.find((a) => a.address.split("/")[0] === ip);
  const lease = leaseQ.data?.items[0];
  const waiting =
    (canIpam && ipamQ.isLoading) || (canLease && leaseQ.isLoading);

  return (
    <section className="mt-4" aria-label="Client">
      <h3 className="mb-1 text-xs font-medium text-muted-foreground">
        Client (current)
      </h3>
      {!canIpam && !canLease && (
        <p className="text-xs text-muted-foreground">
          You do not have access to IPAM or DHCP data.
        </p>
      )}
      <dl className="grid grid-cols-[60px_1fr] gap-x-3 gap-y-1 text-sm">
        {canIpam && !ipamQ.isLoading && (
          <>
            <dt className="text-xs text-muted-foreground">IPAM</dt>
            <dd data-testid="client-ipam" className="min-w-0 break-words">
              {ipamQ.isError ? (
                <span className="text-xs text-muted-foreground">
                  Lookup failed
                </span>
              ) : addr ? (
                <>
                  <span className="font-medium">
                    {addr.hostname || "(no hostname)"}
                  </span>
                  <span className="text-muted-foreground">
                    {" "}
                    · {addr.status} ·{" "}
                    {addr.subnet_name ? `${addr.subnet_name} ` : ""}
                    {addr.subnet_cidr}{" "}
                  </span>
                  <Link
                    to="/ipam"
                    state={{
                      selectSubnet: addr.subnet_id,
                      highlightAddress: addr.id,
                    }}
                    className="text-xs text-primary hover:underline"
                  >
                    Open in IPAM
                  </Link>
                </>
              ) : (
                <span className="text-muted-foreground">Not in IPAM</span>
              )}
            </dd>
          </>
        )}
        {canLease && !leaseQ.isLoading && (
          <>
            <dt className="text-xs text-muted-foreground">DHCP</dt>
            <dd data-testid="client-lease" className="min-w-0 break-words">
              {leaseQ.isError ? (
                <span className="text-xs text-muted-foreground">
                  Lookup failed
                </span>
              ) : lease ? (
                <>
                  <span className="font-mono">
                    {lease.mac_address ?? "no MAC"}
                  </span>
                  <span className="text-muted-foreground">
                    {[
                      lease.hostname,
                      lease.vendor,
                      lease.device_class ?? lease.device_name,
                      lease.state,
                    ]
                      .filter(Boolean)
                      .map((p) => ` · ${p}`)
                      .join("")}{" "}
                  </span>
                  <Link
                    to={`/dhcp?server=${lease.server_id}`}
                    className="text-xs text-primary hover:underline"
                  >
                    Open DHCP server
                  </Link>
                </>
              ) : (
                <span className="text-muted-foreground">No active lease</span>
              )}
            </dd>
          </>
        )}
      </dl>
      {waiting && <p className="text-xs text-muted-foreground">Looking up…</p>}
    </section>
  );
}

// ── Block / Allow button ──────────────────────────────────────────────

export function ActionFooter({
  row,
  triage,
  onFilterClient,
  onFilterQname,
  onClose,
  onDone,
}: {
  row: DNSQueryLogRow;
  triage: Triage;
  onFilterClient?: (ip: string) => void;
  onFilterQname?: (qname: string) => void;
  onClose: () => void;
  onDone: (d: TriageDone) => void;
}) {
  const [dialog, setDialog] = useState<"block" | "allow" | null>(null);
  const reasonId = useId();
  const gate = triage.blocked ? allowGate(triage) : blockGate(triage);
  const label = triage.blocked ? "Allow domain…" : "Block domain…";
  const disabled = gate.reason !== null || gate.pending === true;
  const clientIp = row.client_ip;
  const qname = row.qname;
  const context = [
    `DNS query at ${row.ts}`,
    `server ${row.server_name}`,
    row.view ? `view ${row.view}` : null,
    `client ${clientIp ?? "unknown"}`,
    `qname ${qname ?? "unknown"} ${row.qtype ?? ""}`.trim(),
    `result ${row.rcode ?? "not recorded"}, ${row.answer_count ?? "?"} answers`,
    triage.match?.effective === "blocked"
      ? `blocked by list ${triage.match.matches.find((m) => m.applies_here && !m.excepted)?.list_name}`
      : null,
  ]
    .filter(Boolean)
    .join("; ");

  return (
    <div className="mt-4 space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <AskAIButton
          context={context}
          prompt="Why did this query get this answer?"
          tooltip="Ask AI about this query"
        />
        <div className="flex flex-wrap items-center justify-end gap-2">
          {onFilterClient && clientIp && (
            <button
              type="button"
              onClick={() => {
                onFilterClient(clientIp);
                onClose();
              }}
              className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-accent/50"
            >
              <Search className="h-3.5 w-3.5" />
              Filter by client
            </button>
          )}
          {onFilterQname && qname && (
            <button
              type="button"
              onClick={() => {
                onFilterQname(qname);
                onClose();
              }}
              className="inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-accent/50"
            >
              <Search className="h-3.5 w-3.5" />
              Filter by qname
            </button>
          )}
          <MoreMenu row={row} triage={triage} />
          {!gate.hidden && (
            <button
              type="button"
              aria-disabled={disabled}
              aria-describedby={gate.reason ? reasonId : undefined}
              title={gate.reason ?? undefined}
              onClick={() => {
                if (disabled) return;
                setDialog(triage.blocked ? "allow" : "block");
              }}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-xs font-medium hover:bg-accent/50",
                disabled && "cursor-not-allowed opacity-50 hover:bg-background",
              )}
            >
              {triage.blocked ? (
                <ShieldCheck className="h-3.5 w-3.5" />
              ) : (
                <Ban className="h-3.5 w-3.5" />
              )}
              {label}
            </button>
          )}
        </div>
      </div>
      {gate.reason && !gate.hidden && (
        <p
          id={reasonId}
          className="text-right text-[11px] text-muted-foreground"
        >
          {gate.reason}
        </p>
      )}
      {dialog === "block" && (
        <BlockDomainDialog
          row={row}
          triage={triage}
          onClose={() => setDialog(null)}
          onDone={(d) => {
            setDialog(null);
            onDone(d);
          }}
        />
      )}
      {dialog === "allow" && triage.match && (
        <AllowDomainDialog
          row={row}
          triage={triage}
          match={triage.match}
          onClose={() => setDialog(null)}
          onDone={(d) => {
            setDialog(null);
            onDone(d);
          }}
        />
      )}
    </div>
  );
}

// ── More menu ─────────────────────────────────────────────────────────

function MoreMenu({ row, triage }: { row: DNSQueryLogRow; triage: Triage }) {
  const navigate = useNavigate();
  const { perms, groupId, source } = triage;
  const qname = row.qname ? row.qname.replace(/\.$/, "") : null;
  const canZones = perms.can("read", "dns_zone");
  const canTools = perms.can("read", "use_network_tools");

  const zonesQ = useQuery({
    queryKey: ["dns-zones-for-match", groupId],
    queryFn: () => dnsApi.listZones(groupId!),
    enabled: canZones && !!groupId && !!qname,
    staleTime: 60_000,
    retry: false,
  });
  const zone =
    qname && zonesQ.data
      ? longestZoneMatch(qname.toLowerCase(), zonesQ.data)
      : null;

  const toolsUrl = (tool: "dig" | "whois") => {
    const p = new URLSearchParams({ tool });
    if (tool === "dig") {
      p.set("name", qname ?? "");
      if (row.qtype) p.set("type", row.qtype);
      if (source?.host) p.set("server", source.host);
    } else {
      p.set("query", qname ?? "");
    }
    return `/tools/network?${p.toString()}`;
  };
  const filterLink = () => {
    const p = new URLSearchParams({ tab: "dns-queries" });
    if (row.client_ip) p.set("client", row.client_ip);
    if (qname) p.set("q", qname);
    return `${window.location.origin}/logs?${p.toString()}`;
  };

  const items: HeaderMenuItem[] = [
    {
      key: "zone",
      label: "Open zone",
      onSelect: () => zone && navigate(`/dns?group=${groupId}&zone=${zone.id}`),
      disabled: !canZones || !zone,
      description: !canZones
        ? "Needs read on DNS zones."
        : !zone
          ? "Not in a zone this group serves."
          : undefined,
    },
    {
      key: "dig",
      label: "dig this name",
      onSelect: () => navigate(toolsUrl("dig")),
      disabled: !canTools || !qname,
      description: !canTools ? "Needs access to network tools." : undefined,
    },
    {
      key: "whois",
      label: "whois this domain",
      onSelect: () => navigate(toolsUrl("whois")),
      disabled: !canTools || !qname,
      description: !canTools ? "Needs access to network tools." : undefined,
    },
    {
      key: "copy-qname",
      label: "Copy qname",
      separatorBefore: true,
      onSelect: () => void copyToClipboard(qname ?? ""),
      disabled: !qname,
    },
    {
      key: "copy-ip",
      label: "Copy client IP",
      onSelect: () => void copyToClipboard(row.client_ip ?? ""),
      disabled: !row.client_ip,
    },
    {
      key: "copy-link",
      label: "Copy link to this filter",
      onSelect: () => void copyToClipboard(filterLink()),
    },
    {
      key: "block-client",
      label: "Block client",
      icon: ShieldOff,
      separatorBefore: true,
      onSelect: () => undefined,
      disabled: true,
      description: BLOCK_CLIENT_REASON,
    },
  ];
  return <HeaderMenu label="More" items={items} className="text-xs" />;
}

// ── dialogs ───────────────────────────────────────────────────────────

function scopeLabel(l: DNSBlockList, t: Triage, row: DNSQueryLogRow): string {
  const parts: string[] = [];
  for (const gid of l.applied_group_ids) {
    parts.push(`whole group ${t.groupNames.get(gid) ?? gid.slice(0, 8)}`);
  }
  for (const vid of l.applied_view_ids) {
    parts.push(
      vid === t.viewId && row.view ? `view ${row.view}` : "another view",
    );
  }
  return parts.join(", ") || "no group or view";
}

function responseLabel(l: DNSBlockList): string {
  return l.block_mode === "sinkhole"
    ? `sinkhole ${l.sinkhole_ip ?? "0.0.0.0"}`
    : "NXDOMAIN";
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1 text-xs font-medium text-muted-foreground">
      <span>{label}</span>
      <div className="font-normal text-foreground">{children}</div>
    </label>
  );
}

function ErrorLine({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p
      role="alert"
      className="rounded border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive"
    >
      {message}
    </p>
  );
}

function DialogButtons({
  onClose,
  confirmLabel,
  busy,
  disabled,
}: {
  onClose: () => void;
  confirmLabel: string;
  busy: boolean;
  disabled?: boolean;
}) {
  return (
    <div className="flex justify-end gap-2 pt-1">
      <button
        type="button"
        onClick={onClose}
        className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent/50"
      >
        Cancel
      </button>
      <button
        type="submit"
        disabled={busy || disabled}
        className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
      >
        {busy ? "Working…" : confirmLabel}
      </button>
    </div>
  );
}

export function BlockDomainDialog({
  row,
  triage,
  onClose,
  onDone,
}: {
  row: DNSQueryLogRow;
  triage: Triage;
  onClose: () => void;
  onDone: (d: TriageDone) => void;
}) {
  const qc = useQueryClient();
  const choices = nameChoices(triage.qname!);
  const [name, setName] = useState(choices[0]!);
  const [wildcard, setWildcard] = useState(true);
  const [showFeed, setShowFeed] = useState(false);
  const eligible = triage.applicable.filter(
    (l) => l.source_type === "manual" || showFeed,
  );
  const [listId, setListId] = useState(
    () => triage.applicable.find((l) => l.source_type === "manual")?.id ?? "",
  );
  const list = eligible.find((l) => l.id === listId) ?? eligible[0];
  const [reason, setReason] = useState(
    `Blocked from query log: client ${row.client_ip ?? "unknown"}, ${row.ts}`,
  );
  const [error, setError] = useState<string | null>(null);

  const add = useMutation({
    mutationFn: () =>
      dnsBlocklistApi.addEntry(list!.id, {
        domain: name,
        entry_type: "block",
        is_wildcard: wildcard,
        reason,
      }),
    onSuccess: (entry) => {
      void qc.invalidateQueries({ queryKey: ["blocklist-match"] });
      void qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      onDone({
        kind: "blocked",
        listId: list!.id,
        listName: list!.name,
        entry,
      });
    },
    onError: (e: unknown) => {
      const status = (e as { response?: { status?: number } }).response?.status;
      setError(
        status === 409
          ? `Already in ${list!.name}. Pick another list.`
          : formatApiError(e, "Could not add the entry"),
      );
    },
  });

  const wc = wildcard ? " and every subdomain" : "";
  return (
    <Modal title="Block domain" onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (list) add.mutate();
        }}
      >
        <fieldset className="space-y-1">
          <legend className="text-xs font-medium text-muted-foreground">
            Name to block
          </legend>
          {choices.map((c) => (
            <label key={c} className="flex items-center gap-2 text-sm">
              <input
                type="radio"
                name="block-name"
                checked={name === c}
                onChange={() => setName(c)}
              />
              <span className="font-mono">{c}</span>
            </label>
          ))}
          {name.split(".").length === 2 && (
            <p className="text-[11px] text-amber-700 dark:text-amber-400">
              Check this is a domain you mean to block, not a shared suffix.
            </p>
          )}
        </fieldset>
        <fieldset className="space-y-1">
          <legend className="text-xs font-medium text-muted-foreground">
            Match
          </legend>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              name="block-match"
              checked={wildcard}
              onChange={() => setWildcard(true)}
            />
            This name and every subdomain
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              name="block-match"
              checked={!wildcard}
              onChange={() => setWildcard(false)}
            />
            This exact name only
          </label>
        </fieldset>
        <Field label="Blocking list">
          <select
            className={inputCls}
            value={list?.id ?? ""}
            onChange={(e) => setListId(e.target.value)}
          >
            {eligible.map((l) => (
              <option key={l.id} value={l.id}>
                {l.name} — {scopeLabel(l, triage, row)} — {responseLabel(l)}
              </option>
            ))}
          </select>
          <label className="mt-1 flex items-center gap-2 text-[11px] text-muted-foreground">
            <input
              type="checkbox"
              checked={showFeed}
              onChange={(e) => setShowFeed(e.target.checked)}
            />
            Show feed lists
          </label>
        </Field>
        <Field label="Reason">
          <input
            className={inputCls}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </Field>
        {triage.viewUnresolved && (
          <p className="text-[11px] text-muted-foreground">
            View-scoped lists were not checked: resolving the query&apos;s view
            needs read on DNS server groups.
          </p>
        )}
        {list && (
          <p
            data-testid="block-effect"
            className="rounded border bg-muted/40 p-2 text-xs"
          >
            This adds <span className="font-mono">{name}</span>
            {wc} to <strong>{list.name}</strong>. Clients served by{" "}
            <strong>{scopeLabel(list, triage, row)}</strong> will get{" "}
            <strong>{responseLabel(list)}</strong> for it. The change reaches
            the servers within a few seconds; clients and resolvers that already
            hold an answer keep it until its TTL expires. To undo, remove the
            entry from {list.name}.
          </p>
        )}
        <ErrorLine message={error} />
        <DialogButtons
          onClose={onClose}
          busy={add.isPending}
          disabled={!list}
          confirmLabel={`Block ${name}${wildcard ? " and subdomains" : ""}`}
        />
      </form>
    </Modal>
  );
}

export function AllowDomainDialog({
  row,
  triage,
  match,
  onClose,
  onDone,
}: {
  row: DNSQueryLogRow;
  triage: Triage;
  match: BlocklistMatch;
  onClose: () => void;
  onDone: (d: TriageDone) => void;
}) {
  const qc = useQueryClient();
  const qname = match.domain;
  const blocking = match.matches.filter((m) => m.applies_here && !m.excepted);
  // Deleting an entry only unblocks the name when every entry that blocks it
  // is one this operator made for exactly this name.
  const removable =
    blocking.length > 0 &&
    blocking.every(
      (m) =>
        m.entry_source === "manual" &&
        m.entry_domain === qname &&
        m.entry_type === "block",
    );
  const canDelete = triage.perms.can("delete", "dns_blocklist");
  const [mode, setMode] = useState<"remove" | "except">(
    removable && canDelete ? "remove" : "except",
  );
  const listChoices = useMemo(() => {
    const seen = new Map<string, string>();
    for (const m of blocking) seen.set(m.list_id, m.list_name);
    return [...seen.entries()];
  }, [blocking]);
  const [listId, setListId] = useState(listChoices[0]?.[0] ?? "");
  const [reason, setReason] = useState(
    `Allowed from query log: client ${row.client_ip ?? "unknown"}, ${row.ts}`,
  );
  const [error, setError] = useState<string | null>(null);

  const invalidate = () =>
    void qc.invalidateQueries({ queryKey: ["blocklist-match"] });

  const act = useMutation({
    mutationFn: async (): Promise<TriageDone> => {
      if (mode === "remove") {
        for (const m of blocking) {
          await dnsBlocklistApi.deleteEntry(m.list_id, m.entry_id);
        }
        return { kind: "removed", entries: blocking, domain: qname };
      }
      const ex = await dnsBlocklistApi.addException(listId, {
        domain: qname,
        reason,
      });
      return {
        kind: "excepted",
        listId,
        listName: listChoices.find(([id]) => id === listId)?.[1] ?? "",
        exception: ex,
        domain: qname,
      };
    },
    onSuccess: (d) => {
      invalidate();
      onDone(d);
    },
    onError: (e: unknown) => {
      invalidate();
      setError(formatApiError(e, "Could not allow the name"));
    },
  });

  const first = blocking[0];
  return (
    <Modal title="Allow domain" onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          act.mutate();
        }}
      >
        <div className="text-xs">
          <p className="mb-1 font-medium text-muted-foreground">Blocked by</p>
          <ul className="space-y-0.5">
            {blocking.map((m) => (
              <li key={m.entry_id}>
                <strong>{m.list_name}</strong>: entry{" "}
                <span className="font-mono">{m.entry_domain}</span>,{" "}
                {m.is_wildcard ? "wildcard" : "exact"}, from {m.entry_source}
              </li>
            ))}
          </ul>
        </div>
        <fieldset className="space-y-1">
          <legend className="text-xs font-medium text-muted-foreground">
            Action
          </legend>
          {removable && (
            <label className="flex items-start gap-2 text-sm">
              <input
                type="radio"
                name="allow-mode"
                className="mt-1"
                disabled={!canDelete}
                checked={mode === "remove"}
                onChange={() => setMode("remove")}
              />
              <span>
                Remove the block entry
                {!canDelete && (
                  <span className="block text-[11px] text-muted-foreground">
                    Needs delete on DNS blocklists.
                  </span>
                )}
              </span>
            </label>
          )}
          <label className="flex items-start gap-2 text-sm">
            <input
              type="radio"
              name="allow-mode"
              className="mt-1"
              checked={mode === "except"}
              onChange={() => setMode("except")}
            />
            <span>
              Add an exception for <span className="font-mono">{qname}</span>
            </span>
          </label>
        </fieldset>
        {mode === "except" && (
          <Field label="Add the exception to">
            <select
              className={inputCls}
              value={listId}
              onChange={(e) => setListId(e.target.value)}
            >
              {listChoices.map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field label="Reason">
          <input
            className={inputCls}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        </Field>
        <p
          data-testid="allow-effect"
          className="rounded border bg-muted/40 p-2 text-xs"
        >
          {mode === "remove" ? (
            <>
              This deletes the entry for{" "}
              <span className="font-mono">{qname}</span>. Clients will resolve
              it normally. To undo, add the entry again.
            </>
          ) : (
            <>
              This lets <span className="font-mono">{qname}</span> and
              everything under it resolve normally.{" "}
              {first && first.entry_domain !== qname ? (
                <>
                  The entry for{" "}
                  <span className="font-mono">{first.entry_domain}</span> stays
                  and keeps blocking the rest of it.{" "}
                </>
              ) : null}
              An exception applies to every blocking list in the same group or
              view, not only the one you add it to. To undo, delete the
              exception.
            </>
          )}
        </p>
        <ErrorLine message={error} />
        <DialogButtons
          onClose={onClose}
          busy={act.isPending}
          disabled={mode === "except" && !listId}
          confirmLabel={`Allow ${qname}`}
        />
      </form>
    </Modal>
  );
}

// ── Undo banner ───────────────────────────────────────────────────────

export function UndoBanner({
  done,
  canDelete,
  canWrite,
  onChange,
}: {
  done: TriageDone;
  canDelete: boolean;
  canWrite: boolean;
  onChange: (d: TriageDone | null) => void;
}) {
  const qc = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const undo = useMutation({
    mutationFn: async (): Promise<string> => {
      if (done.kind === "blocked") {
        await dnsBlocklistApi.deleteEntry(done.listId, done.entry.id);
        return `Removed ${done.entry.domain} from ${done.listName}.`;
      }
      if (done.kind === "excepted") {
        await dnsBlocklistApi.deleteException(done.listId, done.exception.id);
        return `Removed the exception for ${done.domain} from ${done.listName}.`;
      }
      if (done.kind === "removed") {
        for (const m of done.entries) {
          await dnsBlocklistApi.addEntry(m.list_id, {
            domain: m.entry_domain,
            entry_type: m.entry_type,
            target: m.target,
            is_wildcard: m.is_wildcard,
            reason: m.reason,
          });
        }
        return `Put back the entry for ${done.domain}.`;
      }
      return "";
    },
    onSuccess: (message) => {
      void qc.invalidateQueries({ queryKey: ["blocklist-match"] });
      void qc.invalidateQueries({ queryKey: ["dns-blocklists"] });
      onChange({ kind: "undone", message });
    },
    onError: (e: unknown) => setError(formatApiError(e, "Undo failed")),
  });

  if (done.kind === "undone") {
    return (
      <div
        role="status"
        className="mb-3 rounded border bg-muted/40 p-2 text-xs"
      >
        Undone. {done.message}
      </div>
    );
  }
  const text =
    done.kind === "blocked"
      ? `Blocked ${done.entry.domain}${done.entry.is_wildcard ? " and subdomains" : ""} on ${done.listName}.`
      : done.kind === "excepted"
        ? `Allowed ${done.domain} on ${done.listName}.`
        : `Removed the block entry for ${done.domain}.`;
  const mayUndo = done.kind === "removed" ? canWrite : canDelete;
  return (
    <div role="status" className="mb-3 rounded border bg-muted/40 p-2 text-xs">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span>
          {text} The change reaches the servers within a few seconds; cached
          answers last until their TTL expires.
        </span>
        {mayUndo && (
          <button
            type="button"
            onClick={() => undo.mutate()}
            disabled={undo.isPending}
            className="rounded border px-2 py-0.5 hover:bg-accent disabled:opacity-50"
          >
            Undo
          </button>
        )}
      </div>
      <ErrorLine message={error} />
    </div>
  );
}
