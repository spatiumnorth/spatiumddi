import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  ArrowLeftRight,
  CircleSlash,
  HelpCircle,
  type LucideIcon,
  Server,
  ShieldAlert,
  Split,
  Unlink,
} from "lucide-react";

import {
  dhcpApi,
  type DHCPFailoverActionResult,
  type DHCPFailoverRelationship,
  type DHCPScopeServing,
  type DHCPServingVerdict,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import {
  AddScopesModal,
  RelationshipModal,
  RemoveModal,
  ReplicateModal,
} from "./WindowsFailoverActions";
import { useGroupFailover } from "./windowsFailover";

type Dialog =
  | { kind: "create" }
  | { kind: "edit"; rel: DHCPFailoverRelationship }
  | { kind: "add"; rel: DHCPFailoverRelationship }
  | { kind: "remove"; rel: DHCPFailoverRelationship; scopeId?: string }
  | { kind: "replicate"; rel: DHCPFailoverRelationship; scopeId?: string };

const ROW_BTN =
  "rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50";

/**
 * Windows DHCP failover awareness (#1110).
 *
 * A group of Windows DHCP servers is only safe where a failover relationship
 * covers the scope: two Windows servers holding the same scope WITHOUT one
 * hand out the same addresses, with nothing on either server reporting a
 * problem. These views show what the topology poll observed — never a live
 * read — so every timestamp here says how old the picture is.
 */

type VerdictStyle = { icon: LucideIcon; label: string; cls: string };

const NEUTRAL =
  "bg-zinc-100 text-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300";
const GOOD =
  "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300";
const WARN =
  "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300";
const BAD = "bg-rose-100 text-rose-800 dark:bg-rose-900/30 dark:text-rose-300";

// Icon + text + colour, never colour alone (WCAG 1.4.1, as StatusTag).
const VERDICT_STYLES: Record<DHCPServingVerdict, VerdictStyle> = {
  single_server: { icon: Server, label: "Single server", cls: NEUTRAL },
  failover: { icon: ArrowLeftRight, label: "Failover", cls: GOOD },
  failover_one_sided: {
    icon: Unlink,
    label: "Failover · partner not in group",
    cls: WARN,
  },
  split_scope: { icon: Split, label: "Split scope", cls: WARN },
  uncoordinated: { icon: ShieldAlert, label: "Uncoordinated", cls: BAD },
  unknown: { icon: HelpCircle, label: "Coordination unknown", cls: WARN },
  not_on_windows: { icon: CircleSlash, label: "Not on Windows", cls: NEUTRAL },
  no_windows_members: { icon: CircleSlash, label: "—", cls: NEUTRAL },
};

export function ServingVerdictTag({
  serving,
  className,
}: {
  serving: DHCPScopeServing;
  className?: string;
}) {
  // A verdict this build does not know (a newer backend) renders as
  // "unknown" rather than crashing the table it sits in.
  const style = VERDICT_STYLES[serving.verdict] ?? VERDICT_STYLES.unknown;
  const Icon = style.icon;
  return (
    <span className="inline-flex items-center gap-1" title={serving.detail}>
      <span
        className={cn(
          "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium",
          style.cls,
          className,
        )}
      >
        <Icon className="h-3 w-3 flex-shrink-0" aria-hidden />
        {style.label}
        {serving.relationship_name && serving.verdict === "failover" && (
          <span className="font-mono font-normal opacity-80">
            {serving.relationship_name}
          </span>
        )}
      </span>
      {serving.drift && (
        <span
          className={cn(
            "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium",
            WARN,
          )}
          title="The failover partners' configuration of this scope differs. Windows syncs leases between partners, not configuration."
        >
          <AlertTriangle className="h-3 w-3" aria-hidden />
          Config drift
        </span>
      )}
    </span>
  );
}

function ago(iso: string | null): string {
  if (!iso) return "never";
  const secs = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (secs < 90) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours} h ago`;
  return `${Math.round(hours / 24)} d ago`;
}

function modeLabel(rel: DHCPFailoverRelationship): string {
  const mode = (rel.mode ?? "").toLowerCase();
  if (mode === "loadbalance") return "Load balance";
  if (mode === "hotstandby") return "Hot standby";
  return rel.mode ?? "—";
}

function seconds(v: number | null): string {
  if (v == null) return "—";
  if (v % 3600 === 0) return `${v / 3600} h`;
  if (v % 60 === 0) return `${v / 60} min`;
  return `${v} s`;
}

/**
 * Group-level panel: each Windows member's read status, the failover
 * relationships they report (merged across the two partners), and every
 * scope that is NOT safely served. Renders nothing for a group without
 * Windows members.
 */
export function WindowsFailoverPanel({ groupId }: { groupId: string }) {
  const { data: report, isLoading } = useGroupFailover(groupId);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [lastResult, setLastResult] = useState<DHCPFailoverActionResult | null>(
    null,
  );
  if (isLoading || !report || report.windows_member_count === 0) return null;
  const canManage = report.windows_member_count >= 2;
  const relByName = new Map(report.relationships.map((r) => [r.name, r]));

  const attention = report.scopes.filter((s) => !s.safe || s.drift);
  const oneSided = report.scopes.filter(
    (s) => s.verdict === "failover_one_sided",
  );

  return (
    <div className="mt-6 space-y-4">
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Windows DHCP failover
          </span>
          {canManage && (
            <button
              type="button"
              className="rounded-md border px-2.5 py-1 text-xs hover:bg-accent"
              onClick={() => setDialog({ kind: "create" })}
            >
              + New relationship
            </button>
          )}
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground">
          Two Windows servers only share a scope safely inside a failover
          relationship that covers it. Windows keeps leases in sync between
          partners but not configuration, so SpatiumDDI writes every change to
          both partners — and never creates a scope on a member that does not
          already hold it.
        </p>
      </div>

      {report.kea_members.length > 0 && (
        <div className="flex items-start gap-1.5 rounded-md border border-rose-300 bg-rose-50 px-3 py-2 text-xs text-rose-900 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-200">
          <ShieldAlert
            className="mt-0.5 h-3.5 w-3.5 flex-shrink-0"
            aria-hidden
          />
          <span>
            This group also has Kea members ({report.kea_members.join(", ")}).
            Kea serves every active scope of the group, and Kea HA cannot
            coordinate with Windows failover — so a scope a Windows server also
            holds is handed out by both. Move the Windows servers to their own
            server group.
          </span>
        </div>
      )}

      {lastResult && (
        <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
          <span className="font-medium">
            {lastResult.relationship}: {lastResult.action.replace("_", " ")}
          </span>{" "}
          ran on {lastResult.ran_on_server_name}.
          {lastResult.warnings.map((w) => (
            <div key={w} className="mt-1 text-amber-800 dark:text-amber-300">
              {w} — the view may lag until the next sync.
            </div>
          ))}
        </div>
      )}

      {report.members.some((m) => m.failover_error || !m.fresh) && (
        <div className="space-y-1 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          {report.members
            .filter((m) => m.failover_error || !m.fresh)
            .map((m) => (
              <div key={m.server_id} className="flex items-start gap-1.5">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
                <span>
                  <span className="font-medium">{m.server_name}</span>
                  {m.failover_error
                    ? `: failover relationships could not be read (${m.failover_error}); showing the ones read ${ago(m.failover_observed_at)}.`
                    : `: scopes last read ${ago(m.scopes_observed_at)} — run Sync on the server, or enable DHCP lease sync, to refresh.`}
                </span>
              </div>
            ))}
        </div>
      )}

      {attention.length > 0 && (
        <div className="rounded-md border border-rose-300 dark:border-rose-900">
          <div className="border-b border-rose-200 bg-rose-50 px-3 py-2 text-xs font-medium text-rose-900 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-200">
            {attention.length}{" "}
            {attention.length === 1 ? "scope needs" : "scopes need"} attention
          </div>
          <ul className="divide-y text-xs">
            {attention.map((s) => (
              <li key={s.cidr} className="space-y-1 px-3 py-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono">{s.cidr}</span>
                  <ServingVerdictTag serving={s} />
                  {s.drift &&
                    s.relationship_name &&
                    relByName.get(s.relationship_name)?.complete && (
                      <button
                        type="button"
                        className={ROW_BTN}
                        onClick={() =>
                          setDialog({
                            kind: "replicate",
                            rel: relByName.get(s.relationship_name!)!,
                            scopeId: s.cidr.split("/")[0],
                          })
                        }
                      >
                        Replicate…
                      </button>
                    )}
                </div>
                <p className="text-muted-foreground">{s.detail}</p>
              </li>
            ))}
          </ul>
        </div>
      )}

      {report.relationships.length === 0 ? (
        <p className="text-sm italic text-muted-foreground">
          No failover relationships reported by
          {report.windows_member_count === 1
            ? " this server."
            : " the Windows servers in this group."}
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full min-w-[760px] text-sm">
            <thead>
              <tr className="border-b bg-muted/30 text-xs">
                <th className="px-3 py-2 text-left font-medium">
                  Relationship
                </th>
                <th className="px-3 py-2 text-left font-medium">Mode</th>
                <th className="px-3 py-2 text-left font-medium">
                  Partners (role · state · share)
                </th>
                <th className="px-3 py-2 text-left font-medium">MCLT</th>
                <th className="px-3 py-2 text-left font-medium">Auth</th>
                <th className="px-3 py-2 text-left font-medium">Scopes</th>
                {canManage && (
                  <th className="px-3 py-2 text-right font-medium">
                    <span className="sr-only">Actions</span>
                  </th>
                )}
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {report.relationships.map((rel) => (
                <tr key={rel.name} className="border-b align-top last:border-0">
                  <td className="px-3 py-2 font-mono text-xs">
                    {rel.name}
                    {!rel.complete && (
                      <div
                        className="mt-1 inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 font-sans text-[11px] text-amber-800 dark:bg-amber-900/30 dark:text-amber-300"
                        title="Only one partner of this relationship is a member of this group, so changes made here reach that one only. Windows does not replicate configuration to the partner on its own."
                      >
                        <Unlink className="h-3 w-3" aria-hidden />
                        {rel.partner_outside_group
                          ? `partner ${rel.partner_outside_group} not in group`
                          : "partner not reporting"}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs">{modeLabel(rel)}</td>
                  <td className="px-3 py-2 text-xs">
                    <div className="space-y-0.5">
                      {rel.sides.map((side) => (
                        <div key={side.server_id}>
                          <span className="font-medium">
                            {side.server_name}
                          </span>
                          <span className="text-muted-foreground">
                            {/* Hot standby only — load-balance sides have no role. */}
                            {side.server_role && ` · ${side.server_role}`}
                            {" · "}
                            <span
                              className={cn(
                                side.state &&
                                  side.state.toLowerCase() !== "normal" &&
                                  "font-medium text-amber-700 dark:text-amber-400",
                              )}
                            >
                              {side.state ?? "—"}
                            </span>
                            {side.load_balance_percent != null &&
                              (rel.mode ?? "").toLowerCase() ===
                                "loadbalance" &&
                              ` · ${side.load_balance_percent}%`}
                            {side.reserve_percent != null &&
                              (rel.mode ?? "").toLowerCase() === "hotstandby" &&
                              ` · ${side.reserve_percent}% reserve`}
                          </span>
                        </div>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs tabular-nums">
                    {seconds(rel.max_client_lead_time_seconds)}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {rel.enable_auth == null
                      ? "—"
                      : rel.enable_auth
                        ? "on"
                        : "off"}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    <div className="flex max-w-[16rem] flex-wrap gap-1">
                      {rel.scope_ids.map((sid) => (
                        <span
                          key={sid}
                          className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
                        >
                          {sid}
                          {canManage && rel.complete && (
                            <button
                              type="button"
                              className="text-muted-foreground hover:text-rose-600"
                              title={`Remove ${sid} from ${rel.name}`}
                              aria-label={`Remove ${sid} from ${rel.name}`}
                              onClick={() =>
                                setDialog({ kind: "remove", rel, scopeId: sid })
                              }
                            >
                              ×
                            </button>
                          )}
                        </span>
                      ))}
                    </div>
                  </td>
                  {canManage && (
                    <td className="px-3 py-2 text-right">
                      <div className="flex flex-wrap justify-end gap-1">
                        <button
                          type="button"
                          className={ROW_BTN}
                          onClick={() => setDialog({ kind: "edit", rel })}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className={ROW_BTN}
                          disabled={!rel.complete}
                          title={
                            rel.complete
                              ? undefined
                              : "The partner is not a member of this group."
                          }
                          onClick={() => setDialog({ kind: "add", rel })}
                        >
                          Add scopes
                        </button>
                        <button
                          type="button"
                          className={ROW_BTN}
                          disabled={!rel.complete}
                          onClick={() => setDialog({ kind: "replicate", rel })}
                        >
                          Replicate
                        </button>
                        <button
                          type="button"
                          className={cn(
                            ROW_BTN,
                            "text-rose-700 dark:text-rose-400",
                          )}
                          onClick={() => setDialog({ kind: "remove", rel })}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {oneSided.length > 0 && attention.length === 0 && (
        <p className="text-xs text-muted-foreground">
          {oneSided.length} scope{oneSided.length === 1 ? " is" : "s are"} in a
          relationship whose partner is not in this group; changes made here
          reach only the member that is.
        </p>
      )}

      {dialog?.kind === "create" && (
        <RelationshipModal
          groupId={groupId}
          report={report}
          onClose={() => setDialog(null)}
          onDone={setLastResult}
        />
      )}
      {dialog?.kind === "edit" && (
        <RelationshipModal
          groupId={groupId}
          report={report}
          relationship={dialog.rel}
          onClose={() => setDialog(null)}
          onDone={setLastResult}
        />
      )}
      {dialog?.kind === "add" && (
        <AddScopesModal
          groupId={groupId}
          report={report}
          relationship={dialog.rel}
          onClose={() => setDialog(null)}
          onDone={setLastResult}
        />
      )}
      {dialog?.kind === "remove" && (
        <RemoveModal
          groupId={groupId}
          relationship={dialog.rel}
          scopeId={dialog.scopeId}
          onClose={() => setDialog(null)}
          onDone={setLastResult}
        />
      )}
      {dialog?.kind === "replicate" && (
        <ReplicateModal
          groupId={groupId}
          relationship={dialog.rel}
          scopeId={dialog.scopeId}
          onClose={() => setDialog(null)}
          onDone={setLastResult}
        />
      )}
    </div>
  );
}

/** Scope-level strip for the IPAM subnet's DHCP panel. */
export function ScopeServingStrip({ scopeId }: { scopeId: string }) {
  const { data } = useQuery({
    queryKey: ["dhcp-scope-failover", scopeId],
    queryFn: () => dhcpApi.getScopeFailover(scopeId),
    staleTime: 30_000,
  });
  if (!data || data.verdict === "no_windows_members") return null;
  const holders = data.servers.filter((s) => s.holds);
  return (
    <div
      className={cn(
        "flex flex-wrap items-center gap-2 border-b px-4 py-2 text-xs",
        !data.safe && "bg-rose-50 dark:bg-rose-950/30",
      )}
    >
      <span className="text-muted-foreground">Windows:</span>
      <ServingVerdictTag serving={data} />
      <span className="text-muted-foreground">
        {holders.length > 0
          ? `held by ${holders.map((h) => h.server_name).join(", ")}`
          : "held by no Windows member"}
      </span>
      {!data.safe && (
        <p className="w-full text-rose-800 dark:text-rose-300">{data.detail}</p>
      )}
    </div>
  );
}
