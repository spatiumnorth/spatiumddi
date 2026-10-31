// Fleet firewall management (#285 Phase 3c-fe).
//
// Operator surface over the declarative policy model: policy + rule + alias
// CRUD, plus the server-side "effective" render of any node's merged drop-in
// (with the enforcement-OFF banner when firewall_enabled is still dark). The
// tab itself is gated in AppliancePage on the appliance.firewall feature
// module — #14's NavItem clause is satisfied by tab-level gating because the
// firewall family lives under the always-visible /appliance parent.
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  Eye,
  Layers,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Tags,
  Trash2,
} from "lucide-react";

import {
  applianceApprovalApi,
  firewallApi,
  formatApiError,
  networkToolsApi,
  type FirewallLogLine,
  type FirewallAction,
  type FirewallEffective,
  type FirewallFamily,
  type FirewallPolicy,
  type FirewallProtocol,
  type FirewallRuleInput,
  type FirewallScopeKind,
  type FirewallSourceKind,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { WebUIAccessCard } from "@/components/WebUIAccessCard";
import { useSessionState } from "@/lib/useSessionState";
import { cn } from "@/lib/utils";
import { useApplianceAdminGate } from "@/hooks/useApplianceAdmin";
import { ListEmpty, ListReadError } from "@/components/ui/list-read-error";
import { isRefused, pollUnlessRefused } from "@/lib/refusal";

const ROLE_OPTIONS = [
  "dns-bind9",
  "dns-powerdns",
  "dns-technitium",
  "dhcp",
  "observer",
  "custom",
  "control-plane",
];
const SOURCE_KINDS: FirewallSourceKind[] = [
  "any",
  "cidr",
  "alias",
  "cluster_peers",
  "pod_cidr",
  "service_cidr",
  "kubeapi",
  "kubelet",
  "mgmt",
  "vip",
];
const PROTOCOLS: FirewallProtocol[] = ["tcp", "udp", "icmp", "icmpv6"];
const FAMILIES: FirewallFamily[] = ["both", "v4", "v6"];

const POSTURE_PRESETS: {
  key: "locked" | "balanced" | "open";
  label: string;
  blurb: string;
}[] = [
  {
    key: "locked",
    label: "Locked",
    blurb: "Builtins + mgmt floor only — nothing extra reachable.",
  },
  {
    key: "balanced",
    label: "Balanced",
    blurb: "SNMP + node-exporter from RFC1918 (private networks) only.",
  },
  {
    key: "open",
    label: "Open",
    blurb: "SNMP + node-exporter from anywhere (flat, trusted LAN).",
  },
];

type FirewallSection =
  | "policies"
  | "aliases"
  | "preview"
  | "effective"
  | "logs";

const FW_SECTIONS: {
  key: FirewallSection;
  label: string;
  icon: typeof ShieldAlert;
  hint: string;
}[] = [
  {
    key: "policies",
    label: "Policies",
    icon: ShieldAlert,
    hint: "Fleet / role / appliance rules",
  },
  {
    key: "aliases",
    label: "Aliases",
    icon: Tags,
    hint: "Named CIDR / port sets",
  },
  {
    key: "preview",
    label: "Preview changes",
    icon: Eye,
    hint: "Stage & diff before save",
  },
  {
    key: "effective",
    label: "Effective render",
    icon: Layers,
    hint: "Per-node merged ruleset",
  },
  {
    key: "logs",
    label: "Logs",
    icon: ScrollText,
    hint: "Realtime nft drop log",
  },
];

function scopeLabel(p: FirewallPolicy): string {
  if (p.scope_kind === "fleet") return "Fleet";
  if (p.scope_kind === "role") return `Role · ${p.scope_role}`;
  return "Appliance override";
}

export function FirewallTab() {
  const [section, setSection] = useSessionState<FirewallSection>(
    "appliance.firewall.section",
    "policies",
  );
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2">
        <ShieldAlert className="mt-0.5 h-5 w-5 text-muted-foreground" />
        <div>
          <h2 className="text-base font-semibold">Fleet firewall</h2>
          <p className="text-xs text-muted-foreground">
            Declarative per-role / per-appliance nftables policy. Edits stay
            dark until the <code>firewall_enabled</code> master switch is on AND
            the next supervisor heartbeat renders — preview any node's effective
            ruleset before you flip enforcement on.
          </p>
        </div>
      </div>

      {/* #404 — left sub-nav (Cluster-style) replacing the old top sub-tabs.
          Enforcement + Web-UI-access cards moved into the Policies section
          (they were confusing full-width bars up here). */}
      <div className="flex gap-6">
        <nav className="w-48 shrink-0 space-y-1">
          <div className="mb-2 flex items-center gap-1.5 px-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
            <ShieldAlert className="h-3.5 w-3.5" />
            Firewall
          </div>
          {FW_SECTIONS.map((s) => {
            const Icon = s.icon;
            const active = section === s.key;
            return (
              <button
                key={s.key}
                type="button"
                onClick={() => setSection(s.key)}
                className={cn(
                  "flex w-full flex-col items-start gap-0.5 rounded-md px-2 py-1.5 text-left",
                  active
                    ? "bg-accent text-foreground"
                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
                )}
              >
                <span className="flex items-center gap-1.5 text-sm">
                  <Icon className="h-3.5 w-3.5" />
                  {s.label}
                </span>
                <span className="pl-5 text-[11px] text-muted-foreground">
                  {s.hint}
                </span>
              </button>
            );
          })}
        </nav>

        <div className="min-w-0 flex-1">
          {section === "policies" && <PoliciesSection />}
          {section === "aliases" && <AliasesSection />}
          {section === "preview" && <PreviewSection />}
          {section === "effective" && <EffectiveSection />}
          {section === "logs" && <FirewallLogsSection />}
        </div>
      </div>
    </div>
  );
}

// #404 Phase 2 — realtime nftables firewall-log viewer.
//
// nft rules don't log by default, so logging is an opt-in toggle: when on, the
// renderer adds a rate-limited catch-all `log prefix "spatium-fw: "` before the
// chain's policy drop. The api pod can't read host kernel logs, so the
// supervisor tails /dev/kmsg and serves the lines over the nettool proxy —
// which routes per-appliance, so any appliance in the fleet is selectable. We
// poll ~2s with a since-cursor for a near-realtime tail.
function recentlySeen(iso: string | null | undefined): boolean {
  if (!iso) return false;
  const t = new Date(iso).getTime();
  return Number.isFinite(t) && Date.now() - t < 120_000;
}

export function FirewallLogsSection() {
  const qc = useQueryClient();
  const applianceGate = useApplianceAdminGate();
  const { data: enf } = useQuery({
    queryKey: ["firewall", "enforcement"],
    queryFn: firewallApi.getEnforcement,
  });
  const setLogging = useMutation({
    mutationFn: firewallApi.setLogging,
    onSuccess: (d) => qc.setQueryData(["firewall", "enforcement"], d),
  });

  const { data: appliances, error: appliancesError } = useQuery({
    queryKey: ["appliance", "fleet", "fw-logs"],
    queryFn: applianceApprovalApi.list,
    // #3106 — a refused list is not asked again every 30 s.
    refetchInterval: pollUnlessRefused(30_000),
  });
  const online = useMemo(
    () =>
      (appliances ?? []).filter(
        (a) =>
          a.state === "approved" &&
          a.deployment_kind === "appliance" &&
          recentlySeen(a.last_seen_at),
      ),
    [appliances],
  );

  const [selected, setSelected] = useState<string>("");
  useEffect(() => {
    if (!selected && online.length) setSelected(online[0].id);
  }, [online, selected]);

  const [lines, setLines] = useState<FirewallLogLine[]>([]);
  const [paused, setPaused] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const cursorRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Reset the buffer when the target appliance changes.
  useEffect(() => {
    setLines([]);
    cursorRef.current = 0;
    setErr(null);
  }, [selected]);

  // Poll the appliance's firewall_logs nettool for new lines (~2s).
  useEffect(() => {
    if (!selected || paused) return;
    let stop = false;
    const tick = async () => {
      try {
        const res = await networkToolsApi.firewallLogs(
          { since_seq: cursorRef.current, limit: 500 },
          { kind: "appliance", id: selected },
        );
        if (stop) return;
        setErr(
          res.available ? null : "kernel log not readable on this appliance",
        );
        if (res.cursor) cursorRef.current = res.cursor;
        if (res.lines.length) {
          setLines((prev) => {
            const next = [...prev, ...res.lines];
            return next.length > 2000 ? next.slice(next.length - 2000) : next;
          });
        }
      } catch (e) {
        if (!stop) setErr(formatApiError(e));
      }
    };
    void tick();
    const h = setInterval(tick, 2000);
    return () => {
      stop = true;
      clearInterval(h);
    };
  }, [selected, paused]);

  // Auto-scroll to the bottom as lines arrive (unless paused).
  useEffect(() => {
    const el = scrollRef.current;
    if (el && !paused) el.scrollTop = el.scrollHeight;
  }, [lines, paused]);

  const loggingOn = !!enf?.logging_enabled;
  const enforcementOff = enf ? !enf.enabled : false;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <ScrollText className="h-4 w-4 text-muted-foreground" />
            Firewall logs
          </h3>
          <p className="mt-1 max-w-xl text-xs text-muted-foreground">
            Live tail of nftables drop events (prefix <code>spatium-fw:</code>)
            for troubleshooting "why is this blocked?". Logging is opt-in; the
            supervisor streams its host kernel log here, so you can watch any
            appliance in the fleet.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setLogging.mutate(!loggingOn)}
          disabled={setLogging.isPending}
          {...applianceGate}
          className={cn(
            "inline-flex shrink-0 items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm disabled:cursor-not-allowed disabled:opacity-50",
            loggingOn
              ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
              : "bg-background hover:bg-accent",
          )}
        >
          {setLogging.isPending && (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          )}
          Logging: {loggingOn ? "On" : "Off"}
        </button>
      </div>

      {loggingOn && enforcementOff && (
        <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2.5 text-xs text-amber-700 dark:text-amber-400">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          Logging is on, but firewall enforcement is off — no packets are being
          dropped, so there's nothing to log yet. Turn on enforcement from the
          Policies section.
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs text-muted-foreground">Appliance</label>
        <select
          value={selected}
          onChange={(e) => setSelected(e.target.value)}
          className="rounded-md border bg-background px-2 py-1 text-sm"
        >
          {online.length === 0 && (
            <option value="">
              {/* #3107 — a refused list is not "no appliances". */}
              {appliancesError
                ? isRefused(appliancesError)
                  ? "Appliance list not permitted"
                  : "Couldn't load appliances"
                : "No online appliances"}
            </option>
          )}
          {online.map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname}
            </option>
          ))}
        </select>
        {appliancesError && (
          <ListReadError
            error={appliancesError}
            what="the appliance list"
            className="text-xs"
          />
        )}
        <button
          type="button"
          onClick={() => setPaused((p) => !p)}
          className="rounded-md border bg-background px-2 py-1 text-xs hover:bg-accent"
        >
          {paused ? "Resume" : "Pause"}
        </button>
        <button
          type="button"
          onClick={() => setLines([])}
          className="rounded-md border bg-background px-2 py-1 text-xs hover:bg-accent"
        >
          Clear
        </button>
        <span className="ml-auto text-[11px] text-muted-foreground">
          {lines.length} line{lines.length === 1 ? "" : "s"}
          {!paused && selected ? " · live" : ""}
        </span>
      </div>

      {err && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-2 text-xs text-destructive">
          {err}
        </div>
      )}

      <div
        ref={scrollRef}
        className="h-[28rem] overflow-auto rounded-md border bg-muted/30 px-3 py-2 font-mono text-[11px] leading-tight"
      >
        {lines.length === 0 ? (
          <span className="text-muted-foreground">
            {selected
              ? loggingOn
                ? "Waiting for dropped packets…"
                : "Enable logging above, then reproduce the blocked connection."
              : "Select an appliance to tail its firewall log."}
          </span>
        ) : (
          lines.map((l) => (
            <div key={l.seq} className="whitespace-pre-wrap break-all">
              {l.text}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ── Enforcement master switch + all-CP-hardened gate (Phase 4a) ──────

function EnforcementCard() {
  // #1342 — every appliance action takes `admin` on `appliance`.
  const applianceGate = useApplianceAdminGate();
  const qc = useQueryClient();
  const { data: e } = useQuery({
    queryKey: ["firewall", "enforcement"],
    queryFn: firewallApi.getEnforcement,
  });
  const [confirm, setConfirm] = useState<
    null | "enable" | "enable-override" | "disable"
  >(null);
  const set = useMutation({
    mutationFn: (b: { enabled: boolean; override_unhardened?: boolean }) =>
      firewallApi.setEnforcement(b),
    onSuccess: () => {
      setConfirm(null);
      qc.invalidateQueries({ queryKey: ["firewall", "enforcement"] });
    },
  });
  if (!e) return null;
  const on = e.enabled;
  const unconfirmed = e.reported_count - e.hardened_count;

  return (
    <div
      className={cn(
        "rounded-md border p-3",
        on
          ? "border-emerald-500/40 bg-emerald-500/5"
          : "border-amber-500/40 bg-amber-500/5",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          {on ? (
            <ShieldCheck className="mt-0.5 h-5 w-5 text-emerald-600 dark:text-emerald-400" />
          ) : (
            <ShieldAlert className="mt-0.5 h-5 w-5 text-amber-600 dark:text-amber-400" />
          )}
          <div>
            <div className="text-sm font-medium">
              Enforcement {on ? "ON" : "OFF (dark)"}
            </div>
            <div className="text-xs text-muted-foreground">
              {on
                ? "The control plane is rendering authoritative firewall drop-ins to the fleet."
                : "Policies are editable + previewable, but not applied to any node until you enable."}{" "}
              {e.hardened_count}/{e.reported_count} reporting node(s) hardened
              {e.lanwide_count > 0 &&
                `, ${e.lanwide_count} still on the legacy LAN-wide base`}
              .
            </div>
          </div>
        </div>
        <div className="shrink-0">
          {on ? (
            <button
              type="button"
              onClick={() => setConfirm("disable")}
              className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
              {...applianceGate}
            >
              Disable
            </button>
          ) : (
            <button
              type="button"
              onClick={() =>
                setConfirm(e.safe_to_enable ? "enable" : "enable-override")
              }
              className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
              {...applianceGate}
            >
              Enable…
            </button>
          )}
        </div>
      </div>

      {!on && e.nodes.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {e.nodes.map((n) => (
            <span
              key={n.appliance_id}
              className={cn(
                "rounded px-1.5 py-0.5 text-[11px]",
                n.hardened
                  ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                  : "bg-rose-500/15 text-rose-600 dark:text-rose-400",
              )}
            >
              {n.hostname}:{" "}
              {n.hardened
                ? "hardened"
                : n.base_lanwide_k3s === true
                  ? "LAN-wide"
                  : "unknown"}
            </span>
          ))}
        </div>
      )}

      {set.isError && (
        <p className="mt-2 text-xs text-destructive">
          {formatApiError(set.error)}
        </p>
      )}

      <ConfirmModal
        open={confirm === "enable"}
        title="Enable firewall enforcement"
        loading={set.isPending}
        message={
          <>
            All {e.reported_count} reporting node(s) are hardened. Enabling
            makes the control-plane render authoritative — the next supervisor
            heartbeat applies each node's policy drop-in.
          </>
        }
        confirmLabel="Enable"
        onConfirm={() => set.mutate({ enabled: true })}
        onClose={() => setConfirm(null)}
      />
      <ConfirmModal
        open={confirm === "enable-override"}
        title="Enable enforcement before all nodes are hardened"
        tone="destructive"
        loading={set.isPending}
        requireCheckboxLabel={`I understand ${unconfirmed} node(s) are not confirmed hardened`}
        message={
          <>
            {unconfirmed} of {e.reported_count} reporting node(s) are not
            confirmed hardened ({e.lanwide_count} still on the legacy LAN-wide
            base). On those nodes the base accept still fires first, so enabling
            is a no-op there until the hardened slot rolls out — and the
            compliance claim would be inaccurate. Enable anyway?
          </>
        }
        confirmLabel="Enable anyway"
        onConfirm={() =>
          set.mutate({ enabled: true, override_unhardened: true })
        }
        onClose={() => setConfirm(null)}
      />
      <ConfirmModal
        open={confirm === "disable"}
        title="Disable firewall enforcement"
        loading={set.isPending}
        message="The fleet falls back to the in-pod (dark) render. Always safe — nothing tightens on disable."
        confirmLabel="Disable"
        onConfirm={() => set.mutate({ enabled: false })}
        onClose={() => setConfirm(null)}
      />
    </div>
  );
}

// ── Web UI source restriction (Phase 6) ─────────────────────────────

// ── Policies ─────────────────────────────────────────────────────────

function PoliciesSection() {
  // #1342 — every appliance action takes `admin` on `appliance`.
  const applianceGate = useApplianceAdminGate();
  const qc = useQueryClient();
  const {
    data: policies,
    isLoading,
    error: policiesError,
  } = useQuery({
    queryKey: ["firewall", "policies"],
    queryFn: () => firewallApi.listPolicies(),
  });
  const [showNew, setShowNew] = useState(false);
  const [editPolicy, setEditPolicy] = useState<FirewallPolicy | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<FirewallPolicy | null>(
    null,
  );
  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["firewall", "policies"] });

  const toggle = useMutation({
    mutationFn: (p: FirewallPolicy) =>
      firewallApi.updatePolicy(p.id, { enabled: !p.enabled }),
    onSuccess: invalidate,
  });
  const del = useMutation({
    mutationFn: (id: string) => firewallApi.deletePolicy(id),
    onSuccess: () => {
      setConfirmDelete(null);
      invalidate();
    },
  });
  const [confirmPreset, setConfirmPreset] = useState<
    null | "locked" | "balanced" | "open"
  >(null);
  const posture = useMutation({
    mutationFn: (p: "locked" | "balanced" | "open") =>
      firewallApi.applyPosture(p),
    onSuccess: () => {
      setConfirmPreset(null);
      invalidate();
    },
  });

  return (
    <div className="space-y-3">
      {/* #404 — firewall master controls (enforcement + Web UI access),
          nested here with the policies they govern instead of as full-width
          bars above the whole tab. Two columns so they stay compact. */}
      <div className="grid gap-3 xl:grid-cols-2">
        <EnforcementCard />
        <WebUIAccessCard editDisabledReason={applianceGate.title} />
      </div>
      <div className="grid gap-2 sm:grid-cols-3">
        {POSTURE_PRESETS.map((p) => (
          <div key={p.key} className="rounded-md border p-2.5">
            <div className="text-sm font-medium">{p.label}</div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              {p.blurb}
            </div>
            <button
              type="button"
              onClick={() => setConfirmPreset(p.key)}
              className="mt-2 rounded-md border px-2.5 py-1 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
              {...applianceGate}
            >
              Apply preset
            </button>
          </div>
        ))}
      </div>

      {posture.isError && (
        <p className="text-xs text-destructive">
          {formatApiError(posture.error)}
        </p>
      )}

      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          {policies?.length ?? 0} policies
        </span>
        <div className="flex gap-1.5">
          <button
            type="button"
            onClick={invalidate}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
          <button
            type="button"
            onClick={() => setShowNew(true)}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            {...applianceGate}
          >
            <Plus className="h-3.5 w-3.5" /> New policy
          </button>
        </div>
      </div>

      {isLoading ? (
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      ) : (
        <div className="overflow-hidden rounded-md border">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Name</th>
                <th className="px-3 py-2 text-left">Scope</th>
                <th className="px-3 py-2 text-left">Rules</th>
                <th className="px-3 py-2 text-left">Enabled</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(policies ?? []).map((p) => (
                <tr key={p.id} className="border-t">
                  <td className="px-3 py-2">
                    <span className="font-medium">{p.name}</span>
                    {p.is_builtin && (
                      <span
                        className="ml-1.5 inline-flex items-center gap-0.5 rounded bg-muted px-1 py-0.5 text-[10px] text-muted-foreground"
                        title="Built-in: identity locked, rules editable, can't delete"
                      >
                        <Lock className="h-2.5 w-2.5" /> builtin
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {scopeLabel(p)}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {p.rules.length}
                  </td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      onClick={() => toggle.mutate(p)}
                      className={cn(
                        "rounded px-1.5 py-0.5 text-xs",
                        p.enabled
                          ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                          : "bg-muted text-muted-foreground",
                      )}
                      {...applianceGate}
                    >
                      {p.enabled ? "enabled" : "disabled"}
                    </button>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex justify-end gap-1.5">
                      <button
                        type="button"
                        onClick={() => setEditPolicy(p)}
                        className="rounded-md border px-2 py-1 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                        {...applianceGate}
                      >
                        Edit rules
                      </button>
                      <button
                        type="button"
                        disabled={p.is_builtin}
                        onClick={() => setConfirmDelete(p)}
                        title={
                          p.is_builtin
                            ? "Built-in policies can't be deleted (disable instead)"
                            : "Delete"
                        }
                        className="rounded-md border px-2 py-1 text-xs text-destructive hover:bg-destructive/10 disabled:opacity-40"
                        {...applianceGate}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {(policies ?? []).length === 0 && (
                <tr>
                  <td
                    colSpan={5}
                    className="px-3 py-6 text-center text-muted-foreground"
                  >
                    <ListEmpty error={policiesError} what="firewall policies">
                      No policies yet. The builtin role policies seed on first
                      migrate; create a fleet baseline or appliance override
                      here.
                    </ListEmpty>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {toggle.isError && (
        <p className="text-xs text-destructive">
          {formatApiError(toggle.error)}
        </p>
      )}

      {showNew && (
        <NewPolicyModal
          onClose={() => setShowNew(false)}
          onSaved={() => {
            setShowNew(false);
            invalidate();
          }}
        />
      )}
      {editPolicy && (
        <RuleEditorModal
          policy={editPolicy}
          onClose={() => setEditPolicy(null)}
          onSaved={() => {
            setEditPolicy(null);
            invalidate();
          }}
        />
      )}
      <ConfirmModal
        open={confirmDelete !== null}
        title="Delete policy"
        tone="destructive"
        loading={del.isPending}
        message={
          <>
            Delete <span className="font-medium">{confirmDelete?.name}</span>{" "}
            and its rules? This can't be undone.
          </>
        }
        confirmLabel="Delete"
        onConfirm={() => confirmDelete && del.mutate(confirmDelete.id)}
        onClose={() => setConfirmDelete(null)}
      />
      <ConfirmModal
        open={confirmPreset !== null}
        title={`Apply "${confirmPreset}" posture preset`}
        loading={posture.isPending}
        message={
          <>
            This replaces the{" "}
            <span className="font-medium">fleet baseline</span> policy's rules
            with the <span className="font-medium">{confirmPreset}</span> preset
            (role + appliance scopes and the builtins are untouched). You can
            fine-tune the fleet policy afterwards.
          </>
        }
        confirmLabel="Apply preset"
        onConfirm={() => confirmPreset && posture.mutate(confirmPreset)}
        onClose={() => setConfirmPreset(null)}
      />
    </div>
  );
}

function NewPolicyModal({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [scopeKind, setScopeKind] = useState<FirewallScopeKind>("fleet");
  const [scopeRole, setScopeRole] = useState("custom");
  const [applianceId, setApplianceId] = useState("");
  const { data: appliances } = useQuery({
    queryKey: ["appliance", "appliances"],
    queryFn: applianceApprovalApi.list,
    enabled: scopeKind === "appliance",
  });
  const save = useMutation({
    mutationFn: () =>
      firewallApi.createPolicy({
        name: name.trim(),
        scope_kind: scopeKind,
        scope_role: scopeKind === "role" ? scopeRole : null,
        scope_appliance_id: scopeKind === "appliance" ? applianceId : null,
      }),
    onSuccess: onSaved,
  });
  const canSave =
    name.trim().length > 0 &&
    (scopeKind !== "appliance" || applianceId.length > 0);

  return (
    <Modal title="New firewall policy" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <label className="block">
          <span className="text-xs text-muted-foreground">Name</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="mt-1 w-full rounded-md border bg-background px-2 py-1.5"
            placeholder="e.g. Fleet baseline"
          />
        </label>
        <label className="block">
          <span className="text-xs text-muted-foreground">Scope</span>
          <select
            value={scopeKind}
            onChange={(e) => setScopeKind(e.target.value as FirewallScopeKind)}
            className="mt-1 w-full rounded-md border bg-background px-2 py-1.5"
          >
            <option value="fleet">Fleet (singleton baseline)</option>
            <option value="role">Per-role overlay</option>
            <option value="appliance">Per-appliance override</option>
          </select>
        </label>
        {scopeKind === "role" && (
          <label className="block">
            <span className="text-xs text-muted-foreground">Role</span>
            <select
              value={scopeRole}
              onChange={(e) => setScopeRole(e.target.value)}
              className="mt-1 w-full rounded-md border bg-background px-2 py-1.5"
            >
              {ROLE_OPTIONS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </label>
        )}
        {scopeKind === "appliance" && (
          <label className="block">
            <span className="text-xs text-muted-foreground">Appliance</span>
            <select
              value={applianceId}
              onChange={(e) => setApplianceId(e.target.value)}
              className="mt-1 w-full rounded-md border bg-background px-2 py-1.5"
            >
              <option value="">— pick —</option>
              {(appliances ?? []).map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname}
                </option>
              ))}
            </select>
          </label>
        )}
        {save.isError && (
          <p className="text-xs text-destructive">
            {formatApiError(save.error)}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!canSave || save.isPending}
            onClick={() => save.mutate()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
          >
            {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Create
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Rule editor (bulk replace) ────────────────────────────────────────

interface EditRow {
  seq: string;
  action: FirewallAction;
  protocol: FirewallProtocol;
  ports: string;
  source_kind: FirewallSourceKind;
  source: string;
  family: FirewallFamily;
  comment: string;
  enabled: boolean;
}

function rowFromRule(r: FirewallRuleInput): EditRow {
  return {
    seq: String(r.seq),
    action: r.action,
    protocol: r.protocol,
    ports: r.ports.join(", "),
    source_kind: r.source_kind,
    source:
      r.source_kind === "alias"
        ? (r.source_alias ?? "")
        : r.source_cidrs.join(", "),
    family: r.family,
    comment: r.comment ?? "",
    enabled: r.enabled,
  };
}

function parseList(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function emptyRow(seq: number): EditRow {
  return {
    seq: String(seq),
    action: "accept",
    protocol: "tcp",
    ports: "",
    source_kind: "any",
    source: "",
    family: "both",
    comment: "",
    enabled: true,
  };
}

function rowsToRules(rows: EditRow[]): FirewallRuleInput[] {
  return rows.map((r) => ({
    seq: Number(r.seq) || 0,
    action: r.action,
    protocol: r.protocol,
    ports: parseList(r.ports)
      .map((p) => Number(p))
      .filter((n) => !Number.isNaN(n)),
    source_kind: r.source_kind,
    source_cidrs: r.source_kind === "cidr" ? parseList(r.source) : [],
    source_alias: r.source_kind === "alias" ? r.source.trim() || null : null,
    family: r.family,
    comment: r.comment.trim() || null,
    enabled: r.enabled,
  }));
}

// Shared editable rule-rows table — used by the rule editor (bulk-replace a
// policy) AND the staged-preview tab (what-if fleet overlay rules).
function RuleRowsEditor({
  rows,
  setRows,
}: {
  rows: EditRow[];
  setRows: Dispatch<SetStateAction<EditRow[]>>;
}) {
  const update = (i: number, patch: Partial<EditRow>) =>
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <>
      <div className="max-h-[45vh] overflow-auto rounded-md border">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-muted/70 text-muted-foreground">
            <tr>
              <th className="px-1.5 py-1 text-left">Seq</th>
              <th className="px-1.5 py-1 text-left">Action</th>
              <th className="px-1.5 py-1 text-left">Proto</th>
              <th className="px-1.5 py-1 text-left">Ports</th>
              <th className="px-1.5 py-1 text-left">Source kind</th>
              <th className="px-1.5 py-1 text-left">Source (CIDRs / alias)</th>
              <th className="px-1.5 py-1 text-left">Family</th>
              <th className="px-1.5 py-1 text-left">Comment</th>
              <th className="px-1.5 py-1"></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-t">
                <td className="px-1 py-1">
                  <input
                    value={r.seq}
                    onChange={(e) => update(i, { seq: e.target.value })}
                    className="w-12 rounded border bg-background px-1 py-0.5"
                  />
                </td>
                <td className="px-1 py-1">
                  <select
                    value={r.action}
                    onChange={(e) =>
                      update(i, { action: e.target.value as FirewallAction })
                    }
                    className="rounded border bg-background px-1 py-0.5"
                  >
                    <option value="accept">accept</option>
                    <option value="drop">drop</option>
                  </select>
                </td>
                <td className="px-1 py-1">
                  <select
                    value={r.protocol}
                    onChange={(e) =>
                      update(i, {
                        protocol: e.target.value as FirewallProtocol,
                      })
                    }
                    className="rounded border bg-background px-1 py-0.5"
                  >
                    {PROTOCOLS.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-1 py-1">
                  <input
                    value={r.ports}
                    onChange={(e) => update(i, { ports: e.target.value })}
                    placeholder="53, 80"
                    className="w-20 rounded border bg-background px-1 py-0.5"
                  />
                </td>
                <td className="px-1 py-1">
                  <select
                    value={r.source_kind}
                    onChange={(e) =>
                      update(i, {
                        source_kind: e.target.value as FirewallSourceKind,
                      })
                    }
                    className="rounded border bg-background px-1 py-0.5"
                  >
                    {SOURCE_KINDS.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-1 py-1">
                  <input
                    value={r.source}
                    onChange={(e) => update(i, { source: e.target.value })}
                    disabled={
                      r.source_kind !== "cidr" && r.source_kind !== "alias"
                    }
                    placeholder={
                      r.source_kind === "alias"
                        ? "alias-name"
                        : r.source_kind === "cidr"
                          ? "10.0.0.0/8"
                          : "(derived)"
                    }
                    className="w-32 rounded border bg-background px-1 py-0.5 disabled:opacity-40"
                  />
                </td>
                <td className="px-1 py-1">
                  <select
                    value={r.family}
                    onChange={(e) =>
                      update(i, { family: e.target.value as FirewallFamily })
                    }
                    className="rounded border bg-background px-1 py-0.5"
                  >
                    {FAMILIES.map((f) => (
                      <option key={f} value={f}>
                        {f}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="px-1 py-1">
                  <input
                    value={r.comment}
                    onChange={(e) => update(i, { comment: e.target.value })}
                    className="w-24 rounded border bg-background px-1 py-0.5"
                  />
                </td>
                <td className="px-1 py-1 text-right">
                  <button
                    aria-label="Remove rule"
                    title="Remove rule"
                    type="button"
                    onClick={() =>
                      setRows((rs) => rs.filter((_, j) => j !== i))
                    }
                    className="text-destructive hover:opacity-70"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button
        type="button"
        onClick={() => setRows((rs) => [...rs, emptyRow((rs.length + 1) * 10)])}
        className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs hover:bg-accent"
      >
        <Plus className="h-3 w-3" /> Add rule
      </button>
    </>
  );
}

function RuleEditorModal({
  policy,
  onClose,
  onSaved,
}: {
  policy: FirewallPolicy;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [rows, setRows] = useState<EditRow[]>(policy.rules.map(rowFromRule));
  const save = useMutation({
    mutationFn: () => firewallApi.replaceRules(policy.id, rowsToRules(rows)),
    onSuccess: onSaved,
  });

  return (
    <Modal title={`Edit rules — ${policy.name}`} onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        <p className="text-xs text-muted-foreground">
          Bulk-replace this policy's rules. Lower <code>seq</code> renders
          first. A rule may not drop port 22. Builtin policy rules are editable;
          the mgmt floor (ssh / ping / loopback) is always emitted regardless.
        </p>
        <RuleRowsEditor rows={rows} setRows={setRows} />
        {save.isError && (
          <p className="text-xs text-destructive">
            {formatApiError(save.error)}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={save.isPending}
            onClick={() => save.mutate()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
          >
            {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Save rules
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Aliases ──────────────────────────────────────────────────────────

function AliasesSection() {
  const qc = useQueryClient();
  const applianceGate = useApplianceAdminGate();
  const {
    data: aliases,
    isLoading,
    error: aliasesError,
  } = useQuery({
    queryKey: ["firewall", "aliases"],
    queryFn: firewallApi.listAliases,
  });
  const [showNew, setShowNew] = useState(false);
  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["firewall", "aliases"] });
  const del = useMutation({
    mutationFn: (id: string) => firewallApi.deleteAlias(id),
    onSuccess: invalidate,
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
          <Tags className="h-3.5 w-3.5" /> {aliases?.length ?? 0} aliases —
          named CIDR / port sets reusable across rules
        </span>
        <button
          type="button"
          onClick={() => setShowNew(true)}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
          {...applianceGate}
        >
          <Plus className="h-3.5 w-3.5" /> New alias
        </button>
      </div>
      {isLoading ? (
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      ) : (
        <div className="overflow-hidden rounded-md border">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 text-xs text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Name</th>
                <th className="px-3 py-2 text-left">Kind</th>
                <th className="px-3 py-2 text-left">Members</th>
                <th className="px-3 py-2 text-right"></th>
              </tr>
            </thead>
            <tbody>
              {(aliases ?? []).map((a) => (
                <tr key={a.id} className="border-t">
                  <td className="px-3 py-2 font-medium">{a.name}</td>
                  <td className="px-3 py-2 text-muted-foreground">{a.kind}</td>
                  <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                    {a.kind === "port"
                      ? a.port_members.join(", ")
                      : [...a.v4_members, ...a.v6_members].join(", ")}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      type="button"
                      disabled={a.is_builtin}
                      onClick={() => del.mutate(a.id)}
                      className="rounded-md border px-2 py-1 text-xs text-destructive hover:bg-destructive/10 disabled:opacity-40"
                      {...applianceGate}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
              {(aliases ?? []).length === 0 && (
                <tr>
                  <td
                    colSpan={4}
                    className="px-3 py-6 text-center text-muted-foreground"
                  >
                    <ListEmpty error={aliasesError} what="firewall aliases">
                      No aliases yet.
                    </ListEmpty>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {showNew && (
        <NewAliasModal
          onClose={() => setShowNew(false)}
          onSaved={() => {
            setShowNew(false);
            invalidate();
          }}
        />
      )}
    </div>
  );
}

function NewAliasModal({
  onClose,
  onSaved,
}: {
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"port" | "cidr">("cidr");
  const [members, setMembers] = useState("");
  const save = useMutation({
    mutationFn: () => {
      const list = parseList(members);
      if (kind === "port") {
        return firewallApi.createAlias({
          name: name.trim(),
          kind,
          port_members: list.map(Number).filter((n) => !Number.isNaN(n)),
        });
      }
      // Family-split at rest: v6 entries contain ':'.
      return firewallApi.createAlias({
        name: name.trim(),
        kind,
        v4_members: list.filter((c) => !c.includes(":")),
        v6_members: list.filter((c) => c.includes(":")),
      });
    },
    onSuccess: onSaved,
  });
  return (
    <Modal title="New alias" onClose={onClose}>
      <div className="space-y-3 text-sm">
        <label className="block">
          <span className="text-xs text-muted-foreground">Name</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="mt-1 w-full rounded-md border bg-background px-2 py-1.5"
          />
        </label>
        <label className="block">
          <span className="text-xs text-muted-foreground">Kind</span>
          <select
            value={kind}
            onChange={(e) => setKind(e.target.value as "port" | "cidr")}
            className="mt-1 w-full rounded-md border bg-background px-2 py-1.5"
          >
            <option value="cidr">CIDR set</option>
            <option value="port">Port set</option>
          </select>
        </label>
        <label className="block">
          <span className="text-xs text-muted-foreground">
            Members (comma-separated; v4 + v6 auto-split)
          </span>
          <input
            value={members}
            onChange={(e) => setMembers(e.target.value)}
            placeholder={
              kind === "port" ? "53, 80, 443" : "10.0.0.0/8, 2001:db8::/64"
            }
            className="mt-1 w-full rounded-md border bg-background px-2 py-1.5 font-mono text-xs"
          />
        </label>
        {save.isError && (
          <p className="text-xs text-destructive">
            {formatApiError(save.error)}
          </p>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!name.trim() || save.isPending}
            onClick={() => save.mutate()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
          >
            {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Create
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Effective render ──────────────────────────────────────────────────

const LAYER_LABELS: { key: string; label: string }[] = [
  { key: "management", label: "Management floor" },
  { key: "role", label: "Per-role service ports" },
  { key: "control_plane", label: "Control-plane derived" },
  { key: "overlay", label: "Fleet / appliance overlay" },
  { key: "firewall_extra", label: "Operator override (firewall_extra)" },
];

function EffectiveSection() {
  const { data: appliances, error: appliancesError } = useQuery({
    queryKey: ["appliance", "appliances"],
    queryFn: applianceApprovalApi.list,
  });
  const [applianceId, setApplianceId] = useState("");
  const {
    data: eff,
    isFetching,
    error,
    refetch,
  } = useQuery<FirewallEffective>({
    queryKey: ["firewall", "effective", applianceId],
    queryFn: () => firewallApi.effective(applianceId),
    enabled: applianceId.length > 0,
  });
  const totalRules = useMemo(
    () =>
      eff
        ? Object.values(eff.layers).reduce((n, lines) => n + lines.length, 0)
        : 0,
    [eff],
  );

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <select
          value={applianceId}
          onChange={(e) => setApplianceId(e.target.value)}
          className="rounded-md border bg-background px-2 py-1.5 text-sm"
        >
          <option value="">— pick an appliance —</option>
          {(appliances ?? []).map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname}
            </option>
          ))}
        </select>
        {appliancesError && (
          <ListReadError
            error={appliancesError}
            what="the appliance list"
            className="text-xs"
          />
        )}
        {applianceId && (
          <button
            type="button"
            onClick={() => refetch()}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", isFetching && "animate-spin")}
            />
            Refresh
          </button>
        )}
      </div>

      {error && (
        <p className="text-xs text-destructive">{formatApiError(error)}</p>
      )}

      {eff && (
        <>
          {!eff.firewall_enabled && (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                Preview only — enforcement is OFF (
                <code>firewall_enabled=false</code>). This is the render that
                would ship once the master switch is flipped on; the node is not
                applying it yet.
              </span>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="rounded bg-muted px-1.5 py-0.5 font-mono">
              {eff.hostname}
            </span>
            <span className="text-muted-foreground">{totalRules} rules</span>
            {eff.drift ? (
              <span className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-amber-600 dark:text-amber-400">
                <AlertTriangle className="h-3 w-3" /> drift: rendered ≠ applied
              </span>
            ) : (
              eff.applied_hash && (
                <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-1.5 py-0.5 text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 className="h-3 w-3" /> converged
                </span>
              )
            )}
            {eff.applied_status && (
              <span className="text-muted-foreground">
                status: {eff.applied_status}
              </span>
            )}
          </div>

          <div className="grid gap-3 lg:grid-cols-2">
            <div className="space-y-2">
              <div className="inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                <Layers className="h-3.5 w-3.5" /> Layer breakdown
              </div>
              {LAYER_LABELS.filter(
                (l) => (eff.layers[l.key] ?? []).length > 0,
              ).map((l) => (
                <div key={l.key} className="rounded-md border">
                  <div className="border-b bg-muted/40 px-2 py-1 text-xs font-medium">
                    {l.label}
                  </div>
                  <pre className="overflow-x-auto px-2 py-1.5 font-mono text-[11px] leading-relaxed">
                    {(eff.layers[l.key] ?? []).join("\n")}
                  </pre>
                </div>
              ))}
            </div>
            <div className="space-y-2">
              <div className="text-xs font-medium text-muted-foreground">
                Rendered drop-in
              </div>
              <pre className="max-h-[60vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-[11px] leading-relaxed">
                {eff.firewall_conf}
              </pre>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Staged-preview diff viewer (Phase 4b) ───────────────────────────

function PreviewSection() {
  const { data: appliances, error: appliancesError } = useQuery({
    queryKey: ["appliance", "appliances"],
    queryFn: applianceApprovalApi.list,
  });
  const [applianceId, setApplianceId] = useState("");
  const [rows, setRows] = useState<EditRow[]>([emptyRow(10)]);
  const preview = useMutation({
    mutationFn: () =>
      firewallApi.preview({
        appliance_id: applianceId,
        fleet_rules: rowsToRules(rows),
      }),
  });

  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        Stage fleet-overlay rules and preview their effect on a node before
        saving — the line diff against its current effective render, plus
        accept↔drop conflict / redundancy warnings. Read-only; nothing is
        applied or saved.
      </p>
      <div className="flex items-center gap-2">
        <select
          value={applianceId}
          onChange={(e) => setApplianceId(e.target.value)}
          className="rounded-md border bg-background px-2 py-1.5 text-sm"
        >
          <option value="">— pick an appliance —</option>
          {(appliances ?? []).map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname}
            </option>
          ))}
        </select>
        {appliancesError && (
          <ListReadError
            error={appliancesError}
            what="the appliance list"
            className="text-xs"
          />
        )}
        <button
          type="button"
          disabled={!applianceId || preview.isPending}
          onClick={() => preview.mutate()}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {preview.isPending && (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          )}
          Preview
        </button>
      </div>

      <RuleRowsEditor rows={rows} setRows={setRows} />

      {preview.isError && (
        <p className="text-xs text-destructive">
          {formatApiError(preview.error)}
        </p>
      )}

      {preview.data && (
        <div className="space-y-2">
          {preview.data.upgrade_in_flight && (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>
                An OS upgrade is in flight — a firewall apply would be blocked
                until it completes.
              </span>
            </div>
          )}
          {preview.data.warnings.length > 0 && (
            <div className="space-y-1">
              {preview.data.warnings.map((w, i) => (
                <div
                  key={i}
                  className={cn(
                    "rounded px-2 py-1 text-xs",
                    w.kind === "conflict"
                      ? "bg-amber-500/15 text-amber-700 dark:text-amber-300"
                      : "bg-muted text-muted-foreground",
                  )}
                >
                  <span className="font-medium">{w.kind}</span> — {w.detail}
                </div>
              ))}
            </div>
          )}
          <div className="grid gap-3 lg:grid-cols-2">
            <div className="rounded-md border">
              <div className="border-b bg-muted/40 px-2 py-1 text-xs font-medium text-emerald-600 dark:text-emerald-400">
                + Added ({preview.data.added.length})
              </div>
              <pre className="overflow-x-auto px-2 py-1.5 font-mono text-[11px] leading-relaxed">
                {preview.data.added.join("\n") || "(none)"}
              </pre>
            </div>
            <div className="rounded-md border">
              <div className="border-b bg-muted/40 px-2 py-1 text-xs font-medium text-rose-600 dark:text-rose-400">
                − Removed ({preview.data.removed.length})
              </div>
              <pre className="overflow-x-auto px-2 py-1.5 font-mono text-[11px] leading-relaxed">
                {preview.data.removed.join("\n") || "(none)"}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
