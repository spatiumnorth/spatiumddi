import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  Award,
  Globe,
  Loader2,
  Network,
  Plug,
  Power,
  Route,
  Search,
  ShieldCheck,
  Terminal,
  Wrench,
} from "lucide-react";
import {
  type ApplianceRow,
  type NetToolCommandResult,
  type NetToolMacVendorResult,
  type NetToolPortTestResult,
  type NetToolTarget,
  type NetToolTlsCertResult,
  type NetToolWolResult,
  type PropagationCheckResult,
  applianceApprovalApi,
  networkToolsApi,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { HeaderButton } from "@/components/ui/header-button";
import { ListReadError } from "@/components/ui/list-read-error";
import { pollUnlessRefused } from "@/lib/refusal";

// ── tool catalog ────────────────────────────────────────────────────

type ToolId =
  | "ping"
  | "traceroute"
  | "mtr"
  | "dig"
  | "whois"
  | "port-test"
  | "tls-cert"
  | "dns-propagation"
  | "mac-vendor"
  | "wol";

interface ToolDef {
  id: ToolId;
  label: string;
  icon: typeof Wrench;
  blurb: string;
  /** off-prem tools carry a tighter rate-limit budget on the server */
  offPrem?: boolean;
  /** the five reachability tools can run from a remote Fleet appliance's
   *  vantage; everything else is control-plane-server-only. */
  reachability?: boolean;
}

const TOOLS: ToolDef[] = [
  {
    id: "ping",
    label: "Ping",
    icon: Activity,
    blurb: "4 ICMP echoes — reachability + round-trip latency.",
    reachability: true,
  },
  {
    id: "traceroute",
    label: "Traceroute",
    icon: Route,
    blurb: "Per-hop path to a host (max 20 hops).",
    reachability: true,
  },
  {
    id: "mtr",
    label: "MTR",
    icon: Network,
    blurb: "Combined traceroute + ping loss report.",
  },
  {
    id: "dig",
    label: "Dig",
    icon: Search,
    blurb: "DNS query against a record type / resolver.",
    reachability: true,
  },
  {
    id: "port-test",
    label: "Port test",
    icon: Plug,
    blurb: "TCP / UDP reachability — open / closed / filtered.",
    reachability: true,
  },
  {
    id: "tls-cert",
    label: "TLS certificate",
    icon: ShieldCheck,
    blurb: "Inspect the cert a host presents — expiry, SAN, issuer.",
    reachability: true,
  },
  {
    id: "dns-propagation",
    label: "DNS propagation",
    icon: Globe,
    blurb: "Query a record across several public resolvers.",
    offPrem: true,
  },
  {
    id: "whois",
    label: "WHOIS",
    icon: Terminal,
    blurb: "Public WHOIS lookup for an IP / domain / ASN.",
    offPrem: true,
  },
  {
    id: "mac-vendor",
    label: "MAC vendor",
    icon: Award,
    blurb: "Resolve OUI vendor names for a batch of MACs.",
  },
  {
    id: "wol",
    label: "Wake-on-LAN",
    icon: Power,
    blurb: "Send a magic packet to a MAC — from the server or an appliance.",
    reachability: true,
  },
];

const inputCls =
  "block w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:border-ring focus:outline-none focus:ring-1 focus:ring-ring";

const labelCls = "mb-1 block text-xs font-medium text-muted-foreground";

const RECORD_TYPES = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "TXT",
  "NS",
  "SOA",
  "PTR",
  "SRV",
  "CAA",
  "TLSA",
  "DS",
  "DNSKEY",
  "NAPTR",
  "ANY",
];

function apiError(e: unknown): string {
  const detail = (e as { response?: { data?: { detail?: unknown } } })?.response
    ?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length) {
    const first = detail[0] as { msg?: string };
    if (first?.msg) return first.msg;
  }
  return "Request failed";
}

/** Map an axios error into operator-friendly copy. When a run was
 *  dispatched to a Fleet appliance, the supervisor path surfaces its
 *  own status codes (503 offline / 504 timeout / 502 supervisor error
 *  / 400 not-allowed / 404 unknown) — translate those to plain English
 *  and fall back to the normal detail-string handling otherwise. */
function toolError(e: unknown, ranRemote: boolean): string {
  const status = (e as { response?: { status?: number } })?.response?.status;
  if (ranRemote) {
    if (status === 503) return "Appliance is offline";
    if (status === 504) return "Timed out waiting for the appliance";
    if (status === 502) return "Appliance error";
    if (status === 404) return "Appliance not found";
    if (status === 400) return apiError(e); // tool-not-allowed reason
  }
  return apiError(e);
}

// ── run-from target ───────────────────────────────────────────────────
//
// Mirror the backend's reachability gate (``agent_cmd.appliance_ready``):
// an appliance is offerable as a run-from target only when it's
// ``approved`` AND has heartbeated within the staleness window.
const APPLIANCE_ONLINE_STALE_MS = 90_000;

function applianceOnline(a: ApplianceRow): boolean {
  if (a.state !== "approved") return false;
  if (!a.last_seen_at) return false;
  const seen = Date.parse(a.last_seen_at);
  if (Number.isNaN(seen)) return false;
  return Date.now() - seen <= APPLIANCE_ONLINE_STALE_MS;
}

/** ``undefined`` = run on the control-plane server (back-compat). */
function buildTarget(selection: string): NetToolTarget | undefined {
  if (selection === "server") return undefined;
  return { kind: "appliance", id: selection };
}

// ── page ──────────────────────────────────────────────────────────────

export function NetworkToolsPage() {
  const [active, setActive] = useState<ToolId>("ping");
  // ``"server"`` or an appliance id. Default = server (back-compat).
  const [runFrom, setRunFrom] = useState("server");
  const tool = TOOLS.find((t) => t.id === active)!;

  // Fleet appliances we can dispatch reachability tools to. Cheap +
  // shared list endpoint; refetch on a short cadence so the online set
  // tracks heartbeats while the page is open — until the read is refused
  // (#1343): a caller without admin on appliance is refused every time,
  // and every refusal is a denied audit row.
  const { data: appliances, error: appliancesError } = useQuery({
    queryKey: ["appliance-approval-list"],
    queryFn: () => applianceApprovalApi.list(),
    refetchInterval: pollUnlessRefused(30_000),
    staleTime: 15_000,
  });

  const onlineAppliances = useMemo(
    () => (appliances ?? []).filter(applianceOnline),
    [appliances],
  );

  // If the picked appliance fell offline (or the list changed), fall
  // back to the server so we never dispatch to a stale target.
  const selectionValid =
    runFrom === "server" || onlineAppliances.some((a) => a.id === runFrom);
  const effectiveRunFrom = selectionValid ? runFrom : "server";

  // Only the reachability tools accept a remote vantage; everything
  // else is server-only, so they ignore ``effectiveRunFrom`` entirely.
  const target = tool.reachability ? buildTarget(effectiveRunFrom) : undefined;

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <div className="border-b bg-card px-6 py-4">
        <div className="flex items-center gap-2">
          <Wrench className="h-5 w-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold">Network Tools</h1>
        </div>
        <p className="mt-1 max-w-3xl text-xs text-muted-foreground">
          Stateless ping / traceroute / MTR / dig / whois / port-test / TLS-cert
          / DNS-propagation / MAC-vendor / Wake-on-LAN utilities. Reachability
          tools can run from the control-plane server or a Fleet appliance's
          vantage; rate-limited per user.
        </p>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left tool picker */}
        <div className="w-60 shrink-0 overflow-auto border-r bg-card/40 p-2">
          {tool.reachability && (
            <RunFromSelector
              value={effectiveRunFrom}
              onChange={setRunFrom}
              appliances={onlineAppliances}
              listError={appliances ? null : appliancesError}
            />
          )}
          <div className="mt-2 space-y-1">
            {TOOLS.map((t) => {
              const Icon = t.icon;
              return (
                <button
                  key={t.id}
                  onClick={() => setActive(t.id)}
                  className={cn(
                    "flex w-full items-start gap-2 rounded-md px-2 py-2 text-left text-sm",
                    active === t.id
                      ? "bg-primary/10 text-primary"
                      : "hover:bg-muted/60",
                  )}
                >
                  <Icon className="mt-0.5 h-4 w-4 shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="flex items-center gap-1 font-medium">
                      {t.label}
                      {t.offPrem && (
                        <span
                          title="Sends traffic off-prem — tighter rate limit"
                          className="rounded bg-amber-500/15 px-1 text-[9px] font-semibold uppercase tracking-wide text-amber-600 dark:text-amber-400"
                        >
                          off-prem
                        </span>
                      )}
                    </span>
                    <span className="block text-[11px] leading-tight text-muted-foreground">
                      {t.blurb}
                    </span>
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right form + result */}
        <div className="flex-1 overflow-auto p-6">
          <div className="mx-auto max-w-3xl">
            <ToolPanel key={active} tool={tool} target={target} />
          </div>
        </div>
      </div>
    </div>
  );
}

/** Live run-from selector for the reachability tools — "Server" plus
 *  every online Fleet appliance. With zero online appliances it still
 *  offers "Server" and notes that nothing's reachable. When the appliance
 *  list could not be read it says that instead: "no appliances online" is
 *  then something nobody knows (#1343). */
function RunFromSelector({
  value,
  onChange,
  appliances,
  listError,
}: {
  value: string;
  onChange: (v: string) => void;
  appliances: ApplianceRow[];
  listError?: unknown;
}) {
  return (
    <div className="rounded-md border border-border bg-muted/30 p-2">
      <label className={labelCls}>Run from</label>
      <select
        className={inputCls}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="server">Server (control plane)</option>
        {appliances.map((a) => (
          <option key={a.id} value={a.id}>
            {a.hostname}
          </option>
        ))}
      </select>
      <p className="mt-1 text-[10px] leading-tight text-muted-foreground/70">
        {listError ? (
          <>
            Runs execute from the control-plane server.{" "}
            <ListReadError error={listError} what="the Fleet appliances" />
          </>
        ) : appliances.length === 0 ? (
          "Runs execute from the control-plane server — no appliances online."
        ) : (
          "Pick the control plane or a Fleet appliance's vantage point."
        )}
      </p>
    </div>
  );
}

function ToolPanel({
  tool,
  target,
}: {
  tool: ToolDef;
  target?: NetToolTarget;
}) {
  const Icon = tool.icon;
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Icon className="h-5 w-5 text-muted-foreground" />
        <h2 className="text-base font-semibold">{tool.label}</h2>
      </div>
      {tool.id === "ping" && <CommandTool kind="ping" target={target} />}
      {tool.id === "traceroute" && (
        <CommandTool kind="traceroute" target={target} />
      )}
      {tool.id === "mtr" && <CommandTool kind="mtr" />}
      {tool.id === "dig" && <DigTool target={target} />}
      {tool.id === "whois" && <WhoisTool />}
      {tool.id === "port-test" && <PortTestTool target={target} />}
      {tool.id === "tls-cert" && <TlsCertTool target={target} />}
      {tool.id === "dns-propagation" && <PropagationTool />}
      {tool.id === "mac-vendor" && <MacVendorTool />}
      {tool.id === "wol" && <WolTool target={target} />}
    </div>
  );
}

// ── shared result blocks ──────────────────────────────────────────────

function ErrorBanner({ msg }: { msg: string }) {
  return (
    <p className="rounded-md border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
      {msg}
    </p>
  );
}

/** Tiny provenance chip — "ran from: server" / "ran from: appliance:host". */
function RanFrom({ value }: { value?: string }) {
  if (!value) return null;
  return (
    <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
      ran from: <span className="font-mono">{value}</span>
    </span>
  );
}

function CommandOutput({ res }: { res: NetToolCommandResult }) {
  const body = res.stdout || res.stderr || res.error || "(no output)";
  return (
    <div className="space-y-2">
      {!res.available && res.error && <ErrorBanner msg={res.error} />}
      <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        <code className="rounded bg-muted px-1.5 py-0.5 font-mono">
          {res.argv.join(" ")}
        </code>
        {res.exit_code !== null && (
          <span
            className={cn(
              "rounded px-1.5 py-0.5 font-medium",
              res.exit_code === 0
                ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                : "bg-amber-500/15 text-amber-600 dark:text-amber-400",
            )}
          >
            exit {res.exit_code}
          </span>
        )}
        {res.timed_out && (
          <span className="rounded bg-destructive/15 px-1.5 py-0.5 font-medium text-destructive">
            timed out
          </span>
        )}
        {res.duration_ms !== null && (
          <span>{Math.round(res.duration_ms)} ms</span>
        )}
      </div>
      <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted/40 p-3 font-mono text-xs">
        {body}
      </pre>
    </div>
  );
}

// ── ping / traceroute / mtr ───────────────────────────────────────────

export function CommandTool({
  kind,
  target,
}: {
  kind: "ping" | "traceroute" | "mtr";
  target?: NetToolTarget;
}) {
  const [host, setHost] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<NetToolCommandResult | null>(null);

  // Generalised beyond "appliance" so a bgp_lg_collector vantage (#566
  // Phase 4 — ping/traceroute from a Looking Glass collector) also gets
  // the friendly remote-error copy in ``toolError`` below.
  const ranRemote = !!target && target.kind !== "server";

  const run = async () => {
    if (!host.trim()) {
      setErr("Host is required");
      return;
    }
    setErr(null);
    setRes(null);
    setBusy(true);
    try {
      const out =
        kind === "ping"
          ? await networkToolsApi.ping(host.trim(), target)
          : kind === "traceroute"
            ? await networkToolsApi.traceroute(host.trim(), target)
            : await networkToolsApi.mtr(host.trim());
      setRes(out);
    } catch (e) {
      setErr(toolError(e, ranRemote));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div>
        <label className={labelCls}>Host</label>
        <input
          className={cn(inputCls, "font-mono")}
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="IP or hostname — e.g. 1.1.1.1, router1.lan"
          onKeyDown={(e) => e.key === "Enter" && run()}
          autoFocus
        />
      </div>
      {err && <ErrorBanner msg={err} />}
      <RunButton busy={busy} onClick={run} label={host || "host"} />
      {res && (
        <div className="space-y-2">
          <RanFrom value={res.ran_from} />
          <CommandOutput res={res} />
        </div>
      )}
    </div>
  );
}

// ── dig ───────────────────────────────────────────────────────────────

function DigTool({ target }: { target?: NetToolTarget }) {
  const [name, setName] = useState("");
  const [recordType, setRecordType] = useState("A");
  const [server, setServer] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<NetToolCommandResult | null>(null);

  const ranRemote = target?.kind === "appliance";

  const run = async () => {
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    setErr(null);
    setRes(null);
    setBusy(true);
    try {
      setRes(
        await networkToolsApi.dig(
          {
            name: name.trim(),
            record_type: recordType,
            server: server.trim() || null,
          },
          target,
        ),
      );
    } catch (e) {
      setErr(toolError(e, ranRemote));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <label className={labelCls}>Name</label>
          <input
            className={cn(inputCls, "font-mono")}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="example.com"
            onKeyDown={(e) => e.key === "Enter" && run()}
            autoFocus
          />
        </div>
        <div>
          <label className={labelCls}>Type</label>
          <select
            className={inputCls}
            value={recordType}
            onChange={(e) => setRecordType(e.target.value)}
          >
            {RECORD_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div>
        <label className={labelCls}>Resolver (optional)</label>
        <input
          className={cn(inputCls, "font-mono")}
          value={server}
          onChange={(e) => setServer(e.target.value)}
          placeholder="@server — e.g. 1.1.1.1 (defaults to system resolver)"
        />
      </div>
      {err && <ErrorBanner msg={err} />}
      <RunButton busy={busy} onClick={run} label="dig" />
      {res && (
        <div className="space-y-2">
          <RanFrom value={res.ran_from} />
          <CommandOutput res={res} />
        </div>
      )}
    </div>
  );
}

// ── whois ─────────────────────────────────────────────────────────────

function WhoisTool() {
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<NetToolCommandResult | null>(null);

  const run = async () => {
    if (!query.trim()) {
      setErr("Query is required");
      return;
    }
    setErr(null);
    setBusy(true);
    try {
      setRes(await networkToolsApi.whois(query.trim()));
    } catch (e) {
      setErr(apiError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div>
        <label className={labelCls}>Query</label>
        <input
          className={cn(inputCls, "font-mono")}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="IP, domain, or ASN — e.g. 1.1.1.1, example.com, AS13335"
          onKeyDown={(e) => e.key === "Enter" && run()}
          autoFocus
        />
        <p className="mt-1 text-[11px] text-muted-foreground/70">
          Sends an outbound WHOIS query to a public registry.
        </p>
      </div>
      {err && <ErrorBanner msg={err} />}
      <RunButton busy={busy} onClick={run} label="whois" />
      {res && <CommandOutput res={res} />}
    </div>
  );
}

// ── port test ─────────────────────────────────────────────────────────

function PortTestTool({ target }: { target?: NetToolTarget }) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<NetToolPortTestResult | null>(null);

  const ranRemote = target?.kind === "appliance";

  const run = async () => {
    const p = Number(port);
    if (!host.trim()) {
      setErr("Host is required");
      return;
    }
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      setErr("Port must be 1–65535");
      return;
    }
    setErr(null);
    setRes(null);
    setBusy(true);
    try {
      setRes(
        await networkToolsApi.portTest(
          {
            host: host.trim(),
            port: p,
            protocol,
          },
          target,
        ),
      );
    } catch (e) {
      setErr(toolError(e, ranRemote));
    } finally {
      setBusy(false);
    }
  };

  const stateColor = (s: string) =>
    s === "open"
      ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
      : s === "closed"
        ? "bg-destructive/15 text-destructive"
        : "bg-amber-500/15 text-amber-600 dark:text-amber-400";

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <label className={labelCls}>Host</label>
          <input
            className={cn(inputCls, "font-mono")}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="IP or hostname"
            onKeyDown={(e) => e.key === "Enter" && run()}
            autoFocus
          />
        </div>
        <div>
          <label className={labelCls}>Port</label>
          <input
            className={cn(inputCls, "font-mono")}
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="443"
            onKeyDown={(e) => e.key === "Enter" && run()}
          />
        </div>
      </div>
      <div>
        <label className={labelCls}>Protocol</label>
        <div className="flex gap-2">
          {(["tcp", "udp"] as const).map((p) => (
            <label
              key={p}
              className={cn(
                "flex cursor-pointer items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm",
                protocol === p
                  ? "border-primary bg-primary/5"
                  : "border-border hover:bg-muted/40",
              )}
            >
              <input
                type="radio"
                name="port-proto"
                checked={protocol === p}
                onChange={() => setProtocol(p)}
              />
              {p.toUpperCase()}
            </label>
          ))}
        </div>
      </div>
      {err && <ErrorBanner msg={err} />}
      <RunButton busy={busy} onClick={run} label="port" />
      {res && (
        <div className="space-y-2 rounded-md border bg-card p-3 text-sm">
          {res.ran_from && (
            <div>
              <RanFrom value={res.ran_from} />
            </div>
          )}
          <div className="flex items-center gap-2">
            <span className="font-mono">
              {res.host}:{res.port}/{res.protocol}
            </span>
            <span
              className={cn(
                "rounded px-1.5 py-0.5 text-xs font-semibold",
                stateColor(res.state),
              )}
            >
              {res.state}
            </span>
            {res.rtt_ms !== null && (
              <span className="text-xs text-muted-foreground">
                {res.rtt_ms.toFixed(1)} ms
              </span>
            )}
          </div>
          {res.error && (
            <p className="text-xs text-muted-foreground">{res.error}</p>
          )}
        </div>
      )}
    </div>
  );
}

// ── TLS cert ──────────────────────────────────────────────────────────

function TlsCertTool({ target }: { target?: NetToolTarget }) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [serverName, setServerName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<NetToolTlsCertResult | null>(null);

  const ranRemote = target?.kind === "appliance";

  const run = async () => {
    const p = Number(port);
    if (!host.trim()) {
      setErr("Host is required");
      return;
    }
    if (!Number.isInteger(p) || p < 1 || p > 65535) {
      setErr("Port must be 1–65535");
      return;
    }
    setErr(null);
    setRes(null);
    setBusy(true);
    try {
      setRes(
        await networkToolsApi.tlsCert(
          {
            host: host.trim(),
            port: p,
            server_name: serverName.trim() || null,
          },
          target,
        ),
      );
    } catch (e) {
      setErr(toolError(e, ranRemote));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <label className={labelCls}>Host</label>
          <input
            className={cn(inputCls, "font-mono")}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="example.com"
            onKeyDown={(e) => e.key === "Enter" && run()}
            autoFocus
          />
        </div>
        <div>
          <label className={labelCls}>Port</label>
          <input
            className={cn(inputCls, "font-mono")}
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
      </div>
      <div>
        <label className={labelCls}>SNI override (optional)</label>
        <input
          className={cn(inputCls, "font-mono")}
          value={serverName}
          onChange={(e) => setServerName(e.target.value)}
          placeholder="Defaults to host"
        />
      </div>
      {err && <ErrorBanner msg={err} />}
      <RunButton busy={busy} onClick={run} label="cert" />
      {res && (
        <div className="space-y-2">
          <RanFrom value={res.ran_from} />
          <TlsCertCard res={res} />
        </div>
      )}
    </div>
  );
}

function TlsCertCard({ res }: { res: NetToolTlsCertResult }) {
  if (!res.ok) {
    return <ErrorBanner msg={res.error || "TLS inspection failed"} />;
  }
  const chip = (label: string, ok: boolean) => (
    <span
      className={cn(
        "rounded px-1.5 py-0.5 text-xs font-semibold",
        ok
          ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
          : "bg-destructive/15 text-destructive",
      )}
    >
      {label}
    </span>
  );
  const days = res.days_remaining;
  return (
    <div className="space-y-2 rounded-md border bg-card p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        {chip(res.expired ? "expired" : "valid", !res.expired)}
        {res.hostname_matches !== null &&
          chip(
            res.hostname_matches ? "hostname ok" : "hostname mismatch",
            res.hostname_matches,
          )}
        {res.self_signed && (
          <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-xs font-semibold text-amber-600 dark:text-amber-400">
            self-signed
          </span>
        )}
        {days !== null && (
          <span
            className={cn(
              "rounded px-1.5 py-0.5 text-xs font-medium",
              days < 0
                ? "bg-destructive/15 text-destructive"
                : days < 30
                  ? "bg-amber-500/15 text-amber-600 dark:text-amber-400"
                  : "bg-muted text-muted-foreground",
            )}
          >
            {days < 0 ? `expired ${-days}d ago` : `${days}d remaining`}
          </span>
        )}
      </div>
      <dl className="grid grid-cols-1 gap-x-4 gap-y-1 text-xs sm:grid-cols-[8rem_1fr]">
        <Field label="Subject" value={res.subject} mono />
        <Field label="Issuer" value={res.issuer} mono />
        <Field label="Not before" value={res.not_before} />
        <Field label="Not after" value={res.not_after} />
        <Field label="Serial" value={res.serial} mono />
        <Field label="Sig alg" value={res.signature_algorithm} />
        <Field
          label="SAN"
          value={res.san.length ? res.san.join(", ") : "(none)"}
          mono
        />
      </dl>
    </div>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string | null;
  mono?: boolean;
}) {
  return (
    <>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={cn("break-all", mono && "font-mono")}>{value ?? "—"}</dd>
    </>
  );
}

// ── DNS propagation ───────────────────────────────────────────────────

function PropagationTool() {
  const [name, setName] = useState("");
  const [recordType, setRecordType] = useState("A");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<PropagationCheckResult | null>(null);

  const run = async () => {
    if (!name.trim()) {
      setErr("Name is required");
      return;
    }
    setErr(null);
    setBusy(true);
    try {
      setRes(
        await networkToolsApi.dnsPropagation({
          name: name.trim(),
          record_type: recordType,
        }),
      );
    } catch (e) {
      setErr(apiError(e));
    } finally {
      setBusy(false);
    }
  };

  const statusColor = (s: string) =>
    s === "ok"
      ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
      : s === "nxdomain"
        ? "bg-amber-500/15 text-amber-600 dark:text-amber-400"
        : "bg-destructive/15 text-destructive";

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
        <div className="sm:col-span-2">
          <label className={labelCls}>Name</label>
          <input
            className={cn(inputCls, "font-mono")}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="example.com"
            onKeyDown={(e) => e.key === "Enter" && run()}
            autoFocus
          />
        </div>
        <div>
          <label className={labelCls}>Type</label>
          <select
            className={inputCls}
            value={recordType}
            onChange={(e) => setRecordType(e.target.value)}
          >
            {RECORD_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      </div>
      {err && <ErrorBanner msg={err} />}
      <RunButton busy={busy} onClick={run} label="propagation" />
      {res && (
        <div className="space-y-2">
          {res.results.map((r) => (
            <div
              key={r.resolver}
              className="flex items-start gap-2 rounded-md border bg-card p-2 text-xs"
            >
              <span
                className={cn(
                  "mt-0.5 rounded px-1.5 py-0.5 font-semibold",
                  statusColor(r.status),
                )}
              >
                {r.status}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{r.name ?? r.resolver}</span>
                  <span className="font-mono text-muted-foreground">
                    {r.resolver}
                  </span>
                  {r.rtt_ms !== null && (
                    <span className="text-muted-foreground">
                      {r.rtt_ms.toFixed(0)} ms
                    </span>
                  )}
                </div>
                {r.answers.length > 0 && (
                  <pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[11px] text-muted-foreground">
                    {r.answers.join("\n")}
                  </pre>
                )}
                {r.error && (
                  <p className="mt-1 text-muted-foreground">{r.error}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── MAC vendor ────────────────────────────────────────────────────────

function MacVendorTool() {
  const [raw, setRaw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<NetToolMacVendorResult | null>(null);

  const run = async () => {
    const macs = raw
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (!macs.length) {
      setErr("Enter at least one MAC address");
      return;
    }
    setErr(null);
    setBusy(true);
    try {
      setRes(await networkToolsApi.macVendor(macs));
    } catch (e) {
      setErr(apiError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div>
        <label className={labelCls}>MAC addresses</label>
        <textarea
          className={cn(inputCls, "min-h-[5rem] font-mono")}
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          placeholder="One per line or comma-separated — e.g. 00:11:22:33:44:55"
        />
      </div>
      {err && <ErrorBanner msg={err} />}
      <RunButton busy={busy} onClick={run} label="lookup" />
      {res && (
        <div className="space-y-2">
          {!res.oui_enabled && (
            <p className="rounded-md border border-amber-500/40 bg-amber-500/5 p-2 text-xs text-amber-700 dark:text-amber-400">
              OUI lookup is disabled. Enable it under Settings → IPAM → OUI
              vendor lookup to resolve vendor names.
            </p>
          )}
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b text-left text-muted-foreground">
                <th className="py-1 font-medium">MAC</th>
                <th className="py-1 font-medium">Vendor</th>
              </tr>
            </thead>
            <tbody>
              {res.entries.map((e, i) => (
                <tr key={`${e.mac}-${i}`} className="border-b last:border-0">
                  <td className="py-1 font-mono">{e.mac}</td>
                  <td className="py-1">
                    {e.vendor ?? (
                      <span className="text-muted-foreground">— unknown —</span>
                    )}
                    {e.is_voip_phone && (
                      <span className="ml-2 rounded bg-sky-500/15 px-1 text-[10px] font-semibold text-sky-600 dark:text-sky-400">
                        VoIP
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── wake-on-lan ───────────────────────────────────────────────────────

function WolTool({ target }: { target?: NetToolTarget }) {
  const [mac, setMac] = useState("");
  const [broadcast, setBroadcast] = useState("");
  const [port, setPort] = useState("9");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<NetToolWolResult | null>(null);

  const ranRemote = target?.kind === "appliance";

  const run = async () => {
    if (!mac.trim()) {
      setErr("MAC address is required");
      return;
    }
    setErr(null);
    setRes(null);
    setBusy(true);
    try {
      setRes(
        await networkToolsApi.wol(
          {
            mac: mac.trim(),
            broadcast: broadcast.trim() || null,
            port: Number(port) || 9,
          },
          target,
        ),
      );
    } catch (e) {
      setErr(toolError(e, ranRemote));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      <div>
        <label className={labelCls}>MAC address</label>
        <input
          className={cn(inputCls, "font-mono")}
          value={mac}
          onChange={(e) => setMac(e.target.value)}
          placeholder="e.g. aa:bb:cc:dd:ee:ff"
        />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={labelCls}>Broadcast (optional)</label>
          <input
            className={cn(inputCls, "font-mono")}
            value={broadcast}
            onChange={(e) => setBroadcast(e.target.value)}
            placeholder="255.255.255.255"
          />
        </div>
        <div>
          <label className={labelCls}>Port</label>
          <input
            className={cn(inputCls, "font-mono")}
            type="number"
            min={1}
            max={65535}
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
      </div>
      <p className="text-[11px] text-muted-foreground">
        Wake-on-LAN only reaches a host on the segment the packet is broadcast
        to — use an appliance vantage on the target's subnet for remote wakes.
        Leave the broadcast blank to hit the local segment.
      </p>
      {err && <ErrorBanner msg={err} />}
      <RunButton busy={busy} onClick={run} label="wake" />
      {res && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/5 p-2 text-xs text-emerald-700 dark:text-emerald-400">
          <Power className="h-3.5 w-3.5" />
          Magic packet sent to <span className="font-mono">
            {res.mac}
          </span> via <span className="font-mono">{res.broadcast}</span>:
          {res.port}
          <RanFrom value={res.ran_from} />
        </div>
      )}
    </div>
  );
}

// ── run button ────────────────────────────────────────────────────────

function RunButton({
  busy,
  onClick,
  label,
}: {
  busy: boolean;
  onClick: () => void;
  label: string;
}) {
  return (
    <div className="flex justify-end">
      <HeaderButton variant="primary" onClick={onClick} disabled={busy}>
        {busy ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Search className="h-3.5 w-3.5" />
        )}
        Run {label}
      </HeaderButton>
    </div>
  );
}
