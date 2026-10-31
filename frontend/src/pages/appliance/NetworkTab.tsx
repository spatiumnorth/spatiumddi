import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Clock,
  Globe,
  Network,
  RefreshCw,
  Server,
  TerminalSquare,
} from "lucide-react";

import {
  applianceApprovalApi,
  applianceSystemApi,
  authApi,
  formatApiError,
  settingsApi,
  type MetalLBBgpPeer,
  type MetalLBConfig,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ListReadError } from "@/components/ui/list-read-error";
import { usePermissions } from "@/hooks/usePermissions";
import { isRefused, pollUnlessRefused } from "@/lib/refusal";

/**
 * Phase 4f — Network & Host info (read-mostly MVP).
 *
 * Today: hostname + detected host IPs + uptime + reboot-pending +
 * appliance version, all read-only. The maintenance toggle and
 * reboot button live on the Maintenance tab.
 *
 * Deferred (post-4g): hostname rename, DHCP/static IP switch,
 * nftables firewall editor, SSH key upload. Those need additional
 * host-side machinery (each writes a different /etc/... file the
 * api can't reach without a privileged writer service).
 */
export function NetworkTab() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["appliance", "system", "info"],
    queryFn: applianceSystemApi.info,
    refetchInterval: pollUnlessRefused(15_000),
  });

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold">
            <Network className="h-4 w-4 text-muted-foreground" />
            Network &amp; Host
          </h2>
          <p className="mt-1 text-xs text-muted-foreground">
            The host&apos;s hostname, addresses, uptime and version, with the
            settings that belong to it below. The host firewall has its own tab,
            and SSH keys theirs.
          </p>
        </div>
        <button
          type="button"
          onClick={() =>
            qc.invalidateQueries({
              queryKey: ["appliance", "system", "info"],
            })
          }
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-accent"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {formatApiError(error)}
        </div>
      )}

      {data?.reboot_pending_from_host && <RebootBanner />}

      <section className="rounded-lg border bg-card shadow-sm">
        <div className="grid grid-cols-1 divide-y sm:grid-cols-2 sm:divide-x sm:divide-y-0">
          <InfoCell
            icon={Server}
            label="Hostname"
            value={isLoading ? "…" : data?.hostname || "—"}
          />
          <InfoCell
            icon={Globe}
            label="Host IPs"
            value={
              isLoading
                ? "…"
                : data?.host_ips && data.host_ips.length > 0
                  ? data.host_ips.join(", ")
                  : "(none detected)"
            }
          />
          <InfoCell
            icon={Clock}
            label="Uptime"
            value={isLoading ? "…" : formatUptime(data?.uptime_seconds)}
          />
          <InfoCell
            icon={Server}
            label="Appliance version"
            value={isLoading ? "…" : data?.appliance_version || "unknown"}
          />
        </div>
      </section>

      <MetalLBConfigCard />
      <VerboseBootCard />
    </div>
  );
}

// Console-mode selector (#393). Picks what the appliance's physical / serial
// console shows: the Talos dashboard, verbose boot output then the dashboard,
// or a plain text login. Backed by platform_settings.console_mode, which the
// supervisor maps to the grubenv `spatium_verbose` value the grub.cfg
// menuentries read — so it applies on the NEXT reboot. Appliance hosts only
// (this tab is already selfOnly).
const CONSOLE_MODES: {
  value: "dashboard" | "verbose_dashboard" | "text_console";
  label: string;
  desc: string;
}[] = [
  {
    value: "dashboard",
    label: "Dashboard (default)",
    desc: "Quiet boot, then the SpatiumDDI console dashboard on screen.",
  },
  {
    value: "verbose_dashboard",
    label: "Verbose boot, then dashboard",
    desc: "Kernel + systemd [ OK ] lines scroll during boot, then the dashboard takes over the console.",
  },
  {
    value: "text_console",
    label: "Plain text console",
    desc: "Verbose boot + a standard Linux login prompt, no dashboard. Best for diagnosing boot hangs or working at the console directly.",
  },
];

function VerboseBootCard() {
  const qc = useQueryClient();
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: authApi.me,
    staleTime: 60_000,
  });
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: settingsApi.get,
  });
  const isSuperadmin = me?.is_superadmin ?? false;
  const mode = settings?.console_mode ?? "dashboard";
  const save = useMutation({
    mutationFn: (v: "dashboard" | "verbose_dashboard" | "text_console") =>
      settingsApi.update({ console_mode: v }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  return (
    <section className="space-y-3 rounded-lg border bg-card p-4 shadow-sm">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-medium">
          <TerminalSquare className="h-4 w-4 text-muted-foreground" />
          Boot console
        </h3>
        <p className="mt-1 text-xs text-muted-foreground">
          What the appliance&apos;s physical / serial console shows. Takes
          effect on the <strong>next reboot</strong>.
        </p>
      </div>
      <div className="space-y-2">
        {CONSOLE_MODES.map((opt) => {
          const active = mode === opt.value;
          return (
            <button
              key={opt.value}
              type="button"
              role="radio"
              aria-checked={active}
              disabled={!isSuperadmin || save.isPending || !settings}
              onClick={() => save.mutate(opt.value)}
              className={cn(
                "flex w-full items-start gap-3 rounded-md border p-2.5 text-left transition-colors disabled:opacity-50",
                active
                  ? "border-primary bg-primary/5"
                  : "border-border hover:bg-muted/50",
              )}
            >
              <span
                className={cn(
                  "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border",
                  active ? "border-primary" : "border-muted-foreground/40",
                )}
              >
                {active && <span className="h-2 w-2 rounded-full bg-primary" />}
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-medium">{opt.label}</span>
                <span className="block text-xs text-muted-foreground">
                  {opt.desc}
                </span>
              </span>
            </button>
          );
        })}
      </div>
      {save.isError && (
        <p className="text-xs text-destructive">{formatApiError(save.error)}</p>
      )}
      {save.isSuccess && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1.5 text-xs text-amber-700 dark:text-amber-400">
          Saved — applies on the next reboot. Reboot the appliance (Maintenance
          tab) to switch the console now.
        </p>
      )}
      {!isSuperadmin && (
        <p className="text-xs text-muted-foreground">
          Changing the boot console is restricted to superadmins.
        </p>
      )}
    </section>
  );
}

// #272 — shown after a VIP add/change. Setting (or changing) the
// control-plane VIP adds it to the API cert's SAN list, so the appliance
// regenerates the self-signed cert and rolls the frontend nginx pod
// (Recreate strategy → :443 briefly closes). That breaks the open TLS
// session exactly like a promote does, so the operator needs the same
// "wait, then reload" guidance. Polls the MetalLB status so it can say
// when the VIP is actually claimed.
function VipChangeNoticeModal({
  vip,
  onClose,
}: {
  vip: string;
  onClose: () => void;
}) {
  // Shares the ["appliance","metallb"] cache with the card; a tighter
  // interval here gives snappier feedback while the modal is open. retry
  // rides out the brief API outage during the cert roll.
  const { data, error } = useQuery({
    queryKey: ["appliance", "metallb"],
    queryFn: applianceApprovalApi.getMetalLBConfig,
    refetchInterval: 3000,
    retry: true,
  });

  const speakersTotal = data?.speakers_total ?? 0;
  const speakersReady = data?.speakers_ready ?? 0;
  const ready =
    !!data?.enabled &&
    (data?.controller_ready ?? false) &&
    speakersTotal > 0 &&
    speakersReady === speakersTotal &&
    data?.control_plane_vip === vip;

  return (
    <Modal title="Control-plane VIP saved" onClose={onClose}>
      <div className="space-y-4 text-sm">
        <p className="text-muted-foreground">
          The VIP <span className="font-mono">{vip}</span> is being applied. The
          seed supervisor picks it up on its next heartbeat (~60 s) and floats
          the frontend on the VIP. The API certificate regenerates to add the
          VIP, so this page may briefly show a connection error — that’s
          expected.
        </p>

        <div className="flex items-center gap-2">
          <span
            className={cn(
              "h-2 w-2 rounded-full",
              ready ? "bg-emerald-500" : "animate-pulse bg-amber-500",
            )}
          />
          <span className="text-xs text-muted-foreground">
            MetalLB:{" "}
            {ready
              ? `VIP active (${speakersReady}/${speakersTotal} speakers ready)`
              : "converging…"}
          </span>
        </div>

        {error && !ready && (
          <p className="text-xs text-amber-600 dark:text-amber-400">
            API briefly unreachable — expected while the certificate
            regenerates. Reconnecting…
          </p>
        )}

        {ready && (
          <p className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-emerald-700 dark:text-emerald-300">
            VIP active. Reload the page — ideally pointing your browser at the
            VIP (<span className="font-mono">{vip}</span>) so you’re no longer
            pinned to a single node.
          </p>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            className="rounded-md border px-3 py-1.5 text-sm"
            onClick={onClose}
          >
            Dismiss
          </button>
          <button
            type="button"
            className={cn(
              "rounded-md border px-3 py-1.5 text-sm",
              ready && "border-emerald-500/50 bg-emerald-500/10 font-medium",
            )}
            onClick={() => window.location.reload()}
          >
            Reload now
          </button>
        </div>
      </div>
    </Modal>
  );
}

// #272 Phase 7c — cluster-wide MetalLB pool + control-plane VIP picker.
// Host-network config, so it lives here on Network & Host (moved off the
// Fleet tab where it sat awkwardly between the two appliance tables).
// The operator sets an L2 address pool + a floating VIP; the seed
// supervisor picks the saved config up on its next heartbeat (~60 s) and
// patches the HelmCharts so the frontend Service floats on the VIP.
function MetalLBConfigCard() {
  const qc = useQueryClient();
  // #3105 — both the read and the save of the MetalLB settings take admin on
  // appliance AND a superadmin; a Viewer is not offered a form over a read it
  // would be refused, and the read is not made for it at all.
  const { isSuperadmin, isLoading: permsLoading } = usePermissions();
  const { data, isLoading, error } = useQuery({
    queryKey: ["appliance", "metallb"],
    queryFn: applianceApprovalApi.getMetalLBConfig,
    staleTime: 30_000,
    enabled: isSuperadmin,
    // Poll so the live status (controller / speaker readiness, VIP
    // claim) updates as MetalLB pods schedule after a save. #3106 — a
    // refusal is not asked again: it does not heal, and every one is a
    // denied audit row.
    refetchInterval: pollUnlessRefused(10_000),
  });

  const [enabled, setEnabled] = useState(false);
  const [poolText, setPoolText] = useState("");
  const [vip, setVip] = useState("");
  // #272 Phase 10 — data-plane resolver VIPs (optional; live in Advanced).
  const [dnsVip, setDnsVip] = useState("");
  const [dhcpRelayVip, setDhcpRelayVip] = useState("");
  const [dirty, setDirty] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  // issue #566 decision D1 — BGP mode (export path). Repeatable peer
  // rows; bgp_advertisements is auto-derived server-side so the form
  // only manages peers.
  const [bgpEnabled, setBgpEnabled] = useState(false);
  const [bgpPeers, setBgpPeers] = useState<MetalLBBgpPeer[]>([]);
  const [showBgp, setShowBgp] = useState(false);

  // Seed the form from the server once it loads (and re-seed after a
  // save) — but never clobber in-progress operator edits.
  useEffect(() => {
    if (data && !dirty) {
      setEnabled(data.enabled);
      const pool = data.pool_addresses ?? [];
      setPoolText(pool.join("\n"));
      setVip(data.control_plane_vip ?? "");
      setDnsVip(data.dns_vip ?? "");
      setDhcpRelayVip(data.dhcp_relay_vip ?? "");
      setBgpEnabled(data.bgp_enabled ?? false);
      setBgpPeers(data.bgp_peers ?? []);
      // Auto-reveal the Advanced pool field when the saved pool is a
      // real range (not just the auto-derived <vip>/32) so editing an
      // existing custom pool isn't hidden behind the disclosure. A
      // data-plane VIP also lives in Advanced, so reveal for those too.
      const autoPool = data.control_plane_vip
        ? [`${data.control_plane_vip}/32`, `${data.control_plane_vip}/128`]
        : [];
      const isCustom =
        pool.length > 1 || (pool.length === 1 && !autoPool.includes(pool[0]));
      if (isCustom || data.dns_vip || data.dhcp_relay_vip)
        setShowAdvanced(true);
      if (data.bgp_enabled || (data.bgp_peers ?? []).length > 0)
        setShowBgp(true);
    }
  }, [data, dirty]);

  // #272 — when a save adds/changes the VIP the cert regenerates and the
  // page disconnects. Capture the pre-save VIP so onSuccess can tell a
  // cert-affecting change from a pool-only / no-op save and pop the
  // reload notice only when it's actually warranted.
  const prevVipRef = useRef<string>("");
  const [vipNotice, setVipNotice] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (body: MetalLBConfig) =>
      applianceApprovalApi.setMetalLBConfig(body),
    onSuccess: (saved) => {
      qc.setQueryData(["appliance", "metallb"], saved);
      setDirty(false);
      const newVip = (saved.control_plane_vip ?? "").trim();
      // A new SAN is only added when the VIP is enabled, non-empty, and
      // different from what was saved before. Clearing a VIP removes a SAN
      // the existing cert already covers (superset) → no regen, no reload.
      if (saved.enabled && newVip && newVip !== prevVipRef.current) {
        setVipNotice(newVip);
      }
    },
  });

  const poolAddresses = poolText
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);

  const onSave = () => {
    prevVipRef.current = (data?.control_plane_vip ?? "").trim();
    save.mutate({
      enabled,
      // When the operator hasn't opened Advanced, send an empty pool —
      // the backend auto-derives a <vip>/32 (or /128) pool. A custom
      // range is only sent when Advanced is open.
      pool_addresses: showAdvanced ? poolAddresses : [],
      control_plane_vip: vip.trim(),
      // Data-plane VIPs are sent unconditionally (no auto-derive); the
      // seeded value carries through even if Advanced is collapsed, so a
      // pool-only edit can't silently drop a configured resolver VIP.
      dns_vip: dnsVip.trim(),
      dhcp_relay_vip: dhcpRelayVip.trim(),
      // issue #566 decision D1 — BGP mode. Sent unconditionally (same
      // "no auto-derive" treatment as the data-plane VIPs above) —
      // bgp_advertisements is auto-derived server-side, so the form
      // never needs an advertisements sub-editor for v1.
      bgp_enabled: bgpEnabled,
      bgp_peers: bgpPeers,
    });
  };

  // Live status descriptor (best-effort fields from the GET).
  const speakersTotal = data?.speakers_total ?? 0;
  const speakersReady = data?.speakers_ready ?? 0;
  const controllerReady = data?.controller_ready ?? false;
  const allReady =
    controllerReady && speakersTotal > 0 && speakersReady === speakersTotal;
  const statusTone = !data?.enabled ? "zinc" : allReady ? "emerald" : "amber";

  if (!isSuperadmin || isRefused(error)) {
    return (
      <section className="rounded-lg border bg-card p-4 shadow-sm">
        <h3 className="text-sm font-semibold">Control-plane VIP (MetalLB)</h3>
        <p className="mt-2 text-xs text-muted-foreground">
          {permsLoading ? (
            "Loading…"
          ) : isRefused(error) ? (
            <ListReadError error={error} what="the MetalLB settings" />
          ) : (
            "Viewing or changing the control-plane VIP is restricted to superadmins."
          )}
        </p>
      </section>
    );
  }

  return (
    <>
      {vipNotice && (
        <VipChangeNoticeModal
          vip={vipNotice}
          onClose={() => setVipNotice(null)}
        />
      )}
      <section className="rounded-lg border bg-card p-4 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span
              className={cn(
                "inline-block h-2 w-2 rounded-full",
                statusTone === "emerald" && "bg-emerald-500",
                statusTone === "amber" && "bg-amber-500",
                statusTone === "zinc" && "bg-zinc-400",
              )}
            />
            <h3 className="text-sm font-semibold">
              Control-plane VIP (MetalLB)
            </h3>
            {data?.enabled && data.control_plane_vip && (
              <span className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                {data.control_plane_vip}
              </span>
            )}
          </div>
        </div>
        <p className="mt-2 text-xs text-muted-foreground">
          A single floating IP that fronts the Web UI so it stays reachable on
          one address regardless of which control-plane node is up (multi-node
          HA). Just enter the VIP — a matching <code>/32</code> pool is created
          for you. Applied across the cluster by the seed within ~60&nbsp;s; the
          served certificate auto-adds the VIP to its SANs. Open{" "}
          <strong>Advanced</strong> to widen the pool and add data-plane
          resolver VIPs (DNS&nbsp;:53 / DHCP relay&nbsp;:67).
        </p>

        {/* Live status — only meaningful once enabled. */}
        {data?.enabled && (
          <div
            className={cn(
              "mt-3 rounded-md border p-2.5 text-xs",
              statusTone === "emerald" &&
                "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
              statusTone === "amber" &&
                "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-400",
            )}
          >
            {allReady ? (
              <>
                <strong>Active</strong> — VIP{" "}
                <span className="font-mono">{data.control_plane_vip}</span> is
                served by MetalLB (controller ready, {speakersReady}/
                {speakersTotal} speakers ready).
              </>
            ) : (
              <>
                <strong>Starting…</strong> controller{" "}
                {controllerReady ? "ready" : "not ready"}, speakers{" "}
                {speakersReady}/{speakersTotal} ready. The seed applies changes
                within ~60&nbsp;s; MetalLB pods then schedule and claim the VIP.
              </>
            )}
          </div>
        )}

        {isLoading ? (
          <p className="mt-3 text-sm text-muted-foreground">Loading…</p>
        ) : (
          <div className="mt-3 flex flex-col gap-3">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => {
                  setEnabled(e.target.checked);
                  setDirty(true);
                }}
              />
              Enable MetalLB + control-plane VIP
            </label>
            <div className="flex flex-col gap-1">
              <span className="text-xs font-medium text-muted-foreground">
                Control-plane VIP
              </span>
              <input
                value={vip}
                onChange={(e) => {
                  setVip(e.target.value);
                  setDirty(true);
                }}
                placeholder="192.168.0.240"
                className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
              />
            </div>

            {/* Advanced — explicit address pool. Hidden by default; the
              VIP alone is enough (backend auto-derives a /32). */}
            <div className="flex flex-col gap-1">
              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                className="self-start text-xs text-muted-foreground underline decoration-dotted underline-offset-2 hover:text-foreground"
              >
                {showAdvanced ? "▾" : "▸"} Advanced — custom address pool
              </button>
              {showAdvanced && (
                <div className="flex flex-col gap-3">
                  <div className="flex flex-col gap-1">
                    <textarea
                      value={poolText}
                      onChange={(e) => {
                        setPoolText(e.target.value);
                        setDirty(true);
                      }}
                      rows={2}
                      placeholder={
                        "192.168.0.240/29\n192.168.0.240-192.168.0.247"
                      }
                      className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
                    />
                    <span className="text-[11px] text-muted-foreground">
                      One CIDR or range per line. Leave blank to auto-create a{" "}
                      <code>/32</code> from the VIP. Provide a range only for
                      headroom, data-plane VIPs, or BGP. Every VIP must fall
                      inside the pool.
                    </span>
                  </div>

                  {/* #272 Phase 10 — data-plane resolver VIPs. Optional;
                    need a pool wide enough to hold them alongside the
                    control-plane VIP. Empty = the hostNetwork data plane. */}
                  <div className="flex flex-col gap-1">
                    <span className="text-xs font-medium text-muted-foreground">
                      DNS resolver VIP (:53) — optional
                    </span>
                    <input
                      value={dnsVip}
                      onChange={(e) => {
                        setDnsVip(e.target.value);
                        setDirty(true);
                      }}
                      placeholder="192.168.0.241"
                      className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
                    />
                    <span className="text-[11px] text-muted-foreground">
                      One floating IP for BIND9 / PowerDNS / Technitium so
                      clients use a single resolver address that follows
                      whichever node is up (the resolver Pods drop{" "}
                      <code>hostNetwork</code> behind an L2 LoadBalancer). Must
                      differ from the control-plane VIP.
                    </span>
                  </div>
                  <div className="flex flex-col gap-1">
                    <span className="text-xs font-medium text-muted-foreground">
                      DHCP relay VIP (:67) — optional
                    </span>
                    <input
                      value={dhcpRelayVip}
                      onChange={(e) => {
                        setDhcpRelayVip(e.target.value);
                        setDirty(true);
                      }}
                      placeholder="192.168.0.242"
                      className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
                    />
                    <span className="text-[11px] text-muted-foreground">
                      Stabilises a DHCP relay's <code>forward-to</code> target
                      so it outlives a single Kea node. Every DHCP server group
                      it fronts must use <strong>relay</strong> client
                      reachability: in direct mode, relays landing on the node
                      that announces the VIP get no answer. A group that also
                      serves directly attached clients needs direct mode, so
                      point its relays at each node's own address instead.
                    </span>
                    {(data?.dhcp_relay_vip_direct_groups ?? []).length > 0 && (
                      <div
                        role="alert"
                        className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
                      >
                        In direct mode behind this VIP:{" "}
                        <span className="font-medium break-all">
                          {(data?.dhcp_relay_vip_direct_groups ?? []).join(
                            ", ",
                          )}
                        </span>
                        . Relays whose traffic lands on the node announcing the
                        VIP get no answer from these groups, and no packet
                        counter shows it. Set each group's client reachability
                        to relay under DHCP → Server groups, or clear this VIP.
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* issue #566 decision D1 — BGP mode. Export path: advertise
              the VIP to upstream routers over BGP. Layered on top of the
              same MetalLB install; hidden by default like Advanced. */}
            <div className="flex flex-col gap-1">
              <button
                type="button"
                onClick={() => setShowBgp((v) => !v)}
                className="self-start text-xs text-muted-foreground underline decoration-dotted underline-offset-2 hover:text-foreground"
              >
                {showBgp ? "▾" : "▸"} BGP mode — advertise to upstream routers
              </button>
              {showBgp && (
                <div className="flex flex-col gap-3">
                  <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs font-medium text-amber-800 dark:text-amber-300">
                    BGP mode activates FRRouting (GPL v2) inside the cluster via
                    MetalLB's frr-k8s backend — a distinct component from the
                    Apache-2.0 MetalLB images already running. See NOTICE.
                  </div>
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={bgpEnabled}
                      onChange={(e) => {
                        setBgpEnabled(e.target.checked);
                        setDirty(true);
                      }}
                    />
                    Enable BGP — advertise the VIP pool to upstream routers
                  </label>
                  <div className="flex flex-col gap-2">
                    {bgpPeers.map((peer, i) => (
                      <div
                        key={i}
                        className="grid grid-cols-1 gap-2 rounded-md border p-2 sm:grid-cols-[2fr_1fr_1fr_auto]"
                      >
                        <div className="flex flex-col gap-1">
                          <span className="text-[11px] text-muted-foreground">
                            Peer address
                          </span>
                          <input
                            value={peer.peer_address}
                            onChange={(e) => {
                              const next = [...bgpPeers];
                              next[i] = {
                                ...peer,
                                peer_address: e.target.value,
                              };
                              setBgpPeers(next);
                              setDirty(true);
                            }}
                            placeholder="203.0.113.1"
                            className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
                          />
                        </div>
                        <div className="flex flex-col gap-1">
                          <span className="text-[11px] text-muted-foreground">
                            Peer ASN
                          </span>
                          <input
                            value={peer.peer_asn}
                            onChange={(e) => {
                              const next = [...bgpPeers];
                              next[i] = {
                                ...peer,
                                peer_asn: Number(e.target.value) || 0,
                              };
                              setBgpPeers(next);
                              setDirty(true);
                            }}
                            placeholder="65001"
                            className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
                          />
                        </div>
                        <div className="flex flex-col gap-1">
                          <span className="text-[11px] text-muted-foreground">
                            My ASN
                          </span>
                          <input
                            value={peer.my_asn}
                            onChange={(e) => {
                              const next = [...bgpPeers];
                              next[i] = {
                                ...peer,
                                my_asn: Number(e.target.value) || 0,
                              };
                              setBgpPeers(next);
                              setDirty(true);
                            }}
                            placeholder="65000"
                            className="w-full rounded-md border bg-background px-2 py-1 font-mono text-xs"
                          />
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            setBgpPeers(bgpPeers.filter((_, j) => j !== i));
                            setDirty(true);
                          }}
                          className="self-end rounded-md border px-2 py-1 text-xs text-muted-foreground hover:text-destructive"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                    <button
                      type="button"
                      onClick={() => {
                        const last = bgpPeers[bgpPeers.length - 1];
                        const nextPeer: MetalLBBgpPeer = {
                          my_asn: last?.my_asn ?? 0,
                          peer_asn: 0,
                          peer_address: "",
                        };
                        setBgpPeers([...bgpPeers, nextPeer]);
                        setDirty(true);
                      }}
                      className="self-start rounded-md border px-2 py-1 text-xs hover:bg-muted"
                    >
                      + Add peer
                    </button>
                    <span className="text-[11px] text-muted-foreground">
                      One BGPPeer session per row. The advertised pool defaults
                      to the control-plane VIP (widen the Advanced pool above
                      for more). <strong>Firewall</strong>: the frr-k8s BGP
                      session listens on tcp/179 on every control-plane node —
                      open tcp/179 on your upstream router / any path-transiting
                      firewall for this peer.
                    </span>
                  </div>
                </div>
              )}
            </div>

            {save.isError && (
              <p className="text-xs text-rose-600">
                {formatApiError(save.error)}
              </p>
            )}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={onSave}
                disabled={!dirty || save.isPending}
                className="rounded-md border bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
              >
                {save.isPending ? "Saving…" : "Save"}
              </button>
              {save.isSuccess && !dirty && (
                <span className="text-xs text-emerald-600">✓ Saved</span>
              )}
            </div>
          </div>
        )}
      </section>
    </>
  );
}

function InfoCell({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Server;
  label: string;
  value: string;
}) {
  return (
    <div className="flex items-start gap-2.5 p-4">
      <Icon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
      <div className="min-w-0 flex-1">
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground/80">
          {label}
        </div>
        <div className="mt-0.5 truncate font-mono text-sm">{value}</div>
      </div>
    </div>
  );
}

function RebootBanner() {
  return (
    <div className="flex items-start gap-2 rounded-md border border-amber-500/50 bg-amber-500/10 p-3 text-xs">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
      <div className="text-amber-700 dark:text-amber-400">
        <strong>Reboot pending.</strong> An unattended-upgrades run installed a
        kernel or libc update that requires a reboot. Schedule one from the
        Maintenance tab when convenient.
      </div>
    </div>
  );
}

function formatUptime(seconds: number | null | undefined): string {
  if (!seconds || seconds < 0) return "—";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}
