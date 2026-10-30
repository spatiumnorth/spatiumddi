import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Pencil, Trash2 } from "lucide-react";

import {
  applianceApprovalApi,
  asnsApi,
  lookingGlassApi,
  networkApi,
  type BGPLGAddressFamily,
  type BGPLGCollector,
  type BGPLGImportFilter,
  type BGPLGPeer,
  type BGPLGPeerCreate,
  type BGPLGPeerUpdate,
  type BGPLGSessionState,
  type MetalLBBgpPeer,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { Field, errMsg, humanDuration, humanTime, inputCls } from "../_shared";
import { PeerDetailModal } from "./PeerDetailModal";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

// Established = green, the transitional FSM states = amber, Idle = rose.
// Exported so PeerDetailModal's header chip reuses the exact same
// mapping instead of a second copy that could drift.
// eslint-disable-next-line react-refresh/only-export-components
export const STATE_COLOR: Partial<Record<BGPLGSessionState, string>> = {
  established: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  active: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  connect: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  opensent: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  openconfirm: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  idle: "bg-rose-500/15 text-rose-700 dark:text-rose-400",
};
export const FALLBACK_STATE_COLOR =
  "bg-zinc-100 text-zinc-700 dark:bg-zinc-500/15 dark:text-zinc-300";

function Pill({ text, cls }: { text: string; cls: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
        cls,
      )}
    >
      {text}
    </span>
  );
}

export function SessionsTab({
  collectors,
  onEdit,
  onViewRoutes,
}: {
  collectors: BGPLGCollector[];
  onEdit: (peer: BGPLGPeer) => void;
  /** Deep-links into the Routes tab, pre-filtered to one peer — passed
   *  through to the peer detail modal's "View all routes" link. */
  onViewRoutes: (peerId: string) => void;
}) {
  const qc = useQueryClient();
  // #3104 — peers sit under the router's 'bgp_lg_peer' gate; a read-only
  // user is offered no write on them.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "bgp_lg_peer"),
    "Requires write permission on BGP peers",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "bgp_lg_peer"),
    "Requires delete permission on BGP peers",
  );
  const [deleteTarget, setDeleteTarget] = useState<BGPLGPeer | null>(null);
  const [viewingPeerId, setViewingPeerId] = useState<string | null>(null);

  // Session-state rows are live telemetry — poll modestly so a flap shows up
  // without the operator hammering Refresh.
  const sessionsQ = useQuery({
    queryKey: ["bgp-lg-sessions"],
    queryFn: () => lookingGlassApi.listSessions(),
    refetchInterval: 15_000,
  });
  // Peers carry the full config (matched_asn_id, collector, description, …)
  // that SessionRead doesn't — needed for the ASN link + the edit/delete
  // actions on each row.
  const peersQ = useQuery({
    queryKey: ["bgp-lg-peers"],
    queryFn: () => lookingGlassApi.listPeers(),
    refetchInterval: 15_000,
  });

  const peersById = useMemo(() => {
    const map = new Map<string, BGPLGPeer>();
    for (const p of peersQ.data ?? []) map.set(p.id, p);
    return map;
  }, [peersQ.data]);

  const sessions = sessionsQ.data ?? [];

  const deleteM = useMutation({
    mutationFn: (id: string) => lookingGlassApi.deletePeer(id),
    onSuccess: () => {
      setDeleteTarget(null);
      void qc.invalidateQueries({ queryKey: ["bgp-lg-sessions"] });
      void qc.invalidateQueries({ queryKey: ["bgp-lg-peers"] });
    },
  });

  if (sessionsQ.isLoading || peersQ.isLoading) {
    return <p className="text-sm text-muted-foreground">Loading sessions…</p>;
  }
  if (sessionsQ.isError) {
    return (
      <p className="text-sm text-destructive">
        {errMsg(sessionsQ.error, "Failed to load BGP sessions.")}
      </p>
    );
  }

  if (collectors.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
        No BGP Looking Glass collector has registered yet. Install and start a
        Looking Glass agent against this control plane, then come back here to
        add a peer.
      </div>
    );
  }

  if (sessions.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
        No peers configured yet — click "Add Peer" above to peer with a router.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b bg-muted/30 text-left text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="px-3 py-2">Peer / router</th>
              <th className="px-3 py-2">Remote ASN</th>
              <th className="px-3 py-2">State</th>
              <th className="px-3 py-2">Uptime</th>
              <th className="px-3 py-2">Prefixes recv / accepted</th>
              <th className="px-3 py-2">Last flap</th>
              <th className="px-3 py-2">RPKI invalid</th>
              <th className="px-3 py-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {sessions.map((s) => {
              const peer = peersById.get(s.peer_id);
              const uptimeSeconds =
                s.session_state === "established" && s.uptime_started_at
                  ? Math.max(
                      0,
                      Math.floor(
                        (Date.now() - new Date(s.uptime_started_at).getTime()) /
                          1000,
                      ),
                    )
                  : null;
              return (
                <tr
                  key={s.peer_id}
                  className="cursor-pointer border-b last:border-0 hover:bg-muted/20"
                  onClick={() => setViewingPeerId(s.peer_id)}
                >
                  <td className="px-3 py-2 align-top">
                    <div className="font-medium">{s.peer_name}</div>
                    <div className="break-all font-mono text-[10px] text-muted-foreground">
                      {s.peer_address}
                    </div>
                    <div className="text-[10px] text-muted-foreground/70">
                      {s.collector_name}
                    </div>
                  </td>
                  <td className="px-3 py-2 align-top font-mono">
                    {peer?.matched_asn_id ? (
                      <Link
                        to={`/network/asns/${peer.matched_asn_id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="hover:text-primary hover:underline"
                      >
                        AS{s.peer_asn}
                      </Link>
                    ) : (
                      `AS${s.peer_asn}`
                    )}
                  </td>
                  <td className="px-3 py-2 align-top">
                    <Pill
                      text={s.session_state}
                      cls={STATE_COLOR[s.session_state] ?? FALLBACK_STATE_COLOR}
                    />
                    {!s.enabled && (
                      <span className="ml-1 text-[10px] text-muted-foreground">
                        (disabled)
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground">
                    {uptimeSeconds != null ? humanDuration(uptimeSeconds) : "—"}
                  </td>
                  <td className="px-3 py-2 align-top tabular-nums">
                    {s.prefixes_received.toLocaleString()} /{" "}
                    {s.prefixes_accepted.toLocaleString()}
                  </td>
                  <td className="px-3 py-2 align-top text-muted-foreground">
                    {humanTime(s.last_flap_at)}
                  </td>
                  <td className="px-3 py-2 align-top tabular-nums">
                    {s.rpki_invalid_count > 0 ? (
                      <span className="font-medium text-rose-600 dark:text-rose-400">
                        {s.rpki_invalid_count}
                      </span>
                    ) : (
                      "0"
                    )}
                  </td>
                  <td
                    className="px-3 py-2 align-top text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {peer && (
                      <div className="flex justify-end gap-1">
                        <button
                          type="button"
                          title="Edit peer"
                          className="rounded p-1 hover:bg-muted"
                          onClick={() => onEdit(peer)}
                          {...writeGate}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          title="Delete peer"
                          className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                          onClick={() => setDeleteTarget(peer)}
                          {...deleteGate}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <ConfirmModal
        open={!!deleteTarget}
        title="Delete peer"
        message={
          deleteTarget
            ? `Delete the BGP session to "${deleteTarget.name}" (AS${deleteTarget.peer_asn} at ${deleteTarget.peer_address})? Its learned routes are removed too. This only tears down the receive-only session on the collector — it does not affect the router on the other end.`
            : ""
        }
        confirmLabel="Delete"
        tone="destructive"
        loading={deleteM.isPending}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && deleteM.mutate(deleteTarget.id)}
      />

      {viewingPeerId && (
        <PeerDetailModal
          peerId={viewingPeerId}
          onClose={() => setViewingPeerId(null)}
          onEdit={(peer) => {
            setViewingPeerId(null);
            onEdit(peer);
          }}
          onDelete={(peer) => {
            setViewingPeerId(null);
            setDeleteTarget(peer);
          }}
          onViewRoutes={(peerId) => {
            setViewingPeerId(null);
            onViewRoutes(peerId);
          }}
        />
      )}
    </div>
  );
}

// ── Add / Edit peer modal ──────────────────────────────────────────────

const AF_OPTIONS: { value: BGPLGAddressFamily; label: string }[] = [
  { value: "ipv4-unicast", label: "IPv4 unicast" },
  { value: "ipv6-unicast", label: "IPv6 unicast" },
  { value: "vpnv4", label: "VPNv4" },
  { value: "vpnv6", label: "VPNv6" },
];

// vpnv4/vpnv6 (issue #566 Phase 6, MP-BGP / RFC 4364) haven't been
// exercised against a live gobgpd VPNv4/VPNv6 session the way plain
// ipv4/ipv6-unicast peering has — flag them as advanced/unverified so an
// operator enabling one for the first time knows what to expect.
const VPN_FAMILIES: BGPLGAddressFamily[] = ["vpnv4", "vpnv6"];

export function PeerFormModal({
  existing,
  collectors,
  onClose,
}: {
  existing: BGPLGPeer | null;
  collectors: BGPLGCollector[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const isEdit = !!existing;

  const [name, setName] = useState(existing?.name ?? "");
  const [collectorId, setCollectorId] = useState(
    existing?.collector_id ?? collectors[0]?.id ?? "",
  );
  const [localAsn, setLocalAsn] = useState(String(existing?.local_asn ?? ""));
  const [peerAsn, setPeerAsn] = useState(String(existing?.peer_asn ?? ""));
  const [peerAddress, setPeerAddress] = useState(existing?.peer_address ?? "");
  const [families, setFamilies] = useState<BGPLGAddressFamily[]>(
    existing?.address_families ?? ["ipv4-unicast"],
  );
  const [md5Password, setMd5Password] = useState("");
  const [clearMd5, setClearMd5] = useState(false);
  const [maxPrefixes, setMaxPrefixes] = useState(
    String(existing?.max_prefixes ?? 10000),
  );
  const [filterMode, setFilterMode] = useState<"accept_all" | "scope">(
    existing?.import_filter.mode ?? "accept_all",
  );
  const [filterPrefixesText, setFilterPrefixesText] = useState(
    (existing?.import_filter.prefixes ?? []).join("\n"),
  );
  const [matchedAsnId, setMatchedAsnId] = useState(
    existing?.matched_asn_id ?? "",
  );
  const [peerRouterId, setPeerRouterId] = useState(
    existing?.peer_router_id ?? "",
  );
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [description, setDescription] = useState(existing?.description ?? "");
  const [err, setErr] = useState<string | null>(null);

  // The collector list can still be loading the first time the modal opens
  // (the header's Add-Peer button only disables once we know for sure it's
  // empty) — default to the first one once it lands, if nothing is picked.
  useEffect(() => {
    if (!collectorId && collectors.length > 0) {
      setCollectorId(collectors[0].id);
    }
  }, [collectors, collectorId]);

  const asnsQ = useQuery({
    queryKey: ["asns-picker"],
    queryFn: () => asnsApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const devicesQ = useQuery({
    queryKey: ["network-devices-picker"],
    queryFn: () => networkApi.listDevices({ page_size: 500 }),
    staleTime: 60_000,
  });

  // issue #566 decision D1 — MetalLB BGP mode ships its own "peer
  // address + ASN" concept (the export path: advertise our VIP to a
  // router); this is a pure UI convenience prefilling THIS form's
  // fields from one, since the same physical router is plausibly both
  // a MetalLB BGP-mode upstream and a Looking Glass (import) peer. Zero
  // backend coupling — same React Query key as NetworkTab so it's
  // already warm if the operator visited Network & Host first. Only on
  // add (never on edit) and never overwrites `name` (MetalLB peers
  // aren't named).
  const metallbQ = useQuery({
    queryKey: ["appliance", "metallb"],
    queryFn: applianceApprovalApi.getMetalLBConfig,
    staleTime: 30_000,
    enabled: !isEdit,
  });
  const metallbBgpPeers = metallbQ.data?.bgp_peers ?? [];

  function prefillFromMetalLB(p: MetalLBBgpPeer) {
    setLocalAsn(String(p.my_asn));
    setPeerAsn(String(p.peer_asn));
    setPeerAddress(p.peer_address);
  }

  function toggleFamily(af: BGPLGAddressFamily) {
    setFamilies((prev) =>
      prev.includes(af) ? prev.filter((f) => f !== af) : [...prev, af],
    );
  }

  function buildImportFilter(): BGPLGImportFilter {
    if (filterMode === "accept_all") return { mode: "accept_all" };
    const prefixes = filterPrefixesText
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    return { mode: "scope", prefixes };
  }

  const createM = useMutation({
    mutationFn: (body: BGPLGPeerCreate) => lookingGlassApi.createPeer(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["bgp-lg-sessions"] });
      void qc.invalidateQueries({ queryKey: ["bgp-lg-peers"] });
      onClose();
    },
    onError: (e) => setErr(errMsg(e, "Failed to create peer.")),
  });

  const updateM = useMutation({
    mutationFn: (body: BGPLGPeerUpdate) =>
      lookingGlassApi.updatePeer(existing!.id, body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["bgp-lg-sessions"] });
      void qc.invalidateQueries({ queryKey: ["bgp-lg-peers"] });
      onClose();
    },
    onError: (e) => setErr(errMsg(e, "Failed to update peer.")),
  });

  const pending = createM.isPending || updateM.isPending;

  function handleSubmit() {
    setErr(null);
    const localAsnNum = Number(localAsn);
    const peerAsnNum = Number(peerAsn);
    if (!name.trim() || !collectorId || !peerAddress.trim()) {
      setErr("Name, collector, and peer address are required.");
      return;
    }
    if (!Number.isFinite(localAsnNum) || !Number.isFinite(peerAsnNum)) {
      setErr("Local ASN and peer ASN must be numbers.");
      return;
    }

    const shared = {
      name: name.trim(),
      collector_id: collectorId,
      local_asn: localAsnNum,
      peer_asn: peerAsnNum,
      peer_address: peerAddress.trim(),
      matched_asn_id: matchedAsnId || null,
      peer_router_id: peerRouterId || null,
      address_families: families,
      // Only default an EMPTY field to 10000. An explicit 0 / invalid value
      // must reach the backend (which rejects max_prefixes < 1 with 422)
      // rather than being silently coerced up to the default cap.
      max_prefixes: maxPrefixes.trim() === "" ? 10000 : Number(maxPrefixes),
      import_filter: buildImportFilter(),
      enabled,
      description,
    };

    if (isEdit) {
      // "" explicitly clears the stored password; omitting (undefined)
      // leaves it untouched; a typed value rotates it.
      const md5_password = clearMd5 ? "" : md5Password || undefined;
      updateM.mutate({ ...shared, md5_password });
    } else {
      createM.mutate({ ...shared, md5_password: md5Password || undefined });
    }
  }

  return (
    <Modal
      title={isEdit ? `Edit peer — ${existing!.name}` : "Add BGP peer"}
      onClose={onClose}
      wide
    >
      <div className="space-y-4">
        <div className="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs font-medium text-amber-800 dark:text-amber-300">
          Receive-only session — SpatiumDDI never advertises routes to your
          network from this session. Every peer is configured as a pure sink:
          import-only, no export policy, no next-hop-self, no redistribution.
        </div>

        {err && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {err}
          </div>
        )}

        {!isEdit && metallbBgpPeers.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span>Prefill from a configured MetalLB BGP peer:</span>
            {metallbBgpPeers.map((p, i) => (
              <button
                key={i}
                type="button"
                onClick={() => prefillFromMetalLB(p)}
                className="rounded-md border px-2 py-1 font-mono hover:bg-muted"
              >
                {p.peer_address} (AS{p.peer_asn})
              </button>
            ))}
          </div>
        )}

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="core-rtr1"
            />
          </Field>
          <Field label="Collector">
            <select
              className={inputCls}
              value={collectorId}
              onChange={(e) => setCollectorId(e.target.value)}
            >
              <option value="" disabled>
                Select a collector…
              </option>
              {collectors.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.status})
                </option>
              ))}
            </select>
          </Field>
          <Field label="Local ASN">
            <input
              className={inputCls}
              type="number"
              value={localAsn}
              onChange={(e) => setLocalAsn(e.target.value)}
              placeholder="65000"
            />
          </Field>
          <Field label="Peer ASN">
            <input
              className={inputCls}
              type="number"
              value={peerAsn}
              onChange={(e) => setPeerAsn(e.target.value)}
              placeholder="65001"
            />
          </Field>
          <Field
            label="Peer address"
            hint="Bare IP — the router's BGP source address"
          >
            <input
              className={inputCls}
              value={peerAddress}
              onChange={(e) => setPeerAddress(e.target.value)}
              placeholder="203.0.113.1"
            />
          </Field>
          <Field
            label="Max prefixes"
            hint="Hard safety cap rendered into the collector's prefix-limit"
          >
            <input
              className={inputCls}
              type="number"
              min={1}
              value={maxPrefixes}
              onChange={(e) => setMaxPrefixes(e.target.value)}
            />
          </Field>
        </div>

        <Field label="Address families">
          <div className="flex flex-wrap gap-4">
            {AF_OPTIONS.map((af) => (
              <label
                key={af.value}
                className="flex items-center gap-1.5 text-sm"
              >
                <input
                  type="checkbox"
                  checked={families.includes(af.value)}
                  onChange={() => toggleFamily(af.value)}
                />
                {af.label}
              </label>
            ))}
          </div>
          {families.some((f) => VPN_FAMILIES.includes(f)) && (
            <p className="mt-1.5 text-xs text-muted-foreground">
              Advanced — VPNv4/VPNv6 (MP-BGP L3VPN) support is new and hasn't
              been verified against a live VPNv4/VPNv6 session yet. Route
              Distinguisher + Route-Target cross-check against VRFs is on the
              Routes tab of each matched VRF once routes start flowing.
            </p>
          )}
        </Field>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field
            label="Matched ASN (optional)"
            hint="Links the remote ASN column to the tracked ASN catalog"
          >
            <select
              className={inputCls}
              value={matchedAsnId}
              onChange={(e) => setMatchedAsnId(e.target.value)}
            >
              <option value="">None</option>
              {(asnsQ.data?.items ?? []).map((a) => (
                <option key={a.id} value={a.id}>
                  AS{a.number} — {a.name}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Peer router device (optional)">
            <select
              className={inputCls}
              value={peerRouterId}
              onChange={(e) => setPeerRouterId(e.target.value)}
            >
              <option value="">None</option>
              {(devicesQ.data?.items ?? []).map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name} ({d.ip_address})
                </option>
              ))}
            </select>
          </Field>
        </div>

        <Field
          label={
            isEdit
              ? `TCP-MD5 password${existing?.md5_password_set ? " (currently set)" : ""}`
              : "TCP-MD5 password (optional)"
          }
        >
          <input
            className={inputCls}
            type="password"
            autoComplete="new-password"
            value={md5Password}
            onChange={(e) => setMd5Password(e.target.value)}
            placeholder={
              isEdit && existing?.md5_password_set
                ? "•••••• (unchanged)"
                : undefined
            }
            disabled={clearMd5}
          />
          {isEdit && existing?.md5_password_set && (
            <label className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={clearMd5}
                onChange={(e) => {
                  setClearMd5(e.target.checked);
                  if (e.target.checked) setMd5Password("");
                }}
              />
              Clear stored password
            </label>
          )}
        </Field>

        <Field label="Import filter">
          <select
            className={inputCls}
            value={filterMode}
            onChange={(e) =>
              setFilterMode(e.target.value as "accept_all" | "scope")
            }
          >
            <option value="accept_all">Accept all routes</option>
            <option value="scope">Scope to specific prefixes</option>
          </select>
          {filterMode === "scope" && (
            <textarea
              className={cn(inputCls, "mt-2 h-20 font-mono text-xs")}
              value={filterPrefixesText}
              onChange={(e) => setFilterPrefixesText(e.target.value)}
              placeholder={"192.0.2.0/24\n198.51.100.0/24"}
            />
          )}
        </Field>

        <Field label="Description">
          <textarea
            className={cn(inputCls, "h-16")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        <label className="flex items-center gap-1.5 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Enabled
        </label>

        <div className="flex justify-end gap-2 border-t pt-3">
          <HeaderButton onClick={onClose}>Cancel</HeaderButton>
          <HeaderButton
            variant="primary"
            onClick={handleSubmit}
            disabled={pending}
          >
            {pending ? "Saving…" : isEdit ? "Save changes" : "Add peer"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}
