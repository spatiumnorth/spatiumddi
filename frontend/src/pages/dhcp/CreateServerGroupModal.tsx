import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { dhcpApi, type DHCPServerGroup } from "@/lib/api";
import { Modal, Field, Btns, inputCls, errMsg } from "./_shared";

export function CreateServerGroupModal({
  group,
  onClose,
}: {
  group?: DHCPServerGroup;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!group;
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const [mode, setMode] = useState(group?.mode ?? "standalone");
  const [heartbeat, setHeartbeat] = useState(
    String(group?.heartbeat_delay_ms ?? 10000),
  );
  const [maxResponse, setMaxResponse] = useState(
    String(group?.max_response_delay_ms ?? 60000),
  );
  const [maxAck, setMaxAck] = useState(
    String(group?.max_ack_delay_ms ?? 10000),
  );
  const [maxUnacked, setMaxUnacked] = useState(
    String(group?.max_unacked_clients ?? 5),
  );
  const [autoFailover, setAutoFailover] = useState(
    group?.auto_failover ?? true,
  );
  const [socketMode, setSocketMode] = useState<"direct" | "relay">(
    group?.dhcp_socket_mode ?? "direct",
  );
  // #637 — Kea lease cache. Empty string in the max-age box means "uncapped",
  // which the API models as null.
  const [leaseCacheThreshold, setLeaseCacheThreshold] = useState(
    String(group?.lease_cache_threshold ?? 0),
  );
  const [leaseCacheMaxAge, setLeaseCacheMaxAge] = useState(
    group?.lease_cache_max_age != null ? String(group.lease_cache_max_age) : "",
  );
  // #980 — Kea packet-path tuning. `?? 1` / `?? true` rather than a falsy
  // fallback: 0 is a real pool size (Kea's auto) and false is a real logging
  // choice, so `||` would silently rewrite either back to the default when
  // editing a group that had opted out.
  const [threadPoolSize, setThreadPoolSize] = useState(
    String(group?.kea_thread_pool_size ?? 1),
  );
  const [packetLogging, setPacketLogging] = useState(
    group?.kea_packet_logging ?? true,
  );
  const [error, setError] = useState("");

  const isHA = mode === "hot-standby" || mode === "load-balancing";

  const mut = useMutation({
    mutationFn: () => {
      // #637 — validate client-side so an out-of-range threshold surfaces as an
      // inline message instead of a raw 422, matching CreateScopeModal's handling
      // of the same field. Blank threshold falls back to 0 (caching disabled);
      // blank max-age means uncapped, which the API models as null.
      const parsedCacheThreshold =
        leaseCacheThreshold.trim() === "" ? 0 : parseFloat(leaseCacheThreshold);
      const parsedCacheMaxAge =
        leaseCacheMaxAge.trim() === "" ? null : parseInt(leaseCacheMaxAge, 10);

      if (
        Number.isNaN(parsedCacheThreshold) ||
        parsedCacheThreshold < 0 ||
        parsedCacheThreshold > 1
      ) {
        throw new Error("Lease cache threshold must be between 0 and 1.");
      }
      if (
        parsedCacheMaxAge !== null &&
        (Number.isNaN(parsedCacheMaxAge) || parsedCacheMaxAge < 1)
      ) {
        throw new Error("Lease cache max age must be at least 1 second.");
      }

      // #980 — blank means the default (1), not 0: 0 is "let Kea auto-size",
      // which is the behaviour this setting exists to replace, and clearing a
      // box should not opt you into it.
      const parsedPool =
        threadPoolSize.trim() === "" ? 1 : parseInt(threadPoolSize, 10);
      if (Number.isNaN(parsedPool) || parsedPool < 0 || parsedPool > 64) {
        throw new Error(
          "Packet worker threads must be between 0 and 64 (0 = let Kea decide).",
        );
      }

      const data = {
        name,
        description,
        mode: mode as "standalone" | "hot-standby" | "load-balancing",
        dhcp_socket_mode: socketMode,
        heartbeat_delay_ms: parseInt(heartbeat, 10) || 10000,
        max_response_delay_ms: parseInt(maxResponse, 10) || 60000,
        max_ack_delay_ms: parseInt(maxAck, 10) || 10000,
        max_unacked_clients: parseInt(maxUnacked, 10) || 5,
        auto_failover: autoFailover,
        lease_cache_threshold: parsedCacheThreshold,
        lease_cache_max_age: parsedCacheMaxAge,
        kea_thread_pool_size: parsedPool,
        kea_packet_logging: packetLogging,
      };
      return editing
        ? dhcpApi.updateGroup(group!.id, data)
        : dhcpApi.createGroup(data);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-groups"] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save group")),
  });

  return (
    <Modal
      title={editing ? "Edit Server Group" : "New DHCP Server Group"}
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
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
        <Field
          label="Mode"
          hint="How servers in this group coordinate. HA modes render the Kea libdhcp_ha.so hook when the group has 2 Kea members. HA covers DHCPv4 only: each member serves DHCPv6 scopes on its own."
        >
          <select
            className={inputCls}
            value={mode}
            onChange={(e) => setMode(e.target.value)}
          >
            <option value="standalone">Standalone</option>
            <option value="hot-standby">
              Hot Standby (one active, one passive)
            </option>
            <option value="load-balancing">Load Balancing (both active)</option>
          </select>
        </Field>

        <Field
          label="Client reachability"
          hint="How Kea receives client traffic. Directly attached uses raw sockets, so Kea hears broadcast DISCOVERs from clients on the same LAN (and also serves relayed clients) — the right choice for an all-in-one / on-LAN server. Relay-only uses UDP sockets; pick it only when every client reaches Kea through a DHCP relay, or the host can't grant raw-socket capability."
        >
          <select
            className={inputCls}
            value={socketMode}
            onChange={(e) =>
              setSocketMode(e.target.value as "direct" | "relay")
            }
          >
            <option value="direct">
              Directly attached / mixed (raw sockets) — recommended
            </option>
            <option value="relay">Relay-only (UDP sockets)</option>
          </select>
        </Field>

        <div className="rounded-md border bg-muted/20 p-3 space-y-3">
          <p className="text-xs font-semibold text-muted-foreground">
            Lease cache
          </p>
          <p className="text-xs text-muted-foreground">
            Kea 3.0 can hand a returning client its existing lease without
            writing to the lease database. That cuts disk churn, but SpatiumDDI
            derives lease events from those writes — so a non-zero threshold
            means fewer DDNS updates and staler IPAM “last seen” timestamps for
            chatty clients. Leave it at 0 unless you need the write reduction.
            Individual scopes can override this.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Field
              label="Cache threshold"
              hint="Fraction of the lease lifetime (0–1). 0 disables caching — every renewal writes through, matching pre-3.0 behaviour. 0.25 is Kea's own default: a client renewing with more than 75% of its lease left is handed the same lease with no database write."
            >
              <input
                className={inputCls}
                type="number"
                min="0"
                max="1"
                step="0.05"
                value={leaseCacheThreshold}
                onChange={(e) => setLeaseCacheThreshold(e.target.value)}
              />
            </Field>
            <Field
              label="Cache max age (sec)"
              hint="Upper bound on how long a cached lease may be reused, regardless of the threshold. Leave blank for no cap (Kea's default)."
            >
              <input
                className={inputCls}
                type="number"
                min="1"
                placeholder="uncapped"
                value={leaseCacheMaxAge}
                onChange={(e) => setLeaseCacheMaxAge(e.target.value)}
              />
            </Field>
          </div>
        </div>

        <div className="rounded-md border bg-muted/20 p-3 space-y-3">
          <p className="text-xs font-semibold text-muted-foreground">
            Packet path (#980)
          </p>
          <p className="text-xs text-muted-foreground">
            When a Kea server is short of CPU it stops draining its receive
            socket fast enough and the kernel discards DHCP packets before Kea
            ever sees them. Kea reports itself perfectly healthy throughout — it
            answers 100% of what it reads — so the only symptom is clients
            taking several retransmit rounds to get an address. Watch{" "}
            <strong>Dropped</strong> on a server&apos;s Stats tab to see whether
            it is happening here.
          </p>
          <div className="grid grid-cols-2 gap-3">
            <Field
              label="Packet worker threads"
              hint="Kea's multi-threading.thread-pool-size. Left to Kea, this is one worker per CPU on the MACHINE, ignoring the share this container actually gets — and those workers then compete with the single thread that has to drain the receive socket. 1 (the default) measured 1.7x–2.9x more packets served than Kea's auto-sizing at every CPU allocation tested. 0 hands sizing back to Kea."
            >
              <input
                className={inputCls}
                type="number"
                min="0"
                max="64"
                step="1"
                value={threadPoolSize}
                onChange={(e) => setThreadPoolSize(e.target.value)}
              />
            </Field>
            <Field
              label="Per-packet logging"
              hint="Kea logs four lines per transaction. Turning this off raises only the two that restate the transaction (DHCP4_PACKET_RECEIVED / _SEND, carrying the source address and receiving interface) to WARN, for roughly 1.3x more packets served on a constrained node. The lines naming the client and the address handed out stay, so the Logs tab keeps one entry per transaction."
            >
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={packetLogging}
                  onChange={(e) => setPacketLogging(e.target.checked)}
                />
                Log every packet received and sent
              </label>
            </Field>
          </div>
        </div>

        {isHA && (
          <div className="rounded-md border bg-muted/20 p-3 space-y-3">
            <p className="text-xs font-semibold text-muted-foreground">
              HA Hook Tuning
            </p>
            <p className="text-[11px] text-muted-foreground">
              Rendered into <code>libdhcp_ha.so</code> on every Kea peer in this
              group. Defaults match Kea&apos;s documented recommendations; only
              tweak if your environment genuinely needs it.
            </p>
            <div className="grid grid-cols-2 gap-3">
              <Field
                label="Heartbeat Delay (ms)"
                hint="How often peers ping each other."
              >
                <input
                  type="number"
                  min={1000}
                  className={inputCls}
                  value={heartbeat}
                  onChange={(e) => setHeartbeat(e.target.value)}
                />
              </Field>
              <Field
                label="Max Response Delay (ms)"
                hint="How long to wait for a heartbeat reply before marking comms interrupted."
              >
                <input
                  type="number"
                  min={1000}
                  className={inputCls}
                  value={maxResponse}
                  onChange={(e) => setMaxResponse(e.target.value)}
                />
              </Field>
              <Field label="Max Ack Delay (ms)">
                <input
                  type="number"
                  min={100}
                  className={inputCls}
                  value={maxAck}
                  onChange={(e) => setMaxAck(e.target.value)}
                />
              </Field>
              <Field
                label="Max Unacked Clients"
                hint="Clients with pending lease-updates before peer is considered down."
              >
                <input
                  type="number"
                  min={0}
                  className={inputCls}
                  value={maxUnacked}
                  onChange={(e) => setMaxUnacked(e.target.value)}
                />
              </Field>
            </div>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={autoFailover}
                onChange={(e) => setAutoFailover(e.target.checked)}
              />
              <span>
                Auto-failover — let peers transition to{" "}
                <code>partner-down</code> without operator approval
              </span>
            </label>
          </div>
        )}

        {error && <p className="text-xs text-destructive">{error}</p>}
        <Btns onClose={onClose} pending={mut.isPending} />
      </form>
    </Modal>
  );
}

export const EditServerGroupModal = CreateServerGroupModal;
