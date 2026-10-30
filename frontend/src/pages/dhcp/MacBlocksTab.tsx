import { useMemo, useState } from "react";
import { fromLocalInputValue, toLocalInputValue } from "@/lib/localTime";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";

import {
  dhcpApi,
  type DHCPMACBlock,
  type DHCPMACBlockReason,
  type DHCPMACBlockWrite,
} from "@/lib/api";
import {
  Modal,
  Field,
  Btns,
  inputCls,
  errMsg,
  DeleteConfirmModal,
} from "./_shared";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const REASON_LABELS: Record<DHCPMACBlockReason, string> = {
  rogue: "Rogue device",
  lost_stolen: "Lost / stolen",
  quarantine: "Quarantine",
  policy: "Policy",
  other: "Other",
};

const REASON_COLORS: Record<DHCPMACBlockReason, string> = {
  rogue: "bg-red-500/10 text-red-700 dark:text-red-400",
  lost_stolen: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
  quarantine: "bg-blue-500/10 text-blue-700 dark:text-blue-400",
  policy: "bg-violet-500/10 text-violet-700 dark:text-violet-400",
  other: "bg-muted text-muted-foreground",
};

// New Devices stores the operator's free text as the reason, so the stored
// value can be outside the five codes (#3083): show it as typed.
function isKnownReason(reason: string): reason is DHCPMACBlockReason {
  return Object.prototype.hasOwnProperty.call(REASON_LABELS, reason);
}

function ReasonPill({ reason }: { reason: string }) {
  const known = isKnownReason(reason);
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium ${known ? REASON_COLORS[reason] : REASON_COLORS.other}`}
    >
      {known ? REASON_LABELS[reason] : reason}
    </span>
  );
}

function ExpiresCell({ block }: { block: DHCPMACBlock }) {
  if (!block.expires_at) {
    return <span className="text-muted-foreground">never</span>;
  }
  const expires = new Date(block.expires_at);
  const now = new Date();
  const past = expires <= now;
  return (
    <span
      className={past ? "text-muted-foreground line-through" : ""}
      title={expires.toLocaleString()}
    >
      {expires.toLocaleDateString()}
    </span>
  );
}

function StatusPill({ block }: { block: DHCPMACBlock }) {
  const expired =
    block.expires_at !== null && new Date(block.expires_at) <= new Date();
  if (!block.enabled) {
    return (
      <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
        disabled
      </span>
    );
  }
  if (expired) {
    return (
      <span className="inline-flex rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
        expired
      </span>
    );
  }
  return (
    <span className="inline-flex rounded bg-emerald-500/10 px-1.5 py-0.5 text-[11px] text-emerald-700 dark:text-emerald-400">
      active
    </span>
  );
}

export function MacBlocksTab({ groupId }: { groupId: string }) {
  // #1339, #1861 — writes take write, deletes delete, on ``dhcp_mac_block``.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "dhcp_mac_block"),
    "Requires write permission on DHCP MAC blocks",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "dhcp_mac_block"),
    "Requires delete permission on DHCP MAC blocks",
  );
  const qc = useQueryClient();
  const { data: blocks = [], isFetching } = useQuery({
    queryKey: ["dhcp-mac-blocks", groupId],
    queryFn: () =>
      groupId ? dhcpApi.listMacBlocks(groupId) : Promise.resolve([]),
    enabled: !!groupId,
  });

  const [showCreate, setShowCreate] = useState(false);
  const [edit, setEdit] = useState<DHCPMACBlock | null>(null);
  const [del, setDel] = useState<DHCPMACBlock | null>(null);
  const [filter, setFilter] = useState("");

  const delMut = useMutation({
    mutationFn: (id: string) => dhcpApi.deleteMacBlock(groupId, id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-mac-blocks", groupId] });
      setDel(null);
    },
  });

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return blocks;
    return blocks.filter(
      (b) =>
        b.mac_address.toLowerCase().includes(q) ||
        (b.vendor ?? "").toLowerCase().includes(q) ||
        b.description.toLowerCase().includes(q) ||
        b.ipam_matches.some(
          (m) =>
            m.ip_address.toLowerCase().includes(q) ||
            m.hostname.toLowerCase().includes(q),
        ),
    );
  }, [blocks, filter]);

  if (!groupId) {
    return (
      <p className="p-6 text-center text-sm text-muted-foreground">
        MAC blocks are configured on the server group — attach this server to a
        group first.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <input
          placeholder="Filter by MAC, vendor, IP, hostname…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-80 rounded-md border bg-background px-2 py-1 text-xs"
        />
        <span className="text-xs text-muted-foreground">
          {filtered.length} of {blocks.length}
        </span>
        <button
          onClick={() =>
            qc.invalidateQueries({ queryKey: ["dhcp-mac-blocks", groupId] })
          }
          className="ml-auto flex items-center gap-1 rounded-md border px-2 py-1 text-xs hover:bg-accent"
          disabled={isFetching}
          title="Refresh MAC blocks"
        >
          <RefreshCw
            className={`h-3 w-3 ${isFetching ? "animate-spin" : ""}`}
          />
          Refresh
        </button>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
          {...writeGate}
        >
          <Plus className="h-3 w-3" /> Block MAC
        </button>
      </div>

      <div className="rounded-lg border">
        {filtered.length === 0 ? (
          <p className="p-6 text-center text-sm text-muted-foreground">
            {blocks.length === 0
              ? "No blocked MACs. Click 'Block MAC' to add one."
              : "No blocks match the filter."}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[960px] text-xs">
              <thead>
                <tr className="border-b bg-muted/30">
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Status
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    MAC
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Vendor
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Reason
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Description
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    IPAM
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Expires
                  </th>
                  <th className="whitespace-nowrap px-3 py-2 text-left font-medium">
                    Added
                  </th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((b) => (
                  <tr key={b.id} className="border-b last:border-0">
                    <td className="whitespace-nowrap px-3 py-2">
                      <StatusPill block={b} />
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 font-mono">
                      {b.mac_address}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-muted-foreground">
                      {b.vendor ?? "—"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <ReasonPill reason={b.reason} />
                    </td>
                    <td
                      className="max-w-xs truncate px-3 py-2 text-muted-foreground"
                      title={b.description}
                    >
                      {b.description || "—"}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      {b.ipam_matches.length === 0 ? (
                        <span className="text-muted-foreground">—</span>
                      ) : (
                        <div className="flex flex-col gap-0.5">
                          {b.ipam_matches.map((m, i) => (
                            <span
                              key={i}
                              title={`${m.hostname || m.ip_address} • ${m.subnet_cidr}`}
                              className="font-mono text-[11px]"
                            >
                              {m.ip_address}
                              {m.hostname ? (
                                <span className="text-muted-foreground">
                                  {" "}
                                  ({m.hostname})
                                </span>
                              ) : null}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2">
                      <ExpiresCell block={b} />
                    </td>
                    <td
                      className="whitespace-nowrap px-3 py-2 text-muted-foreground"
                      title={new Date(b.created_at).toLocaleString()}
                    >
                      {new Date(b.created_at).toLocaleDateString()}
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                      <button
                        onClick={() => setEdit(b)}
                        className="rounded p-1 text-muted-foreground hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                        title="Edit"
                        {...writeGate}
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      <button
                        onClick={() => setDel(b)}
                        className="rounded p-1 text-muted-foreground hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
                        title="Delete"
                        {...deleteGate}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showCreate && (
        <MacBlockModal groupId={groupId} onClose={() => setShowCreate(false)} />
      )}
      {edit && (
        <MacBlockModal
          groupId={groupId}
          block={edit}
          onClose={() => setEdit(null)}
        />
      )}
      {del && (
        <DeleteConfirmModal
          title="Unblock MAC"
          description={`Remove the block on ${del.mac_address}? The device will immediately be able to request leases again.`}
          onConfirm={() => delMut.mutate(del.id)}
          onClose={() => setDel(null)}
          isPending={delMut.isPending}
        />
      )}
    </div>
  );
}

function MacBlockModal({
  groupId,
  block,
  onClose,
}: {
  groupId: string;
  block?: DHCPMACBlock;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!block;
  const [mac, setMac] = useState(block?.mac_address ?? "");
  const [reason, setReason] = useState<string>(block?.reason ?? "other");
  const [description, setDescription] = useState(block?.description ?? "");
  const [enabled, setEnabled] = useState(block?.enabled ?? true);
  const [expiresAt, setExpiresAt] = useState(
    toLocalInputValue(block?.expires_at),
  );
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: () => {
      const data: DHCPMACBlockWrite = {
        reason,
        description,
        enabled,
        expires_at: fromLocalInputValue(expiresAt),
      };
      if (!editing) data.mac_address = mac;
      return editing
        ? dhcpApi.updateMacBlock(groupId, block!.id, data)
        : dhcpApi.createMacBlock(groupId, data);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-mac-blocks", groupId] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save MAC block")),
  });

  return (
    <Modal
      title={editing ? "Edit MAC Block" : "Block a MAC Address"}
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        <Field
          label="MAC Address"
          hint={
            editing
              ? "MAC is immutable. Delete and re-create to re-key an entry."
              : "Any common format — aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff, aabbccddeeff."
          }
        >
          <input
            className={`${inputCls} font-mono`}
            value={mac}
            onChange={(e) => setMac(e.target.value)}
            disabled={editing}
            required
          />
        </Field>
        <Field label="Reason">
          <select
            className={inputCls}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          >
            {/* The stored free text stays offered after another reason is
                picked, so the operator can go back to it (#3083). */}
            {block && !isKnownReason(block.reason) && (
              <option value={block.reason}>{block.reason}</option>
            )}
            {Object.entries(REASON_LABELS).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Description">
          <textarea
            className={inputCls}
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <div className="flex gap-4">
          <Field label="Expires">
            <input
              type="datetime-local"
              className={inputCls}
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
            />
          </Field>
          <label className="flex cursor-pointer items-center gap-2 pt-6 text-sm">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>Enabled</span>
          </label>
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <Btns onClose={onClose} pending={mut.isPending} />
      </form>
    </Modal>
  );
}
