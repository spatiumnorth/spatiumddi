import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";

import { asnsApi, type BGPPeering, type BGPRelationshipType } from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { cn } from "@/lib/utils";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const RELATIONSHIPS: BGPRelationshipType[] = [
  "peer",
  "customer",
  "provider",
  "sibling",
];

const RELATIONSHIP_DESC: Record<BGPRelationshipType, string> = {
  peer: "Settlement-free peering — both sides advertise their own + customer routes only.",
  customer:
    "The other AS is a downstream customer — they pay you for transit, you re-advertise their routes upstream.",
  provider:
    "The other AS is your upstream provider — you pay them for transit, they re-advertise your routes globally.",
  sibling:
    "Both ASes are under the same operational ownership (e.g. AS-A + AS-B in the same org).",
};

const RELATIONSHIP_COLOR: Record<BGPRelationshipType, string> = {
  peer: "bg-sky-500/15 text-sky-700 dark:text-sky-400",
  customer: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  provider: "bg-violet-500/15 text-violet-700 dark:text-violet-400",
  sibling: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
};

// From the *peer's* point of view, customer ↔ provider invert; peer
// and sibling are symmetric.
function invertRelationship(r: BGPRelationshipType): BGPRelationshipType {
  if (r === "customer") return "provider";
  if (r === "provider") return "customer";
  return r;
}

function RelationshipBadge({
  relationship,
}: {
  relationship: BGPRelationshipType;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium capitalize",
        RELATIONSHIP_COLOR[relationship],
      )}
    >
      {relationship}
    </span>
  );
}

// ── Form modal ──────────────────────────────────────────────────────

function PeeringFormModal({
  thisAsnId,
  existing,
  onClose,
}: {
  thisAsnId: string;
  existing: BGPPeering | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  // ``thisIsLocal`` decides whether ``thisAsnId`` should be written as
  // ``local_asn_id`` or ``peer_asn_id`` on the row. Default true = the
  // current page's AS originates the peering relationship description
  // (e.g. "this AS has a customer over there"). Operators can flip if
  // the natural framing is the other way around.
  const initialIsLocal = existing ? existing.local_asn_id === thisAsnId : true;
  const initialCounter = existing
    ? initialIsLocal
      ? existing.peer_asn_id
      : existing.local_asn_id
    : "";
  const initialRel = existing
    ? initialIsLocal
      ? existing.relationship_type
      : invertRelationship(existing.relationship_type)
    : ("peer" as BGPRelationshipType);

  const [thisIsLocal, setThisIsLocal] = useState(initialIsLocal);
  const [counterAsnId, setCounterAsnId] = useState<string>(initialCounter);
  const [relationship, setRelationship] =
    useState<BGPRelationshipType>(initialRel);
  const [description, setDescription] = useState(existing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const { data: asnList } = useQuery({
    queryKey: ["asns-picker"],
    queryFn: () => asnsApi.list({ limit: 500 }),
    staleTime: 60_000,
  });
  const counterChoices = (asnList?.items ?? []).filter(
    (a) => a.id !== thisAsnId,
  );

  const mut = useMutation({
    mutationFn: async () => {
      if (!counterAsnId) throw new Error("Select a counterparty ASN");
      // Normalise to the canonical (local, peer, relationship_type)
      // shape the backend stores. When ``thisIsLocal`` is false the
      // operator described the peering from the peer's side, so we
      // flip both endpoints AND invert the relationship type so the
      // stored row still reads "this is what local does to peer".
      const local = thisIsLocal ? thisAsnId : counterAsnId;
      const peer = thisIsLocal ? counterAsnId : thisAsnId;
      const rel = thisIsLocal ? relationship : invertRelationship(relationship);
      if (existing) {
        return asnsApi.updatePeering(existing.id, {
          relationship_type:
            existing.local_asn_id === thisAsnId ? rel : invertRelationship(rel),
          description,
        });
      }
      return asnsApi.createPeering({
        local_asn_id: local,
        peer_asn_id: peer,
        relationship_type: rel,
        description,
      });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asn-peerings", thisAsnId] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        response?: { data?: { detail?: string } };
        message?: string;
      };
      setError(err?.response?.data?.detail ?? err?.message ?? "Save failed");
    },
  });

  const isEdit = !!existing;

  return (
    <Modal
      title={isEdit ? "Edit BGP peering" : "Add BGP peering"}
      onClose={onClose}
      wide
    >
      <div className="space-y-3">
        {/* Counterparty + direction are immutable on edit (they're the
            row's natural key). Only relationship + description can
            change without a delete-and-readd. */}
        {!isEdit && (
          <>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">
                Counterparty ASN
              </label>
              <select
                className={inputCls}
                value={counterAsnId}
                onChange={(e) => setCounterAsnId(e.target.value)}
              >
                <option value="">— Select an ASN —</option>
                {counterChoices.map((a) => (
                  <option key={a.id} value={a.id}>
                    AS{a.number}
                    {a.name ? ` — ${a.name}` : ""}
                    {a.kind === "private" ? " (private)" : ""}
                  </option>
                ))}
              </select>
              {counterChoices.length === 0 && (
                <p className="text-[11px] text-muted-foreground">
                  No other ASNs in the system yet — add the peer's AS first
                  under{" "}
                  <Link to="/network/asns" className="underline">
                    Network → ASNs
                  </Link>
                  .
                </p>
              )}
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">
                Direction
              </label>
              <div className="flex flex-col gap-1">
                <label className="flex items-start gap-2 rounded border p-2 text-sm hover:bg-accent cursor-pointer">
                  <input
                    type="radio"
                    name="direction"
                    checked={thisIsLocal}
                    onChange={() => setThisIsLocal(true)}
                    className="mt-0.5"
                  />
                  <span>
                    Describe from <strong>this AS</strong>'s perspective (this
                    AS is the local side)
                  </span>
                </label>
                <label className="flex items-start gap-2 rounded border p-2 text-sm hover:bg-accent cursor-pointer">
                  <input
                    type="radio"
                    name="direction"
                    checked={!thisIsLocal}
                    onChange={() => setThisIsLocal(false)}
                    className="mt-0.5"
                  />
                  <span>
                    Describe from <strong>their</strong> perspective (the
                    counterparty is the local side)
                  </span>
                </label>
              </div>
            </div>
          </>
        )}
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Relationship
          </label>
          <div className="flex flex-col gap-1">
            {RELATIONSHIPS.map((r) => (
              <label
                key={r}
                className="flex items-start gap-2 rounded border p-2 text-sm hover:bg-accent cursor-pointer"
              >
                <input
                  type="radio"
                  name="relationship"
                  checked={relationship === r}
                  onChange={() => setRelationship(r)}
                  className="mt-0.5"
                />
                <span className="flex-1">
                  <span className="flex items-center gap-2">
                    <RelationshipBadge relationship={r} />
                    <span className="capitalize">{r}</span>
                  </span>
                  <span className="block text-[11px] text-muted-foreground">
                    {RELATIONSHIP_DESC[r]}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Description
          </label>
          <textarea
            className={cn(inputCls, "min-h-[60px]")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Free-form notes — IXP / circuit ID / contract tag…"
          />
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => mut.mutate()}
            disabled={(!isEdit && !counterAsnId) || mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : isEdit ? "Save" : "Add Peering"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Main tab component ───────────────────────────────────────────────

export function PeeringsTab({ asnId }: { asnId: string }) {
  const qc = useQueryClient();
  // #2518 — the router asks write (delete) on 'manage_asns', as the ASN list does.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_asns"),
    "Requires write permission on ASNs",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "manage_asns"),
    "Requires delete permission on ASNs",
  );
  const { data: peerings = [] } = useQuery({
    queryKey: ["asn-peerings", asnId],
    queryFn: () => asnsApi.listPeerings({ asn_id: asnId }),
  });
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<BGPPeering | null>(null);

  const deleteMut = useMutation({
    mutationFn: (id: string) => asnsApi.deletePeering(id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["asn-peerings", asnId] }),
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Operator-curated BGP relationships involving this ASN. Direction shown
          from this AS's perspective: ``→ outbound`` = this AS is the local
          side; ``← inbound`` = the counterparty is.
        </p>
        <button
          type="button"
          onClick={() => {
            setEditing(null);
            setShowForm(true);
          }}
          className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          {...writeGate}
        >
          <Plus className="h-4 w-4" />
          Add Peering
        </button>
      </div>

      {peerings.length === 0 ? (
        <p className="rounded-lg border p-8 text-center text-sm text-muted-foreground">
          No BGP peerings recorded for this ASN.
        </p>
      ) : (
        <div className="rounded-lg border">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card shadow-[inset_0_-1px_0] shadow-border">
              <tr className="border-b">
                <th className="px-3 py-2 text-left font-medium">Direction</th>
                <th className="px-3 py-2 text-left font-medium">
                  Counterparty
                </th>
                <th className="px-3 py-2 text-left font-medium">
                  Relationship
                </th>
                <th className="px-3 py-2 text-left font-medium">Description</th>
                <th className="px-3 py-2 text-right font-medium" />
              </tr>
            </thead>
            <tbody>
              {peerings.map((p) => {
                const isLocal = p.local_asn_id === asnId;
                const counterAs = isLocal
                  ? `AS${p.peer_asn_number}${p.peer_asn_name ? " — " + p.peer_asn_name : ""}`
                  : `AS${p.local_asn_number}${p.local_asn_name ? " — " + p.local_asn_name : ""}`;
                const rel = isLocal
                  ? p.relationship_type
                  : invertRelationship(p.relationship_type);
                return (
                  <tr key={p.id} className="border-b last:border-b-0">
                    <td className="px-3 py-2 text-muted-foreground">
                      {isLocal ? "→ outbound" : "← inbound"}
                    </td>
                    <td className="px-3 py-2 font-mono">
                      <Link
                        to={`/network/asns/${isLocal ? p.peer_asn_id : p.local_asn_id}`}
                        className="hover:text-primary hover:underline"
                      >
                        {counterAs}
                      </Link>
                    </td>
                    <td className="px-3 py-2">
                      <RelationshipBadge relationship={rel} />
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {p.description || "—"}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <div className="flex justify-end gap-1">
                        <button
                          type="button"
                          onClick={() => {
                            setEditing(p);
                            setShowForm(true);
                          }}
                          title="Edit"
                          className="rounded p-1 hover:bg-accent disabled:opacity-50"
                          {...writeGate}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            const counter = isLocal
                              ? `AS${p.peer_asn_number}`
                              : `AS${p.local_asn_number}`;
                            if (
                              confirm(
                                `Delete peering with ${counter} (${rel})? This cannot be undone.`,
                              )
                            ) {
                              deleteMut.mutate(p.id);
                            }
                          }}
                          disabled={deleteMut.isPending}
                          title="Delete"
                          className="rounded p-1 text-red-600 hover:bg-red-50 dark:hover:bg-red-950/30 disabled:opacity-50"
                          {...deleteGate}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {showForm && (
        <PeeringFormModal
          thisAsnId={asnId}
          existing={editing}
          onClose={() => {
            setShowForm(false);
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}
