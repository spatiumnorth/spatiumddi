import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Pencil, Plus, Trash2 } from "lucide-react";

import {
  asnsApi,
  formatApiError,
  type BGPCommunity,
  type BGPCommunityCreate,
  type BGPCommunityKind,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { cn } from "@/lib/utils";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const REGULAR_RE = /^\d+:\d+$/;
const LARGE_RE = /^\d+:\d+:\d+$/;

const STANDARD_NAMES = new Set([
  "no-export",
  "no-advertise",
  "no-export-subconfed",
  "local-as",
  "graceful-shutdown",
  "blackhole",
  "accept-own",
]);

function validateValue(kind: BGPCommunityKind, value: string): string | null {
  const v = value.trim();
  if (!v) return "Value is required";
  if (kind === "standard") {
    if (!STANDARD_NAMES.has(v)) {
      return "Pick a value from the standard catalog";
    }
  } else if (kind === "regular") {
    if (!REGULAR_RE.test(v)) return "Format must be ASN:N (e.g. 65000:100)";
  } else if (kind === "large") {
    if (!LARGE_RE.test(v)) return "Format must be ASN:N:M (e.g. 65000:100:200)";
  }
  return null;
}

const KIND_LABEL: Record<BGPCommunityKind, string> = {
  standard: "Standard (RFC 1997 / 7611 / 7999)",
  regular: "Regular (ASN:N · RFC 1997)",
  large: "Large (ASN:N:M · RFC 8092)",
};

const KIND_BADGE: Record<BGPCommunityKind, string> = {
  standard: "bg-violet-500/15 text-violet-700 dark:text-violet-400",
  regular: "bg-sky-500/15 text-sky-700 dark:text-sky-400",
  large: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
};

// ── Form modal ──────────────────────────────────────────────────────

function CommunityFormModal({
  asnId,
  existing,
  presetValue,
  presetKind,
  onClose,
}: {
  asnId: string;
  existing: BGPCommunity | null;
  presetValue?: string;
  presetKind?: BGPCommunityKind;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [kind, setKind] = useState<BGPCommunityKind>(
    existing?.kind ?? presetKind ?? "regular",
  );
  const [value, setValue] = useState(existing?.value ?? presetValue ?? "");
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [inboundAction, setInboundAction] = useState(
    existing?.inbound_action ?? "",
  );
  const [outboundAction, setOutboundAction] = useState(
    existing?.outbound_action ?? "",
  );
  const [error, setError] = useState<string | null>(null);

  const valueError = validateValue(kind, value);

  const mut = useMutation({
    mutationFn: async () => {
      if (valueError) throw new Error(valueError);
      const body: BGPCommunityCreate = {
        value: value.trim(),
        kind,
        name,
        description,
        inbound_action: inboundAction,
        outbound_action: outboundAction,
      };
      if (existing) {
        return asnsApi.updateCommunity(existing.id, {
          name,
          description,
          inbound_action: inboundAction,
          outbound_action: outboundAction,
        });
      }
      return asnsApi.createCommunity(asnId, body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asn-communities", asnId] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  // ``kind`` and ``value`` are immutable on existing rows — the wire
  // value is the natural key, and the API enforces this server-side too.
  const isEdit = !!existing;

  return (
    <Modal
      title={isEdit ? `Edit community ${existing.value}` : "Add BGP community"}
      onClose={onClose}
      wide
    >
      <div className="space-y-3">
        {!isEdit && (
          <>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">
                Kind
              </label>
              <div className="flex flex-col gap-1">
                {(["standard", "regular", "large"] as BGPCommunityKind[]).map(
                  (k) => (
                    <label
                      key={k}
                      className="flex items-start gap-2 rounded border p-2 text-sm hover:bg-accent cursor-pointer"
                    >
                      <input
                        type="radio"
                        name="kind"
                        value={k}
                        checked={kind === k}
                        onChange={() => {
                          setKind(k);
                          // Clear the value when flipping kinds — the
                          // format constraint changes.
                          setValue(presetKind === k ? (presetValue ?? "") : "");
                        }}
                        className="mt-0.5"
                      />
                      <span>{KIND_LABEL[k]}</span>
                    </label>
                  ),
                )}
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">
                Value
              </label>
              {kind === "standard" ? (
                <select
                  className={inputCls}
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                >
                  <option value="">— Select a standard —</option>
                  {Array.from(STANDARD_NAMES).map((n) => (
                    <option key={n} value={n}>
                      {n}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  className={cn(
                    inputCls,
                    valueError && value && "border-destructive",
                  )}
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder={
                    kind === "regular" ? "65000:100" : "65000:100:200"
                  }
                />
              )}
              {valueError && value && (
                <p className="text-[11px] text-destructive">{valueError}</p>
              )}
            </div>
          </>
        )}
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Name (operator-friendly label)
          </label>
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. RTBH"
          />
        </div>
        <div className="space-y-1">
          <label className="text-xs font-medium text-muted-foreground">
            Description
          </label>
          <textarea
            className={cn(inputCls, "min-h-[60px]")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What this community does, who applies it"
          />
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Inbound action
            </label>
            <input
              className={inputCls}
              value={inboundAction}
              onChange={(e) => setInboundAction(e.target.value)}
              placeholder="e.g. accept · localpref+100"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-muted-foreground">
              Outbound action
            </label>
            <input
              className={inputCls}
              value={outboundAction}
              onChange={(e) => setOutboundAction(e.target.value)}
              placeholder="e.g. prepend 2x · reject"
            />
          </div>
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
            disabled={(!isEdit && !!valueError) || mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : isEdit ? "Save" : "Add"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Main tab component ───────────────────────────────────────────────

export function CommunitiesTab({ asnId }: { asnId: string }) {
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
  const { data: communities = [] } = useQuery({
    queryKey: ["asn-communities", asnId],
    queryFn: () => asnsApi.listCommunities(asnId),
  });
  const { data: standard = [] } = useQuery({
    queryKey: ["bgp-communities-standard"],
    queryFn: () => asnsApi.listStandardCommunities(),
    staleTime: 60 * 60_000,
  });

  const [showStandard, setShowStandard] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [editing, setEditing] = useState<BGPCommunity | null>(null);
  const [presetValue, setPresetValue] = useState<string | undefined>(undefined);
  const [presetKind, setPresetKind] = useState<BGPCommunityKind | undefined>(
    undefined,
  );

  const deleteMut = useMutation({
    mutationFn: (id: string) => asnsApi.deleteCommunity(id),
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ["asn-communities", asnId] }),
  });

  // Group existing per-AS rows by kind for the operator-list table.
  const byKind = useMemo(() => {
    const out: Record<BGPCommunityKind, BGPCommunity[]> = {
      standard: [],
      regular: [],
      large: [],
    };
    for (const c of communities) out[c.kind].push(c);
    return out;
  }, [communities]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Operator-defined community values for this AS plus a copy of the
          well-known catalog. The catalog rows are read-only — use the "Use on
          this AS" button to attach one to this row with operator notes.
        </p>
        <button
          type="button"
          onClick={() => {
            setEditing(null);
            setPresetValue(undefined);
            setPresetKind(undefined);
            setShowAdd(true);
          }}
          className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          {...writeGate}
        >
          <Plus className="h-4 w-4" />
          Add Community
        </button>
      </div>

      {/* Standard catalog (collapsible). */}
      <div className="rounded-lg border">
        <button
          type="button"
          onClick={() => setShowStandard((s) => !s)}
          className="flex w-full items-center gap-2 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:bg-muted/40"
        >
          {showStandard ? (
            <ChevronDown className="h-3 w-3" />
          ) : (
            <ChevronRight className="h-3 w-3" />
          )}
          Standard catalog (RFC 1997 / 7611 / 7999) · {standard.length}
        </button>
        {showStandard && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card shadow-[inset_0_-1px_0] shadow-border">
              <tr className="border-y">
                <th className="px-3 py-1.5 text-left font-medium">Value</th>
                <th className="px-3 py-1.5 text-left font-medium">Name</th>
                <th className="px-3 py-1.5 text-left font-medium">
                  Description
                </th>
                <th className="px-3 py-1.5 text-right font-medium" />
              </tr>
            </thead>
            <tbody>
              {standard.map((c) => (
                <tr key={c.id} className="border-b last:border-b-0">
                  <td className="px-3 py-2 font-mono text-[11px]">{c.value}</td>
                  <td className="px-3 py-2 font-medium">{c.name}</td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {c.description}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => {
                        setEditing(null);
                        setPresetValue(c.value);
                        setPresetKind("standard");
                        setShowAdd(true);
                      }}
                      className="rounded border px-2 py-0.5 text-[11px] hover:bg-accent disabled:opacity-50"
                      title="Add a copy of this community to this ASN with your own notes"
                      {...writeGate}
                    >
                      Use on this AS
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Per-ASN communities. */}
      {communities.length === 0 ? (
        <p className="rounded-lg border p-8 text-center text-sm text-muted-foreground">
          No communities defined for this ASN yet.
        </p>
      ) : (
        <div className="rounded-lg border">
          <table className="w-full text-xs">
            <thead className="sticky top-0 z-10 bg-card shadow-[inset_0_-1px_0] shadow-border">
              <tr className="border-b">
                <th className="px-3 py-2 text-left font-medium">Kind</th>
                <th className="px-3 py-2 text-left font-medium">Value</th>
                <th className="px-3 py-2 text-left font-medium">Name</th>
                <th className="px-3 py-2 text-left font-medium">Inbound</th>
                <th className="px-3 py-2 text-left font-medium">Outbound</th>
                <th className="px-3 py-2 text-left font-medium">Description</th>
                <th className="px-3 py-2 text-right font-medium" />
              </tr>
            </thead>
            <tbody>
              {(["standard", "regular", "large"] as BGPCommunityKind[]).flatMap(
                (k) =>
                  byKind[k].map((c) => (
                    <tr key={c.id} className="border-b last:border-b-0">
                      <td className="px-3 py-2">
                        <span
                          className={cn(
                            "inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide",
                            KIND_BADGE[c.kind],
                          )}
                        >
                          {c.kind}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-[11px]">
                        {c.value}
                      </td>
                      <td className="px-3 py-2 font-medium">{c.name || "—"}</td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {c.inbound_action || "—"}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {c.outbound_action || "—"}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground max-w-xs truncate">
                        {c.description || "—"}
                      </td>
                      <td className="px-3 py-2 text-right">
                        <div className="flex justify-end gap-1">
                          <button
                            type="button"
                            onClick={() => {
                              setEditing(c);
                              setShowAdd(true);
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
                              if (
                                confirm(
                                  `Delete community "${c.value}"? This cannot be undone.`,
                                )
                              ) {
                                deleteMut.mutate(c.id);
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
                  )),
              )}
            </tbody>
          </table>
        </div>
      )}

      {showAdd && (
        <CommunityFormModal
          asnId={asnId}
          existing={editing}
          presetValue={presetValue}
          presetKind={presetKind}
          onClose={() => {
            setShowAdd(false);
            setEditing(null);
            setPresetValue(undefined);
            setPresetKind(undefined);
          }}
        />
      )}
    </div>
  );
}
