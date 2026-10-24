import { ListEmpty } from "@/components/ui/list-read-error";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  multicastApi,
  type MulticastDomainCreate,
  type MulticastDomainRead,
  type MulticastDomainUpdate,
  type MulticastPIMMode,
} from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { HeaderButton } from "@/components/ui/header-button";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const PIM_MODES: {
  value: MulticastPIMMode;
  label: string;
  needsRP: boolean;
}[] = [
  { value: "sparse", label: "Sparse (PIM-SM, RP required)", needsRP: true },
  { value: "ssm", label: "Source-specific (SSM, no RP)", needsRP: false },
  { value: "bidir", label: "Bidir (PIM-BIDIR, RP required)", needsRP: true },
  { value: "dense", label: "Dense (PIM-DM, flooding)", needsRP: false },
  { value: "none", label: "None (manual / static-RP)", needsRP: false },
];

const PIM_MODE_LABEL: Record<string, string> = Object.fromEntries(
  PIM_MODES.map((m) => [m.value, m.label]),
);

function PimBadge({ mode }: { mode: string }) {
  const styles: Record<string, string> = {
    sparse:
      "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400",
    ssm: "bg-sky-100 text-sky-700 dark:bg-sky-950/30 dark:text-sky-400",
    bidir:
      "bg-violet-100 text-violet-700 dark:bg-violet-950/30 dark:text-violet-400",
    dense:
      "bg-amber-100 text-amber-700 dark:bg-amber-950/30 dark:text-amber-400",
    none: "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium uppercase tracking-wider",
        styles[mode] ?? "bg-zinc-200 text-zinc-700",
      )}
    >
      {mode}
    </span>
  );
}

// ── Editor modal ────────────────────────────────────────────────────

function MulticastDomainModal({
  existing,
  onClose,
}: {
  existing: MulticastDomainRead | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [pimMode, setPimMode] = useState<MulticastPIMMode>(
    (existing?.pim_mode as MulticastPIMMode) ?? "sparse",
  );
  const [rpAddress, setRpAddress] = useState(
    existing?.rendezvous_point_address ?? "",
  );
  const [ssmRange, setSsmRange] = useState(existing?.ssm_range ?? "");
  const [notes, setNotes] = useState(existing?.notes ?? "");
  const [error, setError] = useState<string | null>(null);

  const modeSpec = PIM_MODES.find((m) => m.value === pimMode);
  const needsRP = !!modeSpec?.needsRP;

  const mut = useMutation({
    mutationFn: async () => {
      if (!name.trim()) throw new Error("Name is required");
      const body: MulticastDomainCreate | MulticastDomainUpdate = {
        name: name.trim(),
        description,
        pim_mode: pimMode,
        rendezvous_point_address: rpAddress.trim() || null,
        ssm_range: ssmRange.trim() || null,
        notes,
      };
      if (existing) return multicastApi.updateDomain(existing.id, body);
      return multicastApi.createDomain(body as MulticastDomainCreate);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["multicast-domains"] });
      onClose();
    },
    onError: (e: unknown) => {
      const err = e as {
        message?: string;
        response?: { data?: { detail?: string | { msg?: string }[] } };
      };
      const detail = err?.response?.data?.detail;
      if (Array.isArray(detail)) {
        setError(detail.map((d) => d.msg ?? "validation error").join("; "));
      } else {
        setError(detail ?? err?.message ?? "Save failed");
      }
    },
  });

  return (
    <Modal
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "New PIM domain"}
      wide
    >
      <div className="space-y-3">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              Name
            </label>
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Studio-A PIM"
              autoFocus={!existing}
            />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">
              PIM mode
            </label>
            <select
              className={inputCls}
              value={pimMode}
              onChange={(e) => setPimMode(e.target.value as MulticastPIMMode)}
            >
              {PIM_MODES.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Rendezvous-point address{" "}
              {needsRP && <span className="text-destructive">*</span>}
            </label>
            <input
              className={cn(inputCls, "font-mono")}
              value={rpAddress}
              onChange={(e) => setRpAddress(e.target.value)}
              placeholder={
                needsRP ? "Required for sparse / bidir modes" : "Optional"
              }
            />
            {needsRP && (
              <p className="mt-1 text-[10px] text-muted-foreground">
                Sparse and bidir modes route via the RP — set the IP of the
                router(s) operating as the rendezvous point. Multi-RP redundancy
                + device FK lookup come in a follow-up wave.
              </p>
            )}
          </div>
          {pimMode === "ssm" && (
            <div className="sm:col-span-2">
              <label className="text-xs font-medium text-muted-foreground">
                SSM range
              </label>
              <input
                className={cn(inputCls, "font-mono")}
                value={ssmRange}
                onChange={(e) => setSsmRange(e.target.value)}
                placeholder="232.0.0.0/8 (IANA default) or operator-pinned"
              />
            </div>
          )}
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Description
            </label>
            <textarea
              className={cn(inputCls, "min-h-[80px]")}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional free-text description."
            />
          </div>
          <div className="sm:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">
              Notes
            </label>
            <textarea
              className={cn(inputCls, "min-h-[60px]")}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Anything else worth recording."
            />
          </div>
        </div>

        {error && <p className="text-sm text-destructive">{error}</p>}

        <div className="mt-4 flex justify-end gap-2 border-t pt-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={mut.isPending}
            onClick={() => mut.mutate()}
            className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : existing ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ── Tab body ────────────────────────────────────────────────────────
//
// Renders inside the parent ``MulticastGroupsPage`` when the operator
// selects the ``Domains`` tab. The page-level chrome (h1, sidebar
// gating, route) lives one level up; this body owns just the
// per-tab intro text, the action header (Refresh + New), and the
// domain table + modal.

export function MulticastDomainsTab() {
  // #1340 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'multicast'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "multicast"),
    "Requires write permission on multicast domains",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "multicast"),
    "Requires delete permission on multicast domains",
  );
  const qc = useQueryClient();
  const [editing, setEditing] = useState<MulticastDomainRead | null>(null);
  const [showNew, setShowNew] = useState(false);
  const [confirm, setConfirm] = useState<{
    title: string;
    message: string;
    confirmLabel?: string;
    onConfirm: () => void;
  } | null>(null);

  const query = useQuery({
    queryKey: ["multicast-domains"],
    queryFn: () => multicastApi.listDomains(),
  });

  const items = query.data ?? [];

  const removeOne = useMutation({
    mutationFn: (id: string) => multicastApi.deleteDomain(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["multicast-domains"] }),
  });

  return (
    <>
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <p className="min-w-0 flex-1 text-sm text-muted-foreground">
            Network-layer routing context for multicast groups — PIM mode,
            rendezvous point, optional VRF binding. Groups attach to a domain
            via the General tab on each group's editor.
          </p>
          <div className="flex shrink-0 items-center gap-2">
            <HeaderButton
              icon={RefreshCw}
              onClick={() => query.refetch()}
              iconClassName={query.isFetching ? "animate-spin" : undefined}
            >
              Refresh
            </HeaderButton>
            <HeaderButton
              variant="primary"
              icon={Plus}
              onClick={() => setShowNew(true)}
              {...writeGate}
            >
              New domain
            </HeaderButton>
          </div>
        </div>

        <div className="rounded-md border">
          <table className="w-full text-sm">
            <thead className="text-left text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
              <tr className="border-b bg-muted/30">
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Mode</th>
                <th className="px-3 py-2">RP</th>
                <th className="px-3 py-2">SSM range</th>
                <th className="px-3 py-2 tabular-nums">Groups</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody className={zebraBodyCls}>
              {items.length === 0 && (!query.isFetching || query.error) && (
                <tr>
                  <td
                    colSpan={6}
                    className="px-3 py-10 text-center text-sm text-muted-foreground"
                  >
                    <ListEmpty error={query.error} what="PIM domains">
                      No PIM domains yet. Click <strong>New domain</strong> to
                      add the first.
                    </ListEmpty>
                  </td>
                </tr>
              )}
              {items.map((d) => (
                <tr key={d.id} className="border-b hover:bg-muted/30">
                  <td className="px-3 py-1.5">
                    <div className="font-medium">{d.name}</div>
                    {d.description && (
                      <div className="text-[11px] text-muted-foreground">
                        {d.description}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-1.5">
                    <PimBadge mode={d.pim_mode} />
                    <div className="mt-0.5 text-[10px] text-muted-foreground">
                      {PIM_MODE_LABEL[d.pim_mode] ?? d.pim_mode}
                    </div>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[11px] text-muted-foreground">
                    {d.rendezvous_point_address || "—"}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[11px] text-muted-foreground">
                    {d.ssm_range || "—"}
                  </td>
                  <td className="px-3 py-1.5 tabular-nums">{d.group_count}</td>
                  <td className="px-3 py-1.5 text-right">
                    <button
                      type="button"
                      onClick={() => setEditing(d)}
                      title="Edit"
                      className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
                      {...writeGate}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setConfirm({
                          title: "Delete PIM domain",
                          message: `Delete PIM domain "${d.name}"? Member groups stay; their domain_id orphans to NULL.`,
                          confirmLabel: "Delete",
                          onConfirm: () => removeOne.mutate(d.id),
                        });
                      }}
                      title="Delete"
                      className="ml-1 rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive disabled:cursor-not-allowed disabled:opacity-50"
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
      </div>

      {(showNew || editing) && (
        <MulticastDomainModal
          existing={editing}
          onClose={() => {
            setShowNew(false);
            setEditing(null);
          }}
        />
      )}
      <ConfirmModal
        open={confirm !== null}
        title={confirm?.title ?? ""}
        message={confirm?.message ?? ""}
        confirmLabel={confirm?.confirmLabel}
        tone="destructive"
        onConfirm={() => {
          confirm?.onConfirm();
          setConfirm(null);
        }}
        onClose={() => setConfirm(null)}
      />
    </>
  );
}
