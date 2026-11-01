import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Pencil, Plus, Trash2 } from "lucide-react";

import { dnsApi, formatApiError, type DNSSECPolicy } from "@/lib/api";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import {
  NEEDS_SUPERADMIN,
  permissionGate,
  usePermissions,
} from "@/hooks/usePermissions";
import { cn } from "@/lib/utils";

const ALGORITHMS = [
  "ecdsap256sha256",
  "ecdsap384sha384",
  "ed25519",
  "ed448",
  "rsasha256",
  "rsasha512",
];

const inputCls =
  "w-full rounded-md border bg-background px-2 py-1.5 text-sm focus:outline-none focus:ring-1 focus:ring-ring";

/**
 * DNSSEC policy management (issue #49). A policy maps 1:1 to a BIND9
 * ``dnssec-policy`` block — algorithm, NSEC3 params, KSK/ZSK lifetimes —
 * and is attached to a zone from the zone's DNSSEC card. The built-in
 * "default" policy is read-only.
 */
export function DNSSECPoliciesPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<DNSSECPolicy | null>(null);
  const [creating, setCreating] = useState(false);
  const [toDelete, setToDelete] = useState<DNSSECPolicy | null>(null);

  const policies = useQuery({
    queryKey: ["dns-dnssec-policies"],
    queryFn: () => dnsApi.listDnssecPolicies(),
  });

  const del = useMutation({
    mutationFn: (id: string) => dnsApi.deleteDnssecPolicy(id),
    onSuccess: () => {
      setToDelete(null);
      qc.invalidateQueries({ queryKey: ["dns-dnssec-policies"] });
    },
  });

  const rows = policies.data ?? [];
  // The policy routes take a superadmin whatever the grants (#1879).
  const gate = permissionGate(usePermissions().isSuperadmin, NEEDS_SUPERADMIN);

  return (
    <div className="flex min-w-0 flex-1 flex-col gap-4 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="flex items-center gap-2 text-xl font-semibold">
            <KeyRound className="h-5 w-5 shrink-0" /> DNSSEC Policies
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Reusable BIND9 signing policies (algorithm, NSEC3, KSK/ZSK
            lifetimes). Attach one to a zone from its DNSSEC card; leave a zone
            on <code>default</code> for BIND&rsquo;s built-in policy.
          </p>
        </div>
        <HeaderButton
          variant="primary"
          onClick={() => setCreating(true)}
          {...gate}
        >
          <Plus className="h-4 w-4" /> New policy
        </HeaderButton>
      </div>

      <div className="min-w-0 overflow-x-auto rounded-md border">
        <table className="w-full min-w-[720px] text-sm">
          <thead className="bg-muted/40 text-left text-xs uppercase text-muted-foreground">
            <tr>
              <th className="px-3 py-2">Name</th>
              <th className="px-3 py-2">Algorithm</th>
              <th className="px-3 py-2">NSEC3</th>
              <th className="px-3 py-2">KSK life</th>
              <th className="px-3 py-2">ZSK life</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-8 text-center text-muted-foreground"
                >
                  {policies.isLoading ? "Loading…" : "No policies."}
                </td>
              </tr>
            ) : (
              rows.map((p) => (
                <tr key={p.id} className="border-t hover:bg-muted/20">
                  <td className="px-3 py-2 font-medium">
                    {p.name}
                    {p.is_builtin && (
                      <span className="ml-2 rounded-full bg-muted px-2 py-0.5 text-[10px] text-muted-foreground">
                        built-in
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{p.algorithm}</td>
                  <td className="px-3 py-2">
                    {p.nsec3 ? `iter ${p.nsec3_iterations}` : "—"}
                  </td>
                  <td className="px-3 py-2 tabular-nums">
                    {p.ksk_lifetime_days === 0
                      ? "unlimited"
                      : `${p.ksk_lifetime_days}d`}
                  </td>
                  <td className="px-3 py-2 tabular-nums">
                    {p.zsk_lifetime_days === 0
                      ? "unlimited"
                      : `${p.zsk_lifetime_days}d`}
                  </td>
                  <td className="px-3 py-2 text-right">
                    {!p.is_builtin && (
                      <span className="inline-flex gap-1">
                        <button
                          type="button"
                          onClick={() => setEditing(p)}
                          className="rounded border p-1 hover:bg-accent"
                          title="Edit"
                          aria-label="Edit"
                          {...gate}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => setToDelete(p)}
                          className="rounded border border-destructive/40 p-1 text-destructive hover:bg-destructive/10"
                          title="Delete"
                          aria-label="Delete"
                          {...gate}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {(creating || editing) && (
        <PolicyModal
          existing={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
        />
      )}

      <ConfirmModal
        open={toDelete !== null}
        tone="destructive"
        title="Delete DNSSEC policy?"
        confirmLabel="Delete"
        loading={del.isPending}
        message={
          <>
            Delete <strong>{toDelete?.name}</strong>? Zones using it fall back
            to BIND&rsquo;s built-in <code>default</code> policy on the next
            config sync.
          </>
        }
        onConfirm={() => toDelete && del.mutate(toDelete.id)}
        onClose={() => setToDelete(null)}
      />
    </div>
  );
}

function PolicyModal({
  existing,
  onClose,
}: {
  existing: DNSSECPolicy | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(existing?.name ?? "");
  const [description, setDescription] = useState(existing?.description ?? "");
  const [algorithm, setAlgorithm] = useState(
    existing?.algorithm ?? "ecdsap256sha256",
  );
  const [kskLife, setKskLife] = useState(existing?.ksk_lifetime_days ?? 0);
  const [zskLife, setZskLife] = useState(existing?.zsk_lifetime_days ?? 90);
  const [nsec3, setNsec3] = useState(existing?.nsec3 ?? false);
  const [saltLen, setSaltLen] = useState(existing?.nsec3_salt_length ?? 0);
  const [optout, setOptout] = useState(existing?.nsec3_optout ?? false);
  const [error, setError] = useState<string | null>(null);

  const mut = useMutation({
    mutationFn: () => {
      const body: Partial<DNSSECPolicy> = {
        description,
        algorithm,
        ksk_lifetime_days: kskLife,
        zsk_lifetime_days: zskLife,
        nsec3,
        nsec3_iterations: 0,
        nsec3_salt_length: saltLen,
        nsec3_optout: optout,
      };
      if (existing) return dnsApi.updateDnssecPolicy(existing.id, body);
      return dnsApi.createDnssecPolicy({ ...body, name });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-dnssec-policies"] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(formatApiError(e, "Save failed"));
    },
  });

  return (
    <Modal
      title={existing ? "Edit DNSSEC policy" : "New DNSSEC policy"}
      onClose={onClose}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        {!existing && (
          <label className="block text-xs font-medium text-muted-foreground">
            Name
            <input
              className={cn(inputCls, "mt-1")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. nsec3-ecdsa"
              required
            />
          </label>
        )}
        <label className="block text-xs font-medium text-muted-foreground">
          Description
          <input
            className={cn(inputCls, "mt-1")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </label>
        <label className="block text-xs font-medium text-muted-foreground">
          Algorithm
          <select
            className={cn(inputCls, "mt-1")}
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            {ALGORITHMS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="block text-xs font-medium text-muted-foreground">
            KSK lifetime (days, 0 = unlimited)
            <input
              type="number"
              min={0}
              className={cn(inputCls, "mt-1")}
              value={kskLife}
              onChange={(e) => setKskLife(Number(e.target.value))}
            />
          </label>
          <label className="block text-xs font-medium text-muted-foreground">
            ZSK lifetime (days, 0 = unlimited)
            <input
              type="number"
              min={0}
              className={cn(inputCls, "mt-1")}
              value={zskLife}
              onChange={(e) => setZskLife(Number(e.target.value))}
            />
          </label>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={nsec3}
            onChange={(e) => setNsec3(e.target.checked)}
          />
          NSEC3 (instead of NSEC)
        </label>
        {nsec3 && (
          <div className="grid grid-cols-3 gap-3 pl-6">
            <label className="block text-xs font-medium text-muted-foreground">
              Iterations
              <input
                type="number"
                className={cn(inputCls, "mt-1")}
                value={0}
                readOnly
                disabled
                aria-label="Iterations"
                title="BIND 9.20 only accepts 0 (RFC 9276)"
              />
            </label>
            <label className="block text-xs font-medium text-muted-foreground">
              Salt length
              <input
                type="number"
                min={0}
                max={255}
                className={cn(inputCls, "mt-1")}
                value={saltLen}
                onChange={(e) => setSaltLen(Number(e.target.value))}
              />
            </label>
            <label className="flex items-end gap-2 text-sm">
              <input
                type="checkbox"
                checked={optout}
                onChange={(e) => setOptout(e.target.checked)}
              />
              Opt-out
            </label>
          </div>
        )}
        {nsec3 && (
          <p className="text-[11px] text-muted-foreground">
            Iterations are fixed at 0: BIND 9.20 refuses any other value (RFC
            9276), and a refused policy stops the whole server group&rsquo;s
            config from applying.
          </p>
        )}
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {mut.isPending ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
