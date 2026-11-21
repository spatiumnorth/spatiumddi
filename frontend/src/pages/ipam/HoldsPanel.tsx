/**
 * HoldsPanel — CIDRs held for a future project (#4492), shown on the block
 * they sit in. A hold blocks subnet creation, resize, split, merge and
 * allocate-next over its CIDR until it is released or converted to a subnet.
 * An expired hold keeps holding and is flagged; nothing here frees it
 * automatically.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Modal } from "@/components/ui/modal";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { FormError } from "@/components/ui/form-error";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import {
  formatApiError,
  subnetHoldsApi,
  type IPBlock,
  type SubnetHold,
} from "@/lib/api";
import { fromLocalInputValue, toLocalInputValue } from "@/lib/localTime";

const INPUT_CLS =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-60";
const NEEDS_SUBNET_WRITE = "Requires write permission on subnets";

type Dialog =
  | { kind: "create" }
  | { kind: "edit"; hold: SubnetHold }
  | { kind: "convert"; hold: SubnetHold }
  | { kind: "release"; hold: SubnetHold };

function formatExpiry(iso: string | null): string {
  if (!iso) return "No expiry";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function HoldsPanel({ block }: { block: IPBlock }) {
  const perms = usePermissions();
  const canWrite = perms.can("write", "subnet");
  const [dialog, setDialog] = useState<Dialog | null>(null);

  const { data: holds = [] } = useQuery({
    queryKey: ["subnet-holds", block.space_id],
    queryFn: () =>
      subnetHoldsApi.list({ space_id: block.space_id, status: "active" }),
  });
  const mine = holds.filter((h) => h.block_id === block.id);
  // Nothing to show and nothing the caller can add: stay out of the way.
  if (mine.length === 0 && !canWrite) return null;

  return (
    <div className="border-t px-6 py-3" data-testid="holds-panel">
      <div className="mb-2 flex items-center gap-3">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Holds ({mine.length})
        </h3>
        <button
          type="button"
          onClick={() => setDialog({ kind: "create" })}
          className="text-[11px] font-medium text-primary hover:underline disabled:opacity-50"
          {...permissionGate(canWrite, NEEDS_SUBNET_WRITE)}
        >
          + Hold a CIDR
        </button>
      </div>
      {mine.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          No CIDR in this block is held for a future project.
        </p>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-muted-foreground">
              <th className="py-1 pr-3 font-medium">CIDR</th>
              <th className="py-1 pr-3 font-medium">Reason</th>
              <th className="py-1 pr-3 font-medium">Expires</th>
              <th className="py-1 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {mine.map((h) => (
              <tr key={h.id} className="border-t">
                <td className="py-1 pr-3 font-mono">{h.network}</td>
                <td className="py-1 pr-3">{h.reason}</td>
                <td className="py-1 pr-3">
                  {formatExpiry(h.expires_at)}
                  {h.expired && (
                    <span className="ml-2 rounded bg-destructive/10 px-1.5 py-0.5 text-[10px] font-medium text-destructive">
                      Expired
                    </span>
                  )}
                </td>
                <td className="space-x-3 py-1 text-right">
                  <button
                    type="button"
                    className="text-primary hover:underline disabled:opacity-50"
                    onClick={() => setDialog({ kind: "edit", hold: h })}
                    {...permissionGate(canWrite, NEEDS_SUBNET_WRITE)}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    className="text-primary hover:underline disabled:opacity-50"
                    onClick={() => setDialog({ kind: "convert", hold: h })}
                    {...permissionGate(canWrite, NEEDS_SUBNET_WRITE)}
                  >
                    Convert to subnet
                  </button>
                  <button
                    type="button"
                    className="text-destructive hover:underline disabled:opacity-50"
                    onClick={() => setDialog({ kind: "release", hold: h })}
                    {...permissionGate(canWrite, NEEDS_SUBNET_WRITE)}
                  >
                    Release
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {dialog?.kind === "create" && (
        <HoldFormModal block={block} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "edit" && (
        <HoldFormModal
          block={block}
          hold={dialog.hold}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === "convert" && (
        <ConvertHoldModal hold={dialog.hold} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "release" && (
        <ReleaseHoldDialog hold={dialog.hold} onClose={() => setDialog(null)} />
      )}
    </div>
  );
}

function useRefreshHolds() {
  const qc = useQueryClient();
  return () => {
    qc.invalidateQueries({ queryKey: ["subnet-holds"] });
    qc.invalidateQueries({ queryKey: ["subnets"] });
  };
}

function HoldFormModal({
  block,
  hold,
  onClose,
}: {
  block: IPBlock;
  hold?: SubnetHold;
  onClose: () => void;
}) {
  const refresh = useRefreshHolds();
  const [network, setNetwork] = useState(hold?.network ?? "");
  const [reason, setReason] = useState(hold?.reason ?? "");
  const [expires, setExpires] = useState(toLocalInputValue(hold?.expires_at));
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: () => {
      const iso = fromLocalInputValue(expires);
      if (hold) {
        return subnetHoldsApi.update(hold.id, {
          reason,
          ...(iso ? { expires_at: iso } : { clear_expiry: true }),
        });
      }
      return subnetHoldsApi.create({
        space_id: block.space_id,
        network: network.trim(),
        reason,
        expires_at: iso,
      });
    },
    onSuccess: () => {
      refresh();
      onClose();
    },
    onError: (e) => setError(formatApiError(e, "Could not save the hold")),
  });

  return (
    <Modal
      title={hold ? `Edit hold ${hold.network}` : "Hold a CIDR"}
      onClose={onClose}
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          save.mutate();
        }}
      >
        {!hold && (
          <label className="block text-sm">
            <span className="mb-1 block text-xs text-muted-foreground">
              CIDR (inside {block.network})
            </span>
            <input
              className={INPUT_CLS}
              value={network}
              onChange={(e) => setNetwork(e.target.value)}
              placeholder="10.0.8.0/22"
              required
            />
          </label>
        )}
        <label className="block text-sm">
          <span className="mb-1 block text-xs text-muted-foreground">
            Reason
          </span>
          <input
            className={INPUT_CLS}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            required
          />
        </label>
        <label className="block text-sm">
          <span className="mb-1 block text-xs text-muted-foreground">
            Expires (optional)
          </span>
          <input
            type="datetime-local"
            className={INPUT_CLS}
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
          />
        </label>
        <FormError>{error}</FormError>
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
            disabled={save.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-60"
          >
            {hold ? "Save" : "Hold"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ConvertHoldModal({
  hold,
  onClose,
}: {
  hold: SubnetHold;
  onClose: () => void;
}) {
  const refresh = useRefreshHolds();
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const convert = useMutation({
    mutationFn: () => subnetHoldsApi.convert(hold.id, { name }),
    onSuccess: () => {
      refresh();
      onClose();
    },
    onError: (e) => setError(formatApiError(e, "Could not convert the hold")),
  });
  return (
    <Modal title={`Convert hold ${hold.network} to a subnet`} onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          convert.mutate();
        }}
      >
        <p className="text-xs text-muted-foreground">
          Creates a subnet on {hold.network} through the normal create path and
          ends the hold.
        </p>
        <label className="block text-sm">
          <span className="mb-1 block text-xs text-muted-foreground">
            Subnet name (optional)
          </span>
          <input
            className={INPUT_CLS}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <FormError>{error}</FormError>
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
            disabled={convert.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-60"
          >
            Convert
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ReleaseHoldDialog({
  hold,
  onClose,
}: {
  hold: SubnetHold;
  onClose: () => void;
}) {
  const refresh = useRefreshHolds();
  const [error, setError] = useState<string | null>(null);
  const release = useMutation({
    mutationFn: () => subnetHoldsApi.release(hold.id),
    onSuccess: () => {
      refresh();
      onClose();
    },
    onError: (e) => setError(formatApiError(e, "Could not release the hold")),
  });
  return (
    <ConfirmModal
      open
      title={`Release hold ${hold.network}?`}
      message={`${hold.network} becomes available for subnets again.`}
      confirmLabel="Release"
      tone="destructive"
      loading={release.isPending}
      error={error}
      onConfirm={() => {
        setError(null);
        release.mutate();
      }}
      onClose={onClose}
    />
  );
}
