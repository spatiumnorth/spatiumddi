import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { dhcpApi, type DHCPLease } from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { Field, inputCls } from "./_shared";

function errText(e: unknown): string {
  const err = e as { response?: { data?: { detail?: unknown } } };
  const d = err?.response?.data?.detail;
  if (typeof d === "string") return d;
  return "Request failed — check your permissions and try again.";
}

function List({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <div className="text-xs font-medium text-muted-foreground">{title}</div>
      <ul className="ml-4 list-disc font-mono text-xs">
        {items.map((i) => (
          <li key={i}>{i}</li>
        ))}
      </ul>
    </div>
  );
}

/** Re-provision a dynamic lease onto a static address (#1287): preview, then
 *  commit. Superadmin-only on the server; callers gate the entry point. */
export function ReprovisionLeaseModal({
  lease,
  onClose,
}: {
  lease: Pick<DHCPLease, "id" | "ip_address" | "mac_address" | "hostname">;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  // What the operator typed; the preview re-runs when they press Preview.
  const [targetInput, setTargetInput] = useState("");
  const [hostInput, setHostInput] = useState(lease.hostname ?? "");
  const [applied, setApplied] = useState<{
    target_ip?: string;
    hostname?: string;
  }>({});
  const [done, setDone] = useState(false);

  const preview = useQuery({
    queryKey: ["dhcp-reprovision-preview", lease.id, applied],
    queryFn: () => dhcpApi.previewReprovision(lease.id, applied),
    retry: false,
  });
  const plan = preview.data;

  const commit = useMutation({
    mutationFn: () =>
      dhcpApi.commitReprovision(lease.id, {
        target_ip: plan!.target_ip,
        hostname: plan!.hostname,
      }),
    onSuccess: () => {
      setDone(true);
      qc.invalidateQueries({ queryKey: ["dhcp-leases"] });
      qc.invalidateQueries({ queryKey: ["dhcp-statics"] });
      qc.invalidateQueries({ queryKey: ["addresses"] });
    },
  });

  const refresh = () =>
    setApplied({
      ...(targetInput.trim() ? { target_ip: targetInput.trim() } : {}),
      ...(hostInput.trim() ? { hostname: hostInput.trim() } : {}),
    });

  return (
    <Modal title="Re-provision to static address" onClose={onClose} wide>
      <div className="space-y-3 text-sm">
        <p className="text-muted-foreground">
          Move {lease.mac_address ?? "this device"} from the dynamic address{" "}
          <span className="font-mono">{lease.ip_address}</span> to a permanent
          reservation.
        </p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Target address">
            <input
              className={inputCls}
              value={targetInput}
              placeholder="auto-pick"
              onChange={(e) => setTargetInput(e.target.value)}
            />
          </Field>
          <Field label="New hostname">
            <input
              className={inputCls}
              value={hostInput}
              onChange={(e) => setHostInput(e.target.value)}
            />
          </Field>
        </div>
        <button
          type="button"
          className="rounded-md border px-3 py-1 text-xs hover:bg-muted"
          onClick={refresh}
        >
          Preview
        </button>

        {preview.isFetching && (
          <div className="text-xs text-muted-foreground">Loading preview…</div>
        )}
        {preview.isError && !preview.isFetching && (
          <div role="alert" className="text-xs text-destructive">
            {errText(preview.error)}
          </div>
        )}
        {plan && !preview.isFetching && (
          <div className="space-y-2 rounded-md border p-3">
            <div>
              Target{" "}
              <span className="font-mono font-semibold">{plan.target_ip}</span>{" "}
              as <span className="font-mono">{plan.fqdn ?? plan.hostname}</span>
            </div>
            <div className="text-xs text-muted-foreground">
              {plan.target_reason}
            </div>
            <List title="DNS records created" items={plan.dns_create} />
            <List title="DNS records removed" items={plan.dns_remove} />
            <List title="IPAM rows removed" items={plan.ipam_remove} />
            <List title="Reservation written to" items={plan.servers} />
            <div className="text-xs">
              {plan.old_lease === "removed_now"
                ? "The old lease is no longer live and is removed now."
                : "The old lease is kept until the device moves."}{" "}
              {plan.expected_move}
            </div>
            {plan.warnings.map((w) => (
              <div key={w} className="text-xs text-amber-600">
                {w}
              </div>
            ))}
          </div>
        )}
        {commit.isError && (
          <div role="alert" className="text-xs text-destructive">
            {errText(commit.error)}
          </div>
        )}
        {done && (
          <div role="status" className="text-xs text-green-600">
            Reservation created. The device picks it up at its next renewal, or
            reboot it to move now.
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-muted"
            onClick={onClose}
          >
            {done ? "Close" : "Cancel"}
          </button>
          {!done && (
            <button
              type="button"
              className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
              disabled={!plan || preview.isFetching || commit.isPending}
              onClick={() => commit.mutate()}
            >
              Re-provision
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

/** IPAM entry point: resolve the lease behind a lease-mirror address row,
 *  then open the same modal. */
export function ReprovisionAddressModal({
  ip,
  onClose,
}: {
  ip: string;
  onClose: () => void;
}) {
  const q = useQuery({
    queryKey: ["dhcp-lease-by-ip", ip],
    queryFn: () => dhcpApi.findLeasesByIp(ip),
    retry: false,
  });
  const lease = q.data?.items.find((l) => l.state === "active") ?? null;
  if (lease) return <ReprovisionLeaseModal lease={lease} onClose={onClose} />;
  return (
    <Modal title="Re-provision to static address" onClose={onClose}>
      <p className="text-sm text-muted-foreground">
        {q.isLoading
          ? "Looking up the lease…"
          : `No active DHCP lease found for ${ip}.`}
      </p>
    </Modal>
  );
}
