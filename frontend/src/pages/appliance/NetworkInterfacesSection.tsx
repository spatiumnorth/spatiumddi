import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  applianceApi,
  formatApiError,
  type NetworkInterface,
  type NetworkInterfaceInput,
  type NetworkInterfaceState,
  type NetworkNic,
} from "@/lib/api";
import { countNoun } from "@/lib/count-noun";
import { parseRoutes } from "./networkInterfaces";
import { cn } from "@/lib/utils";
import { usePermissions } from "@/hooks/usePermissions";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { Field } from "@/components/ui/field";
import { FormError } from "@/components/ui/form-error";
import { HeaderButton } from "@/components/ui/header-button";
import { Modal } from "@/components/ui/modal";

// ── #4428 — additional network interfaces ───────────────────────────
//
// Static addresses, 802.1Q VLANs and static routes for every NIC except the
// primary one. The reading rides the node's heartbeat; the node applies a
// change with a rollback if it loses the control plane.

const STATE_CLS: Record<NetworkInterfaceState, string> = {
  active: "border-emerald-500/40 bg-emerald-500/10 text-emerald-600",
  // Applied, link down — usually no cable. Amber, not red: the profile is in
  // place and NetworkManager raises the link when the carrier arrives.
  inactive: "border-amber-500/40 bg-amber-500/10 text-amber-600",
  confirming: "border-sky-500/40 bg-sky-500/10 text-sky-600",
  pending: "border-amber-500/40 bg-amber-500/10 text-amber-600",
  reverted: "border-rose-500/40 bg-rose-500/10 text-rose-600",
  failed: "border-rose-500/40 bg-rose-500/10 text-rose-600",
  unreported: "border-border bg-muted/40 text-muted-foreground",
};

const STATE_HELP: Record<NetworkInterfaceState, string> = {
  active: "Applied, and the node reports the link up.",
  inactive:
    "Applied, but the link is down — usually no cable or no carrier. NetworkManager raises it when one arrives.",
  confirming:
    "Applied. The node is waiting to confirm it can still reach the control plane, and rolls the change back if it cannot.",
  pending: "Not applied yet. It lands on the node's next heartbeat.",
  reverted:
    "The node lost contact with the control plane after applying this and restored the previous configuration. This is NOT in force.",
  failed: "The node refused or failed to apply this.",
  unreported: "This node has not reported yet.",
};

function toInput(i: NetworkInterface): NetworkInterfaceInput {
  return {
    kind: i.kind,
    name: i.name,
    parent: i.parent,
    vlan_id: i.vlan_id,
    addresses: i.addresses,
    mtu: i.mtu,
    up: i.up,
    routes: i.routes.map((r) => ({
      destination: r.destination,
      gateway: r.gateway ?? "",
      metric: r.metric,
    })),
    description: i.description,
  };
}

function InterfaceModal({
  applianceId,
  existing,
  current,
  nics,
  onClose,
}: {
  applianceId: string;
  existing: NetworkInterface | null;
  current: NetworkInterface[];
  nics: NetworkNic[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const taken = new Set(current.map((i) => i.name));
  const ports = nics.filter(
    (n) =>
      n.kind === "ethernet" &&
      !n.protected_reason &&
      !n.master &&
      (!taken.has(n.name) || n.name === existing?.name),
  );
  const parents = nics.filter((n) =>
    ["ethernet", "bond", "bridge"].includes(n.kind),
  );

  const [kind, setKind] = useState<"ethernet" | "vlan">(
    existing?.kind ?? "ethernet",
  );
  const [port, setPort] = useState(
    existing?.kind === "ethernet" ? existing.name : (ports[0]?.name ?? ""),
  );
  const [parent, setParent] = useState(
    existing?.parent ?? parents[0]?.name ?? "",
  );
  const [vlanId, setVlanId] = useState(
    existing?.vlan_id ? String(existing.vlan_id) : "",
  );
  const [vlanName, setVlanName] = useState(
    existing?.kind === "vlan" ? existing.name : "",
  );
  const [addresses, setAddresses] = useState(
    (existing?.addresses ?? []).join("\n"),
  );
  const [mtu, setMtu] = useState(existing?.mtu ? String(existing.mtu) : "");
  const [up, setUp] = useState(existing?.up ?? true);
  const [routes, setRoutes] = useState(
    (existing?.routes ?? [])
      .map(
        (r) =>
          `${r.destination} via ${r.gateway}${r.metric ? ` metric ${r.metric}` : ""}`,
      )
      .join("\n"),
  );
  const [description, setDescription] = useState(existing?.description ?? "");
  const [error, setError] = useState<string | null>(null);

  const save = useMutation({
    mutationFn: (entry: NetworkInterfaceInput) => {
      const others = current
        .filter((i) => i.name !== existing?.name)
        .map(toInput);
      return applianceApi.putNetworkInterfaces(applianceId, [...others, entry]);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance-network", applianceId] });
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      onClose();
    },
    // Matched on the FastAPI detail, never on err.message — on an
    // AxiosError that is always "Request failed with status code 422".
    onError: (err: unknown) =>
      setError(formatApiError(err, "Could not save the interface.")),
  });

  function submit() {
    setError(null);
    let parsedRoutes;
    try {
      parsedRoutes = parseRoutes(routes);
    } catch (e) {
      setError((e as Error).message);
      return;
    }
    const entry: NetworkInterfaceInput = {
      kind,
      name: kind === "ethernet" ? port : vlanName.trim() || null,
      parent: kind === "vlan" ? parent : null,
      vlan_id: kind === "vlan" ? Number(vlanId) : null,
      addresses: addresses
        .split("\n")
        .map((a) => a.trim())
        .filter(Boolean),
      mtu: mtu.trim() ? Number(mtu) : null,
      up,
      routes: parsedRoutes,
      description: description.trim() || null,
    };
    save.mutate(entry);
  }

  const canSubmit =
    !save.isPending &&
    (kind === "ethernet" ? !!port : !!parent && Number(vlanId) > 0);

  return (
    <Modal
      onClose={onClose}
      title={existing ? `Edit ${existing.name}` : "Add network interface"}
    >
      <div className="space-y-3 text-sm">
        <Field label="Kind">
          <select
            className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
            value={kind}
            disabled={!!existing}
            onChange={(e) => setKind(e.target.value as "ethernet" | "vlan")}
          >
            <option value="ethernet">Physical port</option>
            <option value="vlan">VLAN (802.1Q) sub-interface</option>
          </select>
        </Field>

        {kind === "ethernet" ? (
          <Field
            label="Port"
            hint="Only ports the node reports that are not its primary interface are offered."
          >
            <select
              className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
              value={port}
              disabled={!!existing}
              onChange={(e) => setPort(e.target.value)}
            >
              {ports.length === 0 && (
                <option value="">No port available</option>
              )}
              {ports.map((n) => (
                <option key={n.name} value={n.name}>
                  {n.name}
                  {n.mac ? ` (${n.mac})` : ""}
                </option>
              ))}
            </select>
          </Field>
        ) : (
          <>
            <Field label="Parent interface">
              <select
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
                value={parent}
                disabled={!!existing}
                onChange={(e) => setParent(e.target.value)}
              >
                {parents.map((n) => (
                  <option key={n.name} value={n.name}>
                    {n.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="VLAN ID" hint="1 to 4094.">
              <input
                className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
                inputMode="numeric"
                value={vlanId}
                disabled={!!existing}
                onChange={(e) => setVlanId(e.target.value)}
              />
            </Field>
            <Field
              label="Interface name"
              hint="Optional. Defaults to parent.vlan-id; needed when that is longer than 15 characters."
            >
              <input
                className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm"
                value={vlanName}
                disabled={!!existing}
                onChange={(e) => setVlanName(e.target.value)}
              />
            </Field>
          </>
        )}

        <Field
          label="Addresses"
          hint="One per line, with a prefix length: 10.9.0.2/24 or fd00:9::2/64."
        >
          <textarea
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm"
            rows={3}
            value={addresses}
            onChange={(e) => setAddresses(e.target.value)}
          />
        </Field>
        <Field
          label="Static routes"
          hint="One per line: “10.20.0.0/16 via 10.9.0.1”, optionally “metric 100”. The gateway must sit inside one of this interface's subnets. Default routes are refused."
        >
          <textarea
            className="w-full rounded-md border bg-background px-2 py-1.5 font-mono text-sm"
            rows={3}
            value={routes}
            onChange={(e) => setRoutes(e.target.value)}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="MTU" hint="576 to 9216. Blank keeps the default.">
            <input
              className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
              inputMode="numeric"
              value={mtu}
              onChange={(e) => setMtu(e.target.value)}
            />
          </Field>
          <Field label="Link">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={up}
                onChange={(e) => setUp(e.target.checked)}
              />
              Bring the interface up
            </label>
          </Field>
        </div>
        <Field label="Note" hint="Shown here only.">
          <input
            className="w-full rounded-md border bg-background px-2 py-1.5 text-sm"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>

        <p className="rounded-md border bg-muted/30 px-2 py-1.5 text-[11px] text-muted-foreground">
          The node applies this and then checks it can still reach the control
          plane. If it cannot within a few minutes it restores the previous
          configuration by itself.
        </p>
        <FormError>{error}</FormError>
        <div className="flex justify-end gap-2 pt-1">
          <HeaderButton variant="secondary" onClick={onClose}>
            Cancel
          </HeaderButton>
          <HeaderButton
            variant="primary"
            disabled={!canSubmit}
            onClick={submit}
          >
            {save.isPending ? "Saving…" : "Save"}
          </HeaderButton>
        </div>
      </div>
    </Modal>
  );
}

export function ApplianceNetworkInterfacesSection({
  applianceId,
}: {
  applianceId: string;
}) {
  const qc = useQueryClient();
  const { can } = usePermissions();
  const canAdmin = can("admin", "appliance");
  const [editing, setEditing] = useState<NetworkInterface | null>(null);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<NetworkInterface | null>(null);
  const [removeError, setRemoveError] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["appliance-network", applianceId],
    queryFn: () => applianceApi.getNetworkInterfaces(applianceId),
    // The reading rides the node's heartbeat, so a change (and its rollback)
    // shows up within a tick or two without a Refresh button.
    refetchInterval: 15_000,
  });

  const remove = useMutation({
    mutationFn: (name: string) =>
      applianceApi.deleteNetworkInterface(applianceId, name),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["appliance-network", applianceId] });
      qc.invalidateQueries({ queryKey: ["appliance", "fleet"] });
      setRemoving(null);
    },
    onError: (err: unknown) =>
      setRemoveError(formatApiError(err, "Could not remove the interface.")),
  });

  if (isLoading || !data) return null;

  return (
    <div className="border-t pt-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            Network interfaces
          </h3>
          <p className="mt-1 text-xs text-muted-foreground">
            Addresses, VLANs and static routes for every port except the primary
            one — for example a second NIC serving DHCP on another VLAN, plus
            the route back to a relay&apos;s subnet. The primary interface is
            set at install and from the console&apos;s F4 screen.
          </p>
        </div>
        {canAdmin && data.reported && (
          <HeaderButton variant="secondary" onClick={() => setAdding(true)}>
            Add interface…
          </HeaderButton>
        )}
      </div>

      {!data.reported && (
        <p className="mt-2 rounded-md border bg-muted/30 px-2 py-1.5 text-[11px] text-muted-foreground">
          This node has not reported its network interfaces yet. It may be
          offline, or running a supervisor that predates this feature.
        </p>
      )}
      {data.apply_state === "pending-confirm" && (
        <p className="mt-2 rounded-md border border-sky-500/40 bg-sky-500/10 px-2 py-1.5 text-[11px] text-sky-600">
          The node applied a change and is confirming it can still reach the
          control plane. It restores the previous configuration by itself if it
          cannot within {data.revert_seconds} seconds.
        </p>
      )}
      {data.apply_state === "reverted" && (
        <p
          role="alert"
          className="mt-2 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1.5 text-[11px] text-rose-600"
        >
          The last change was rolled back.{" "}
          {data.apply_error ??
            "The node lost contact with the control plane after applying it."}{" "}
          The configuration below is what you asked for, not what the node is
          running — edit it before it is applied again.
        </p>
      )}
      {data.apply_state === "failed" && (
        <p
          role="alert"
          className="mt-2 rounded-md border border-rose-500/40 bg-rose-500/10 px-2 py-1.5 text-[11px] text-rose-600"
        >
          The node could not apply the last change
          {data.apply_error ? `: ${data.apply_error}` : "."} See{" "}
          <code>/var/log/spatiumddi/netif-reload.log</code> on the node.
        </p>
      )}

      {data.interfaces.length > 0 && (
        <div className="mt-2 overflow-x-auto rounded-md border">
          <table className="w-full text-xs">
            <thead className="bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-3 py-1.5 text-left font-medium">Interface</th>
                <th className="px-3 py-1.5 text-left font-medium">State</th>
                <th className="px-3 py-1.5 text-left font-medium">Addresses</th>
                <th className="px-3 py-1.5 text-left font-medium">Routes</th>
                <th className="px-3 py-1.5 text-left font-medium">MTU</th>
                <th className="px-3 py-1.5 text-left font-medium" />
              </tr>
            </thead>
            <tbody className="divide-y">
              {data.interfaces.map((i) => (
                <tr key={i.name}>
                  <td className="px-3 py-1.5">
                    <div className="font-mono">{i.name}</div>
                    {i.kind === "vlan" && (
                      <div className="text-[10px] text-muted-foreground">
                        VLAN {i.vlan_id} on {i.parent}
                      </div>
                    )}
                    {i.description && (
                      <div className="text-[10px] text-muted-foreground">
                        {i.description}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-1.5">
                    <span
                      className={cn(
                        "inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium",
                        STATE_CLS[i.state] ?? STATE_CLS.unreported,
                      )}
                      title={STATE_HELP[i.state]}
                    >
                      {i.state}
                    </span>
                    {i.detail && (
                      <div className="mt-0.5 max-w-[16rem] text-[10px] text-muted-foreground">
                        {i.detail}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-1.5 font-mono">
                    {i.addresses.length ? i.addresses.join(", ") : "—"}
                  </td>
                  <td className="px-3 py-1.5">
                    {i.routes.length === 0
                      ? "—"
                      : i.routes.map((r) => (
                          <div key={`${r.destination}-${r.metric}`}>
                            <code>
                              {r.destination} via {r.gateway}
                            </code>
                          </div>
                        ))}
                  </td>
                  <td className="px-3 py-1.5">{i.mtu ?? "default"}</td>
                  <td className="px-3 py-1.5 text-right">
                    {canAdmin && (
                      <span className="inline-flex gap-2">
                        <HeaderButton
                          variant="secondary"
                          onClick={() => setEditing(i)}
                        >
                          Edit
                        </HeaderButton>
                        <HeaderButton
                          variant="destructive"
                          onClick={() => setRemoving(i)}
                        >
                          Remove
                        </HeaderButton>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data.reported && (
        <div className="mt-3">
          <div className="text-[11px] font-medium text-muted-foreground">
            Detected interfaces ({countNoun(data.nics.length, "interface")})
          </div>
          <ul className="mt-1 space-y-1">
            {data.nics.map((n) => (
              <li
                key={n.name}
                className="flex flex-wrap items-center gap-2 rounded-md border px-2 py-1.5 text-[11px]"
              >
                <span className="font-mono font-medium">{n.name}</span>
                <span className="text-muted-foreground">
                  {n.kind}
                  {n.state ? ` · ${n.state}` : ""}
                  {n.mtu ? ` · MTU ${n.mtu}` : ""}
                  {n.addresses.length ? ` · ${n.addresses.join(", ")}` : ""}
                </span>
                {n.protected_reason && (
                  <span className="ml-auto text-muted-foreground">
                    Not manageable here: {n.protected_reason}
                  </span>
                )}
                {n.managed && (
                  <span className="ml-auto text-muted-foreground">managed</span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {(adding || editing) && (
        <InterfaceModal
          applianceId={applianceId}
          existing={editing}
          current={data.interfaces}
          nics={data.nics}
          onClose={() => {
            setAdding(false);
            setEditing(null);
          }}
        />
      )}
      {removing && (
        <ConfirmModal
          open
          title={`Remove ${removing.name}?`}
          message={
            `The node deletes the profile for ${removing.name} (its addresses and routes). ` +
            `If the node cannot reach the control plane afterwards it puts it back.`
          }
          error={removeError}
          confirmLabel="Remove"
          tone="destructive"
          loading={remove.isPending}
          onConfirm={() => remove.mutate(removing.name)}
          onClose={() => {
            setRemoveError(null);
            setRemoving(null);
          }}
        />
      )}
    </div>
  );
}
