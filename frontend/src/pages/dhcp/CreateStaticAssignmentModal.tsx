import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  dhcpApi,
  type DHCPStaticAssignment,
  type DHCPStaticAssignmentWrite,
  type DHCPScope,
} from "@/lib/api";
import { changedFields, refetchRow, useFreshRow } from "@/hooks/useFreshRow";
import { FreshRowError } from "@/components/FreshRowError";
import { hostnameError } from "@/lib/dnsNames";
import { staticDuidField } from "@/lib/formPayloads";
import { Modal, Field, Btns, inputCls, errMsg } from "./_shared";

type StaticModalProps = {
  staticAssignment?: DHCPStaticAssignment;
  scope: DHCPScope;
  onClose: () => void;
};

// Edit reads the reservation fresh on open (#3076): the list row can predate
// an inline IPAM edit of the same address, and a Save of the old hostname
// would put it back on both the static and its IPAM row.
export function CreateStaticAssignmentModal(props: StaticModalProps) {
  const qc = useQueryClient();
  const fresh = useFreshRow(props.staticAssignment, () =>
    refetchRow<DHCPStaticAssignment>(
      qc,
      [["dhcp-statics", props.scope.id]],
      props.staticAssignment!.id,
    ),
  );
  if (fresh.error)
    return (
      <FreshRowError
        title="Edit Static Assignment"
        error={fresh.error}
        onRetry={fresh.retry}
        onClose={props.onClose}
      />
    );
  if (!fresh.ready) return null;
  return <StaticModalForm {...props} staticAssignment={fresh.row} />;
}

function StaticModalForm({
  staticAssignment,
  scope,
  onClose,
}: StaticModalProps) {
  const qc = useQueryClient();
  const editing = !!staticAssignment;
  const [mac, setMac] = useState(staticAssignment?.mac_address ?? "");
  const [ip, setIp] = useState(staticAssignment?.ip_address ?? "");
  const [hostname, setHostname] = useState(staticAssignment?.hostname ?? "");
  const [description, setDescription] = useState(
    staticAssignment?.description ?? "",
  );
  const [clientId, setClientId] = useState(staticAssignment?.client_id ?? "");
  // DHCPv6 DUID (#368) — keys the reservation on a v6 scope.
  const isV6 = scope.address_family === "ipv6";
  const [duid, setDuid] = useState(staticAssignment?.duid ?? "");
  const [error, setError] = useState("");
  // Hostname is optional here — only validate (and block submit) when non-empty.
  const hostnameErr = hostname.trim() ? hostnameError(hostname) : null;

  const { data: pools = [] } = useQuery({
    queryKey: ["dhcp-pools", scope.id],
    queryFn: () => dhcpApi.listPools(scope.id),
  });

  // A reservation may sit anywhere in the subnet, including inside a dynamic
  // pool (#631) — pinning a MAC in-range is the standard idiom on every driver.
  // `reserved`-type pools are the ranges explicitly carved out for statics, so
  // surface those as IP suggestions; they're hints, not a restriction.
  const eligiblePools = pools.filter((p) => p.pool_type === "reserved");

  const mut = useMutation({
    mutationFn: () => {
      const data: DHCPStaticAssignmentWrite = {
        mac_address: mac,
        ip_address: ip,
        hostname,
        description,
        client_id: clientId || null,
        ...staticDuidField({ isV6, duid }, editing),
      };
      if (!editing) return dhcpApi.createStatic(scope.id, data);
      // Send only what changed (#3076): an untouched Save writes nothing to
      // the reservation, its IPAM address or DNS.
      const st = staticAssignment!;
      const was = {
        mac_address: st.mac_address,
        ip_address: st.ip_address,
        hostname: st.hostname ?? "",
        description: st.description ?? "",
        client_id: st.client_id || null,
        duid: isV6 ? st.duid || null : undefined,
      };
      const diff = changedFields(was, {
        ...data,
        duid: isV6 ? data.duid : undefined,
      });
      if (Object.keys(diff).length === 0) return Promise.resolve(st);
      return dhcpApi.updateStatic(scope.id, st.id, diff);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-statics", scope.id] });
      // Static upserts an IPAM row (status=static_dhcp) — refresh IPAM views.
      qc.invalidateQueries({ queryKey: ["addresses", scope.subnet_id] });
      qc.invalidateQueries({ queryKey: ["subnet-dns-sync", scope.subnet_id] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Conflict or validation error")),
  });

  return (
    <Modal
      title={editing ? "Edit Static Assignment" : "New Static Assignment"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
        className="space-y-3"
      >
        <div className="grid grid-cols-2 gap-3">
          <Field label="MAC Address" hint="Format: aa:bb:cc:dd:ee:ff">
            <input
              className={`${inputCls} font-mono`}
              value={mac}
              onChange={(e) => setMac(e.target.value)}
              required
            />
          </Field>
          <Field
            label="IP Address"
            hint={
              eligiblePools.length > 0
                ? `Any IP in the subnet, including inside a dynamic pool; reserved-pool ranges are suggested below.`
                : "Any IP within the subnet (may be inside a dynamic pool)."
            }
          >
            <input
              className={`${inputCls} font-mono`}
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              required
              list="dhcp-pool-hint"
            />
            <datalist id="dhcp-pool-hint">
              {eligiblePools.flatMap((p) => [
                <option key={`${p.id}-s`} value={p.start_ip}>
                  {p.name || p.pool_type} start
                </option>,
                <option key={`${p.id}-e`} value={p.end_ip}>
                  {p.name || p.pool_type} end
                </option>,
              ])}
            </datalist>
          </Field>
          <Field label="Hostname">
            <input
              className={inputCls}
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
            />
            {hostnameErr && (
              <p className="text-xs text-destructive">{hostnameErr}</p>
            )}
          </Field>
          <Field
            label="Client ID"
            hint="Optional DHCP client identifier override"
          >
            <input
              className={inputCls}
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
            />
          </Field>
          {isV6 && (
            <Field
              label="DUID"
              hint="DHCPv6 identifier — keys the reservation instead of the MAC"
            >
              <input
                className={`${inputCls} font-mono`}
                value={duid}
                onChange={(e) => setDuid(e.target.value)}
                placeholder="00:03:00:01:aa:bb:cc:dd:ee:ff"
              />
            </Field>
          )}
        </div>
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        {error && (
          <p className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
            {error}
          </p>
        )}
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          disabled={!!hostnameErr}
        />
      </form>
    </Modal>
  );
}

export const EditStaticAssignmentModal = CreateStaticAssignmentModal;
