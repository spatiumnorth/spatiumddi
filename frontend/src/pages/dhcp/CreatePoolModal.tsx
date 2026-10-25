import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { dhcpApi, type DHCPPool, type DHCPScope } from "@/lib/api";
import { Modal, Field, Btns, inputCls, errMsg } from "./_shared";

export function CreatePoolModal({
  pool,
  scope,
  onClose,
}: {
  pool?: DHCPPool;
  scope: DHCPScope;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!pool;
  const [name, setName] = useState(pool?.name ?? "");
  const [startIp, setStartIp] = useState(pool?.start_ip ?? "");
  const [endIp, setEndIp] = useState(pool?.end_ip ?? "");
  const [poolType, setPoolType] = useState(pool?.pool_type ?? "dynamic");
  const [classRestriction, setClassRestriction] = useState(
    pool?.class_restriction ?? "",
  );
  // DHCPv6 prefix delegation (#368) — only offered on v6 scopes.
  const isV6 = scope.address_family === "ipv6";
  const isPd = poolType === "pd";
  const [pdPrefix, setPdPrefix] = useState(pool?.pd_prefix ?? "");
  const [delegatedLength, setDelegatedLength] = useState(
    pool?.delegated_length != null ? String(pool.delegated_length) : "",
  );
  const [excludedPrefix, setExcludedPrefix] = useState(
    pool?.excluded_prefix ?? "",
  );
  const [error, setError] = useState("");
  const [existingWarning, setExistingWarning] = useState<
    { address: string; status: string; hostname: string }[] | null
  >(null);

  const { data: classes = [] } = useQuery({
    queryKey: ["dhcp-client-classes", scope.group_id],
    queryFn: () =>
      scope.group_id
        ? dhcpApi.listClientClasses(scope.group_id)
        : Promise.resolve([]),
    enabled: !!scope.group_id,
  });

  // #2752 — the class each device policy of this group generates. The API
  // takes it as a pool's class_restriction (known_class_names), and the Device
  // Policies tab says a pool binds to that exact string.
  const { data: devicePolicies = [] } = useQuery({
    queryKey: ["dhcp-device-policies", scope.group_id],
    queryFn: () =>
      scope.group_id
        ? dhcpApi.listDevicePolicies(scope.group_id)
        : Promise.resolve([]),
    enabled: !!scope.group_id,
  });

  const mut = useMutation({
    mutationFn: () => {
      const data: Partial<DHCPPool> = isPd
        ? {
            name,
            pool_type: "pd",
            pd_prefix: pdPrefix,
            delegated_length: delegatedLength
              ? parseInt(delegatedLength, 10)
              : null,
            excluded_prefix: excludedPrefix || null,
            class_restriction: classRestriction || null,
          }
        : {
            name,
            start_ip: startIp,
            end_ip: endIp,
            pool_type: poolType,
            class_restriction: classRestriction || null,
            // Kea has no per-pool lease time (#1689): clear any stored
            // override instead of offering one the server would refuse.
            ...(pool?.lease_time_override != null
              ? { lease_time_override: null }
              : {}),
          };
      return editing
        ? dhcpApi.updatePool(scope.id, pool!.id, data)
        : dhcpApi.createPool(scope.id, data);
    },
    onSuccess: (result) => {
      qc.invalidateQueries({ queryKey: ["dhcp-pools", scope.id] });
      const existing = result.existing_ips_in_range;
      if (existing && existing.length > 0) {
        setExistingWarning(existing);
      } else {
        onClose();
      }
    },
    onError: (e) => setError(errMsg(e, "Failed to save pool")),
  });

  return (
    <Modal title={editing ? "Edit Pool" : "New Pool"} onClose={onClose} wide>
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
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          {!isPd && (
            <>
              <Field label="Start IP">
                <input
                  className={inputCls}
                  value={startIp}
                  onChange={(e) => setStartIp(e.target.value)}
                  required={!isPd}
                />
              </Field>
              <Field label="End IP">
                <input
                  className={inputCls}
                  value={endIp}
                  onChange={(e) => setEndIp(e.target.value)}
                  required={!isPd}
                />
              </Field>
            </>
          )}
          <Field label="Type">
            <select
              className={inputCls}
              value={poolType}
              onChange={(e) => setPoolType(e.target.value)}
            >
              <option value="dynamic">Dynamic</option>
              <option value="excluded">Excluded</option>
              <option value="reserved">Reserved</option>
              {isV6 && <option value="pd">Prefix delegation (IA_PD)</option>}
            </select>
          </Field>
          {isPd && (
            <>
              <Field label="Delegatable prefix (CIDR)">
                <input
                  className={inputCls}
                  value={pdPrefix}
                  onChange={(e) => setPdPrefix(e.target.value)}
                  placeholder="2001:db8:1::/56"
                  required={isPd}
                />
              </Field>
              <Field label="Delegated length">
                <input
                  type="number"
                  className={inputCls}
                  value={delegatedLength}
                  onChange={(e) => setDelegatedLength(e.target.value)}
                  placeholder="64"
                  required={isPd}
                />
              </Field>
              <Field label="Excluded prefix (optional CIDR)">
                <input
                  className={inputCls}
                  value={excludedPrefix}
                  onChange={(e) => setExcludedPrefix(e.target.value)}
                  placeholder="2001:db8:1:1::/64"
                />
              </Field>
            </>
          )}
          <Field label="Restrict to Client Class">
            <select
              className={inputCls}
              value={classRestriction}
              onChange={(e) => setClassRestriction(e.target.value)}
            >
              <option value="">— No restriction —</option>
              {classes.map((c) => (
                <option key={c.id} value={c.name}>
                  {c.name}
                </option>
              ))}
              {devicePolicies
                .filter((p) => !classes.some((c) => c.name === p.class_name))
                .map((p) => (
                  <option key={p.id} value={p.class_name}>
                    {p.class_name} (device policy {p.name}
                    {p.enabled ? "" : ", disabled"})
                  </option>
                ))}
              {/* #2481 — the API also takes names that are not a row of this
                  group (Kea's built-in KNOWN, generated PXE / phone /
                  device-policy classes). Show a stored one as itself. */}
              {classRestriction &&
                !classes.some((c) => c.name === classRestriction) &&
                !devicePolicies.some(
                  (p) => p.class_name === classRestriction,
                ) && (
                  <option value={classRestriction}>
                    {classRestriction} (built-in or generated class)
                  </option>
                )}
            </select>
          </Field>
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
        {existingWarning && (
          <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 space-y-2">
            <p className="text-sm font-medium text-amber-700 dark:text-amber-400">
              Pool created — {existingWarning.length} existing IP
              {existingWarning.length !== 1 ? "s" : ""} in this range:
            </p>
            <ul className="text-xs space-y-0.5 max-h-32 overflow-y-auto">
              {existingWarning.map((ip) => (
                <li key={ip.address} className="font-mono">
                  {ip.address}{" "}
                  <span className="text-muted-foreground">
                    ({ip.status}){ip.hostname ? ` — ${ip.hostname}` : ""}
                  </span>
                </li>
              ))}
            </ul>
            <p className="text-xs text-muted-foreground">
              These IPs may conflict with dynamic DHCP leases. Consider marking
              them as excluded or reserved.
            </p>
            <button
              type="button"
              onClick={onClose}
              className="rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground hover:bg-primary/90"
            >
              OK
            </button>
          </div>
        )}
        {!existingWarning && <Btns onClose={onClose} pending={mut.isPending} />}
      </form>
    </Modal>
  );
}

export const EditPoolModal = CreatePoolModal;
