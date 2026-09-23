import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  dhcpApi,
  ipamApi,
  settingsApi,
  type DHCPScope,
  type DHCPOption,
} from "@/lib/api";
import {
  Modal,
  Field,
  Btns,
  inputCls,
  errMsg,
  isAdoptionRequired,
} from "./_shared";
import { DHCPOptionsEditor } from "./DHCPOptionsEditor";
import { GROUP_FAILOVER_QUERY_KEY, useGroupFailover } from "./windowsFailover";

// Suggest a dynamic pool range for a v4 subnet: skip the first 10 hosts
// (reserve for infra / static) and the last host (broadcast). Returns null
// for IPv6 or subnets too small to be useful.
function suggestRange(
  subnet: { network?: string | null } | undefined,
): { start: string; end: string } | null {
  if (!subnet?.network) return null;
  const [cidr, prefixStr] = subnet.network.split("/");
  if (!cidr || !prefixStr || cidr.includes(":")) return null;
  const prefix = parseInt(prefixStr, 10);
  if (prefix < 8 || prefix > 30) return null;
  const parts = cidr.split(".").map((n) => parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => isNaN(n))) return null;
  const netInt =
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  const base = (netInt & mask) >>> 0;
  const hostBits = 32 - prefix;
  const total = 1 << hostBits;
  if (total < 16) return null;
  const startInt = (base + 10) >>> 0;
  const endInt = (base + total - 2) >>> 0;
  const fmt = (n: number) =>
    `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
  return { start: fmt(startInt), end: fmt(endInt) };
}

export function CreateScopeModal({
  scope,
  subnetId: fixedSubnetId,
  defaultGroupId,
  onClose,
}: {
  scope?: DHCPScope;
  /** When creating from a subnet, pin the subnet; otherwise show a picker. */
  subnetId?: string;
  /** When opened from within a specific group's view, pin the group so
   * the user isn't re-picking it from the list. */
  defaultGroupId?: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!scope;
  const [subnetId, setSubnetId] = useState<string>(
    scope?.subnet_id ?? fixedSubnetId ?? "",
  );
  const [groupId, setGroupId] = useState<string>(
    scope?.group_id ?? defaultGroupId ?? "",
  );
  const [name, setName] = useState(scope?.name ?? "");
  const [description, setDescription] = useState(scope?.description ?? "");
  const [enabled, setEnabled] = useState(scope?.enabled ?? true);
  const [leaseTime, setLeaseTime] = useState(
    String(scope?.lease_time ?? 86400),
  );
  const [minLease, setMinLease] = useState(
    scope?.min_lease_time != null ? String(scope.min_lease_time) : "",
  );
  const [maxLease, setMaxLease] = useState(
    scope?.max_lease_time != null ? String(scope.max_lease_time) : "",
  );
  // #637 — per-scope Kea lease-cache override. Blank = inherit the group.
  // Note "0" is NOT blank: it explicitly disables caching for this scope.
  const [leaseCacheThreshold, setLeaseCacheThreshold] = useState(
    scope?.lease_cache_threshold != null
      ? String(scope.lease_cache_threshold)
      : "",
  );
  const [leaseCacheMaxAge, setLeaseCacheMaxAge] = useState(
    scope?.lease_cache_max_age != null ? String(scope.lease_cache_max_age) : "",
  );
  const [ddnsEnabled, setDdnsEnabled] = useState(scope?.ddns_enabled ?? false);
  const [ddnsPolicy, setDdnsPolicy] = useState(
    scope?.ddns_hostname_policy ?? "client",
  );
  // When off, this scope's dynamic-pool lease mirrors are excluded from the
  // IPAM↔DNS drift check (ephemeral pulled leases don't read as "out of sync").
  const [dnsTrackDynamicLeases, setDnsTrackDynamicLeases] = useState(
    scope?.dns_track_dynamic_leases ?? true,
  );
  const [pxeProfileId, setPxeProfileId] = useState<string>(
    scope?.pxe_profile_id ?? "",
  );
  // Canonical DB vocabulary (disabled | on_static_only | on_lease). The API
  // response echoes these, so the <select> below must speak them too or edits
  // snap back to the first option (#475). Default matches the backend model.
  const [hostnameSync, setHostnameSync] = useState(
    scope?.hostname_sync_mode ?? "on_static_only",
  );
  const [options, setOptions] = useState<DHCPOption[]>(scope?.options ?? []);
  // DHCPv6 mode (issue #52) — only surfaced/sent for IPv6 scopes.
  const [v6Mode, setV6Mode] = useState<"stateful" | "stateless" | "slaac">(
    scope?.v6_address_mode ?? "stateful",
  );
  const [raManaged, setRaManaged] = useState(scope?.ra_managed_flag ?? true);
  const [raOther, setRaOther] = useState(scope?.ra_other_flag ?? true);
  // IPv6 Router Advertisements (issue #524).
  const [raEnabled, setRaEnabled] = useState(scope?.ra_enabled ?? false);
  const [raMoOverride, setRaMoOverride] = useState(
    scope?.ra_mo_override ?? false,
  );
  const [raRouterLifetime, setRaRouterLifetime] = useState(
    String(scope?.ra_router_lifetime ?? 1800),
  );
  const [raValidLifetime, setRaValidLifetime] = useState(
    String(scope?.ra_prefix_valid_lifetime ?? 86400),
  );
  const [raPreferredLifetime, setRaPreferredLifetime] = useState(
    String(scope?.ra_prefix_preferred_lifetime ?? 14400),
  );
  const [raOnLink, setRaOnLink] = useState(scope?.ra_prefix_on_link ?? true);
  const [raAutonomous, setRaAutonomous] = useState(
    scope?.ra_prefix_autonomous ?? true,
  );
  const [raInterface, setRaInterface] = useState(scope?.ra_interface ?? "");
  // Relay-agent (giaddr) IPs (issue #337). Freeform multiline / comma
  // textarea; parsed into a list on submit. Set when a centralized DHCP
  // server serves this subnet through an upstream relay / ip-helper.
  const [relayAddresses, setRelayAddresses] = useState(
    (scope?.relay_addresses ?? []).join("\n"),
  );
  // Initial pool — only used when creating; edits happen in the Pools tab.
  const [poolStart, setPoolStart] = useState("");
  const [poolEnd, setPoolEnd] = useState("");
  // #1110 — where a NEW scope goes on a group with two or more Windows DHCP
  // members: "" (let the server decide — the one relationship the members
  // share, else it refuses and lists the choices), "rel:<name>" or
  // "srv:<server id>". Creating it on every member is the outage.
  const [placement, setPlacement] = useState("");
  const [error, setError] = useState("");
  // 409 + X-Adoption-Required from a cloud (FortiGate) group member: a DHCP
  // server already exists on the interface that SpatiumDDI didn't create
  // (#865). Holds the provider detail so we can offer an adopt-and-retry —
  // the save is always attempted WITHOUT the flag first.
  const [adoptConflict, setAdoptConflict] = useState<string | null>(null);

  const { data: subnets = [] } = useQuery({
    queryKey: ["subnets"],
    queryFn: () => ipamApi.listSubnets(),
    enabled: !fixedSubnetId,
  });
  const { data: dhcpGroups = [] } = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: () => dhcpApi.listGroups(),
  });
  // Effective DHCP group for this subnet, resolved up the IPAM hierarchy
  // (subnet → block ancestry → space). If set, we default the scope's
  // group to it, so scopes land on whatever DHCP was configured at the
  // IPAM level.
  const { data: effectiveDhcp } = useQuery({
    queryKey: ["subnet-effective-dhcp", subnetId],
    queryFn: () => ipamApi.getEffectiveSubnetDhcp(subnetId),
    enabled: !editing && !defaultGroupId && !!subnetId,
  });
  const effectiveGroupId = effectiveDhcp?.dhcp_server_group_id ?? null;
  const effectiveGroup = dhcpGroups.find((g) => g.id === effectiveGroupId);
  const inheritSource = effectiveDhcp?.inherited_from_block_id
    ? "a parent block"
    : effectiveDhcp?.inherited_from_space
      ? "the space"
      : "this subnet";

  // Auto-select the inherited group on first load, unless the user has
  // already picked one explicitly.
  const [groupAutoPicked, setGroupAutoPicked] = useState(!!groupId);
  useEffect(() => {
    if (editing || defaultGroupId) return;
    if (groupAutoPicked) return;
    if (!effectiveGroupId) return;
    setGroupId(effectiveGroupId);
    setGroupAutoPicked(true);
  }, [editing, defaultGroupId, groupAutoPicked, effectiveGroupId]);

  // When the parent already chose the subnet (the "+ New Scope on subnet"
  // dropdown), the modal hides the subnet picker but we still need the
  // network label + gateway for the pinned display and for prefill.
  const { data: pinnedSubnet } = useQuery({
    queryKey: ["subnet", fixedSubnetId ?? ""],
    queryFn: () => ipamApi.getSubnet(fixedSubnetId!),
    enabled: !!fixedSubnetId,
  });
  const pinnedGroup = dhcpGroups.find((g) => g.id === defaultGroupId);
  // Settings + specific subnet feed the auto-prefill for new scopes.
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: settingsApi.get,
    enabled: !editing,
  });
  const { data: subnetDetail } = useQuery({
    queryKey: ["subnet", subnetId],
    queryFn: () => ipamApi.getSubnet(subnetId),
    enabled: !editing && !!subnetId,
  });

  // Is this an IPv6 scope? On edit we trust the stored family; on create
  // we sniff the selected subnet's CIDR (": " ⇒ v6). Drives the DHCPv6
  // mode section + whether the initial-pool block applies.
  const selectedNetwork =
    subnetDetail?.network ??
    pinnedSubnet?.network ??
    subnets.find((s) => s.id === subnetId)?.network ??
    null;
  const isV6 = editing
    ? scope?.address_family === "ipv6"
    : !!selectedNetwork && selectedNetwork.includes(":");
  // When the operator picks a v6 mode, seed the recommended RA M/O flags
  // (they can still override). stateful → M+O, stateless → O, slaac → none.
  function applyV6Mode(m: "stateful" | "stateless" | "slaac") {
    setV6Mode(m);
    setRaManaged(m === "stateful");
    setRaOther(m !== "slaac");
  }

  const { data: failover } = useGroupFailover(groupId || undefined);
  const windowsMembers = failover?.members ?? [];
  const pairedRelationships = (failover?.relationships ?? []).filter(
    (r) => r.complete,
  );
  // An existing scope stays where it is held; a placement is only asked for
  // when no Windows member holds it — a new scope, or one restored from Trash
  // or deleted on Windows.
  const heldNowhere =
    !editing ||
    failover?.scopes.find((s) => s.scope_id === scope?.id)?.verdict ===
      "not_on_windows";
  const needsPlacement = !isV6 && windowsMembers.length >= 2 && heldNowhere;

  const [prefilled, setPrefilled] = useState(false);
  useEffect(() => {
    if (editing || prefilled) return;
    if (!settings && !subnetDetail) return;
    const next: DHCPOption[] = [];
    const gw = subnetDetail?.gateway;
    if (gw) next.push({ code: 3, value: [gw] });
    if (settings?.dhcp_default_dns_servers?.length)
      next.push({ code: 6, value: settings.dhcp_default_dns_servers });
    if (settings?.dhcp_default_domain_name)
      next.push({ code: 15, value: settings.dhcp_default_domain_name });
    if (settings?.dhcp_default_domain_search?.length)
      next.push({ code: 119, value: settings.dhcp_default_domain_search });
    if (settings?.dhcp_default_ntp_servers?.length)
      next.push({ code: 42, value: settings.dhcp_default_ntp_servers });
    if (next.length) setOptions(next);
    if (settings?.dhcp_default_lease_time)
      setLeaseTime(String(settings.dhcp_default_lease_time));
    // Suggest a pool range: skip the first 10 and last 1 host of the subnet.
    // User can freely edit or clear.
    const range = suggestRange(subnetDetail);
    if (range) {
      setPoolStart(range.start);
      setPoolEnd(range.end);
    }
    setPrefilled(true);
  }, [editing, prefilled, settings, subnetDetail]);

  const mut = useMutation({
    mutationFn: (adoptExisting: boolean) => {
      const parsedLeaseTime = parseInt(leaseTime, 10) || 86400;
      const parsedMinLease = minLease ? parseInt(minLease, 10) : null;
      const parsedMaxLease = maxLease ? parseInt(maxLease, 10) : null;
      // #637 — blank means "inherit the group"; "0" means "caching off for this
      // scope". Test the string against "" rather than truthiness, because the
      // string "0" is falsy in JS and a truthy check would silently turn an
      // explicit disable into an inherit.
      const parsedCacheThreshold =
        leaseCacheThreshold.trim() === ""
          ? null
          : parseFloat(leaseCacheThreshold);
      const parsedCacheMaxAge =
        leaseCacheMaxAge.trim() === "" ? null : parseInt(leaseCacheMaxAge, 10);

      if (
        parsedCacheThreshold !== null &&
        (Number.isNaN(parsedCacheThreshold) ||
          parsedCacheThreshold < 0 ||
          parsedCacheThreshold > 1)
      ) {
        throw new Error("Lease cache threshold must be between 0 and 1.");
      }

      if (parsedMinLease !== null && parsedMinLease > parsedLeaseTime) {
        throw new Error(
          "Minimum lease time must be less than or equal to lease time.",
        );
      }
      if (parsedMaxLease !== null && parsedLeaseTime > parsedMaxLease) {
        throw new Error(
          "Lease time must be less than or equal to maximum lease time.",
        );
      }
      if (
        parsedMinLease !== null &&
        parsedMaxLease !== null &&
        parsedMinLease > parsedMaxLease
      ) {
        throw new Error(
          "Minimum lease time must be less than or equal to maximum lease time.",
        );
      }

      const data: Partial<DHCPScope> & {
        group_id?: string;
        clear_pxe_profile?: boolean;
        windows_placement?: {
          server_id?: string;
          failover_relationship?: string;
        };
      } = {
        group_id: groupId || undefined,
        name,
        description,
        enabled,
        lease_time: parsedLeaseTime,
        min_lease_time: parsedMinLease,
        max_lease_time: parsedMaxLease,
        lease_cache_threshold: parsedCacheThreshold,
        lease_cache_max_age: parsedCacheMaxAge,
        ddns_enabled: ddnsEnabled,
        ddns_hostname_policy: ddnsEnabled ? ddnsPolicy : null,
        hostname_sync_mode: hostnameSync,
        dns_track_dynamic_leases: dnsTrackDynamicLeases,
        options,
        // Relay-agent IPs (issue #337). Split on commas / whitespace /
        // newlines; the backend validates each entry as an IP. Always
        // sent so clearing the textarea clears the scope's relay set.
        relay_addresses: relayAddresses
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
      };
      // DHCPv6 mode + RA flags only apply to v6 scopes (issue #52).
      if (isV6) {
        data.v6_address_mode = v6Mode;
        data.ra_managed_flag = raManaged;
        data.ra_other_flag = raOther;
        // IPv6 Router Advertisements (issue #524).
        data.ra_enabled = raEnabled;
        data.ra_mo_override = raMoOverride;
        // Blank → fall back to the field's default (never coerce an empty
        // input to 0, which would render an invalid radvd config); an
        // explicitly typed 0 is preserved.
        const raLifetime = (v: string, dflt: number) => {
          const t = v.trim();
          return t === "" ? dflt : Number(t);
        };
        data.ra_router_lifetime = raLifetime(raRouterLifetime, 1800);
        data.ra_prefix_valid_lifetime = raLifetime(raValidLifetime, 86400);
        data.ra_prefix_preferred_lifetime = raLifetime(
          raPreferredLifetime,
          14400,
        );
        data.ra_prefix_on_link = raOnLink;
        data.ra_prefix_autonomous = raAutonomous;
        data.ra_interface = raInterface.trim();
      }
      // PXE binding (issue #51). The backend distinguishes "no
      // change" from "explicit detach" via ``clear_pxe_profile``;
      // pass it true when the operator picked "(none)" on an
      // existing scope that previously had a profile bound.
      if (pxeProfileId) {
        data.pxe_profile_id = pxeProfileId;
      } else if (editing && scope?.pxe_profile_id) {
        data.clear_pxe_profile = true;
      }
      if (needsPlacement && placement.startsWith("rel:")) {
        data.windows_placement = { failover_relationship: placement.slice(4) };
      } else if (needsPlacement && placement.startsWith("srv:")) {
        data.windows_placement = { server_id: placement.slice(4) };
      }
      if (editing) return dhcpApi.updateScope(scope!.id, data, adoptExisting);
      return dhcpApi
        .createScope(subnetId, data, adoptExisting)
        .then(async (created) => {
          if (poolStart && poolEnd) {
            await dhcpApi.createPool(created.id, {
              name: "default",
              start_ip: poolStart,
              end_ip: poolEnd,
              pool_type: "dynamic",
            });
          }
          return created;
        });
    },
    onSuccess: () => {
      // Invalidate every shape of the scope query so the DHCP page
      // picks up the new row without a hard reload:
      //   * ``dhcp-scopes-subnet`` — IPAM's subnet-panel list
      //   * ``dhcp-scopes-group`` — DHCPPage's per-server lookup
      //     (it reads via the server's group now, not the server id)
      //   * ``dhcp-pools`` — per-scope pool query keys (broad prefix
      //     invalidation so the seeded initial pool shows up too)
      qc.invalidateQueries({ queryKey: ["dhcp-scopes"] });
      qc.invalidateQueries({ queryKey: ["dhcp-scopes-subnet", subnetId] });
      qc.invalidateQueries({ queryKey: ["dhcp-scopes-group"] });
      qc.invalidateQueries({ queryKey: ["dhcp-pools"] });
      qc.invalidateQueries({ queryKey: [GROUP_FAILOVER_QUERY_KEY] });
      if (editing && scope?.subnet_id && scope.subnet_id !== subnetId) {
        qc.invalidateQueries({
          queryKey: ["dhcp-scopes-subnet", scope.subnet_id],
        });
      }
      onClose();
    },
    onError: (e) => {
      if (isAdoptionRequired(e)) {
        // Don't show the generic error too — the banner carries the detail
        // plus the retry action.
        setAdoptConflict(
          errMsg(e, "A DHCP server already exists on the interface."),
        );
        setError("");
      } else {
        setAdoptConflict(null);
        setError(errMsg(e, "Failed to save scope"));
      }
    },
  });

  return (
    <Modal
      title={editing ? "Edit DHCP Scope" : "New DHCP Scope"}
      onClose={onClose}
      wide
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          // Always try without adopting first; the 409 banner below offers
          // the explicit adopt-and-retry (#865).
          mut.mutate(false);
        }}
        className="space-y-3"
      >
        {!editing && (
          <p className="rounded border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
            A DHCP scope binds an <strong>IPAM subnet</strong> to a{" "}
            <strong>DHCP server</strong> so that server hands out leases from
            the subnet&apos;s address range. The subnet must exist in IPAM first
            — create it under IPAM → Subnets if it doesn&apos;t.
          </p>
        )}

        {/* Subnet — pin as a read-only pill when passed from the parent
            (the "+ New Scope on subnet" dropdown picked it already), else
            show a picker. */}
        {!editing &&
          (fixedSubnetId ? (
            <Field label="Subnet (IPAM)">
              <div className="flex items-center gap-2 rounded-md border bg-muted/30 px-3 py-1.5 text-sm">
                <span className="font-mono">
                  {pinnedSubnet?.network ?? "…"}
                </span>
                {pinnedSubnet?.name && (
                  <span className="text-muted-foreground">
                    — {pinnedSubnet.name}
                  </span>
                )}
              </div>
            </Field>
          ) : (
            <Field label="Subnet (IPAM)">
              <select
                className={inputCls}
                value={subnetId}
                onChange={(e) => setSubnetId(e.target.value)}
                required
              >
                <option value="">— Pick a subnet —</option>
                {subnets.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.network} {s.name ? `— ${s.name}` : ""}
                  </option>
                ))}
              </select>
            </Field>
          ))}

        <div className="grid grid-cols-2 gap-3">
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </Field>
          {/* Group — pin as a read-only pill when the parent already
              picked one (e.g. opened from inside a group's Scopes tab),
              else show a picker. Defaults to the DHCP group inherited
              from the subnet / block / space. Scopes belong to groups,
              and every server in the group serves this scope. */}
          {defaultGroupId && pinnedGroup ? (
            <Field label="DHCP Server Group">
              <div className="flex items-center gap-2 rounded-md border bg-muted/30 px-3 py-1.5 text-sm">
                <span className="font-medium">{pinnedGroup.name}</span>
                <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] text-muted-foreground">
                  {pinnedGroup.mode}
                </span>
              </div>
            </Field>
          ) : (
            <Field
              label="DHCP Server Group"
              hint={
                effectiveGroupId && effectiveGroup
                  ? `Inherited group "${effectiveGroup.name}" from ${inheritSource}.`
                  : effectiveGroupId === null && subnetId && !editing
                    ? "No DHCP group set on this subnet's space/block. Edit the subnet to set one, or pick any group below."
                    : undefined
              }
            >
              <select
                className={inputCls}
                value={groupId}
                onChange={(e) => {
                  setGroupId(e.target.value);
                  setGroupAutoPicked(true);
                }}
                required
              >
                <option value="">— Pick a group —</option>
                {dhcpGroups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name} ({g.mode})
                  </option>
                ))}
              </select>
            </Field>
          )}
        </div>
        {needsPlacement && (
          <Field
            label="Windows placement"
            hint={
              "This group has more than one Windows DHCP server. Two Windows servers " +
              "holding the same scope without a failover relationship each hand out the " +
              "same addresses, so a new scope goes to ONE of them — on its own, or into " +
              "a failover relationship, which copies it to the partner."
            }
          >
            <select
              className={inputCls}
              value={placement}
              onChange={(e) => setPlacement(e.target.value)}
            >
              <option value="">
                {pairedRelationships.length === 1
                  ? `Automatic — failover relationship '${pairedRelationships[0].name}'`
                  : "— Choose —"}
              </option>
              {pairedRelationships.length > 0 && (
                <optgroup label="Into a failover relationship">
                  {pairedRelationships.map((r) => (
                    <option key={r.name} value={`rel:${r.name}`}>
                      {r.name} ({r.sides.map((s) => s.server_name).join(" ↔ ")})
                    </option>
                  ))}
                </optgroup>
              )}
              <optgroup label="On one server only">
                {windowsMembers.map((m) => (
                  <option key={m.server_id} value={`srv:${m.server_id}`}>
                    Only {m.server_name}
                  </option>
                ))}
              </optgroup>
            </select>
          </Field>
        )}
        <Field label="Description">
          <input
            className={inputCls}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <div className="grid grid-cols-3 gap-3">
          <Field label="Lease Time (sec)">
            <input
              type="number"
              min="0"
              step="1"
              className={inputCls}
              value={leaseTime}
              onChange={(e) => setLeaseTime(e.target.value)}
            />
          </Field>
          <Field label="Min Lease (sec)">
            <input
              type="number"
              min="0"
              step="1"
              className={inputCls}
              value={minLease}
              onChange={(e) => setMinLease(e.target.value)}
            />
          </Field>
          <Field label="Max Lease (sec)">
            <input
              type="number"
              min="0"
              step="1"
              className={inputCls}
              value={maxLease}
              onChange={(e) => setMaxLease(e.target.value)}
            />
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field
            label="Lease cache threshold"
            hint="Overrides the server group's setting for this scope. Leave blank to inherit. 0 disables caching here (every renewal writes through); a value up to 1 lets Kea reuse a lease without a database write, which also means no DDNS update and no IPAM last-seen refresh for that client."
          >
            <input
              type="number"
              min="0"
              max="1"
              step="0.05"
              placeholder="inherit"
              className={inputCls}
              value={leaseCacheThreshold}
              onChange={(e) => setLeaseCacheThreshold(e.target.value)}
            />
          </Field>
          <Field
            label="Lease cache max age (sec)"
            hint="Overrides the server group's cap on how long a cached lease may be reused. Leave blank to inherit."
          >
            <input
              type="number"
              min="1"
              step="1"
              placeholder="inherit"
              className={inputCls}
              value={leaseCacheMaxAge}
              onChange={(e) => setLeaseCacheMaxAge(e.target.value)}
            />
          </Field>
        </div>

        {isV6 && (
          <div className="space-y-3 rounded-md border p-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold">DHCPv6 mode</h3>
              <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] text-muted-foreground">
                IPv6 scope
              </span>
            </div>
            <Field
              label="Address assignment"
              hint="How clients on this subnet obtain their IPv6 address."
            >
              <select
                className={inputCls}
                value={v6Mode}
                onChange={(e) =>
                  applyV6Mode(
                    e.target.value as "stateful" | "stateless" | "slaac",
                  )
                }
              >
                <option value="stateful">
                  Stateful — Kea assigns addresses from the pool
                </option>
                <option value="stateless">
                  Stateless — clients SLAAC their address; Kea serves options
                  (DNS, etc.)
                </option>
                <option value="slaac">
                  SLAAC only — the router&apos;s RA does everything; no DHCPv6
                </option>
              </select>
            </Field>
            <div className="rounded border bg-muted/20 p-2 text-[11px] text-muted-foreground">
              Set these Router Advertisement flags on your{" "}
              <strong>router</strong> (radvd / gateway) — SpatiumDDI&apos;s Kea
              agent doesn&apos;t send RAs. These are recorded as intent and
              auto-suggested from the mode above.
              <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-foreground">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={raManaged}
                    onChange={(e) => setRaManaged(e.target.checked)}
                  />
                  <span>
                    <strong>M</strong> (Managed) — use DHCPv6 for addresses
                  </span>
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={raOther}
                    onChange={(e) => setRaOther(e.target.checked)}
                  />
                  <span>
                    <strong>O</strong> (Other) — use DHCPv6 for other config
                  </span>
                </label>
              </div>
            </div>

            <div className="space-y-3 rounded-md border p-3">
              <label className="flex items-center gap-2 text-sm font-semibold">
                <input
                  type="checkbox"
                  checked={raEnabled}
                  onChange={(e) => setRaEnabled(e.target.checked)}
                />
                Manage Router Advertisements (radvd)
              </label>
              <p className="text-[11px] text-muted-foreground">
                When on, SpatiumDDI ships a rendered radvd.conf for this subnet
                in the DHCP ConfigBundle so the agent can run radvd and actually
                emit RAs (needs <code>RADVD_MANAGED=1</code> on the agent). M/O
                flags default-derive from the DHCPv6 mode above; RDNSS/DNSSL
                come from the scope&apos;s DNS options.
              </p>
              {raEnabled && (
                <div className="space-y-3">
                  <label className="flex items-center gap-2 text-xs">
                    <input
                      type="checkbox"
                      checked={raMoOverride}
                      onChange={(e) => setRaMoOverride(e.target.checked)}
                    />
                    Override M/O flags (use the M/O checkboxes above verbatim
                    instead of deriving from the mode)
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    <Field label="Router lifetime (s)">
                      <input
                        type="number"
                        className={inputCls}
                        value={raRouterLifetime}
                        onChange={(e) => setRaRouterLifetime(e.target.value)}
                      />
                    </Field>
                    <Field label="Interface" hint="Blank = agent default NIC.">
                      <input
                        type="text"
                        className={inputCls}
                        placeholder="eth0"
                        value={raInterface}
                        onChange={(e) => setRaInterface(e.target.value)}
                      />
                    </Field>
                    <Field label="Prefix valid lifetime (s)">
                      <input
                        type="number"
                        className={inputCls}
                        value={raValidLifetime}
                        onChange={(e) => setRaValidLifetime(e.target.value)}
                      />
                    </Field>
                    <Field label="Prefix preferred lifetime (s)">
                      <input
                        type="number"
                        className={inputCls}
                        value={raPreferredLifetime}
                        onChange={(e) => setRaPreferredLifetime(e.target.value)}
                      />
                    </Field>
                  </div>
                  <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={raOnLink}
                        onChange={(e) => setRaOnLink(e.target.checked)}
                      />
                      On-link
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={raAutonomous}
                        onChange={(e) => setRaAutonomous(e.target.checked)}
                      />
                      Autonomous (SLAAC)
                    </label>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        <Field
          label="Relay agents (giaddr)"
          hint="Optional. Relay / ip-helper IP addresses (one per line or comma-separated). Set this when a centralized DHCP server serves this subnet through a relay it isn't directly attached to. Leave blank for directly-connected subnets."
        >
          <textarea
            className={`${inputCls} min-h-[60px] font-mono`}
            placeholder={"10.20.0.1\n192.0.2.250"}
            value={relayAddresses}
            onChange={(e) => setRelayAddresses(e.target.value)}
          />
        </Field>

        {!editing && !(isV6 && v6Mode !== "stateful") && (
          <div className="rounded-md border bg-muted/30 p-3">
            <div className="mb-2 flex items-baseline justify-between">
              <span className="text-sm font-medium">Initial pool</span>
              <span className="text-xs text-muted-foreground">
                Address range DHCP will hand out. Leave blank to add pools later
                from the Pools tab.
              </span>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Start IP">
                <input
                  type="text"
                  className={inputCls}
                  placeholder="10.0.0.10"
                  value={poolStart}
                  onChange={(e) => setPoolStart(e.target.value)}
                />
              </Field>
              <Field label="End IP">
                <input
                  type="text"
                  className={inputCls}
                  placeholder="10.0.0.254"
                  value={poolEnd}
                  onChange={(e) => setPoolEnd(e.target.value)}
                />
              </Field>
            </div>
          </div>
        )}

        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          <span>Enabled (serve leases from this scope)</span>
        </label>

        <div className="rounded-md border p-3 space-y-2">
          <label className="flex items-center gap-2 text-sm font-medium">
            <input
              type="checkbox"
              checked={ddnsEnabled}
              onChange={(e) => setDdnsEnabled(e.target.checked)}
            />
            <span>DDNS — push lease updates to DNS</span>
          </label>
          {ddnsEnabled && (
            <div className="space-y-2 pl-6">
              <Field label="Hostname Policy">
                <select
                  className={inputCls}
                  value={ddnsPolicy}
                  onChange={(e) => setDdnsPolicy(e.target.value)}
                >
                  <option value="client">Client-supplied</option>
                  <option value="ipam">From IPAM</option>
                  <option value="generate">Generate</option>
                </select>
              </Field>
              {/* #784 — a "Domain Override" input used to sit here. Nothing
                  stored it: no column, no field on the create/update models,
                  and the response hardcoded null, so a typed value was
                  silently discarded. The setting is real one level up, on the
                  subnet, which is where the DDNS resolution chain reads it. */}
              <p className="text-xs text-muted-foreground">
                The DDNS domain comes from the subnet (inherited from its block
                or IP space unless overridden). Set it in IPAM → the subnet's
                DDNS settings.
              </p>
            </div>
          )}
        </div>

        <Field
          label="Hostname → IPAM Sync"
          hint="How learned hostnames from DHCP clients feed back into IPAM address records."
        >
          <select
            className={inputCls}
            value={hostnameSync}
            onChange={(e) => setHostnameSync(e.target.value)}
          >
            <option value="disabled">Don't sync to IPAM</option>
            <option value="on_static_only">Static reservations only</option>
            <option value="on_lease">Write to IPAM on every lease</option>
          </select>
        </Field>

        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={dnsTrackDynamicLeases}
            onChange={(e) => setDnsTrackDynamicLeases(e.target.checked)}
          />
          <span>
            Track dynamic-lease DNS drift
            <span className="block text-xs text-muted-foreground">
              When off, this scope's dynamic-pool lease mirrors are excluded
              from the IPAM ↔ DNS drift check, so ephemeral pulled leases
              without DNS records don't show as “out of sync”.
            </span>
          </span>
        </label>

        <div className="border-t pt-3">
          <div className="mb-2 flex items-center justify-between gap-3">
            <h3 className="text-sm font-semibold">Options</h3>
            <ApplyTemplateControl
              groupId={groupId}
              currentOptions={options}
              onApply={setOptions}
            />
          </div>
          <DHCPOptionsEditor value={options} onChange={setOptions} />
        </div>

        <PXEProfileSection
          groupId={groupId}
          value={pxeProfileId}
          onChange={setPxeProfileId}
        />

        {error && <p className="text-xs text-destructive">{error}</p>}
        {adoptConflict && (
          <div className="flex items-center justify-between gap-2 rounded border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
            <span>{adoptConflict}</span>
            <div className="flex flex-shrink-0 gap-1.5">
              <button
                type="button"
                onClick={() => mut.mutate(true)}
                disabled={mut.isPending}
                className="rounded-md border border-amber-500/50 bg-amber-500/10 px-2.5 py-1 font-medium hover:bg-amber-500/20 disabled:opacity-50"
              >
                Adopt existing &amp; save
              </button>
              <button
                type="button"
                onClick={() => setAdoptConflict(null)}
                className="rounded border px-1.5 py-0.5 text-[10px] hover:bg-accent"
              >
                dismiss
              </button>
            </div>
          </div>
        )}
        <Btns onClose={onClose} pending={mut.isPending} />
      </form>
    </Modal>
  );
}

export const EditScopeModal = CreateScopeModal;

/**
 * PXE / iPXE profile picker on the scope edit modal (issue #51).
 *
 * Renders a single dropdown of profiles in the scope's group plus a
 * read-only summary of the selected profile's next-server + first
 * few arch-matches. Profile CRUD lives at ``/dhcp/groups/:gid/pxe`` —
 * the picker doesn't open a nested editor (keeps this modal focused
 * on the scope).
 */
function PXEProfileSection({
  groupId,
  value,
  onChange,
}: {
  groupId: string;
  value: string;
  onChange: (v: string) => void;
}) {
  const { data: profiles = [] } = useQuery({
    queryKey: ["dhcp-pxe-profiles", groupId],
    queryFn: () =>
      groupId ? dhcpApi.listPxeProfiles(groupId) : Promise.resolve([]),
    enabled: !!groupId,
  });
  const selected = profiles.find((p) => p.id === value);

  if (!groupId) return null;

  return (
    <div className="space-y-2 border-t pt-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold">PXE / iPXE provisioning</h3>
        {profiles.length > 0 && (
          <span className="text-[11px] text-muted-foreground">
            {profiles.length} profile{profiles.length === 1 ? "" : "s"} in group
          </span>
        )}
      </div>
      <p className="text-[11px] text-muted-foreground">
        Bind a PXE profile to render Kea client-classes for BIOS / UEFI / iPXE
        boot. Manage profiles at{" "}
        <a
          href={`/dhcp/groups/${encodeURIComponent(groupId)}/pxe`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary hover:underline"
        >
          DHCP → PXE Profiles
        </a>
        .
      </p>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={inputCls}
      >
        <option value="">— none (no PXE) —</option>
        {profiles.map((p) => (
          <option key={p.id} value={p.id}>
            {p.name}
            {!p.enabled ? " (disabled)" : ""} — {p.matches.length} arch
            {p.matches.length === 1 ? "" : "es"}
          </option>
        ))}
      </select>
      {selected && (
        <div className="rounded border bg-muted/20 p-2 text-[11px]">
          <p>
            <strong>next-server:</strong>{" "}
            <code className="font-mono">{selected.next_server}</code>
          </p>
          <p className="mt-0.5">
            <strong>matches</strong> (priority order):
          </p>
          <ul className="ml-3 mt-0.5 space-y-0.5 font-mono text-[11px]">
            {selected.matches.slice(0, 6).map((m) => (
              <li key={m.id}>
                #{m.priority}{" "}
                {m.vendor_class_match ? `[${m.vendor_class_match}]` : "[any]"}
                {m.arch_codes && m.arch_codes.length > 0
                  ? ` arch=${m.arch_codes.join(",")}`
                  : ""}{" "}
                → {m.boot_filename}
              </li>
            ))}
            {selected.matches.length > 6 && (
              <li className="text-muted-foreground">
                … and {selected.matches.length - 6} more
              </li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

/**
 * "Apply template…" dropdown above the options editor. Client-side merge
 * into the local options state — operator still has to hit Save to persist.
 * On conflict, template wins (most natural — operator just picked it). The
 * conflict-key list is shown in a small caption so the operator knows what
 * was overwritten.
 */
function ApplyTemplateControl({
  groupId,
  currentOptions,
  onApply,
}: {
  groupId: string;
  currentOptions: DHCPOption[];
  onApply: (next: DHCPOption[]) => void;
}) {
  const { data: templates = [] } = useQuery({
    queryKey: ["dhcp-option-templates", groupId],
    queryFn: () =>
      groupId ? dhcpApi.listOptionTemplates(groupId) : Promise.resolve([]),
    enabled: !!groupId,
  });
  const [overwritten, setOverwritten] = useState<string[]>([]);
  const [pickerKey, setPickerKey] = useState(0);

  if (!groupId || templates.length === 0) return null;

  function handleSelect(templateId: string) {
    if (!templateId) return;
    const tpl = templates.find((t) => t.id === templateId);
    if (!tpl) return;
    const tplOptions = tpl.options ?? {};
    // Build a name->existing-DHCPOption map for the current value so we can
    // diff and report which keys we're about to clobber.
    const byName = new Map<string, DHCPOption>();
    for (const o of currentOptions) {
      const n = o.name || `option-${o.code}`;
      byName.set(n, o);
    }
    const conflicts: string[] = [];
    for (const [n, v] of Object.entries(tplOptions)) {
      const existing = byName.get(n);
      if (existing) {
        const a = JSON.stringify(existing.value);
        const b = JSON.stringify(v);
        if (a !== b) conflicts.push(n);
        byName.set(n, { ...existing, name: n, value: v });
      } else {
        byName.set(n, { code: 0, name: n, value: v });
      }
    }
    onApply(Array.from(byName.values()));
    setOverwritten(conflicts);
    // Reset the select so picking the same template again still fires.
    setPickerKey((k) => k + 1);
  }

  return (
    <div className="flex items-center gap-2">
      {overwritten.length > 0 && (
        <span className="text-[11px] text-amber-600 dark:text-amber-400">
          Overwrote: {overwritten.join(", ")}
        </span>
      )}
      <select
        key={pickerKey}
        defaultValue=""
        onChange={(e) => handleSelect(e.target.value)}
        className="rounded-md border bg-background px-2 py-1 text-xs hover:bg-accent"
      >
        <option value="">Apply template…</option>
        {templates.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
            {t.address_family === "ipv6" ? " (v6)" : ""}
          </option>
        ))}
      </select>
    </div>
  );
}
