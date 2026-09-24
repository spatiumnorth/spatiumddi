import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import {
  dhcpApi,
  type DHCPFailoverActionResult,
  type DHCPFailoverMode,
  type DHCPFailoverRelationship,
  type DHCPGroupFailover,
} from "@/lib/api";
import { Btns, Field, Modal, errMsg, inputCls } from "./_shared";
import { GROUP_FAILOVER_QUERY_KEY } from "./windowsFailover";

/**
 * Windows DHCP failover relationship management (#1110 Phase 2).
 *
 * Each action runs one Windows cmdlet on one member, which reaches the partner
 * from there — so the member's WinRM transport has to be CredSSP, and the API
 * says so (422) before anything is sent when it is not. The modals therefore
 * say WHICH server an action runs on and what it does to the other one: a
 * create copies scopes to the partner, a removal deletes the partner's copy.
 */

const CREDSSP_NOTE =
  "Runs on one server and reaches the partner from there, so that server's WinRM transport must be CredSSP (Enable-WSManCredSSP -Role Server on Windows).";

function useFailoverAction(
  groupId: string,
  onDone: (result: DHCPFailoverActionResult) => void,
) {
  const qc = useQueryClient();
  return (fn: () => Promise<DHCPFailoverActionResult>) =>
    ({
      mutationFn: fn,
      onSuccess: (result: DHCPFailoverActionResult) => {
        qc.setQueryData([GROUP_FAILOVER_QUERY_KEY, groupId], result.failover);
        qc.invalidateQueries({ queryKey: ["dhcp-scope-failover"] });
        onDone(result);
      },
    }) as const;
}

function ErrorLine({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <p className="rounded-md border border-rose-300 bg-rose-50 px-3 py-2 text-xs text-rose-800 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300">
      {errMsg(error, "The failover change failed")}
    </p>
  );
}

function toInt(v: string): number | null {
  const t = v.trim();
  if (t === "") return null;
  const n = Number(t);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

/** Create a relationship, or change an existing one's mode and tuning. */
export function RelationshipModal({
  groupId,
  report,
  relationship,
  onClose,
  onDone,
}: {
  groupId: string;
  report: DHCPGroupFailover;
  /** Present = edit. */
  relationship?: DHCPFailoverRelationship;
  onClose: () => void;
  onDone: (result: DHCPFailoverActionResult) => void;
}) {
  const editing = !!relationship;
  const members = report.members;
  // Windows applies a load-balance share and a hot-standby role to the server
  // the cmdlet runs on, so an edit runs on — and shows the values of — one
  // named side. For a create that side is the server it is created on.
  const editSide = relationship?.sides[0];
  const currentMode = relationship?.mode as DHCPFailoverMode | undefined;
  const [name, setName] = useState(relationship?.name ?? "");
  const [serverId, setServerId] = useState(members[0]?.server_id ?? "");
  const [partnerId, setPartnerId] = useState(members[1]?.server_id ?? "");
  const [mode, setMode] = useState<DHCPFailoverMode>(
    (relationship?.mode as DHCPFailoverMode) ?? "LoadBalance",
  );
  const [role, setRole] = useState<"Active" | "Standby">(
    (editSide?.server_role as "Active" | "Standby" | null) ?? "Active",
  );
  const [lbPercent, setLbPercent] = useState(
    String(relationship?.sides[0]?.load_balance_percent ?? 50),
  );
  const [reserve, setReserve] = useState(
    String(relationship?.sides[0]?.reserve_percent ?? 5),
  );
  const [mclt, setMclt] = useState(
    String(relationship?.max_client_lead_time_seconds ?? 3600),
  );
  const [autoState, setAutoState] = useState(
    relationship?.auto_state_transition ?? false,
  );
  const [switchInterval, setSwitchInterval] = useState(
    relationship?.state_switch_interval_seconds != null
      ? String(relationship.state_switch_interval_seconds)
      : "",
  );
  const [secret, setSecret] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const sideName =
    editSide?.server_name ??
    members.find((m) => m.server_id === serverId)?.server_name ??
    "This server";

  // Scopes the chosen server holds alone, outside any relationship — the only
  // ones Windows can put into a new relationship (it copies them over).
  const candidates = report.scopes.filter((s) => {
    const holders = s.servers.filter((x) => x.holds);
    return (
      !s.relationship_name &&
      holders.length === 1 &&
      holders[0].server_id === serverId
    );
  });

  const action = useFailoverAction(groupId, (r) => {
    onDone(r);
    onClose();
  });
  const mut = useMutation(
    action(() => {
      const tuning = {
        max_client_lead_time_seconds: toInt(mclt),
        auto_state_transition: autoState,
        state_switch_interval_seconds: autoState ? toInt(switchInterval) : null,
        shared_secret: secret || null,
        ...(mode === "HotStandby"
          ? { server_role: role, reserve_percent: toInt(reserve) }
          : { load_balance_percent: toInt(lbPercent) }),
      };
      if (editing) {
        return dhcpApi.updateFailoverRelationship(groupId, relationship!.name, {
          ...tuning,
          // Only a real change of mode is sent; resending the current one
          // would make Windows re-validate every per-mode field.
          mode: mode !== currentMode ? mode : null,
          server_id: editSide?.server_id ?? null,
        });
      }
      return dhcpApi.createFailoverRelationship(groupId, {
        name: name.trim(),
        server_id: serverId,
        partner_server_id: partnerId,
        mode,
        scope_ids: [...picked].map((cidr) => cidr.split("/")[0]),
        ...tuning,
      });
    }),
  );

  return (
    <Modal
      title={
        editing
          ? `Edit failover relationship ${relationship!.name}`
          : "New failover relationship"
      }
      onClose={onClose}
      wide
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
      >
        <p className="rounded border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
          {editing
            ? "Changes apply to both partners. "
            : "Windows creates the relationship on both servers and copies each chosen scope from the first server to the partner, which must not hold it yet. "}
          {CREDSSP_NOTE}
        </p>
        {!editing && (
          <>
            <Field label="Name">
              <input
                className={inputCls}
                value={name}
                onChange={(e) => setName(e.target.value)}
                maxLength={126}
                required
              />
            </Field>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Field label="Server (holds the scopes)">
                <select
                  className={inputCls}
                  value={serverId}
                  onChange={(e) => {
                    setServerId(e.target.value);
                    setPicked(new Set());
                  }}
                >
                  {members.map((m) => (
                    <option key={m.server_id} value={m.server_id}>
                      {m.server_name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Partner">
                <select
                  className={inputCls}
                  value={partnerId}
                  onChange={(e) => setPartnerId(e.target.value)}
                >
                  {members
                    .filter((m) => m.server_id !== serverId)
                    .map((m) => (
                      <option key={m.server_id} value={m.server_id}>
                        {m.server_name}
                      </option>
                    ))}
                </select>
              </Field>
            </div>
            <Field
              label="Scopes"
              hint="Windows cannot create a relationship without at least one scope. Only scopes the server holds alone are listed — create a scope placed on that server first if there is none."
            >
              <div className="max-h-40 space-y-1 overflow-y-auto rounded-md border p-2 text-sm">
                {candidates.length === 0 ? (
                  <p className="text-xs italic text-muted-foreground">
                    No scope is held by this server alone.
                  </p>
                ) : (
                  candidates.map((s) => (
                    <label key={s.cidr} className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={picked.has(s.cidr)}
                        onChange={(e) => {
                          const next = new Set(picked);
                          if (e.target.checked) next.add(s.cidr);
                          else next.delete(s.cidr);
                          setPicked(next);
                        }}
                      />
                      <span className="font-mono text-xs">{s.cidr}</span>
                    </label>
                  ))
                )}
              </div>
            </Field>
          </>
        )}
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Mode">
            <select
              className={inputCls}
              value={mode}
              onChange={(e) => setMode(e.target.value as DHCPFailoverMode)}
            >
              <option value="LoadBalance">Load balance</option>
              <option value="HotStandby">Hot standby</option>
            </select>
          </Field>
          {mode === "LoadBalance" ? (
            <Field
              label={`${sideName}'s share (%)`}
              hint="Of client requests; the partner answers the rest."
            >
              <input
                type="number"
                min={0}
                max={100}
                className={inputCls}
                value={lbPercent}
                onChange={(e) => setLbPercent(e.target.value)}
              />
            </Field>
          ) : (
            <div className="grid grid-cols-2 gap-3">
              <Field label={`${sideName}'s role`}>
                <select
                  className={inputCls}
                  value={role}
                  onChange={(e) =>
                    setRole(e.target.value as "Active" | "Standby")
                  }
                >
                  <option value="Active">Active</option>
                  <option value="Standby">Standby</option>
                </select>
              </Field>
              <Field label="Reserve (%)">
                <input
                  type="number"
                  min={0}
                  max={100}
                  className={inputCls}
                  value={reserve}
                  onChange={(e) => setReserve(e.target.value)}
                />
              </Field>
            </div>
          )}
        </div>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field
            label="Max client lead time (s)"
            hint="How far one partner may extend a lease beyond what the other knows."
          >
            <input
              type="number"
              min={0}
              className={inputCls}
              value={mclt}
              onChange={(e) => setMclt(e.target.value)}
            />
          </Field>
          <Field label="Shared secret">
            <input
              type="password"
              autoComplete="new-password"
              className={inputCls}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={editing ? "Leave blank to keep" : "Optional"}
            />
          </Field>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={autoState}
            onChange={(e) => setAutoState(e.target.checked)}
          />
          Switch to partner-down automatically
        </label>
        {autoState && (
          <Field label="After (s)">
            <input
              type="number"
              min={0}
              className={inputCls}
              value={switchInterval}
              onChange={(e) => setSwitchInterval(e.target.value)}
            />
          </Field>
        )}
        <ErrorLine error={mut.error} />
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label={editing ? "Save" : "Create relationship"}
          disabled={!editing && (picked.size === 0 || !partnerId || !name)}
        />
      </form>
    </Modal>
  );
}

/** Add scopes one side holds alone; Windows copies them to the other. */
export function AddScopesModal({
  groupId,
  report,
  relationship,
  onClose,
  onDone,
}: {
  groupId: string;
  report: DHCPGroupFailover;
  relationship: DHCPFailoverRelationship;
  onClose: () => void;
  onDone: (result: DHCPFailoverActionResult) => void;
}) {
  const sideIds = new Set(relationship.sides.map((s) => s.server_id));
  const candidates = report.scopes.filter((s) => {
    const holders = s.servers.filter((x) => x.holds);
    return (
      !s.relationship_name &&
      holders.length === 1 &&
      sideIds.has(holders[0].server_id)
    );
  });
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const action = useFailoverAction(groupId, (r) => {
    onDone(r);
    onClose();
  });
  const mut = useMutation(
    action(() =>
      dhcpApi.addFailoverScopes(
        groupId,
        relationship.name,
        [...picked].map((c) => c.split("/")[0]),
      ),
    ),
  );
  return (
    <Modal title={`Add scopes to ${relationship.name}`} onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
      >
        <p className="text-xs text-muted-foreground">
          Only scopes one partner holds alone are listed. Windows copies each to
          the other partner. {CREDSSP_NOTE}
        </p>
        <div className="max-h-56 space-y-1 overflow-y-auto rounded-md border p-2 text-sm">
          {candidates.length === 0 ? (
            <p className="text-xs italic text-muted-foreground">
              No scope is held by exactly one partner.
            </p>
          ) : (
            candidates.map((s) => {
              const holder = s.servers.find((x) => x.holds);
              return (
                <label key={s.cidr} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={picked.has(s.cidr)}
                    onChange={(e) => {
                      const next = new Set(picked);
                      if (e.target.checked) next.add(s.cidr);
                      else next.delete(s.cidr);
                      setPicked(next);
                    }}
                  />
                  <span className="font-mono text-xs">{s.cidr}</span>
                  <span className="text-xs text-muted-foreground">
                    on {holder?.server_name}
                  </span>
                </label>
              );
            })
          )}
        </div>
        <ErrorLine error={mut.error} />
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label="Add scopes"
          disabled={picked.size === 0}
        />
      </form>
    </Modal>
  );
}

/**
 * Take a scope out of a relationship, or delete the whole relationship.
 * Windows deletes the PARTNER's copy, so the operator picks which side keeps
 * serving — a destructive choice, never defaulted silently.
 */
export function RemoveModal({
  groupId,
  relationship,
  scopeId,
  onClose,
  onDone,
}: {
  groupId: string;
  relationship: DHCPFailoverRelationship;
  /** Present = remove this one scope; absent = delete the relationship. */
  scopeId?: string;
  onClose: () => void;
  onDone: (result: DHCPFailoverActionResult) => void;
}) {
  const active = relationship.sides.find((s) => s.server_role === "Active");
  const [keep, setKeep] = useState(
    active?.server_id ?? relationship.sides[0]?.server_id ?? "",
  );
  const [ack, setAck] = useState(false);
  const other = relationship.sides.find((s) => s.server_id !== keep);
  const action = useFailoverAction(groupId, (r) => {
    onDone(r);
    onClose();
  });
  const mut = useMutation(
    action(() =>
      scopeId
        ? dhcpApi.removeFailoverScope(groupId, relationship.name, scopeId, keep)
        : dhcpApi.deleteFailoverRelationship(groupId, relationship.name, keep),
    ),
  );
  const what = scopeId
    ? `scope ${scopeId}`
    : `all ${relationship.scope_ids.length} scope(s) of the relationship`;
  return (
    <Modal
      title={
        scopeId
          ? `Remove ${scopeId} from ${relationship.name}`
          : `Delete failover relationship ${relationship.name}`
      }
      onClose={onClose}
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
      >
        <Field label="Keep serving on">
          <select
            className={inputCls}
            value={keep}
            onChange={(e) => setKeep(e.target.value)}
          >
            {relationship.sides.map((s) => (
              <option key={s.server_id} value={s.server_id}>
                {s.server_name}
                {s.server_role ? ` (${s.server_role})` : ""}
              </option>
            ))}
          </select>
        </Field>
        <p className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-200">
          Windows deletes {what} from{" "}
          <strong>
            {other?.server_name ??
              relationship.partner_outside_group ??
              "the partner"}
          </strong>
          , including its leases for them; the server kept above serves them
          alone afterwards. {CREDSSP_NOTE}
        </p>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
          />
          I understand the partner&apos;s copy is deleted
        </label>
        <ErrorLine error={mut.error} />
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label={scopeId ? "Remove scope" : "Delete relationship"}
          disabled={!ack || !keep}
        />
      </form>
    </Modal>
  );
}

/** Copy one side's scope configuration over the partner's. */
export function ReplicateModal({
  groupId,
  relationship,
  scopeId,
  onClose,
  onDone,
}: {
  groupId: string;
  relationship: DHCPFailoverRelationship;
  /** Limit to one scope; absent = every scope of the relationship. */
  scopeId?: string;
  onClose: () => void;
  onDone: (result: DHCPFailoverActionResult) => void;
}) {
  const [source, setSource] = useState("");
  const other = relationship.sides.find((s) => s.server_id !== source);
  const action = useFailoverAction(groupId, (r) => {
    onDone(r);
    onClose();
  });
  const mut = useMutation(
    action(() =>
      dhcpApi.replicateFailover(
        groupId,
        relationship.name,
        source,
        scopeId ? [scopeId] : [],
      ),
    ),
  );
  return (
    <Modal title={`Replicate ${relationship.name}`} onClose={onClose}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          mut.mutate();
        }}
      >
        <p className="text-xs text-muted-foreground">
          Windows keeps leases in sync between partners but not configuration.
          Replication copies one partner&apos;s configuration of{" "}
          {scopeId ? `scope ${scopeId}` : "every scope in the relationship"}{" "}
          over the other&apos;s. To write SpatiumDDI&apos;s own configuration to
          both instead, re-save the scope. {CREDSSP_NOTE}
        </p>
        <Field label="Copy from">
          <select
            className={inputCls}
            value={source}
            onChange={(e) => setSource(e.target.value)}
            required
          >
            <option value="">— Choose the side whose config wins —</option>
            {relationship.sides.map((s) => (
              <option key={s.server_id} value={s.server_id}>
                {s.server_name}
              </option>
            ))}
          </select>
        </Field>
        {source && other && (
          <p className="text-xs text-amber-800 dark:text-amber-300">
            {other.server_name}&apos;s configuration will be overwritten.
          </p>
        )}
        <ErrorLine error={mut.error} />
        <Btns
          onClose={onClose}
          pending={mut.isPending}
          label="Replicate"
          disabled={!source}
        />
      </form>
    </Modal>
  );
}
