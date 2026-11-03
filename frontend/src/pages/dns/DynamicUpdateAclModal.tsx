import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Loader2,
  Plus,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { Modal } from "@/components/ui/modal";
import { HeaderButton } from "@/components/ui/header-button";
import { dnsApi, formatApiError, type UpdateAclEntryInput } from "@/lib/api";

/**
 * Dynamic-update (RFC 2136) ACL editor for a single zone (issue #641).
 *
 * Lets an operator authorize third-party DDNS writers (an AD DC, a DHCP
 * server) to the zone by TSIG key or source IP/CIDR — a full ordered
 * replace. The controls render only what the zone's DNS backend can
 * express (from the group's driver capabilities): a cloud-driver group
 * greys the whole thing out, and BIND9-P1 hides the not-yet-supported
 * name-scoping / per-type / deny controls.
 *
 * Secrets never appear here — TSIG entries reference a key by id/name; the
 * key material stays server-side.
 */

// ``_types_text`` holds the raw record-types input so an in-progress comma /
// space isn't stripped on every keystroke (the parsed array drives logic + save).
type Row = UpdateAclEntryInput & { _key: number; _types_text?: string };

// BIND update-policy ruletypes that take a name argument.
const NAMED_SCOPES = ["subdomain", "name", "wildcard", "self"];

export function DynamicUpdateAclModal({
  groupId,
  zoneId,
  zoneName,
  onClose,
}: {
  groupId: string;
  zoneId: string;
  zoneName: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const rowKey = useRef(0);
  const nextKey = () => (rowKey.current += 1);

  const [enabled, setEnabled] = useState(false);
  const [rows, setRows] = useState<Row[]>([]);
  const seededRef = useRef(false);
  // Version token of the ACL the editor was seeded from / last saved (#3381).
  const versionRef = useRef<string | undefined>(undefined);
  const [conflict, setConflict] = useState(false);

  const aclQuery = useQuery({
    queryKey: ["dns-zone-update-acl", groupId, zoneId],
    queryFn: () => dnsApi.getZoneUpdateAcl(groupId, zoneId),
  });

  const keysQuery = useQuery({
    queryKey: ["dns-tsig-keys", groupId],
    queryFn: () => dnsApi.listTSIGKeys(groupId),
  });

  // Seed local editable state once, the first time the server response
  // arrives (a ref guard, not setState-during-render, so a later refetch
  // doesn't clobber in-progress edits).
  useEffect(() => {
    if (!aclQuery.data || seededRef.current) return;
    seededRef.current = true;
    versionRef.current = aclQuery.data.version;
    setConflict(false);
    setEnabled(aclQuery.data.dynamic_update_enabled);
    setRows(
      aclQuery.data.entries.map((e) => ({
        _key: nextKey(),
        match_kind: e.match_kind,
        action: e.action,
        ip_cidr: e.ip_cidr,
        tsig_key_id: e.tsig_key_id,
        name_scope: e.name_scope,
        name_pattern: e.name_pattern,
        record_types: e.record_types,
      })),
    );
    // nextKey is a stable ref bump; aclQuery.data is the real trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aclQuery.data]);

  const caps = aclQuery.data?.caps;
  const supported = caps?.supported ?? false;
  const fineGrained = caps?.supports_name_scoping ?? false;
  const hasIpEntry = rows.some((r) => r.match_kind === "ip");
  const needsName = (r: Row) =>
    !!r.name_scope && NAMED_SCOPES.includes(r.name_scope);
  const rowIsFine = (r: Row) =>
    r.action === "deny" ||
    !!r.name_scope ||
    !!(r.record_types && r.record_types.length);
  // update-policy (any fine-grained row) is TSIG-only; mixing it with an IP
  // row is unsatisfiable — the backend 422s it, so block Save + warn.
  const mixingConflict = rows.some(rowIsFine) && hasIpEntry;
  // Every row must be complete before Save: an IP row needs a CIDR, a TSIG
  // row needs a key (and a name pattern when its scope takes one).
  const rowsComplete = rows.every((r) =>
    r.match_kind === "ip"
      ? !!(r.ip_cidr && r.ip_cidr.trim())
      : !!r.tsig_key_id &&
        (!needsName(r) || !!(r.name_pattern && r.name_pattern.trim())),
  );

  const saveMut = useMutation({
    mutationFn: () =>
      dnsApi.replaceZoneUpdateAcl(groupId, zoneId, {
        expected_version: versionRef.current,
        dynamic_update_enabled: enabled,
        entries: rows.map((r) => ({
          match_kind: r.match_kind,
          action: r.action ?? "grant",
          ip_cidr: r.match_kind === "ip" ? (r.ip_cidr ?? null) : null,
          tsig_key_id:
            r.match_kind === "tsig_key" ? (r.tsig_key_id ?? null) : null,
          name_scope: r.match_kind === "tsig_key" ? r.name_scope || null : null,
          name_pattern:
            r.match_kind === "tsig_key" ? r.name_pattern || null : null,
          record_types:
            r.match_kind === "tsig_key" &&
            r.record_types &&
            r.record_types.length
              ? r.record_types
              : null,
        })),
      }),
    onMutate: () => setConflict(false),
    onError: (err) => {
      if ((err as { response?: { status?: number } })?.response?.status === 409)
        setConflict(true);
    },
    onSuccess: (data) => {
      versionRef.current = data.version;
      qc.setQueryData(["dns-zone-update-acl", groupId, zoneId], data);
      qc.invalidateQueries({ queryKey: ["dns-zones"] });
      qc.invalidateQueries({ queryKey: ["dns-records", zoneId] });
    },
  });

  // Reload after a 409: re-read the ACL and re-seed the editor from it.
  const reload = async () => {
    seededRef.current = false;
    saveMut.reset();
    await aclQuery.refetch();
  };

  const savedWarnings = saveMut.data?.warnings ?? aclQuery.data?.warnings ?? [];

  const addRow = () =>
    setRows((rs) => [
      ...rs,
      {
        _key: nextKey(),
        match_kind: caps?.supports_tsig_acl ? "tsig_key" : "ip",
        action: "grant",
        ip_cidr: "",
        tsig_key_id: null,
      },
    ]);

  const updateRow = (key: number, patch: Partial<Row>) =>
    setRows((rs) => rs.map((r) => (r._key === key ? { ...r, ...patch } : r)));

  const removeRow = (key: number) =>
    setRows((rs) => rs.filter((r) => r._key !== key));

  const displayName = zoneName.replace(/\.$/, "");
  const tsigKeys = useMemo(() => keysQuery.data ?? [], [keysQuery.data]);

  return (
    <Modal title={`Dynamic updates · ${displayName}`} onClose={onClose} wide>
      <div className="space-y-4 text-sm">
        {aclQuery.isLoading && (
          <p className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" /> Loading ACL…
          </p>
        )}
        {aclQuery.error && (
          <p className="text-xs text-destructive">
            {formatApiError(aclQuery.error, "Could not load the ACL")}
          </p>
        )}

        {aclQuery.data && (
          <>
            <p className="text-xs text-muted-foreground">
              Authorize external RFC 2136 dynamic-update writers to this zone —
              by TSIG key or source IP/CIDR. This is on top of SpatiumDDI's own
              internal writes. Driver:{" "}
              <span className="font-mono">
                {aclQuery.data.driver_names.join(", ")}
              </span>
            </p>

            {!supported && (
              <div className="rounded border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300">
                This zone's DNS backend has no RFC 2136 dynamic-update surface,
                so this feature is unavailable. (Cloud-hosted DNS providers
                can't express update ACLs.)
              </div>
            )}

            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={enabled}
                disabled={!supported || saveMut.isPending}
                onChange={(e) => setEnabled(e.target.checked)}
              />
              <span>Accept dynamic updates on this zone</span>
            </label>

            {supported && (
              <>
                <div className="flex items-center justify-between">
                  <div className="text-xs font-medium text-muted-foreground">
                    Authorized writers (first match wins)
                  </div>
                  <HeaderButton icon={Plus} onClick={addRow}>
                    Add entry
                  </HeaderButton>
                </div>

                {rows.length === 0 && (
                  <p className="text-xs text-muted-foreground italic">
                    No entries — only SpatiumDDI's internal loopback writer is
                    authorized.
                  </p>
                )}

                <div className="space-y-2">
                  {rows.map((r) => (
                    <div
                      key={r._key}
                      className="flex flex-wrap items-center gap-2 rounded border p-2"
                    >
                      <select
                        className="rounded border bg-background px-2 py-1 text-xs"
                        value={r.match_kind}
                        disabled={saveMut.isPending}
                        onChange={(e) =>
                          updateRow(r._key, {
                            match_kind: e.target.value as "ip" | "tsig_key",
                          })
                        }
                      >
                        {caps?.supports_tsig_acl && (
                          <option value="tsig_key">TSIG key</option>
                        )}
                        {caps?.supports_ip_acl && (
                          <option value="ip">Source IP/CIDR</option>
                        )}
                      </select>

                      {r.match_kind === "tsig_key" ? (
                        <select
                          className="min-w-40 flex-1 rounded border bg-background px-2 py-1 text-xs"
                          value={r.tsig_key_id ?? ""}
                          disabled={saveMut.isPending}
                          onChange={(e) =>
                            updateRow(r._key, {
                              tsig_key_id: e.target.value || null,
                            })
                          }
                        >
                          <option value="">— pick a TSIG key —</option>
                          {tsigKeys.map((k) => (
                            <option key={k.id} value={k.id}>
                              {k.name} ({k.algorithm})
                            </option>
                          ))}
                        </select>
                      ) : (
                        <input
                          className="min-w-40 flex-1 rounded border bg-background px-2 py-1 font-mono text-xs"
                          placeholder="10.0.0.0/24 or 10.0.0.5"
                          value={r.ip_cidr ?? ""}
                          disabled={saveMut.isPending}
                          onChange={(e) =>
                            updateRow(r._key, { ip_cidr: e.target.value })
                          }
                        />
                      )}

                      {fineGrained && r.match_kind === "tsig_key" && (
                        <>
                          <select
                            className="rounded border bg-background px-2 py-1 text-xs"
                            value={r.action ?? "grant"}
                            disabled={saveMut.isPending}
                            title="grant or (BIND update-policy only) deny"
                            onChange={(e) =>
                              updateRow(r._key, {
                                action: e.target.value as "grant" | "deny",
                              })
                            }
                          >
                            <option value="grant">grant</option>
                            <option value="deny">deny</option>
                          </select>
                          <select
                            className="rounded border bg-background px-2 py-1 text-xs"
                            value={r.name_scope ?? ""}
                            disabled={saveMut.isPending}
                            title="Name scope (BIND update-policy ruletype)"
                            onChange={(e) =>
                              updateRow(r._key, {
                                name_scope: e.target.value || null,
                              })
                            }
                          >
                            <option value="">any name</option>
                            <option value="zonesub">whole zone</option>
                            <option value="subdomain">subdomain of…</option>
                            <option value="name">exact name…</option>
                            <option value="wildcard">wildcard…</option>
                            <option value="self">self…</option>
                          </select>
                          {needsName(r) && (
                            <input
                              className="min-w-32 flex-1 rounded border bg-background px-2 py-1 font-mono text-xs"
                              placeholder="wks.example.com."
                              value={r.name_pattern ?? ""}
                              disabled={saveMut.isPending}
                              onChange={(e) =>
                                updateRow(r._key, {
                                  name_pattern: e.target.value,
                                })
                              }
                            />
                          )}
                          <input
                            className="min-w-24 rounded border bg-background px-2 py-1 font-mono text-xs"
                            placeholder="types (A, PTR…)"
                            title="Restrict to these record types (comma-separated); empty = all"
                            value={
                              r._types_text ?? (r.record_types ?? []).join(", ")
                            }
                            disabled={saveMut.isPending}
                            onChange={(e) =>
                              updateRow(r._key, {
                                _types_text: e.target.value,
                                record_types: e.target.value
                                  .split(",")
                                  .map((t) => t.trim().toUpperCase())
                                  .filter(Boolean),
                              })
                            }
                          />
                        </>
                      )}

                      <button
                        type="button"
                        className="rounded p-1 text-muted-foreground hover:text-destructive"
                        title="Remove"
                        disabled={saveMut.isPending}
                        onClick={() => removeRow(r._key)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                </div>

                {hasIpEntry && (
                  <div className="flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-300">
                    <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>
                      IP-based authorization is UDP-spoofable. For any writer
                      outside a trusted segment, prefer a TSIG key.
                    </span>
                  </div>
                )}

                {mixingConflict && (
                  <div className="flex items-start gap-2 rounded border border-destructive/50 bg-destructive/10 p-2 text-xs text-destructive">
                    <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                    <span>
                      A name-scoped / per-type / deny grant renders as BIND{" "}
                      <span className="font-mono">update-policy</span>, which
                      matches TSIG identity only — it can't be combined with an
                      IP entry. Remove the IP row(s) or the fine-grained fields.
                    </span>
                  </div>
                )}
              </>
            )}

            {savedWarnings.length > 0 && (
              <div className="space-y-1 rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-300">
                {savedWarnings.map((w, i) => (
                  <div key={i} className="flex items-start gap-1.5">
                    <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                    <span>{w}</span>
                  </div>
                ))}
              </div>
            )}

            {conflict && (
              <div className="flex items-center justify-between gap-2 rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-300">
                <span>
                  Someone changed this ACL since you opened it. Reload to see
                  the current entries; your edits here will be discarded.
                </span>
                <button
                  type="button"
                  className="shrink-0 rounded-md border px-2 py-1"
                  onClick={reload}
                >
                  Reload
                </button>
              </div>
            )}

            {saveMut.error && !conflict && (
              <p className="text-xs text-destructive">
                {formatApiError(saveMut.error, "Could not save the ACL")}
              </p>
            )}

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                className="rounded-md border px-3 py-1.5 text-sm"
                onClick={onClose}
                disabled={saveMut.isPending}
              >
                Close
              </button>
              <button
                type="button"
                className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
                disabled={
                  !supported ||
                  saveMut.isPending ||
                  !rowsComplete ||
                  mixingConflict
                }
                title={
                  mixingConflict
                    ? "Can't mix IP entries with name-scoped / per-type / deny grants."
                    : !rowsComplete
                      ? "Every entry needs a source IP/CIDR, or a TSIG key (and a name where the scope requires one)."
                      : undefined
                }
                onClick={() => saveMut.mutate()}
              >
                {saveMut.isPending ? "Saving…" : "Save ACL"}
              </button>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
