import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ConfirmModal } from "@/components/ui/confirm-modal";
import { Field } from "@/components/ui/field";
import { FormError } from "@/components/ui/form-error";
import { Modal } from "@/components/ui/modal";
import {
  dnsApi,
  formatApiError,
  type DNSRecord,
  type DNSScheduledChange,
  type DNSScheduledChangeCreate,
} from "@/lib/api";
import { countNoun } from "@/lib/count-noun";

export type ScheduleKind = "create" | "update" | "delete";

export interface ScheduleForm {
  kind: ScheduleKind;
  /** ``datetime-local`` value: the operator's wall clock, no offset. */
  when: string;
  name: string;
  recordType: string;
  value: string;
  ttl: string;
}

/** ``datetime-local`` text (local time) to a UTC ISO string, or null when it
 *  is empty or not a date. The server wants a UTC offset on the wire. */
export function localToUtcIso(local: string): string | null {
  if (!local) return null;
  const d = new Date(local);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** The first reason the form cannot be sent, or null. Mirrors what the server
 *  would refuse so the operator hears it before the round trip. */
export function validateSchedule(
  f: ScheduleForm,
  now: Date = new Date(),
): string | null {
  const iso = localToUtcIso(f.when);
  if (!iso) return "Pick the date and time to apply the change.";
  if (new Date(iso).getTime() <= now.getTime())
    return "The time must be in the future.";
  if (f.ttl.trim() !== "" && !/^\d+$/.test(f.ttl.trim()))
    return "TTL must be a whole number of seconds.";
  if (f.kind === "create") {
    if (!f.name.trim()) return "Enter the record name (@ for the apex).";
    if (!f.recordType.trim()) return "Enter the record type.";
    if (!f.value.trim()) return "Enter the record value.";
  }
  if (f.kind === "update" && !f.value.trim() && f.ttl.trim() === "")
    return "Change the value or the TTL.";
  return null;
}

export function buildScheduleBody(
  f: ScheduleForm,
  record: DNSRecord | null,
): DNSScheduledChangeCreate {
  const scheduled_at = localToUtcIso(f.when) as string;
  const ttl = f.ttl.trim() === "" ? undefined : Number(f.ttl);
  if (f.kind === "create")
    return {
      action: "create",
      scheduled_at,
      record: {
        name: f.name.trim(),
        record_type: f.recordType.trim().toUpperCase(),
        value: f.value.trim(),
        ...(ttl !== undefined ? { ttl } : {}),
      },
    };
  const record_id = (record as DNSRecord).id;
  if (f.kind === "delete") return { action: "delete", scheduled_at, record_id };
  return {
    action: "update",
    scheduled_at,
    record_id,
    changes: {
      ...(f.value.trim() ? { value: f.value.trim() } : {}),
      ...(ttl !== undefined ? { ttl } : {}),
    },
  };
}

const KIND_LABEL: Record<ScheduleKind, string> = {
  create: "Activate (create the record)",
  update: "Update the record",
  delete: "Deactivate (delete the record)",
};

/** Schedule a record change. With ``record`` the choice is update or
 *  deactivate; without one it is activate (a create). */
export function ScheduleChangeModal({
  groupId,
  zoneId,
  record,
  onClose,
}: {
  groupId: string;
  zoneId: string;
  record: DNSRecord | null;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [f, setF] = useState<ScheduleForm>({
    kind: record ? "update" : "create",
    when: "",
    name: "",
    recordType: "A",
    value: "",
    ttl: "",
  });
  const [error, setError] = useState<string | null>(null);
  const mut = useMutation({
    mutationFn: () =>
      dnsApi.createScheduledChange(
        groupId,
        zoneId,
        buildScheduleBody(f, record),
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-scheduled-changes", zoneId] });
      onClose();
    },
    onError: (e) =>
      setError(formatApiError(e, "Could not schedule the change")),
  });
  const set = (patch: Partial<ScheduleForm>) =>
    setF((p) => ({ ...p, ...patch }));
  const kinds: ScheduleKind[] = record ? ["update", "delete"] : ["create"];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const bad = validateSchedule(f);
    setError(bad);
    if (!bad) mut.mutate();
  };

  return (
    <Modal
      title={
        record
          ? `Schedule change: ${record.name} ${record.record_type}`
          : "Schedule a new record"
      }
      onClose={onClose}
    >
      <form onSubmit={submit} className="space-y-3">
        {record && (
          <Field label="Change">
            <select
              className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
              value={f.kind}
              onChange={(e) => set({ kind: e.target.value as ScheduleKind })}
            >
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABEL[k]}
                </option>
              ))}
            </select>
          </Field>
        )}
        <Field
          label="Apply at"
          hint={`Your local time (${Intl.DateTimeFormat().resolvedOptions().timeZone}); stored as UTC.`}
        >
          <input
            type="datetime-local"
            className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
            value={f.when}
            onChange={(e) => set({ when: e.target.value })}
          />
        </Field>
        {f.kind === "create" && (
          <>
            <Field label="Name">
              <input
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
                value={f.name}
                onChange={(e) => set({ name: e.target.value })}
              />
            </Field>
            <Field label="Type">
              <input
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
                value={f.recordType}
                onChange={(e) => set({ recordType: e.target.value })}
              />
            </Field>
          </>
        )}
        {f.kind !== "delete" && (
          <>
            <Field
              label="Value"
              hint={
                f.kind === "update"
                  ? "Leave empty to keep the value."
                  : undefined
              }
            >
              <input
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
                value={f.value}
                onChange={(e) => set({ value: e.target.value })}
              />
            </Field>
            <Field label="TTL (seconds)">
              <input
                className="w-full rounded-md border bg-background px-3 py-1.5 text-sm"
                inputMode="numeric"
                value={f.ttl}
                onChange={(e) => set({ ttl: e.target.value })}
              />
            </Field>
          </>
        )}
        <FormError className="text-sm">{error}</FormError>
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={mut.isPending}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
          >
            {mut.isPending ? "Scheduling…" : "Schedule"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

const ACTION_WORD: Record<DNSScheduledChange["action"], string> = {
  create: "Activate",
  update: "Update",
  delete: "Deactivate",
};

/** A zone's scheduled changes: pending, finished, failed and cancelled. */
export function ScheduledChangesPanel({
  groupId,
  zoneId,
  canWrite,
  onSchedule,
}: {
  groupId: string;
  zoneId: string;
  canWrite: boolean;
  onSchedule: () => void;
}) {
  const qc = useQueryClient();
  const [toCancel, setToCancel] = useState<DNSScheduledChange | null>(null);
  const { data, isError, error } = useQuery({
    queryKey: ["dns-scheduled-changes", zoneId],
    queryFn: () =>
      dnsApi.listScheduledChanges(groupId, zoneId, { page_size: 100 }),
    refetchInterval: 30_000,
  });
  const cancel = useMutation({
    mutationFn: (c: DNSScheduledChange) =>
      dnsApi.cancelScheduledChange(groupId, zoneId, c.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dns-scheduled-changes", zoneId] });
      setToCancel(null);
    },
  });
  const items = data?.items ?? [];
  const pending = items.filter((c) => c.state === "pending").length;

  return (
    <section className="rounded-lg border" aria-label="Scheduled changes">
      <div className="flex items-center justify-between px-5 py-3">
        <h3 className="text-sm font-semibold">
          Scheduled changes
          {data ? (
            <span className="ml-2 font-normal text-muted-foreground">
              {countNoun(pending, "pending change")}
            </span>
          ) : null}
        </h3>
        {canWrite && (
          <button
            type="button"
            onClick={onSchedule}
            className="rounded-md border px-3 py-1 text-xs"
          >
            Schedule change
          </button>
        )}
      </div>
      {isError && (
        <FormError className="px-5 pb-3">
          {formatApiError(error, "Could not load scheduled changes")}
        </FormError>
      )}
      {data && items.length === 0 && (
        <p className="px-5 pb-3 text-sm text-muted-foreground">
          No changes scheduled. Use a record's menu to schedule an update or
          deactivation, or Schedule change to activate a new record.
        </p>
      )}
      {items.length > 0 && (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-t text-left text-xs text-muted-foreground">
              <th className="px-5 py-1.5">When</th>
              <th className="px-2 py-1.5">Change</th>
              <th className="px-2 py-1.5">Record</th>
              <th className="px-2 py-1.5">State</th>
              <th className="px-2 py-1.5" />
            </tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id} className="border-t">
                <td className="px-5 py-1.5 whitespace-nowrap">
                  {new Date(c.scheduled_at).toLocaleString()}
                </td>
                <td className="px-2 py-1.5">{ACTION_WORD[c.action]}</td>
                <td className="px-2 py-1.5 font-mono">{c.record_label}</td>
                <td className="px-2 py-1.5">
                  <span className="capitalize">{c.state}</span>
                  {c.result_message && c.state !== "executed" && (
                    <span className="block text-xs text-muted-foreground">
                      {c.result_message}
                    </span>
                  )}
                </td>
                <td className="px-2 py-1.5 text-right">
                  {c.state === "pending" && canWrite && (
                    <button
                      type="button"
                      onClick={() => setToCancel(c)}
                      className="text-xs text-destructive hover:underline"
                    >
                      Cancel
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <ConfirmModal
        open={toCancel !== null}
        title="Cancel scheduled change"
        message={
          toCancel
            ? `${ACTION_WORD[toCancel.action]} ${toCancel.record_label} at ${new Date(toCancel.scheduled_at).toLocaleString()} will not run.`
            : ""
        }
        confirmLabel="Cancel change"
        cancelLabel="Keep it"
        tone="destructive"
        loading={cancel.isPending}
        error={cancel.isError ? formatApiError(cancel.error) : null}
        onConfirm={() => toCancel && cancel.mutate(toCancel)}
        onClose={() => {
          cancel.reset();
          setToCancel(null);
        }}
      />
    </section>
  );
}
