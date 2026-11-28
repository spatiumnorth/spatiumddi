import type { DNSRecord, DNSScheduledChangeCreate } from "@/lib/api";

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
