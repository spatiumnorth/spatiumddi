import type { SchemaRollbackCheck } from "@/lib/api";

/** The 409 a slot rollback / downgrade answers when the target release
 *  cannot run on the database, or null for any other error. Keyed on
 *  ``detail.code``, never on the message text. */
export function schemaRollbackRefusal(
  err: unknown,
): SchemaRollbackCheck | null {
  const res = (
    err as { response?: { status?: number; data?: { detail?: unknown } } }
  )?.response;
  if (res?.status !== 409) return null;
  const body = res.data?.detail as
    | (SchemaRollbackCheck & { code?: unknown })
    | undefined;
  return body &&
    typeof body === "object" &&
    body.code === "schema_rollback_unsafe"
    ? body
    : null;
}
