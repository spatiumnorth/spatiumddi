import type { CustomField } from "@/lib/api";

// A Default Value is always a string (Settings → Custom Fields stores what
// was typed), and so is a value imported from CSV, so a boolean field reads
// "true" / "false" as well as a real boolean. `!!"false"` is true, which is
// how a default of "false" came to render checked (#1303).
const TRUE_WORDS = /^(true|1|yes|on)$/i;
const FALSE_WORDS = /^(false|0|no|off)$/i;

/** Whether a boolean custom field's value reads as checked. */
export function customFieldChecked(value: unknown): boolean {
  return typeof value === "string"
    ? TRUE_WORDS.test(value.trim())
    : Boolean(value);
}

/**
 * The value a create dialog starts a custom field at: its definition's
 * Default Value, typed the way the field's control sends it. Undefined when
 * the definition has none, or one its control cannot show: a boolean default
 * that is neither true nor false, a select default outside its options, a
 * number default that is not a number.
 */
export function customFieldDefault(def: CustomField): unknown {
  const raw = def.default_value;
  if (raw == null || raw.trim() === "") return undefined;
  switch (def.field_type) {
    case "boolean":
      if (TRUE_WORDS.test(raw.trim())) return true;
      if (FALSE_WORDS.test(raw.trim())) return false;
      return undefined;
    case "select":
      return def.options?.includes(raw) ? raw : undefined;
    case "number":
      return Number.isFinite(Number(raw)) ? raw : undefined;
    default:
      return raw;
  }
}

/**
 * `values` with every field it does not hold set to its definition's
 * default: what a create dialog shows, and so what it sends (#1303). The
 * console applies the default because the API applies none on create.
 * Returns `values` itself when there is nothing to add.
 */
export function withCustomFieldDefaults(
  definitions: CustomField[],
  values: Record<string, unknown>,
): Record<string, unknown> {
  let out = values;
  for (const def of definitions) {
    if (values[def.name] !== undefined) continue;
    const value = customFieldDefault(def);
    if (value === undefined) continue;
    if (out === values) out = { ...values };
    out[def.name] = value;
  }
  return out;
}
