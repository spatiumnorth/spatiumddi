// Payload builder for the Bulk edit custom-field section (#4304).

/** The `custom_fields` merge payload: ticked fields only, empty -> null. */
export function bulkCustomFieldChanges(
  optIn: Record<string, boolean>,
  values: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, on] of Object.entries(optIn)) {
    if (!on) continue;
    const v = values[key];
    // Explicitly empty is a removal (null); "" would store a set-looking value.
    out[key] =
      v === "" || v === undefined || (Array.isArray(v) && v.length === 0)
        ? null
        : v;
  }
  return out;
}
