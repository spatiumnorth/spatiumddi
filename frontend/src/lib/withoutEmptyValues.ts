// A cleared custom field is "no value of its own": send no key for it, so
// the row inherits the parent block's value again (#4558). false and 0 are
// real values and stay.
export function withoutEmptyValues(
  fields: Record<string, unknown>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(fields).filter(([, v]) => v !== "" && v != null),
  );
}
