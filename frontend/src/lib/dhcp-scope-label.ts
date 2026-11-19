/** #2447 — a scope's label in a picker. Scopes are commonly left with the
 *  same name, so the subnet it serves is named beside it. */
export function scopePickerLabel(
  scope: { id: string; name: string | null },
  network: string | null | undefined,
): string {
  const name = scope.name || `Scope ${scope.id.slice(0, 8)}`;
  return network ? `${name} (${network})` : name;
}
