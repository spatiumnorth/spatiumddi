/** The delete is refused (409, #2285) while a pool names the class, so the
 * sentence says that rather than describing pools that lose their class (#2608). */
export function deletePolicyDescription(name: string, className: string) {
  return `Delete "${name}"? A policy whose class a pool is restricted to (${className}) cannot be deleted: clear that restriction on the pool first.`;
}
