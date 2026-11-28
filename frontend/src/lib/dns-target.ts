/**
 * Name targets in DNS record values (#5021).
 *
 * A name typed in the value of a CNAME / MX / NS / SRV / PTR / DNAME record is
 * relative to the zone unless it ends with a dot, as in a zone file: in
 * `corp.test.`, `target.example.com` points at `target.example.com.corp.test.`.
 * The API accepts relative names on purpose; the dialog tells the operator what
 * they will get.
 */

/** Record types whose value (or, for MX / SRV, whose whole value) is a name. */
const NAME_TARGET_TYPES = new Set(["CNAME", "MX", "NS", "SRV", "PTR", "DNAME"]);

export function isNameTargetType(recordType: string): boolean {
  return NAME_TARGET_TYPES.has(recordType.toUpperCase());
}

export interface ResolvedTarget {
  /** The absolute name the value resolves to, or null when it cannot be told
   * (a relative name with no zone to be relative to). */
  fqdn: string | null;
  relative: boolean;
  /** A dotted name without the trailing dot: probably meant as an outside
   * name. `@` and single-label names (`www`) are plainly relative. */
  looksLikeOutsideName: boolean;
}

/** What a typed name target resolves to in `zoneName`; null while it is empty. */
export function resolveTarget(
  value: string,
  zoneName: string | undefined,
): ResolvedTarget | null {
  const v = value.trim();
  if (!v) return null;
  const zone = zoneName
    ? zoneName.endsWith(".")
      ? zoneName
      : `${zoneName}.`
    : null;
  if (v.endsWith(".")) {
    return { fqdn: v, relative: false, looksLikeOutsideName: false };
  }
  if (v === "@") {
    return { fqdn: zone, relative: true, looksLikeOutsideName: false };
  }
  return {
    fqdn: zone ? `${v}.${zone}` : null,
    relative: true,
    looksLikeOutsideName: v.includes("."),
  };
}
