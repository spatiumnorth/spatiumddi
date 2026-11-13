import type { ServedApex } from "@/lib/api";

type ApexWords = Pick<
  ServedApex,
  | "ns"
  | "source"
  | "placeholder_glue_loopback"
  | "placeholder_reason"
  | "unaddressed_primary_ns"
  | "unaddressed_ns"
>;

const PLACEHOLDER_LABEL = "ns1";

/** The sentences the served-apex rows say about the NS a zone serves (#3518,
 * #3670, #3840), chosen from the API's own fields. `warning` is the one beside
 * the NS rows (or, for a declared apex, the first line of the declared box);
 * `unaddressed` is the declared apex's line for an in-zone name server BIND
 * cannot load the zone with. */
export function servedApexWords(
  apex: ApexWords,
  zoneName: string,
): { warning: string | null; unaddressed: string | null } {
  const primary = apex.unaddressed_primary_ns;
  const unaddressedNs = apex.unaddressed_ns ?? [];
  const declared = apex.source === "declared";
  const zone = zoneName.endsWith(".") ? zoneName : `${zoneName}.`;
  const placeholder = `${PLACEHOLDER_LABEL}.${zone}`.toLowerCase();
  // The only name server of a declared set the agent glues to 127.0.0.1 is
  // the placeholder ns1.<zone>; a name server outside the zone needs no
  // address in it and is never glued.
  const glued = apex.placeholder_glue_loopback
    ? apex.ns.filter((n) => n.toLowerCase() === placeholder)
    : [];

  if (declared && unaddressedNs.length > 0) {
    // BIND9 does not load the zone, so nothing of it is served, glue included.
    const bad = new Set(
      [...unaddressedNs, ...glued].map((n) => n.toLowerCase()),
    );
    const names = apex.ns.filter((n) => bad.has(n.toLowerCase()));
    return {
      warning: null,
      unaddressed: `The apex NS ${names.join(", ")} ${names.length > 1 ? "lie" : "lies"} inside the zone with no A or AAAA record, and BIND will not load a zone whose NS has no address, so the zone is held back and nothing of it is served until ${names.length > 1 ? "each has" : "it has"} one. Add the address record${names.length > 1 ? "s" : ""}.`,
    };
  }

  let warning: string | null;
  if (apex.placeholder_glue_loopback && primary) {
    warning = `The Primary NS ${primary} is inside the zone, but the zone holds no A or AAAA record for it, and BIND will not load a zone whose NS has no address. This placeholder name server, glued to 127.0.0.1, is served instead, so resolvers that follow the zone's NS set are sent to their own loopback. Add an A or AAAA record for ${primary}.`;
  } else if (apex.placeholder_glue_loopback && declared) {
    warning = `The apex NS record ${glued.join(", ")} has no A or AAAA record in the zone, so it is served glued to 127.0.0.1: resolvers that follow the zone's NS set are sent to their own loopback. Add an A or AAAA record for it.`;
  } else if (apex.placeholder_glue_loopback) {
    warning =
      "This is a placeholder name server glued to 127.0.0.1: resolvers that follow the zone's NS set are sent to their own loopback. Set a Primary NS in Edit Zone, or add NS records.";
  } else if (primary) {
    // An addressed placeholder: the Primary NS is named in Edit Zone, but it
    // is inside the zone with no address record, so ns1 is served instead.
    warning = `The Primary NS ${primary} is inside the zone, but the zone holds no A or AAAA record for it, so the placeholder name server ${apex.ns.join(", ")} (which has an address record) is served instead. Add an A or AAAA record for ${primary}.`;
  } else if (apex.source === "placeholder" && apex.ns.includes("invalid.")) {
    warning =
      "This is a placeholder name server that never resolves. Set a Primary NS in Edit Zone, or add NS records.";
  } else if (apex.source === "placeholder") {
    warning =
      "This is a placeholder name server, used because the zone names none of its own (no Primary NS that resolves, no NS records). Set a Primary NS in Edit Zone, or add NS records.";
  } else {
    warning = null;
  }
  return { warning, unaddressed: null };
}
