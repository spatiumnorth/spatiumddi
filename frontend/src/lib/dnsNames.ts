/**
 * Client-side mirror of the backend DNS-name validators (issue #597).
 *
 * The backend (`app/core/dns_names.py`) is the enforcement layer; these
 * helpers give instant inline feedback in forms so an operator isn't told
 * "invalid hostname" only after hitting Save. Keep the rules in step with
 * the Python module — same per-context split:
 *
 *   - hostnames (IPAM / DHCP reservation): RFC 1123 LDH, no `_`
 *   - DNS record owners: RFC 2181, permits `_` and a leftmost `*`, plus `@`
 *   - FQDNs (zone names, domain-name option): dotted RFC 2181 labels
 *
 * Each returns `null` when valid, or a short human-readable reason string
 * when not. They do NOT normalize (the server canonicalizes on write); a
 * unicode label is reported as needing ASCII/punycode rather than being
 * silently converted, since the browser can't run IDNA reliably.
 */

import { parseSecondsInput } from "./seconds";

export const MAX_LABEL_LEN = 63;
export const MAX_NAME_LEN = 253;

// RFC 1123 host label: LDH, 1–63, no leading/trailing hyphen.
const HOST_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
// RFC 2181 owner label as constrained by the backend: LDH + underscore.
const DNS_LABEL_RE = /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/;
// A control character (incl. newline) — never valid in any name.
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x1f\x7f]/;

function isAscii(s: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /^[\x00-\x7f]*$/.test(s);
}

/** Validate a single RFC 1123 host label. Returns an error string or null. */
export function hostLabelError(label: string): string | null {
  if (!label) return "contains an empty label";
  if (!isAscii(label))
    return `label "${label}" must be ASCII (use its punycode xn-- form)`;
  if (label.length > MAX_LABEL_LEN)
    return `label "${label}" exceeds ${MAX_LABEL_LEN} characters`;
  if (!HOST_LABEL_RE.test(label))
    return `label "${label}" is not a valid host label (letters, digits and hyphens only; no leading or trailing hyphen)`;
  return null;
}

/** Validate a dotted RFC 1123 host name (IPAM / DHCP reservation hostname). */
export function hostnameError(name: string): string | null {
  const raw = name.trim();
  if (!raw) return "must not be empty";
  const body = raw.endsWith(".") ? raw.slice(0, -1) : raw;
  if (!body) return "must not be the root domain";
  for (const label of body.split(".")) {
    const err = hostLabelError(label);
    if (err) return err;
  }
  if (body.length > MAX_NAME_LEN) return `exceeds ${MAX_NAME_LEN} characters`;
  return null;
}

/**
 * Whether `<hostname>.<zone>` fits a DNS name (issue #2072): at most 253
 * characters of dotted presentation form (255 octets on the wire), the
 * whole name and not just the hostname. Mirrors `name_in_zone_error` in
 * `app/core/dns_names.py`.
 */
export function nameInZoneError(host: string, zone: string): string | null {
  const h = host.trim().replace(/\.+$/, "");
  const z = zone.trim().replace(/\.+$/, "");
  if (!h || !z) return null;
  const full = `${h}.${z}`;
  if (full.length > MAX_NAME_LEN)
    return `"${h.length > 40 ? h.slice(0, 37) + "..." : h}" in zone "${z}" makes a ${full.length}-character name; a DNS name holds at most ${MAX_NAME_LEN}. Shorten the hostname or choose another zone.`;
  return null;
}

/** Validate a DNS record owner (RFC 2181 — permits `_`, leftmost `*`, and `@`). */
export function recordOwnerError(name: string): string | null {
  const raw = name.trim();
  if (raw === "" || raw === "@") return null; // apex
  if (CONTROL_RE.test(raw)) return "contains a control character";
  const body = raw.endsWith(".") ? raw.slice(0, -1) : raw;
  if (!body) return null;
  const parts = body.split(".");
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (part === "*") {
      if (i === 0) continue; // wildcard only as leftmost label
      return "a '*' wildcard is only valid as the leftmost label";
    }
    if (!part) return "contains an empty label";
    if (!isAscii(part))
      return `label "${part}" must be ASCII (use its punycode xn-- form)`;
    if (part.length > MAX_LABEL_LEN)
      return `label "${part}" exceeds ${MAX_LABEL_LEN} characters`;
    if (!DNS_LABEL_RE.test(part))
      return `label "${part}" is not a valid DNS label (letters, digits, hyphen and underscore only; no leading or trailing hyphen)`;
  }
  if (body.length > MAX_NAME_LEN) return `exceeds ${MAX_NAME_LEN} characters`;
  return null;
}

/** Validate an FQDN (zone name, domain-name option). Permits `_` labels. */
export function fqdnError(name: string): string | null {
  const raw = name.trim();
  if (!raw) return "must not be empty";
  const body = raw.endsWith(".") ? raw.slice(0, -1) : raw;
  if (!body) return "must not be the root domain";
  for (const label of body.split(".")) {
    if (!label) return "contains an empty label";
    if (!isAscii(label))
      return `label "${label}" must be ASCII (use its punycode xn-- form)`;
    if (label.length > MAX_LABEL_LEN)
      return `label "${label}" exceeds ${MAX_LABEL_LEN} characters`;
    if (!DNS_LABEL_RE.test(label))
      return `label "${label}" is not a valid domain label`;
  }
  if (body.length > MAX_NAME_LEN) return `exceeds ${MAX_NAME_LEN} characters`;
  return null;
}

/**
 * The lookup kind of a zone named `name` (#1310): `reverse` for a name under
 * `in-addr.arpa` / `ip6.arpa`, `forward` for every other. Mirror of
 * `zone_kind_for_name` (`app/services/dns/name_scope.py`): for a primary zone
 * the API takes an omitted kind from the name the same way and refuses
 * `forward` for a reverse-lookup name, since IPAM publishes PTR records only
 * into reverse zones. Label-wise, like the server: `notin-addr.arpa` is
 * forward.
 */
export function zoneKindForName(name: string): "forward" | "reverse" {
  const labels = name.trim().toLowerCase().split(".").filter(Boolean);
  const tree = labels.slice(-2).join(".");
  return tree === "in-addr.arpa" || tree === "ip6.arpa" ? "reverse" : "forward";
}

/**
 * A list of zone names for one line of text, cut to the first `max` with a
 * count of the rest: a subnet wider than a /24 has a reverse zone per /24
 * (#1840), so a /17 has 128 and a plain join would fill the dialog.
 */
export function summarizeZoneNames(names: string[], max = 4): string {
  if (names.length <= max) return names.join(", ");
  return `${names.slice(0, max).join(", ")} + ${names.length - max} more`;
}

/** RFC 2181 §8: the largest TTL, and what the API accepts (#2073). */
export const DNS_TTL_MAX = 2147483647;

/**
 * A TTL field's text as seconds (#2073 / #2074): `null` when blank, a reason
 * string when it is not a whole number in 0..DNS_TTL_MAX. Never `parseInt`:
 * it reads `"1h"` as 1 and `"1e3"` (a number input accepts it) as 1.
 */
export function parseTtlInput(
  text: string,
  bounds: { min: number; max: number } = { min: 0, max: DNS_TTL_MAX },
): number | null | string {
  return parseSecondsInput(text, bounds);
}

/** A DNS pool's TTL bounds: the API's `ge=1, le=86400` (`api/v1/dns/pools.py`). */
export const POOL_TTL_BOUNDS = { min: 1, max: 86400 } as const;

/** Whether a typed confirmation names the zone (trailing dot optional,
 *  case-insensitive) — the same comparison the server makes. */
export function confirmsZone(typed: string, zoneName: string): boolean {
  const norm = (s: string) => s.trim().replace(/\.$/, "").toLowerCase();
  return typed.trim() !== "" && norm(typed) === norm(zoneName);
}
