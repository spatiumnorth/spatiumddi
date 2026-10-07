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
