/**
 * The request portal's words (#3252, #3253).
 *
 * The portal's form is rendered from each operation's args model, which was
 * written for the Copilot: its titles are schema names ("Block Id"), its
 * descriptions speak to a model ("UUID of the parent IP block …") and its
 * previews are Markdown. The people reading the portal are requesters and
 * approvers, so this module is the one place those are turned into words they
 * use. Unknown fields fall back to a generic clean-up, so a field added to an
 * operation still renders sensibly before anyone adds a row here.
 */

export const IP_STATUSES = [
  "allocated",
  "available",
  "deprecated",
  "dhcp",
  "orphan",
  "reserved",
  "static_dhcp",
] as const;

export const DNS_RECORD_TYPES = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "TXT",
  "NS",
  "PTR",
  "SRV",
  "CAA",
  "TLSA",
  "SSHFP",
  "NAPTR",
  "LOC",
] as const;

type FieldWords = {
  label: string;
  hint?: string;
  options?: readonly string[];
  /** How each option reads in the picker; the submitted value is the key. */
  optionLabels?: Record<string, string>;
};

const IP_STATUS_LABELS: Record<string, string> = {
  allocated: "Allocated",
  available: "Available",
  deprecated: "Deprecated",
  dhcp: "DHCP (dynamic)",
  orphan: "Orphan",
  reserved: "Reserved",
  static_dhcp: "Static DHCP",
};

const WORDS: Record<string, FieldWords> = {
  block_id: {
    label: "Block",
    hint: "The block the new subnet is carved from.",
  },
  prefix_len: {
    label: "Prefix length",
    hint: "The size of the subnet: 24 for a /24, or 64 for an IPv6 /64.",
  },
  template_id: {
    label: "Template",
    // A free field, not a picker: there is no template picker yet, so the
    // hint says plainly that it takes the template's id.
    hint: "Optional. The id of an IPAM template to apply to the new subnet; your network team can give it to you.",
  },
  subnet_id: {
    label: "Subnet",
    hint: "The subnet the address is created in.",
  },
  address: { label: "IP address", hint: "For example 10.0.5.10." },
  ip_address: {
    label: "IP address",
    hint: "The address to reserve; it must fall inside the scope.",
  },
  status: {
    label: "Status",
    hint: "Defaults to allocated. A static DHCP address needs a MAC address.",
    options: IP_STATUSES,
    optionLabels: IP_STATUS_LABELS,
  },
  fqdn: {
    label: "Full host name",
    hint: "For example web01.prod.example.com.",
  },
  mac_address: { label: "MAC address", hint: "In any standard format." },
  zone_id: { label: "Zone", hint: "The zone the record is created in." },
  scope_id: { label: "Scope", hint: "The DHCP scope the reservation is in." },
  record_type: { label: "Record type", options: DNS_RECORD_TYPES },
  ttl: {
    label: "TTL (seconds)",
    hint: "Leave blank to use the zone's default. Between 60 and 604800.",
  },
  priority: {
    label: "Priority",
    hint: "Needed for MX and SRV records.",
  },
  weight: { label: "Weight", hint: "Needed for SRV records." },
  port: { label: "Port", hint: "Needed for SRV records." },
};

// Words that differ by what is being asked for.
const KIND_WORDS: Record<string, Record<string, FieldWords>> = {
  dns_record: {
    name: {
      label: "Record name",
      hint: "Use @ for the zone apex. Enter only the host part: host1, not host1.example.com.",
    },
    value: {
      label: "Value",
      hint: "An IP for A and AAAA records, a target host name for CNAME and NS, the text for TXT.",
    },
  },
  subnet: { name: { label: "Name", hint: "Optional." } },
};

function cleanText(s: string): string {
  return s.replace(/``/g, "").replace(/`/g, "").trim();
}

/** "Prefix Len" / "prefix_len" -> a sentence-case fallback label. */
function fallbackLabel(name: string, title?: string): string {
  const base = (title ?? name.replace(/_/g, " "))
    .replace(/\bId\b/g, "")
    .replace(/\bLen\b/g, "length")
    .replace(/\bIp\b/g, "IP")
    .replace(/\bMac\b/g, "MAC")
    .replace(/\bTtl\b/g, "TTL")
    .replace(/\bFqdn\b/g, "full host name")
    .replace(/\s+/g, " ")
    .trim();
  if (!base) return name;
  return base.charAt(0).toUpperCase() + base.slice(1).toLowerCase();
}

export function fieldWords(
  kind: string,
  name: string,
  title?: string,
  description?: string,
): FieldWords {
  const known = KIND_WORDS[kind]?.[name] ?? WORDS[name];
  if (known) return known;
  const label = fallbackLabel(name, title);
  let hint = description ? cleanText(description) : undefined;
  // A picker or free field must never ask a person for an id.
  if (hint && /\buuid\b/i.test(hint)) hint = undefined;
  return { label, hint };
}

/**
 * Markdown a Copilot preview carries (`code`, **bold**), as plain text.
 *
 * Only paired marks are removed: a lone `*` is data, the wildcard owner in a
 * DNS record request (`*.example.com`) above all. The result is rendered as a
 * React text node, so nothing here is ever interpreted as HTML.
 */
export function plainText(s: string): string {
  return s.replace(/\*\*(.+?)\*\*/g, "$1").replace(/`([^`]*)`/g, "$1");
}

type FieldError = {
  type?: unknown;
  loc?: unknown;
  msg?: unknown;
  ctx?: Record<string, unknown>;
};

/** One field error's words, by its Pydantic error ``type``. */
function errorWords(e: FieldError, field: string | null): string {
  const ctx = e.ctx ?? {};
  switch (e.type) {
    case "missing":
      return "is required";
    case "int_parsing":
    case "int_type":
    case "int_from_float":
      return "must be a whole number";
    case "float_parsing":
    case "float_type":
      return "must be a number";
    case "greater_than_equal":
      return `must be at least ${String(ctx.ge)}`;
    case "less_than_equal":
      return `must be at most ${String(ctx.le)}`;
    case "greater_than":
      return `must be more than ${String(ctx.gt)}`;
    case "less_than":
      return `must be less than ${String(ctx.lt)}`;
    case "string_too_short":
      return `must be at least ${String(ctx.min_length)} characters`;
    case "string_too_long":
      return `must be at most ${String(ctx.max_length)} characters`;
    case "string_type":
      return "must be text";
  }
  let m = typeof e.msg === "string" ? e.msg : "is not valid";
  m = m
    .replace(/^(Value error|Assertion failed),\s*/i, "")
    .replace(/^Input should be /i, "should be ")
    .trim();
  // "status must be one of …": the label already names the field.
  if (field) {
    for (const w of [field, field.replace(/_/g, " ")]) {
      if (m.toLowerCase().startsWith(`${w.toLowerCase()} `))
        m = m.slice(w.length + 1);
    }
  }
  return m.charAt(0).toLowerCase() + m.slice(1);
}

/**
 * The submit's field errors (#3253), named as the form labels each field.
 *
 * The server answers an args payload that does not validate with FastAPI's
 * own 422 shape, each entry located under ``body.args``, so the words come
 * from the error ``type`` and its ``ctx`` rather than from Pydantic's English.
 * Returns null for any other error, which the caller shows as it came.
 */
export function submitErrorWords(
  err: unknown,
  labelOf: (field: string) => string,
): string | null {
  const detail = (err as { response?: { data?: { detail?: unknown } } })
    ?.response?.data?.detail;
  if (!Array.isArray(detail) || detail.length === 0) return null;
  const parts: string[] = [];
  for (const raw of detail) {
    if (!raw || typeof raw !== "object") return null;
    const e = raw as FieldError;
    const loc = Array.isArray(e.loc) ? e.loc : [];
    if (loc[0] !== "body" || loc[1] !== "args") return null;
    const field = typeof loc[2] === "string" ? loc[2] : null;
    const text = errorWords(e, field);
    if (!field) {
      parts.push(text.charAt(0).toUpperCase() + text.slice(1));
      continue;
    }
    const label = labelOf(field);
    // "Status must be one of …" reads whole; anything else needs a colon.
    parts.push(
      /^(is |must |should )/.test(text)
        ? `${label} ${text}`
        : `${label}: ${text}`,
    );
  }
  const out = parts.join("; ");
  return /[.!?]$/.test(out) ? out : `${out}.`;
}
