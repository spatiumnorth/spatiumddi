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

type FieldWords = { label: string; hint?: string; options?: readonly string[] };

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
    hint: "Optional. An IPAM template to apply to the new subnet.",
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

/** Markdown a Copilot preview carries, as plain text (`code`, **bold**). */
export function plainText(s: string): string {
  return s
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/`([^`]*)`/g, "$1")
    .replace(/[*`]/g, "");
}

const PAYLOAD_PREFIX = /^Invalid request payload\s*[—-]\s*/;

function plainMessage(msg: string, field: string): string {
  let m = msg.replace(/^Value error,\s*/i, "").trim();
  // "status must be one of …": the label already names the field.
  for (const w of [field, field.replace(/_/g, " ")]) {
    if (m.toLowerCase().startsWith(`${w} `)) m = m.slice(w.length + 1);
  }
  if (/^field required$/i.test(m) || /^Input should be a valid string/i.test(m))
    return "is required";
  if (/^Input should be a valid (integer|number)/i.test(m))
    return "must be a number";
  const ge = m.match(/^Input should be greater than or equal to (\S+)/i);
  if (ge) return `must be at least ${ge[1]}`;
  const le = m.match(/^Input should be less than or equal to (\S+)/i);
  if (le) return `must be at most ${le[1]}`;
  return m.charAt(0).toLowerCase() + m.slice(1);
}

/**
 * The submit's 400 is one string, "Invalid request payload — loc: msg; …".
 * Name each field as the form labels it and drop the validator's phrasing.
 * Anything that is not that shape is returned as it came.
 */
export function plainSubmitError(
  message: string,
  labelOf: (field: string) => string,
): string {
  if (!PAYLOAD_PREFIX.test(message)) return message;
  const parts = message
    .replace(PAYLOAD_PREFIX, "")
    .split("; ")
    .map((seg) => {
      const m = seg.match(/^([A-Za-z0-9_.]+): ([\s\S]*)$/);
      if (!m) return seg;
      const field = m[1].split(".")[0];
      const text = plainMessage(m[2], field);
      const label = labelOf(field);
      // "Status must be one of …" reads whole; "is required" needs the label.
      return /^(is |must |should )/.test(text)
        ? `${label} ${text}`
        : `${label}: ${text}`;
    });
  return parts.join("; ") + ".";
}
