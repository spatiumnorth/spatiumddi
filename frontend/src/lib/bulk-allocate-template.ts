/**
 * Bulk-allocate hostname template, mirroring the server (#2071):
 *
 *  - `parseTemplate` is Python's `string.Formatter().parse`, which the
 *    server tokenizes with (escaped `{{` / `}}`, nested braces in a spec,
 *    `!conversion`, and the same "malformed" verdicts);
 *  - `templateFormatError` is `_bulk_template_format_error`;
 *  - `expandTemplate` is `_expand_bulk_template` for the specs that pass;
 *  - `hostLabelError` / `storedHostname` are `validate_host_label`;
 *  - `templateStartError` is `BulkAllocateRequest.template_start`'s bounds.
 *
 * Both sides are pinned to `bulk-allocate-template.vectors.json`, read by the
 * vitest beside this file and by
 * `backend/tests/test_ipam_bulk_allocate_template_vectors_2071.py`, so the
 * live preview cannot drift from the names the server stores.
 */

/** Upper bound on the iterator start (the server's `_BULK_TEMPLATE_START_MAX`). */
export const TEMPLATE_START_MAX = 999_999_999;

const TEMPLATE_FIELDS = new Set(["n", "oct1", "oct2", "oct3", "oct4"]);
// Token format specs the server accepts (`_BULK_SPEC_RE`): plain, d, x, X,
// each optionally zero-padded to a width of at most 99.
const SPEC_RE = /^(?:0([1-9][0-9]?))?([dxX]?)$/;
// RFC 1123 host label (core/dns_names `_HOST_LABEL_RE`).
const HOST_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
// eslint-disable-next-line no-control-regex
const ASCII_RE = /^[\x00-\x7f]*$/;

export interface TemplatePart {
  literal: string;
  field: string | null;
  spec: string;
  conversion: string | null;
}

/** `string.Formatter().parse`; throws an Error carrying Python's message. */
export function parseTemplate(s: string): TemplatePart[] {
  const out: TemplatePart[] = [];
  let i = 0;
  while (i < s.length) {
    // Literal text up to the next brace.
    const start = i;
    let c = "";
    let markup = false;
    while (i < s.length) {
      c = s[i++];
      if (c === "{" || c === "}") {
        markup = true;
        break;
      }
    }
    const atEnd = i >= s.length;
    let len = i - start;
    if (markup && c === "}" && (atEnd || s[i] !== "}")) {
      throw new Error("Single '}' encountered in format string");
    }
    if (markup && atEnd && c === "{") {
      throw new Error("Single '{' encountered in format string");
    }
    if (markup) {
      if (s[i] === c) {
        // An escaped brace: literal text keeping one of the pair.
        i++;
        markup = false;
      } else {
        len--;
      }
    }
    const literal = s.slice(start, start + len);
    if (!markup) {
      out.push({ literal, field: null, spec: "", conversion: null });
      continue;
    }
    // A field, up to its closing brace. In the field name a `[...]` index
    // hides braces and a `{` is an error; after the first `:` or `!` (and
    // its conversion character) a spec may nest braces, so they are counted.
    let count = 1;
    let inName = true;
    const fieldStart = i;
    let fieldEnd = -1;
    while (i < s.length) {
      const d = s[i++];
      if (inName) {
        if (d === "[") {
          while (i < s.length && s[i] !== "]") i++;
        } else if (d === "{") {
          throw new Error("unexpected '{' in field name");
        } else if (d === ":" || d === "!") {
          // A conversion is the one character after `!`, whatever it is
          // (`{n!}}` converts with `}`).
          if (d === "!" && i < s.length) i++;
          inName = false;
        } else if (d === "}") {
          fieldEnd = i - 1;
          break;
        }
      } else if (d === "{") {
        count++;
      } else if (d === "}" && --count === 0) {
        fieldEnd = i - 1;
        break;
      }
    }
    if (fieldEnd < 0) throw new Error("expected '}' before end of string");
    out.push({ literal, ...parseField(s.slice(fieldStart, fieldEnd)) });
  }
  return out;
}

function parseField(f: string): Omit<TemplatePart, "literal"> {
  let i = 0;
  let c = "";
  while (i < f.length) {
    c = f[i++];
    if (c === "{") throw new Error("unexpected '{' in field name");
    if (c === "[") {
      while (i < f.length && f[i] !== "]") i++;
      continue;
    }
    if (c === ":" || c === "!") {
      const field = f.slice(0, i - 1);
      let conversion: string | null = null;
      if (c === "!") {
        if (i >= f.length) {
          throw new Error(
            "end of string while looking for conversion specifier",
          );
        }
        conversion = f[i++];
        if (i < f.length && f[i++] !== ":") {
          throw new Error("expected ':' after conversion specifier");
        }
      }
      return { field, spec: f.slice(i), conversion };
    }
  }
  return { field: f, spec: "", conversion: null };
}

/** Why the server refuses the template's token forms, or null. */
export function templateFormatError(template: string): string | null {
  if (!ASCII_RE.test(template)) {
    return "Template must be ASCII; host names are letters, digits and hyphens.";
  }
  let parts: TemplatePart[];
  try {
    parts = parseTemplate(template);
  } catch (e) {
    return `Template is malformed: ${(e as Error).message}`;
  }
  for (const p of parts) {
    if (p.field === null) continue;
    if (p.conversion) {
      return `Template token {${p.field}!${p.conversion}}: conversions are not supported.`;
    }
    if (TEMPLATE_FIELDS.has(p.field) && !SPEC_RE.test(p.spec)) {
      const f = p.field;
      return `Template token {${f}:${p.spec}} is not supported; use {${f}}, {${f}:03d} (zero-pad), {${f}:x} or {${f}:X}.`;
    }
  }
  return null;
}

function formatValue(value: number | string, spec: string): string {
  // An IPv4 octet token on an IPv6 address is "" (Python's fallback too).
  if (typeof value === "string") return value;
  const m = SPEC_RE.exec(spec);
  if (!m) return String(value); // refused by templateFormatError anyway
  const digits =
    m[2] === "x"
      ? value.toString(16)
      : m[2] === "X"
        ? value.toString(16).toUpperCase()
        : String(value);
  return m[1] ? digits.padStart(Number(m[1]), "0") : digits;
}

/** The rendered (not yet normalized) name for one address. */
export function expandTemplate(
  template: string,
  ip: string,
  n: number,
  v6: boolean,
): string {
  let parts: TemplatePart[];
  try {
    parts = parseTemplate(template);
  } catch {
    return template;
  }
  const octets = v6 ? [] : ip.split(".");
  return parts
    .map((p) => {
      if (p.field === null) return p.literal;
      let value: number | string;
      if (p.field === "n") {
        value = n;
      } else if (/^oct[1-4]$/.test(p.field)) {
        const o = octets[Number(p.field[3]) - 1];
        value = o === undefined ? "" : Number(o);
      } else {
        // Unknown token: re-emitted literally, as the server does.
        const conv = p.conversion ? `!${p.conversion}` : "";
        const spec = p.spec ? `:${p.spec}` : "";
        return `${p.literal}{${p.field}${conv}${spec}}`;
      }
      return p.literal + formatValue(value, p.spec);
    })
    .join("");
}

/** Reason `name` is not a host label, or null. */
export function hostLabelError(name: string): string | null {
  if (!name) return "renders an empty name";
  if (name.length > 63) return `'${name}' exceeds 63 characters`;
  if (!HOST_LABEL_RE.test(name)) {
    return `'${name}' is not a host name: letters, digits and hyphens, no leading or trailing hyphen`;
  }
  return null;
}

/** Normalized (lower-case) name the server stores for a valid rendering. */
export function storedHostname(name: string): string {
  return name.toLowerCase();
}

/** Why the server refuses this iterator start, or null. */
export function templateStartError(n: number): string | null {
  if (!Number.isInteger(n) || n < 0 || n > TEMPLATE_START_MAX) {
    return `Iterator start must be a whole number from 0 to ${TEMPLATE_START_MAX}`;
  }
  return null;
}
