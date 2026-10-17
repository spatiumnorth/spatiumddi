/**
 * Bulk-allocate hostname template, mirroring the server's expansion and
 * validation (`_expand_bulk_template`, `_bulk_template_format_error` and
 * `validate_host_label` in backend). The dialog previews exactly the names the
 * server will store (#2071); keep the three in step.
 */

const BULK_TEMPLATE_RE = /\{(n|oct[1-4])(?::([^}]+))?\}/g;
// `{n}` format specs the server accepts: plain, d, x, X, zero-padded 0<w>d.
const N_SPEC_RE = /^(|d|x|X|0[1-9][0-9]*d)$/;
// RFC 1123 host label, 1-63 chars, no leading / trailing hyphen.
const HOST_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

export function expandTemplate(
  template: string,
  ip: string,
  n: number,
  v6: boolean,
): string {
  const octets = v6 ? [] : ip.split(".");
  return template.replace(
    BULK_TEMPLATE_RE,
    (_match, token: string, fmt: string | undefined) => {
      if (token === "n") {
        if (!fmt || fmt === "d") return String(n);
        const padMatch = /^0([1-9][0-9]*)d$/.exec(fmt);
        if (padMatch) return String(n).padStart(Number(padMatch[1]), "0");
        if (fmt === "x") return n.toString(16);
        if (fmt === "X") return n.toString(16).toUpperCase();
        return String(n);
      }
      const idx = Number(token[3]) - 1;
      return octets[idx] ?? "";
    },
  );
}

/** Why the server would refuse the template's token forms, or null. */
export function templateFormatError(template: string): string | null {
  const re = /\{([^{}]*)\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(template)) !== null) {
    const inner = m[1];
    const bang = /^n!/.test(inner);
    if (bang)
      return `Template token {${inner}}: conversions are not supported.`;
    const nm = /^n:(.*)$/.exec(inner);
    if (nm && !N_SPEC_RE.test(nm[1])) {
      return `Template token {${inner}} is not supported; use {n}, {n:03d} (zero-pad), {n:x} or {n:X}.`;
    }
  }
  return null;
}

/** Reason `name` is not a host label, or null (lower-casing aside). */
export function hostLabelError(name: string): string | null {
  if (!name) return "Template renders an empty name";
  if (!HOST_LABEL_RE.test(name)) {
    return `Renders to '${name}' — host names are letters, digits and hyphens, no leading or trailing hyphen, at most 63 characters`;
  }
  return null;
}

/** Normalized (lower-case) name the server stores for a valid rendering. */
export function storedHostname(name: string): string {
  return name.toLowerCase();
}
