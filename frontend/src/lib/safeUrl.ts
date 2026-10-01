// Links built from data the operator did not type (#1361).
//
// A URL from PeeringDB or the GitHub API goes into an <a href> only when
// it is http(s). React 18 warns about a javascript: href and renders it
// anyway, so the check cannot be left to React, to the upstream's own
// validation, or to the CSP alone.

/**
 * The URL to put in an href, or null when the value must not become a
 * link: unparseable, relative, or any scheme other than http/https.
 *
 * Returns the parsed form, so the href is exactly what was checked. The
 * URL parser strips the tabs, newlines and leading control characters a
 * browser also ignores, which is what makes "java\tscript:" and
 * " javascript:" read as javascript: here rather than slip through.
 */
export function safeExternalHref(
  value: string | null | undefined,
): string | null {
  if (!value) return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  // URL lowercases the scheme, so "HTTPS:" and "JAVASCRIPT:" land here
  // already folded.
  const scheme = parsed.protocol.toLowerCase();
  return scheme === "http:" || scheme === "https:" ? parsed.href : null;
}
