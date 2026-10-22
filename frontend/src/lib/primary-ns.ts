// The zone's Primary NS is the SOA MNAME, a host name BIND checks (#2075).
// Mirrors backend `primary_ns_error` (app/core/dns_names.py); the shared test
// vectors in primary-ns.test.ts keep the two in step. Empty is "unset".
const HOST_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/;

export function primaryNsError(value: string): string | null {
  if (value === "") return null;
  const body = value.endsWith(".") ? value.slice(0, -1) : value;
  if (!body.includes(".")) {
    return "Primary NS must be a fully qualified host name such as ns1.example.com. (a single label such as 'ns1' would be served as a name at the root, not under the zone)";
  }
  if (body.length > 253) return "Primary NS is longer than 253 characters";
  for (const label of body.split(".")) {
    if (label === "") return "Primary NS contains an empty label";
    if (label.length > 63) {
      return "Primary NS has a label longer than 63 characters";
    }
    if (!HOST_LABEL.test(label)) {
      return `Primary NS label "${label}" is not a host name label: letters, digits and hyphens only, no leading or trailing hyphen`;
    }
  }
  return null;
}
