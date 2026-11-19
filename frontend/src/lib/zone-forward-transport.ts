// A forward zone's OWN upstream transport (#2121). It does not inherit the
// group's forward_transport, which covers the group's resolver forwarders
// only. Mirrors `_check_zone_forward_transport` and
// `_ZONE_TRANSPORT_DRIVER_GATE` in backend/app/api/v1/dns/router.py; the
// API is the authority, this only stops a save the API would refuse.
import { hostnameError } from "./dnsNames";

export type ZoneForwardTransport = "do53" | "tls" | "https" | "quic";

export const ZONE_FORWARD_TRANSPORT_LABELS: Record<
  ZoneForwardTransport,
  string
> = {
  do53: "Plain DNS (port 53)",
  tls: "DNS-over-TLS (port 853)",
  https: "DNS-over-HTTPS",
  quic: "DNS-over-QUIC",
};

// The drivers that can forward a zone over each encrypted transport.
const DRIVER_GATE: Record<
  Exclude<ZoneForwardTransport, "do53">,
  readonly string[]
> = {
  tls: ["bind9", "technitium"],
  https: ["technitium"],
  quic: ["technitium"],
};

// A group with no servers yet reads as BIND9, as on the API.
function effectiveDrivers(drivers: readonly string[]): readonly string[] {
  return drivers.length > 0 ? drivers : ["bind9"];
}

/** The transports every driver in the group can forward a zone over. */
export function zoneTransportOptions(
  drivers: readonly string[],
): ZoneForwardTransport[] {
  const eff = effectiveDrivers(drivers);
  const out: ZoneForwardTransport[] = ["do53"];
  for (const t of ["tls", "https", "quic"] as const) {
    if (eff.every((d) => DRIVER_GATE[t].includes(d))) out.push(t);
  }
  return out;
}

/** Why the API would refuse this transport + hostname, or null. */
export function zoneTransportError(
  transport: ZoneForwardTransport,
  hostname: string,
  drivers: readonly string[],
): string | null {
  if (transport === "do53") return null;
  if (!zoneTransportOptions(drivers).includes(transport)) {
    return `${ZONE_FORWARD_TRANSPORT_LABELS[transport]} is not supported for a forward zone by every server in this group`;
  }
  if (!hostname.trim()) {
    return "TLS hostname is required: it is the name the upstream's certificate is checked against";
  }
  const err = hostnameError(hostname);
  return err ? `TLS hostname ${err}` : null;
}
