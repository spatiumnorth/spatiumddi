/**
 * Client as ``ip:port`` (IPv6 as ``[addr]:port``) instead of BIND's
 * ``ip#port`` (#4248). Display only: filters and the raw line keep the
 * bare address / original text. An IPv4-mapped IPv6 address is shown as
 * the IPv4 address it carries; no port means no suffix.
 */
export function formatClientEndpoint(ip: string, port?: number | null): string {
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  const addr = mapped ? mapped[1] : ip;
  if (!port) return addr;
  return addr.includes(":") ? `[${addr}]:${port}` : `${addr}:${port}`;
}
