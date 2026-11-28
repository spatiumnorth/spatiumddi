/** "10.20.0.0/16 via 10.9.0.1 metric 100" per line → route objects. */
export function parseRoutes(
  text: string,
): { destination: string; gateway: string; metric: number | null }[] {
  const out: { destination: string; gateway: string; metric: number | null }[] =
    [];
  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  lines.forEach((line, i) => {
    const m = /^(\S+)\s+via\s+(\S+)(?:\s+metric\s+(\d+))?$/i.exec(line);
    if (!m) {
      throw new Error(
        `Route line ${i + 1} (“${line}”) is not in the form “10.20.0.0/16 via 10.9.0.1” (optionally “metric 100”).`,
      );
    }
    out.push({
      destination: m[1],
      gateway: m[2],
      metric: m[3] ? Number(m[3]) : null,
    });
  });
  return out;
}
