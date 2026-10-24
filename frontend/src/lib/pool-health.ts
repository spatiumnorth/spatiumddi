// Age for the chip: s / m under an hour, then h, then d. (The shared
// formatAge keeps minutes up to 90 min, so an hour-old check read "61m".)
function chipAge(fromIso: string, now: number): string | null {
  const t = Date.parse(fromIso);
  if (!Number.isFinite(t)) return null;
  const s = Math.max(0, Math.floor((now - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

// Last-checked cell of a DNS pool member (#2312). `check_stale` is decided by
// the server (older than 3 x the pool's check interval), the same test the
// `dns_pool_health_stale` alert uses; this only words it. A stale member is
// STILL SERVED when it last checked healthy (pools fail open), so the cell says
// so rather than leaving "healthy" unqualified.

export interface MemberCheckInput {
  last_check_state: string;
  last_check_at: string | null;
  check_stale?: boolean;
}

export interface MemberCheckCell {
  text: string;
  stale: boolean;
  title: string;
}

export function memberCheckCell(
  m: MemberCheckInput,
  now: number = Date.now(),
): MemberCheckCell {
  if (!m.last_check_at) return { text: "\u2014", stale: false, title: "" };
  if (!m.check_stale) return { text: "", stale: false, title: "" };
  const age = chipAge(m.last_check_at, now);
  return {
    text: age ? `stale \u00b7 ${age} ago` : "stale",
    stale: true,
    title:
      m.last_check_state === "healthy"
        ? "Health checks have stopped refreshing this verdict. The member last checked healthy and is still being served."
        : "Health checks have stopped refreshing this verdict.",
  };
}
