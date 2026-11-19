/** #980 — reading the DHCP packet-loss counters without lying about them.
 *
 * Two counters ride on every metric bucket and they do not mean the same
 * thing:
 *
 *  * `socket_drop` — the kernel discarded the datagram because Kea's receive
 *    buffer was full, so Kea never saw it. Unambiguous loss, usually a node
 *    short of CPU.
 *  * `receive_drop` — Kea read the packet and discarded it, which INCLUDES
 *    doing so on purpose: a blocklisted MAC (the shipped DHCP MAC blocklist
 *    renders a Kea `DROP` class) or an HA standby declining an out-of-scope
 *    query both land here.
 *
 * A third, `queue_evicted` (#2889), is loss like `socket_drop` one stage
 * later: DHCPv4 requests Kea read and then evicted from its full packet
 * queue during a burst. No Kea counter records it; the agent derives it.
 *
 * So everything user-facing reads `socket_drop` + `queue_evicted`, never
 * `receive_drop`. Extracted from the
 * server-detail modal because the null handling below is the load-bearing
 * property of the whole feature and is invisible to `tsc`.
 */

/** One bucket, as the API sends it — deliberately looser than the generated
 *  type. `undefined` models a control plane older than #980, which omits the
 *  key entirely; the point of this module is that such a bucket must not read
 *  as "measured, no loss". */
export interface LossBucket {
  socket_drop?: number | null;
  queue_evicted?: number | null;
}

/**
 * Loss for one bucket — kernel drops plus queue evictions — or `null` when
 * neither was measured.
 *
 * `?? null` normalises at the boundary: the generated type says
 * `number | null`, but an omitted key arrives as `undefined` and every
 * downstream check is `!== null`. Without this a version-skewed API reads as
 * measured-and-zero — the one thing this feature exists not to say. One
 * unmeasured half adds nothing rather than voiding the other: a server
 * without a raw socket still measures its kernel drops.
 */
export function bucketLoss(b: LossBucket): number | null {
  const sock = b.socket_drop ?? null;
  const evicted = b.queue_evicted ?? null;
  if (sock === null && evicted === null) return null;
  return (sock ?? 0) + (evicted ?? 0);
}

export interface LossSummary {
  /** False when NOTHING in the window measured loss — an agent older than
   *  #980, or one that cannot read /proc/net/udp. Distinct from measuring
   *  zero, and must render as "not measured" rather than as a clean bill. */
  measured: boolean;
  total: number;
  /** #2889 — the part of `total` that was evicted from Kea's queue, and
   *  whether anything in the window measured it at all. */
  evicted: number;
  evictionMeasured: boolean;
}

/**
 * Roll a window of buckets into the three states the UI distinguishes:
 * measured and lossy, measured and clean, never measured.
 *
 * A window that mixes measured and unmeasured buckets counts as measured and
 * sums the ones that were: partial knowledge is still knowledge, and the
 * alternative would hide real loss behind one agent restart.
 */
export function summariseLoss(buckets: LossBucket[]): LossSummary {
  const measured = buckets
    .map(bucketLoss)
    .filter((v): v is number => v !== null);
  const evictions = buckets
    .map((b) => b.queue_evicted ?? null)
    .filter((v): v is number => v !== null);
  const evicted = evictions.reduce((a, v) => a + v, 0);
  const evictionMeasured = evictions.length > 0;
  if (measured.length === 0)
    return { measured: false, total: 0, evicted, evictionMeasured };
  return {
    measured: true,
    total: measured.reduce((a, v) => a + v, 0),
    evicted,
    evictionMeasured,
  };
}
