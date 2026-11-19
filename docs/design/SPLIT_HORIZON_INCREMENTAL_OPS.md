# Split-horizon groups: shipping record ops incrementally, per view

> Design note for [#2242](https://github.com/spatiumnorth/spatiumddi/issues/2242), the structural cause of the DNS stall found in the #2240 scale lab. No code in this change; it fixes the shape so the implementation can be reviewed in slices. Status: proposal.

---

## 1. The problem

In a group **without** views, a record change is an op. `zones_structural` leaves `records` and `serial` out of the structural fingerprint (`_RECORD_DRIVEN_KEYS`, #1373), so the bundle ETag does not move, the agent applies the queued op over RFC 2136 to `127.0.0.1`, and a full bundle is needed only at bootstrap.

In a group **with** views (or geo steering), records are part of the structural fingerprint and the op path is switched off:

- `agent_bundle_render.render_and_store` stores `ships_ops = not rendered.has_views`.
- The same call runs `retire_queued_ops`, which marks the server's queued record ops `applied`, because the body they would have been applied from already contains them.
- The agent, whose BIND9 driver cannot aim an nsupdate at a view (a loopback update lands in whichever view matches `127.0.0.1`), takes the change by `rndc reconfig`/reload of re-rendered zone files.

So one record change costs **one full render per server in the group**: the whole record set read from PostgreSQL, serialised, hashed and gzipped (N servers, N renders; the group's bundle is not shared between servers), then a full re-read of every changed zone file on the agent. At 2M records and 7 servers (#2240) the renders queue faster than they finish; the op backlog reached 5.69M and servers fell behind.

What already limits the damage, and stays: the per-server render lock plus DIRTY flag (a seed of 1,000 batches becomes a handful of renders), the fleet render slots, and the wake bus. They bound how many renders run; they cannot make a render cheaper than "read every record of the group".

## 2. Goal and non-goals

Goal: a record change in a split-horizon group ships as an op scoped to the view(s) that serve it, applied by the agent into that view's copy of the zone. A full render happens only on structural change, exactly as without views. Convergence stays decided by the ETag; ops stay advisory-ordered deltas on top of it (non-negotiables #5, #8, #9).

Non-goals: changing the flat-group path; changing how a zone's copies are chosen (`views_rendering_zone`, `records_for_view`, `places_zone`).

## 3. Design

### 3.1 The ETag split moves records out of the structural payload under views too

`_zone_structural(zone, has_views)` stops keeping the record-driven keys under views. A record-only change then leaves `structural_etag` unchanged, as in a flat group. The full ETag (what the agent compares) still covers the body, so a re-render is still triggered whenever the stored body is stale; what changes is that `ships_ops` can be true and the agent is not forced to reload from the body.

The hard part is which writes are *record-only*. Under views a record write can change which copies exist (a record scoped to a view that does not yet render the zone makes `views_rendering_zone` place a new copy; geo steering changes the member set a view answers with, `records_for_view`). These **placement changes** are structural and must keep moving the structural ETag. So the structural payload carries, per zone, the **placement** (`{view_name}` set and, for geo, the member-set key per view) but not the records.

### 3.2 Ops carry the view

`DNSRecordOp` has `server_id`, `zone_name` and (since #964's follow-up) `zone_id`, but no view discriminator, and `sweep_zone_ops` is name-scoped on that account. This design adds a nullable `view_name` (or `view_id`) column to the op:

- written by the enqueue chokepoint (`enqueue_record_op`) from the record's zone (`zone.view_id`), one op per view that serves the record (`records_for_view` is the single predicate; a record in a global zone fans out to every view that renders the zone, which is the same set the render writes today);
- `NULL` on rows queued before the column and in flat groups, meaning "the only copy";
- `sweep_zone_ops` can then become exact under views; the over-sweep it documents stops being an accepted cost.

This needs a migration (backup-catalogue registration, per the `new-migration` recipe).

### 3.3 Agent: apply into the right view

BIND chooses the view by `match-clients`, which can select by TSIG key. #920 already gives every view a derived key (`tsig.view_transfer_key`, `transfer_key` in the bundle's view dict, `_view_transfer_keys` / `_render_match_clients` in the BIND9 driver) so the control plane's AXFR lands in a chosen view. The op path reuses it:

- the agent signs each op's nsupdate with the key of `op["view_name"]` (the `dns.update.Update` already takes a keyring), so named routes it into that view without relying on the source address;
- the key's `update-policy` grant on the zone is the same as the loopback key's (`ANY` on the SOA included, #2835); the renderer adds the per-view key to each zone's grant in that view only;
- an op naming a view the agent's rendered config does not have, or a bundle that predates `transfer_key`, is not applied: the op is returned `failed` with the reason, and the next full render (which the ETag will trigger, because the op's view is a placement the structural payload covers) carries it. Never a silent drop.

PowerDNS and Technitium agents have no split-horizon rendering in this repo at the same granularity; they keep `ships_ops = not has_views` until each driver declares a `per_view_ops` capability. The capability, not the group's view count, decides `ships_ops`.

### 3.4 Retire and ack

`retire_queued_ops` stops running for a view-capable agent; the ops ship and are acked through the existing in-flight/applied lifecycle (`page_pending_ops`, dispatch, `mark_ops_applied`). `retire_queued_ops` remains for placement changes (a re-render does cover those ops) and as the fallback for non-capable drivers, using the same `_covered_by` snapshot gate.

### 3.5 Rollout

The agent advertises `per_view_ops` in its poll. The control plane ships view-scoped ops only to an agent that does, and keeps today's path for the rest, so a mixed fleet (control plane upgraded first, agents later) converges. No flag day.

## 4. Slices

1. **This note** (docs only).
2. Measurement: a render counter (`dns_agent_bundle_renders_total{reason}`) and a test pinning "one record change in a split-horizon group = N renders" today, so slice 4's effect is demonstrable and a regression is visible.
3. Op `view_name` column + enqueue fan-out + exact sweep; still `ships_ops = False` under views (no behaviour change; ops queued under views are retired as before).
4. Structural payload carries placement not records; agent `per_view_ops` capability and per-view keyed nsupdate; `ships_ops` turned on for capable agents; `retire_queued_ops` limited to placement changes.
5. Geo steering (`records_for_view` with member filtering) enabled last; until then a geo-active group stays on the re-render path.

## 5. Risks and how each is covered

| Risk | Handling |
|---|---|
| A record op lands in the wrong view | The view key selects the view, not the source address; an integration test with two views serving the same name asserts each view answers its own record. |
| A placement change treated as record-only (zone never appears in a view) | Placement is in the structural payload; a test per `places_zone` / `views_rendering_zone` case. |
| Agent and control plane disagree after a missed op | Unchanged: the ETag of the full body is the source of truth, and the sync-with-servers drift report (#1133, reads each zone from the view that holds it) detects divergence. |
| Mixed-version fleet | Capability advertised by the agent (3.5). |
| Op backlog on an agent that cannot apply views | Those agents keep `retire_queued_ops`; the backlog of #2240 came from exactly that path being the only one. |

## 6. Open questions

- One op per view versus one op naming a list of views. One-per-view keeps the existing per-op ack and retry; the cost is fan-out in a global zone with many views.
- Whether the per-view key should be a distinct `update` key from the transfer key, so an update grant cannot be used to transfer and the reverse. Cheap to separate; costs one more derived secret per view.
- DNSSEC-signed zones under views: the agent's signed-zone serial handling (`raw_before` in the op path) is per zone name today and would need to be per `(view, zone)`.
