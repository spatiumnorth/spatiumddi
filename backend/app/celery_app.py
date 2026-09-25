import importlib

from celery import Celery
from celery.schedules import crontab, schedule

from app.config import settings

celery_app = Celery(
    "spatiumddi",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "app.tasks.ipam_dns_sync",
        "app.tasks.ipam_utilization_recount",
        "app.tasks.dns",
        "app.tasks.dns_pull",
        "app.tasks.looking_glass",
        "app.tasks.dhcp_health",
        "app.tasks.dhcp_lease_cleanup",
        "app.tasks.dhcp_mac_blocks",
        "app.tasks.dhcp_mirror_sweep",
        "app.tasks.dhcp_pull_leases",
        "app.tasks.alerts",
        "app.tasks.conformity",
        "app.tasks.heartbeat",
        "app.tasks.oui_update",
        "app.tasks.backup_sweep",
        "app.tasks.backup_drill",
        "app.tasks.dns_threat",
        "app.tasks.prune_internal_errors",
        "app.tasks.prune_logs",
        "app.tasks.prune_metrics",
        "app.tasks.influxdb_push",
        "app.tasks.prune_multicast_memberships",
        "app.tasks.prune_pairing_codes",
        "app.tasks.firewall_lint_scan",
        "app.tasks.prune_revoked_appliances",
        "app.tasks.trash_purge",
        "app.tasks.ipam_reservation_sweep",
        "app.tasks.ipam_discovery",
        "app.tasks.subnet_utilization_snapshot",
        "app.tasks.reverse_dns",
        "app.tasks.dhcp_lease_history_prune",
        "app.tasks.update_check",
        "app.tasks.kubernetes_sync",
        "app.tasks.docker_sync",
        "app.tasks.proxmox_sync",
        "app.tasks.opnsense_sync",
        "app.tasks.panos_sync",
        "app.tasks.fortinet_sync",
        "app.tasks.meraki_sync",
        "app.tasks.tailscale_sync",
        "app.tasks.netbird_sync",
        "app.tasks.unifi_sync",
        "app.tasks.block_sync",
        "app.tasks.cloud_sync",
        "app.tasks.snmp_poll",
        "app.tasks.nmap",
        "app.tasks.pcap",
        "app.tasks.dns_pool_healthcheck",
        "app.tasks.dhcp_fingerprint",
        "app.tasks.event_outbox",
        "app.tasks.asn_whois_refresh",
        "app.tasks.rpki_roa_refresh",
        "app.tasks.bgp_hijack_poll",
        "app.tasks.domain_whois_refresh",
        "app.tasks.ai_digest",
        "app.tasks.audit_chain_verify",
        "app.tasks.upgrade_orchestrator",
        "app.tasks.time_bound_grant_sweep",
        "app.tasks.change_request_expiry",
        "app.tasks.acme",
        "app.tasks.tls_certs",
        "app.tasks.dnsbl_sweep",
        "app.tasks.schema_check",
        "app.tasks.wol_scheduler",
        "app.tasks.wol_calendar",
        "app.tasks.agent_bundles",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,  # Required for idempotency — task not acked until complete
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.tasks.ipam_dns_sync.*": {"queue": "ipam"},
        "app.tasks.ipam_utilization_recount.*": {"queue": "ipam"},
        "app.tasks.dns.*": {"queue": "dns"},
        "app.tasks.dns_pull.*": {"queue": "dns"},
        "app.tasks.dhcp_health.*": {"queue": "dhcp"},
        "app.tasks.dhcp_lease_cleanup.*": {"queue": "dhcp"},
        "app.tasks.dhcp_mac_blocks.*": {"queue": "dhcp"},
        "app.tasks.dhcp_mirror_sweep.*": {"queue": "dhcp"},
        "app.tasks.dhcp_pull_leases.*": {"queue": "dhcp"},
        "app.tasks.alerts.*": {"queue": "default"},
        "app.tasks.heartbeat.*": {"queue": "default"},
        "app.tasks.oui_update.*": {"queue": "default"},
        "app.tasks.backup_sweep.*": {"queue": "default"},
        "app.tasks.backup_drill.*": {"queue": "default"},
        "app.tasks.dns_threat.*": {"queue": "default"},
        "app.tasks.prune_internal_errors.*": {"queue": "default"},
        "app.tasks.prune_logs.*": {"queue": "default"},
        "app.tasks.prune_metrics.*": {"queue": "default"},
        "app.tasks.influxdb_push.*": {"queue": "default"},
        "app.tasks.subnet_utilization_snapshot.*": {"queue": "default"},
        "app.tasks.prune_multicast_memberships.*": {"queue": "default"},
        "app.tasks.prune_pairing_codes.*": {"queue": "default"},
        "app.tasks.firewall_lint_scan.*": {"queue": "default"},
        "app.tasks.trash_purge.*": {"queue": "default"},
        "app.tasks.ipam_reservation_sweep.*": {"queue": "ipam"},
        "app.tasks.ipam_discovery.*": {"queue": "ipam"},
        "app.tasks.reverse_dns.*": {"queue": "ipam"},
        "app.tasks.dhcp_lease_history_prune.*": {"queue": "dhcp"},
        "app.tasks.update_check.*": {"queue": "default"},
        "app.tasks.kubernetes_sync.*": {"queue": "default"},
        "app.tasks.docker_sync.*": {"queue": "default"},
        "app.tasks.proxmox_sync.*": {"queue": "default"},
        "app.tasks.opnsense_sync.*": {"queue": "default"},
        "app.tasks.panos_sync.*": {"queue": "default"},
        "app.tasks.fortinet_sync.*": {"queue": "default"},
        "app.tasks.meraki_sync.*": {"queue": "default"},
        "app.tasks.block_sync.*": {"queue": "default"},
        "app.tasks.tailscale_sync.*": {"queue": "default"},
        "app.tasks.netbird_sync.*": {"queue": "default"},
        "app.tasks.unifi_sync.*": {"queue": "default"},
        "app.tasks.cloud_sync.*": {"queue": "default"},
        "app.tasks.snmp_poll.*": {"queue": "default"},
        "app.tasks.nmap.*": {"queue": "default"},
        "app.tasks.pcap.*": {"queue": "default"},
        "app.tasks.dns_pool_healthcheck.*": {"queue": "dns"},
        "app.tasks.dhcp_fingerprint.*": {"queue": "dhcp"},
        "app.tasks.event_outbox.*": {"queue": "default"},
        "app.tasks.asn_whois_refresh.*": {"queue": "default"},
        "app.tasks.rpki_roa_refresh.*": {"queue": "default"},
        "app.tasks.bgp_hijack_poll.*": {"queue": "default"},
        "app.tasks.domain_whois_refresh.*": {"queue": "default"},
        "app.tasks.ai_digest.*": {"queue": "default"},
        "app.tasks.audit_chain_verify.*": {"queue": "default"},
        "app.tasks.time_bound_grant_sweep.*": {"queue": "default"},
        "app.tasks.change_request_expiry.*": {"queue": "default"},
        "app.tasks.acme.*": {"queue": "default"},
        "app.tasks.tls_certs.*": {"queue": "default"},
        "app.tasks.schema_check.*": {"queue": "default"},
        "app.tasks.wol_scheduler.*": {"queue": "default"},
        "app.tasks.wol_calendar.*": {"queue": "default"},
        # #1111 — DNS agent bundle renders. Their own queue so a 30–60 s
        # render of a million-row group never sits in front of the
        # latency-bound ipam/dns/dhcp work, and so an operator can give
        # them a dedicated worker (concurrency 1, its own memory cap).
        "app.tasks.agent_bundles.*": {"queue": "bundles"},
    },
    beat_schedule={
        # #1111 — every 30 s, enqueue a render for any enabled agent-based
        # DNS server whose newest stored bundle is behind its dirty
        # sequence (or absent). The mutating transaction already enqueued
        # one after commit; this is the belt and braces for a lost broker
        # message or a worker restart mid-render, bounding staleness to
        # one tick — the class of the long-poll's own 12 s wake tick.
        "dns-agent-bundle-sweep": {
            "task": "app.tasks.agent_bundles.render_missing_sweep",
            "schedule": schedule(run_every=30.0),
        },
        # Every 60 s, mark DNS agents as ``unreachable`` if their
        # heartbeat hasn't been seen within the staleness window
        # (issue #217 — this entry used to live in a separate
        # ``celery_app.conf.beat_schedule = {...}`` assignment that
        # was silently clobbered by this ``conf.update(beat_schedule
        # =...)`` call, so the sweep never fired and stale agents
        # stayed ``status='active'`` forever).
        "dns-agent-stale-sweep": {
            "task": "app.tasks.dns.agent_stale_sweep",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60s, flip a Looking Glass collector to ``unreachable`` when its
        # heartbeat has gone silent past the staleness window (#566).
        "lg-collector-stale-sweep": {
            "task": "app.tasks.looking_glass.collector_stale_sweep",
            "schedule": schedule(run_every=60.0),
        },
        # Every 5 min, re-run the IPAM/ASN/VRF matcher over every active
        # Looking Glass route — catches IPAM edits made between RIB
        # pushes that a route's own re-announce wouldn't otherwise
        # trigger a fresh resolve for (#566 Phase 3).
        "lg-route-reresolve-sweep": {
            "task": "app.tasks.looking_glass.reresolve_route_links",
            "schedule": schedule(run_every=300.0),
        },
        # Every 60s, fan-out health checks to every registered DNS server.
        "dns-health-sweep": {
            "task": "app.tasks.dns.check_all_dns_servers_health",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60s, fan-out health checks to every registered DHCP server.
        "dhcp-health-sweep": {
            "task": "app.tasks.dhcp_health.check_all_dhcp_servers_health",
            "schedule": schedule(run_every=60.0),
        },
        # Every 5 min, sweep DHCP leases whose expires_at has passed the grace
        # window and remove their mirrored IPAM rows (auto_from_lease=True).
        "dhcp-lease-cleanup": {
            "task": "app.tasks.dhcp_lease_cleanup.sweep_expired_leases",
            "schedule": schedule(run_every=300.0),
        },
        # Hourly backstop for reservation mirrors no release path freed (#620).
        # A healthy install frees nothing here, so the cadence only bounds how
        # long a stranded address stays stuck — it is not on any hot path.
        "dhcp-mirror-sweep": {
            "task": "app.tasks.dhcp_mirror_sweep.sweep_orphaned_mirrors",
            "schedule": schedule(run_every=3600.0),
        },
        # Every 60 s, tick the IPAM↔DNS auto-sync task. The task itself
        # checks ``PlatformSettings.dns_auto_sync_enabled`` and the per-run
        # interval, so changing cadence in the UI takes effect without
        # restarting celery-beat.
        "ipam-dns-auto-sync": {
            "task": "app.tasks.ipam_dns_sync.auto_sync_ipam_dns",
            "schedule": schedule(run_every=60.0),
        },
        # Every hour, recount cached IPAM utilization counters
        # (``Subnet.allocated_ips`` / ``utilization_percent`` + the
        # recursive ``IPBlock`` rollups) against the live row counts,
        # correcting drift from the estimate-a-delta code paths (address
        # importer, bulk integration reconcilers). Issue #521. Idempotent
        # + always-safe — it only touches derived counters, so there's no
        # opt-out gate; a converged install writes (and audits) nothing.
        "ipam-utilization-recount": {
            "task": "app.tasks.ipam_utilization_recount.recount_ipam_utilization",
            "schedule": schedule(run_every=3600.0),
        },
        # Every 60 s, dispatch IP-discovery sweeps for subnets whose
        # per-subnet interval has elapsed (issue #23). Per-subnet gating
        # lives in the task (``discovery_enabled`` + ``last_discovery_at``
        # vs ``discovery_interval_minutes``) so cadence changes in the UI
        # take effect without restarting beat.
        "ipam-discovery-dispatch": {
            "task": "app.tasks.ipam_discovery.dispatch_due_subnets",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, tick the reverse-DNS (PTR) auto-population sweep
        # (issue #41). The task gates on ``PlatformSettings.reverse_dns_enabled``
        # and the per-run interval, so cadence changes in the UI take effect
        # without restarting celery-beat.
        "reverse-dns-sweep": {
            "task": "app.tasks.reverse_dns.sweep_reverse_dns",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, tick the DNS pull-from-server task. The task itself
        # checks ``PlatformSettings.dns_pull_from_server_enabled`` and the
        # per-run interval, so cadence changes in the UI take effect without
        # restarting celery-beat. Additive-only — never deletes existing
        # DB rows.
        "dns-pull-from-server": {
            "task": "app.tasks.dns_pull.auto_pull_dns_from_servers",
            "schedule": schedule(run_every=60.0),
        },
        # Every 10 s, tick the DHCP lease-pull task. The task itself checks
        # ``PlatformSettings.dhcp_pull_leases_enabled`` and the per-run
        # interval (in seconds, min 10), so cadence changes in the UI take
        # effect without restarting celery-beat. The 10-second tick caps the
        # fastest achievable cadence — enough for near-real-time IPAM
        # population from agentless DHCP servers while leaving the upstream
        # endpoint breathing room. Only applies to agentless drivers
        # (windows_dhcp, fortigate). Additive-only — the existing lease-cleanup
        # sweep handles stale expiry.
        "dhcp-pull-leases": {
            "task": "app.tasks.dhcp_pull_leases.auto_pull_dhcp_leases",
            "schedule": schedule(run_every=10.0),
        },
        # Every 60 s, reconcile the Windows DHCP server-level deny
        # filter list against each group's active MAC blocks. Kea is
        # driven by the ConfigBundle DROP class render and needs no
        # periodic push. Windows has no built-in expiry so this tick
        # handles the ``expires_at`` transitions uniformly.
        "dhcp-mac-blocks-sync": {
            "task": "app.tasks.dhcp_mac_blocks.sync_dhcp_mac_blocks",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, evaluate every enabled AlertRule. Idempotent —
        # opens events for fresh matches, resolves events whose
        # subject no longer matches. Delivery reuses the
        # audit-forward syslog + webhook targets.
        "alerts-evaluate": {
            "task": "app.tasks.alerts.evaluate_alerts",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, tick the conformity evaluator. Per-policy
        # gating via ``eval_interval_hours`` keeps the work cheap —
        # default policies run once a day, on-demand re-eval is the
        # immediate path for "did my fix turn this green?" workflows.
        "conformity-evaluate": {
            "task": "app.tasks.conformity.evaluate_conformity",
            "schedule": schedule(run_every=60.0),
        },
        # Every 10 s, drain the typed-event outbox (webhooks). Uses
        # ``SELECT … FOR UPDATE SKIP LOCKED`` so multiple workers can
        # cooperate without double-delivery; idempotent on its own.
        # Cadence is hardcoded — no operator knob — because the
        # outbox is per-event so a slow tick just defers individual
        # deliveries, it doesn't batch up the world.
        "event-outbox-drain": {
            "task": "app.tasks.event_outbox.process_event_outbox",
            "schedule": schedule(run_every=10.0),
        },
        # Every hour, tick the IEEE OUI refresh. Opt-in feature — the
        # task itself checks ``PlatformSettings.oui_lookup_enabled`` and
        # ``oui_update_interval_hours`` (default 24h) so the effective
        # cadence is UI-controlled. Hourly beat is the granularity knob;
        # anyone who wants "every 4 hours" sets interval_hours=4 and the
        # task self-skips the other 3 fires.
        "oui-refresh": {
            "task": "app.tasks.oui_update.auto_update_oui_database",
            "schedule": schedule(run_every=3600.0),
        },
        # Nightly prune of dns/dhcp metric_sample rows older than the
        # configured retention window (default 7 d). Keeps the two
        # tables a bounded size without coarsening resolution. Cadence
        # is deliberately slow — the tables are already small and
        # pruning more often just burns cycles.
        "metric-samples-prune": {
            "task": "app.tasks.prune_metrics.prune_metric_samples",
            "schedule": schedule(run_every=24 * 3600.0),
        },
        # #889 — InfluxDB push export. Coarse 30 s tick; each target is
        # gated on its own ``push_interval_seconds`` inside the task, so
        # cadence edits in the UI apply without restarting beat. A tick
        # with no enabled targets is one indexed SELECT and returns.
        "influxdb-push": {
            "task": "app.tasks.influxdb_push.push_influxdb_metrics",
            "schedule": schedule(run_every=30.0),
        },
        # #44 — daily per-subnet utilization snapshot + 90-day prune,
        # powering the "% used over time" chart on the subnet detail.
        "subnet-utilization-snapshot": {
            "task": "app.tasks.subnet_utilization_snapshot.snapshot_subnet_utilization",
            "schedule": schedule(run_every=24 * 3600.0),
        },
        # Nightly prune of agent-shipped query / activity log entries
        # older than the retention window (default 24 h). Query logs
        # are a firehose; the short window keeps the tables manageable
        # without operator tuning.
        "log-entries-prune": {
            "task": "app.tasks.prune_logs.prune_log_entries",
            "schedule": schedule(run_every=24 * 3600.0),
        },
        # Daily at 03:45 UTC (offset from the other prunes), delete
        # terminal packet-capture rows past the retention window
        # (default 7 d) + unlink their .pcap files, and reap captures
        # stuck non-terminal past their deadline. Issue #59.
        "pcap-captures-prune": {
            "task": "app.tasks.pcap.prune_captures",
            "schedule": crontab(hour=3, minute=45),
        },
        # Every 5 min, reap IGMP-snooping membership rows whose
        # ``last_seen_at`` is older than 30 min — see issue #126
        # Phase 4 Wave 2. Manual / sap_announce rows survive.
        "multicast-igmp-membership-reaper": {
            "task": ("app.tasks.prune_multicast_memberships." "prune_stale_igmp_memberships"),
            "schedule": schedule(run_every=5 * 60.0),
        },
        # Daily at 03:00 UTC, hard-delete soft-deleted rows older than the
        # configured retention window (default 30 d). Gated on
        # ``PlatformSettings.soft_delete_purge_days`` — set to 0 to
        # disable purge entirely.
        "trash-purge": {
            "task": "app.tasks.trash_purge.purge_expired_soft_deletes",
            "schedule": crontab(hour=3, minute=0),
        },
        # Every 5 min, release IPAM reservations whose reserved_until has
        # passed. Gated on ``PlatformSettings.reservation_sweep_enabled`` —
        # turn off to keep all reservations indefinitely.
        "reservation-sweep": {
            "task": "app.tasks.ipam_reservation_sweep.sweep_expired_reservations",
            "schedule": schedule(run_every=300.0),
        },
        # Daily at 03:15 UTC, prune DHCPLeaseHistory rows older than the
        # configured retention window (default 90 d). Offset from trash-purge
        # to avoid simultaneous heavy writes.
        "dhcp-lease-history-prune": {
            "task": "app.tasks.dhcp_lease_history_prune.prune_lease_history",
            "schedule": crontab(hour=3, minute=15),
        },
        # Every 12 h, re-issue active Let's Encrypt Web-UI certs that are
        # within 30 d of expiry (issue #438 Phase 2). Idempotent +
        # advisory-locked; gated on acme_enabled + acme_auto_renew.
        "acme-renew-due": {
            "task": "app.tasks.acme.renew_due_certificates",
            "schedule": schedule(run_every=12 * 3600.0),
        },
        # Daily DNSBL / RBL reputation sweep of every public-facing
        # candidate IP against the enabled blocklists (issue #528). Gated
        # inside the task on the ``security.dnsbl`` module + the
        # ``dnsbl_monitoring_enabled`` master switch — no DNS queries fire
        # until the operator opts in and enables at least one list.
        "dnsbl-daily-sweep": {
            "task": "app.tasks.dnsbl_sweep.sweep_dnsbl",
            "schedule": crontab(hour=4, minute=30),
        },
        # Once a day, check GitHub for the latest release tag. Gated
        # on ``PlatformSettings.github_release_check_enabled`` — so
        # operators can turn this off in air-gapped deployments
        # without restarting beat. Unauthenticated call; the 60/hour
        # rate limit is plenty for a daily tick.
        "update-check": {
            "task": "app.tasks.update_check.check_github_release",
            "schedule": schedule(run_every=24 * 3600.0),
        },
        # Every 30 s, sweep every enabled KubernetesCluster. The per-
        # cluster ``sync_interval_seconds`` (min 30) gates the actual
        # reconciler pass, so a cluster configured with a 5-minute
        # interval sees 10 beat ticks between passes. Gated overall by
        # ``PlatformSettings.integration_kubernetes_enabled`` — turn
        # the master toggle off and no cluster is polled.
        "kubernetes-sync-sweep": {
            "task": "app.tasks.kubernetes_sync.sweep_kubernetes_clusters",
            "schedule": schedule(run_every=30.0),
        },
        # Same pattern for Docker — 30 s beat, per-host interval gates
        # the actual reconcile pass. Gated overall by
        # ``PlatformSettings.integration_docker_enabled``.
        "docker-sync-sweep": {
            "task": "app.tasks.docker_sync.sweep_docker_hosts",
            "schedule": schedule(run_every=30.0),
        },
        # Proxmox VE — same 30 s beat, per-endpoint interval gate.
        # Gated overall by ``PlatformSettings.integration_proxmox_enabled``.
        "proxmox-sync-sweep": {
            "task": "app.tasks.proxmox_sync.sweep_proxmox_nodes",
            "schedule": schedule(run_every=30.0),
        },
        # OPNsense — same 30 s beat, per-firewall interval gate.
        # Gated overall by ``PlatformSettings.integration_opnsense_enabled``.
        "opnsense-sync-sweep": {
            "task": "app.tasks.opnsense_sync.sweep_opnsense_routers",
            "schedule": schedule(run_every=30.0),
        },
        # Palo Alto PAN-OS / Panorama (#605) — same 30 s beat, per-firewall
        # interval gate. Gated overall by
        # ``PlatformSettings.integration_panos_enabled``.
        "panos-sync-sweep": {
            "task": "app.tasks.panos_sync.sweep_panos_firewalls",
            "schedule": schedule(run_every=30.0),
        },
        # Fortinet FortiGate (#606) — same 30 s beat, per-firewall interval
        # gate. Gated overall by ``PlatformSettings.integration_fortinet_enabled``.
        "fortinet-sync-sweep": {
            "task": "app.tasks.fortinet_sync.sweep_fortinet_firewalls",
            "schedule": schedule(run_every=30.0),
        },
        # Cisco Meraki (#606) — same 30 s beat, per-org interval gate (Meraki's
        # slower cloud rate limit defaults to a 300 s per-org interval). Gated
        # overall by ``PlatformSettings.integration_meraki_enabled``.
        "meraki-sync-sweep": {
            "task": "app.tasks.meraki_sync.sweep_meraki_orgs",
            "schedule": schedule(run_every=30.0),
        },
        # Active block sync (#601) — converge SpatiumDDI-owned network
        # blocks onto every armed OPNsense/UniFi target. 60 s cadence
        # (enforcement, not discovery — the on-create/lift path handles
        # immediacy). Gated by the ``security.block_sync`` feature module
        # + each target's own ``block_sync_enabled`` master switch.
        "block-sync-sweep": {
            "task": "app.tasks.block_sync.sweep_block_sync",
            "schedule": schedule(run_every=60.0),
        },
        # Tailscale — same 30 s beat, per-tenant interval gate.
        # Gated overall by ``PlatformSettings.integration_tailscale_enabled``.
        "tailscale-sync-sweep": {
            "task": "app.tasks.tailscale_sync.sweep_tailscale_tenants",
            "schedule": schedule(run_every=30.0),
        },
        # NetBird — same 30 s beat, per-instance interval gate.
        # Gated overall by ``PlatformSettings.integration_netbird_enabled``.
        "netbird-sync-sweep": {
            "task": "app.tasks.netbird_sync.sweep_netbird_instances",
            "schedule": schedule(run_every=30.0),
        },
        # UniFi — same 30 s beat, per-controller interval gate.
        # Gated overall by ``PlatformSettings.integration_unifi_enabled``.
        # Cloud-mode controllers floor at 60 s inside the task.
        "unifi-sync-sweep": {
            "task": "app.tasks.unifi_sync.sweep_unifi_controllers",
            "schedule": schedule(run_every=30.0),
        },
        # Cloud (AWS/Azure/GCP) — same 30 s beat, per-endpoint interval
        # gate (300 s default, cloud APIs are rate-limited). Gated overall
        # by ``PlatformSettings.integration_cloud_enabled``.
        "cloud-sync-sweep": {
            "task": "app.tasks.cloud_sync.sweep_cloud_endpoints",
            "schedule": schedule(run_every=30.0),
        },
        # Every 60 s, fan-out SNMP polls to network devices whose
        # ``next_poll_at`` has elapsed. The dispatcher itself respects
        # each device's ``poll_interval_seconds`` so a 5-minute poller
        # only fires every 5 ticks. Per-device tasks acquire SELECT
        # FOR UPDATE SKIP LOCKED so a manual "Poll Now" running in
        # parallel won't double-poll.
        "snmp-poll-dispatch": {
            "task": "app.tasks.snmp_poll.dispatch_due_devices",
            "schedule": schedule(run_every=60.0),
        },
        # Daily, purge ARP entries that have been stale for > 30 days.
        # FDB rows are absence-deleted on every poll so they don't
        # need a janitor.
        "snmp-arp-purge": {
            "task": "app.tasks.snmp_poll.purge_stale_arp_entries",
            "schedule": crontab(hour=3, minute=30),
        },
        # Beat self-heartbeat — writes a redis key every 30 s with a
        # 5-min TTL so the platform-health endpoint can tell a stalled
        # beat from a healthy one. Celery has no built-in beat-liveness
        # primitive, so a trivial heartbeat task is the cheapest signal.
        "platform-beat-heartbeat": {
            "task": "app.tasks.heartbeat.beat_tick",
            "schedule": schedule(run_every=30.0),
        },
        # Every 30 s, fan-out health-check tasks to enabled DNS pools
        # whose ``next_check_at`` has elapsed. The dispatcher itself
        # respects each pool's ``hc_interval_seconds`` by setting
        # ``next_check_at`` after each check, so a pool configured with
        # a 5-minute interval only fires every 10 ticks.
        "dns-pool-healthcheck-dispatch": {
            "task": "app.tasks.dns_pool_healthcheck.dispatch_due_pools",
            "schedule": schedule(run_every=30.0),
        },
        # Every 1 h, tick the ASN RDAP refresh task. The task itself
        # walks every ``asn`` row whose ``next_check_at`` has elapsed
        # (or is NULL) and bumps it forward by
        # ``PlatformSettings.asn_whois_interval_hours`` (default 24h,
        # min 1h). The hourly beat tick is just a cadence ceiling;
        # per-row gating is what actually paces refreshes.
        "asn-whois-refresh-tick": {
            "task": "app.tasks.asn_whois_refresh.refresh_due_asns",
            "schedule": schedule(run_every=3600.0),
        },
        # Every 1 h, tick the RPKI ROA refresh task.
        "rpki-roa-refresh-tick": {
            "task": "app.tasks.rpki_roa_refresh.refresh_due_roas",
            "schedule": schedule(run_every=3600.0),
        },
        # Hourly tick of the Domain WHOIS refresh sweep — same
        # per-row gating pattern as the ASN tick above.
        "domain-whois-refresh-tick": {
            "task": "app.tasks.domain_whois_refresh.refresh_due_domains",
            "schedule": schedule(run_every=3600.0),
        },
        # Hourly tick of the BGP prefix-hijack poll (issue #527). The
        # task no-ops unless ``PlatformSettings.bgp_monitoring_enabled``
        # is on; per-prefix ``next_check_at`` gates against
        # ``bgp_monitoring_interval_hours``.
        "bgp-hijack-poll-tick": {
            "task": "app.tasks.bgp_hijack_poll.poll_bgp_hijacks",
            "schedule": schedule(run_every=3600.0),
        },
        # Daily at 08:00 UTC, fire the Operator Copilot digest. The
        # task itself gates on ``PlatformSettings.ai_daily_digest_enabled``
        # so the cron is harmless on installs that haven't opted in.
        # 08:00 UTC = 03:00 EST / 04:00 EDT — lands in the inbox before
        # the start of the US business day; operators in other time
        # zones can adjust by editing this entry directly.
        "ai-daily-digest": {
            "task": "app.tasks.ai_digest.send_daily_digest",
            "schedule": crontab(hour=8, minute=0),
        },
        # Nightly at 02:00 UTC, walk the audit_log chain and verify
        # every row's hash. Issue #73. Read-only — never tries to
        # repair, opens an AlertEvent against the
        # ``audit-chain-broken`` rule when something doesn't line up.
        # 02:00 UTC is intentionally off-peak for most deployments;
        # the walk is O(rows) and we don't want it competing with
        # the morning digest at 08:00.
        "audit-chain-verify": {
            "task": "app.tasks.audit_chain_verify.verify_audit_chain",
            "schedule": crontab(hour=2, minute=0),
        },
        # Daily at 03:30 UTC, prune the diagnostics ``internal_error``
        # table — acked rows after 30 d, unacked after 90 d (issue
        # #123). Off-peak vs the morning AI digest at 08:00 and the
        # audit-chain verify at 02:00.
        "internal-errors-prune": {
            "task": "app.tasks.prune_internal_errors.prune_internal_errors",
            "schedule": crontab(hour=3, minute=30),
        },
        # Every 30 min, sweep stale appliance pairing codes — claimed
        # rows after 30 d, revoked after 7 d, expired after 24 h of
        # grace (issue #169). High-cadence vs. the nightly prunes
        # because the operator-facing list endpoint should reflect
        # the rolling-window state of recent codes without a long lag.
        "pairing-codes-prune": {
            "task": "app.tasks.prune_pairing_codes.prune_pairing_codes",
            "schedule": schedule(run_every=1800.0),
        },
        # Every 30 min, advisory-lint every appliance's firewall_extra
        # (#285 Phase 5). Self-gates on an audit-log marker row so the
        # body runs exactly once per install; the beat cadence just means
        # a fresh install scans within 30 min of the worker coming up.
        "firewall-extra-lint-scan": {
            "task": "app.tasks.firewall_lint_scan.scan_firewall_extra",
            "schedule": schedule(run_every=1800.0),
        },
        # Hourly sweep of soft-deleted appliance rows past the
        # ``platform_settings.appliance_revoked_retention_days``
        # window (#170 Wave E follow-up). Hourly is plenty — the
        # retention default is 30 days; an hour of imprecision on
        # when the row finally drops is invisible to operators.
        "appliances-prune-revoked": {
            "task": "app.tasks.prune_revoked_appliances.prune_revoked_appliances",
            "schedule": schedule(run_every=3600.0),
        },
        # Every 60 s, fire any backup target whose ``next_run_at``
        # is now in the past (issue #117 Phase 1b). The sweep + the
        # per-target ``last_run_status`` mutex keep the cost bounded
        # — a single in-progress target won't be re-fired by the
        # next tick.
        "backup-target-sweep": {
            "task": "app.tasks.backup_sweep.sweep_backup_targets",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, fire any restore-verification drill whose
        # ``drill_next_run_at`` is now in the past (issue #702).
        # Same sweep + per-target mutex shape as the backup sweep
        # above; drills carry their own cron because replaying a
        # full dump into a scratch database costs far more than
        # taking a backup does.
        "restore-drill-sweep": {
            "task": "app.tasks.backup_drill.sweep_restore_drills",
            "schedule": schedule(run_every=60.0),
        },
        # Every 15 min, roll DNS query-log lines into per-client hourly
        # windows and score them for tunneling (#699). Recomputes the
        # current + previous bucket by upsert, so running far more often
        # than the bucket width keeps the picture near-live without
        # adding rows. Self-gates on the default-off
        # ``security.dns_threat`` module, so this cron is a no-op on
        # installs that haven't opted in.
        "dns-threat-rollup": {
            "task": "app.tasks.dns_threat.aggregate_dns_client_windows",
            "schedule": schedule(run_every=900.0),
        },
        # Every 60 s, fire any Scheduled Wake-on-LAN schedule whose
        # ``next_run_at`` (denormalised UTC) is now in the past (issue #586
        # Phase 1). The sweep + the per-schedule ``last_run_status`` mutex +
        # the runner's ``next_run_at`` re-stamp keep a double-tick from
        # double-firing. The task self-gates on the ``tools.wake_scheduler``
        # feature module, so this cron is harmless when the module is off.
        "wol-schedule-sweep": {
            "task": "app.tasks.wol_scheduler.sweep_wol_schedules",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, refresh any enabled Wake-on-LAN calendar subscription
        # (iCal .ics URL / CalDAV) whose ``refresh_interval_minutes`` cadence
        # has elapsed (issue #586 Phase 2). Per-calendar interval gating lives
        # inside the task; it self-gates on the ``tools.wake_scheduler`` feature
        # module, so this cron is harmless when the module is off.
        "wol-calendar-sweep": {
            "task": "app.tasks.wol_calendar.sweep_wol_calendars",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, soft-revoke time-bound RBAC grants whose
        # ``expires_at`` has passed (issue #65). Always-on — there is no
        # opt-out setting; the per-row ``expires_at`` is the only knob.
        # Enforcement is already immediate via the ``expires_at > now()``
        # filter at request time, so this sweep is the durable bookkeeping
        # layer (sets ``revoked_at`` + writes one permission_change audit
        # row per expired grant).
        "time-bound-grant-sweep": {
            "task": "app.tasks.time_bound_grant_sweep.sweep_expired_grants",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, flip pending change requests (#62) whose TTL has
        # elapsed to ``expired`` (terminal) + write the system-actor audit
        # row. Idempotent — only pending+past-expiry rows match. The approve
        # endpoint also lazily expires a stale row on read, so a request
        # never executes past its TTL regardless of this sweep's cadence.
        "change-request-expiry-sweep": {
            "task": "app.tasks.change_request_expiry.sweep_expired_change_requests",
            "schedule": schedule(run_every=60.0),
        },
        # Every 60 s, probe every enabled TLS cert target whose
        # ``next_check_at`` has elapsed (issue #118). Per-target cadence
        # default is ``PlatformSettings.tls_cert_check_interval_hours``
        # (6 h), read each run so UI changes take effect without a beat
        # restart. Idle when no targets are due.
        "tls-cert-probe-dispatch": {
            "task": "app.tasks.tls_certs.probe_due_certs",
            "schedule": schedule(run_every=60.0),
        },
        # Every 5 min, project TLS cert probe targets from opted-in DNS
        # A/AAAA records + relink targets to zones/domains by SAN.
        "tls-cert-discovery": {
            "task": "app.tasks.tls_certs.reconcile_discovered",
            "schedule": schedule(run_every=300.0),
        },
        # Daily at 03:50 UTC, prune tls_cert_probe history older than the
        # retention window (90 d). Offset from the other 03:xx prunes.
        "tls-cert-probe-prune": {
            "task": "app.tasks.tls_certs.prune_probes",
            "schedule": crontab(hour=3, minute=50),
        },
        # Every 5 min, re-check that the DB schema is at the Alembic
        # head bundled in this image (issue #565). Opens/resolves the
        # ``schema-behind-head`` alert on drift. Complements the api's
        # /health/ready gate — the worker/beat had no equivalent, so a
        # "code deployed before migrate ran" window failed background
        # tasks silently. The startup check (worker_ready/beat_init)
        # catches the cold-boot case; this periodic tick catches a
        # later divergence (stale image / mid-rollout).
        "schema-at-head-check": {
            "task": "app.tasks.schema_check.check_schema_at_head",
            "schedule": schedule(run_every=300.0),
        },
    },
)


# ── Redis Sentinel broker/backend (#272 Phase 3) ────────────────────────
#
# When the broker / result-backend URLs carry the ``sentinel://``
# scheme (umbrella chart with ``redis.kind=sentinel``), Celery's
# kombu transport needs the master name in transport options to know
# which Sentinel-monitored master to resolve. The Sentinel auth
# password (when the data nodes require auth) rides in
# ``sentinel_kwargs``. Plain ``redis://`` URLs need none of this.
if settings.celery_broker_url.startswith(("sentinel://", "redis+sentinel://")):
    _sentinel_opts: dict = {"master_name": settings.redis_sentinel_master}
    if settings.redis_sentinel_password:
        _sentinel_opts["sentinel_kwargs"] = {"password": settings.redis_sentinel_password}
    celery_app.conf.broker_transport_options = _sentinel_opts
    celery_app.conf.result_backend_transport_options = dict(_sentinel_opts)


# ── Diagnostics — Celery task_failure capture (issue #123) ──────────────
#
# Mirror of the FastAPI exception handler in ``app.main``. Every
# uncaught task exception lands in the ``internal_error`` table so
# operators can review crashes without tailing ``docker compose logs
# worker``. ``task_revoked`` and ``task_unknown`` are deliberately
# *not* hooked — those are operational signals, not bugs.
from celery.signals import task_failure  # noqa: E402

# Schema-at-head signal registration (issue #565). ``app.tasks.
# schema_check`` connects ``worker_ready`` / ``beat_init`` /
# ``task_prerun`` handlers at import time. The ``include=[…]`` list only
# imports task modules in the *worker* bootstrap — beat loads the config
# (schedule) but not the task modules — so import it here explicitly to
# guarantee the startup check + strict gate register in every process.
# Use import_module (not a bound ``import … as _x``) so static analysis
# doesn't flag a side-effect-only import as unused.
importlib.import_module("app.tasks.schema_check")

from celery.signals import beat_init, worker_init  # noqa: E402


@worker_init.connect
@beat_init.connect
def _install_session_listeners(**_: object) -> None:
    """Install the SQLAlchemy session listeners in the worker and beat: audit
    forwarding and the typed-event outbox (#1168), and the DNS bundle
    dirty-mark (#1111). They register on import, and nothing a worker imports
    reaches them otherwise (``app.main`` installs them for the api only).
    Without them a task's audit rows produce no typed webhook events, and a
    task's DNS writes commit unmarked, so agents never receive them.

    From the signals, not at import (#1189): the worker's liveness probe runs
    ``celery -A app.celery_app inspect ping``, which imports this module on
    every run, and the listeners pull in the models, the DNS drivers, httpx,
    cryptography and jinja2. ``worker_init`` runs in the prefork master before
    the pool forks, so every child inherits them."""
    importlib.import_module("app.services.session_listeners").install_session_listeners()


@worker_init.connect
@beat_init.connect
def _dispatch_after_commit_in_background(**_: object) -> None:
    """#1168 — in a Celery process, run the listeners' after-commit work on a
    per-process background loop. A task's own ``asyncio.run`` cancels
    whatever is still pending when it returns, and a task usually commits
    last: measured, 0 of 5 typed events reached the outbox that way. Wired
    to the Celery signals rather than done at import because the api imports
    this module too, and its request loop is fine as it is. ``worker_init``
    runs in the prefork master; the loop itself starts lazily per PID, so
    each forked child gets its own."""
    importlib.import_module("app.services.after_commit_dispatch").use_background_loop()


@task_failure.connect
def _capture_task_failure(
    sender: object | None = None,
    task_id: str | None = None,
    exception: BaseException | None = None,
    args: tuple | None = None,
    kwargs: dict | None = None,
    traceback: object | None = None,
    einfo: object | None = None,
    **_: object,
) -> None:
    if exception is None:
        return
    # Lazy import — keeps the celery_app module light and avoids any
    # accidental circular at import time (capture pulls in app.config
    # + app.models.diagnostics).
    from app.services.diagnostics import (  # noqa: PLC0415
        record_unhandled_exception,
    )

    task_name = getattr(sender, "name", None) if sender else None
    context = {
        "task_id": task_id,
        "task_args": args,
        "task_kwargs": kwargs,
    }
    record_unhandled_exception(
        service="worker",
        exc=exception,
        route_or_task=task_name,
        request_id=task_id,
        context=context,
    )
