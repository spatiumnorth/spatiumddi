---
layout: default
title: Operator Copilot
---

# Operator Copilot

AI assistant grounded in your live IPAM / DNS / DHCP / Network data. Hosted-API or fully on-prem (Ollama). One provider config, **hundreds of tools**, real conversations about your network.

The README carries the short version; this page is the reference for how the Copilot behaves: provider failover, per-provider prompts and tool allowlists, the tool registry, the MCP endpoint, the chat surface, reliability guards and token caps. See also [System Administration](SYSTEM_ADMIN.md) for the Admin → AI pages, and [Architecture](../ARCHITECTURE.md).

## Provider + model

- **Multi-vendor** — OpenAI, Anthropic (Claude), Azure OpenAI, Google Gemini, plus OpenAI-compat (Ollama, OpenWebUI, vLLM, LM Studio, llama.cpp server, LocalAI, Together, Groq, Fireworks). Add multiple providers in priority order; orchestrator picks the highest-priority enabled one
- **Automatic failover chain** — on transient failure (5xx / timeout / rate-limit) the orchestrator walks remaining providers; first successful chunk wins. Permanent errors (4xx / auth) surface immediately
- **Per-provider system prompt override** — admin-editable inside the AI Provider modal; baked-in default is also viewable inline so you can fork it. Snapshotted onto each session at creation so live edits don't break in-flight chats
- **Per-provider tool allowlist** — set through the API (the provider's `enabled_tools`); the AI Providers page has no control for it, and the AI Provider modal has only the Connection and System prompt tabs. NULL = "use whatever the registry has"; non-empty list pins exactly those tools. Right call for small Ollama models that struggle with a large tool set, kiosk providers limited to read-only, and per-provider compliance posture
- **Reasoning-channel fallback** — `qwen3.5` / DeepSeek-R1 / o1 / o3 family that route their answer to `reasoning` instead of `content` are handled transparently by the driver
- **Ollama context-window forwarding** — driver forwards `options.num_ctx` / `num_predict` / `extra_body` so Ollama respects the configured context window. Operators can also set `OLLAMA_CONTEXT_LENGTH` env var on the server side (recommended); without one or the other, Ollama silently truncates to 2048 tokens and small models hallucinate tool names from a half-cut tool list

## Tool registry (hundreds of tools — highlights below)

Each tool is gated by both the `feature_module` it belongs to (`integrations.unifi` off → UniFi tool disappears from the registry) and an admin-controlled per-tool allowlist at **Admin → AI → Tools**, so operators can trim what the model can see without touching code. Every tool can also be limited per-provider through the API (the provider's `enabled_tools`; the AI Providers page has no control for it) — the right call for small Ollama models that struggle with hundreds of tool schemas.

The per-category bullets below are a representative tour, not an exhaustive enumeration — the canonical inventory is `backend/app/services/ai/tools/` (one module per category, every `@register_tool(...)` decorator is a live entry) and the live `/api/v1/ai/tools` endpoint on a running install. Categories not surfaced here (multicast, host-config firewall / LLDP / syslog / SSH, …) round out the full registry.

- **IPAM** — `list_ip_spaces`, `list_ip_blocks`, `list_subnets`, `get_subnet_summary`, `find_ip` (returns MAC + **vendor**), `find_ip_addresses` (cross-subnet paginated search), `find_by_tag`, `count_ipam_resources`, `find_devices_by_vendor`, `count_devices_by_vendor`, `propose_create_ip_address`. Name-or-UUID resolution on `space_id` / `block_id` so the model can pass `"home"` directly without a UUID-lookup hop
- **DNS** — `list_dns_server_groups`, `list_dns_zones`, `list_dns_views`, `list_dns_records` (cross-zone substring search), `export_dns_zone_records` (one zone's records as the rows of its CSV / XLSX export), `list_dns_pools` (GSLB pools + per-member health), `list_dns_blocklists` (RPZ rows + sync state), `list_blocklist_templates` (the catalog's inline templates + profiles, e.g. SafeSearch and Family filter), `list_resolver_presets` (each upstream's addresses **with** the certificate name they present, which is what a DoT forwarder has to match), `query_dns_records`, `forward_dns`, `reverse_dns`, `propose_create_dns_record`
- **DHCP** — `list_dhcp_server_groups`, `list_dhcp_servers`, `list_dhcp_scopes`, `list_dhcp_pools` (dynamic / excluded / reserved), `list_dhcp_statics` (MAC → IP reservations), `list_dhcp_client_classes`, `list_dhcp_option_templates`, `list_pxe_profiles`, `list_dhcp_mac_blocks`, `find_dhcp_leases` (returns MAC + **vendor**), `find_ra_subnets` / `find_observed_ra_routers` / `count_rogue_ra_routers` / `propose_allowlist_ra_router` (IPv6 RA + rogue-RA), `propose_create_dhcp_static`
- **Network modeling** — `list_asns` + `get_asn` (RDAP holder, RPKI ROAs, BGP peerings), `find_bgp_hijacks` / `count_bgp_hijacks` / `find_tracked_prefixes` / `propose_allowlist_bgp_origin` (prefix-hijack detection), `list_domains` (registrar / expiry / DNSSEC / NS drift), `list_vrfs` (RDs + RTs + ASN linkage), `list_circuits` (transport + bandwidth + cost + endpoints), `trace_circuit_impact` (down-circuit blast radius across services + sites), `list_network_services` + `get_network_service_summary` (service-catalog deliverables — MPLS L3VPN, etc.), `list_overlay_networks` + `get_overlay_topology` (SD-WAN sites + policies), `list_application_categories` (RFC 4594 DSCP catalog), `list_network_devices`, `find_switchport`, `ping_host`, `list_nmap_scans`, `get_nmap_scan_results`, `propose_run_nmap_scan`
- **BGP Looking Glass** — `find_bgp_lg_sessions` (peer state + uptime), `find_bgp_routes` / `count_bgp_routes` / `get_bgp_route` (the collector's live RIB, filterable by prefix, origin ASN, community, or a Cisco / Juniper as-path regexp), `find_bgp_route_for_ip` (which learned prefix covers this address), `find_vrf_learned_routes` (Route-Target matched VPNv4 / VPNv6 routes), `find_multicast_bgp_reachability`, `propose_create_lg_peer`
- **Scheduled Wake-on-LAN** — `find_wol_schedules` / `get_wol_schedule` / `count_wol_schedules`, `preview_wol_schedule_targets` (which hosts would this fire wake, right now), `find_wol_runs` (history + per-host verify rollup), `find_wol_wake_failures` / `count_wol_wake_failures` (hosts that didn't come up, with the per-source evidence trail), `find_wol_calendars` / `get_wol_calendar` / `find_wol_calendar_events`, `propose_create_wol_schedule` / `propose_run_wol_schedule_now` / `propose_set_wol_schedule_enabled`
- **Ownership** — `list_customers`, `list_sites`, `list_providers`, `get_customer_summary` (per-customer rollup of subnets / blocks / spaces / circuits / services / ASNs / zones / domains / overlays in one call)
- **Admin** — `list_users`, `list_groups`, `list_roles` (superadmin-gated inline; the orchestrator returns an error dict for non-admins)
- **Appliance fleet config** — `find_snmp_settings`, `find_ntp_settings`, `find_pairing_codes`. All three superadmin-gated; pairing codes also redact the cleartext code + sha256 hash, only the last two digits ever leave the database. No `propose_*` write companions by design — the create response for a pairing code carries the cleartext code, which we don't want in chat transcripts
- **Backup + factory-reset** — `list_backup_targets` (every configured destination with last-run state, schedule, retention; `config` blob deliberately omitted so destination credentials stay out of the LLM context), `list_backup_archives_at_target` (calls the driver's `list_archives` so the result matches the Backup admin Archives drawer), `find_backup_audit_history` (windowed timeline of backup_created / target-run-success/failed / backup_restored / factory_reset_performed audit rows), `get_backup_health` (per scheduled target: ok / failed / stale / stuck, the same decision as the `backup_failed` / `backup_stale` alerts). All superadmin-gated. **No `propose_*` writes by design** — restore + factory-reset are password-gated + confirm-phrase-gated, an LLM intermediary in "should I restore?" adds friction without value
- **Integration mirrors** — `list_kubernetes_targets`, `list_docker_targets`, `list_proxmox_targets`, `list_tailscale_targets`, `list_netbird_targets`, `list_unifi_targets`, `list_cloud_targets`, `list_opnsense_targets`, `list_panos_targets`, `list_fortinet_targets`, `list_meraki_targets` (each tagged with the matching `integrations.*` module so disabling the integration removes the tool in lock-step with the sidebar entry; credentials never enter the response)
- **Firewall objects, block sync + feeds** — `find_firewall_objects` / `count_firewall_objects` (vendor-neutral over the Palo Alto / Fortinet / Meraki shadow-IPAM store, filterable by `source_kind`), `find_network_blocks` / `count_network_blocks`, `list_firewall_feeds`, and the default-disabled `propose_create_network_block` write proposal. Gated on the `security.block_sync` / `security.firewall_feeds` modules; write-scoped target credentials never enter the response
- **Ops, observability + audit** — `list_alerts`, `list_alert_rules`, `get_audit_history`, `audit_walk` (paginated chronology), `current_state` (platform health snapshot), `query_dns_query_log`, `query_dhcp_activity_log`, `query_logs`, `get_dns_query_rate` / `get_dhcp_lease_rate` (24-bucket timeseries), `global_search`, `lookup_whois_asn` / `lookup_whois_domain` / `lookup_whois_ip`, `tls_cert_check`, `find_nonconforming_names` (audit pre-existing hostnames / record owners / zone names against the DNS standards), `help_write_permission`, `find_agents_with_config_failures` (which DNS / DHCP / looking-glass agents rejected their last config and reverted — the one state where `status`, the health check and `last_seen_at` all read normal while the saved config is live nowhere), `find_branding_settings`, `get_support_bundle_preview` (default **off** — a broad read), `propose_create_alert_rule`, `propose_archive_session`
- **Reputation (DNSBL)** — `find_blocklisted_ips`, `count_blocklisted_ips`, `find_dnsbl_lists` (curated catalog + per-list sweep state), `propose_pin_ip_for_dnsbl` (add an IP to the monitored set). Gated on the `security.dnsbl` module
- **Compliance** — `list_conformity_policies` (per-framework registry filter), `find_conformity_results` (append-only evaluation history), `get_conformity_summary` (per-framework rollup of policy + result counts)
- **Typed-event webhooks** (superadmin-gated) — `list_webhooks` (registry; secrets NEVER returned, `secret_set` boolean only), `get_webhook_event_types` (the full typed-event vocabulary so the LLM can validate `event_types[]` references before proposing a subscription), `find_webhook_deliveries` (outbox history — state / attempts / last_error / last_status_code)
- **Rolling upgrade orchestrator** — `find_upgrade_preflight`, `find_upgrade_runs`, `find_upgrade_lease` — read state of the multi-node A/B slot rolling upgrade so the LLM can answer "what's in flight?" without operator copy-paste
- **Windows cutover** (superadmin-gated, tagged `migration.cutover`) — `find_cutover_plans`, `find_cutover_plan_status`, `count_cutover_blockers` read plan and item state straight from the database. `find_cutover_parity_check` is the one **default-off** member of the set, because it runs a live WinRM pull against the Windows server rather than reading a stored report
- **Write proposals** (Apply-gated, default-off, double-validated in the Tool Catalog UI) — every `propose_*` returns a planned diff first; the operator clicks Apply in the chat drawer to actually write. Apply lands an audit row with `via=ai_proposal` so the trail distinguishes operator vs. AI-driven mutations

## MCP integration

- **MCP HTTP endpoint** at `/api/v1/ai/mcp` exposes the full read-only tool set so external MCP clients (Claude Desktop, Cursor, Cline, Continue.dev) can drop SpatiumDDI in as a tool source — no Copilot UI required

## Chat surface

- **Floating chat drawer** — slide-in panel with sessionStorage-backed state (close + reopen lands on the same conversation, draft text survives), Markdown + GFM tables + code blocks, blinking caret during streaming. Opens via the floating "Ask AI" button, the Cmd-K palette entry, or the per-row "Ask AI about this" affordances on every IPAM / DNS / DHCP / alerts row
- **Per-message footer** — token-count + copy + info popover (sent timestamp, tokens in / out, latency, role) on every assistant reply; matches the OpenWebUI footer pattern
- **Daily token + cost chip** — live in the drawer header; refetches automatically when you delete chats
- **Multi-select session history** — checkbox column on every history row; "Select all" + "Delete N" + "Delete all" toolbar; bulk delete fans out per-id and updates the daily tally on success
- **Live nmap proposal results** — when a `propose_run_nmap_scan` Apply lands, the proposal card polls `GET /nmap/scans/{id}` every 2 s and renders the full results table (alive flag, open ports + service / version, OS guess, CIDR-host list) inline once status flips to `completed`
- **Custom prompts library** — operator-curated templates persisted per platform; none ship built in — a fresh install has an empty library until an operator creates a prompt
- **Cmd-K palette "Ask AI" entry** — top entry in the global palette, pre-fills with the current page's context

## Reliability + safety

- **Per-turn dedup loop guard** — if the model emits the exact same tool call twice in a turn (a known failure mode of smaller open-weight models), the orchestrator skips re-execution and feeds back a synthetic warning telling the model the result is already in context
- **Tool-not-found auto-correction** — when the model hallucinates a tool name, the error response includes the full list of real tool names + a hint, so the next iteration self-corrects rather than giving up
- **Scope rules in the system prompt** — Copilot is explicitly *not* a general-purpose coding assistant; refuses code-generation requests outside narrow platform-config contexts
- **Audit everything** — every tool call, every Apply, every chat turn writes through to the append-only audit log

## Token / cost observability + per-user caps

- Per-request usage tracked in `ai_chat_message`; pricing table covers the major hosted models; per-user daily token + cost caps; AI usage card on Platform Insights aggregates the last 7 days by provider + model
- **Daily digest** — optional 0900 local Operator Copilot summary fired through audit-forward / SMTP / webhook channels

## Self-host with Ollama in five minutes

```bash
# On the Ollama host:
docker run -d --gpus all -p 11434:11434 \
  -e OLLAMA_CONTEXT_LENGTH=32768 \
  -e OLLAMA_KEEP_ALIVE=30m \
  -v ollama:/root/.ollama --name ollama ollama/ollama:latest

docker exec ollama ollama pull qwen3.5:latest
```

Then in SpatiumDDI: **Admin → AI Providers → New** → `kind: openai_compat`, `base_url: http://<ollama-host>:11434/v1`, `default_model: qwen3.5:latest`, save → click the floating "Ask AI" button. `OLLAMA_CONTEXT_LENGTH` is **required** — Ollama defaults to 2048 tokens which silently truncates the system prompt + tool schemas; the result is a model that hallucinates tool names. We recommend `qwen3.5:latest` for tool calling on the small open-weight class.
