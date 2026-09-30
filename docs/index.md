---
title: Documentation
description: SpatiumDDI documentation — setup, architecture, feature specs, deployment, driver internals and the privacy statement.
---


<div class="idx-lead" markdown="0">
  <div class="idx-lead-main">
    <p class="idx-eyebrow">Reference documentation</p>
    <h1>SpatiumDDI Documentation</h1>
    <p>
      SpatiumDDI is an open-source, self-hosted <strong>DNS, DHCP and IP Address
      Management</strong> platform. It does not merely configure external servers —
      it runs BIND9, PowerDNS, Technitium and Kea as managed service containers,
      with one control plane over all three.
    </p>
    <div class="idx-actions">
      <a class="idx-btn idx-btn-primary" href="deployment/APPLIANCE_INSTALL.html">Install the appliance</a>
      <a class="idx-btn" href="GETTING_STARTED.html">Set up DNS, DHCP and IPAM</a>
      <a class="idx-btn" href="ARCHITECTURE.html">How it fits together</a>
    </div>
  </div>
  <dl class="idx-facts">
    <div class="idx-fact"><dt>DNS engines</dt><dd>BIND9 · PowerDNS · Technitium · Windows DNS · Cloudflare · Route 53 · Azure · Google</dd></div>
    <div class="idx-fact"><dt>DHCP engines</dt><dd>Kea · Windows DHCP</dd></div>
    <div class="idx-fact"><dt>Deploy as</dt><dd>OS appliance · Docker Compose · Kubernetes</dd></div>
    <div class="idx-fact"><dt>Telemetry</dt><dd><a href="PRIVACY.html">None — ever</a></dd></div>
    <div class="idx-fact"><dt>License</dt><dd>Apache 2.0 · <a href="{{ site.links.github }}">source on GitHub</a></dd></div>
  </dl>
</div>

<nav class="idx-jump" aria-label="Sections" markdown="0">
  <span class="idx-jump-label">Jump to</span>
  <a href="#start-here">Start here</a>
  <a href="#architecture">Architecture &amp; design</a>
  <a href="#features">Feature specs</a>
  <a href="#deployment">Deployment</a>
  <a href="#internals">Internals &amp; development</a>
  <a href="#project">Project</a>
</nav>


<section class="idx-section" id="start-here" markdown="0">
  <header class="idx-section-head">
    <span class="idx-section-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
           stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
    </span>
    <div>
      <h2>Start here</h2>
      <p>New to SpatiumDDI? Install the appliance, then work the setup order.</p>
    </div>
  </header>
  <div class="idx-grid idx-grid-steps">
    <a class="idx-card" href="deployment/APPLIANCE_INSTALL.html">
      <span class="idx-card-num">1</span>
      <span class="idx-card-title">Install the OS appliance</span>
      <span class="idx-card-desc">Boot one ISO, answer the installer, and the full stack is on HTTPS a few minutes after the reboot — no Docker or Kubernetes to set up</span>
    </a>
    <a class="idx-card" href="GETTING_STARTED.html">
      <span class="idx-card-num">2</span>
      <span class="idx-card-title">Getting Started</span>
      <span class="idx-card-desc">First login, the concepts, and the setup order that avoids re-doing work: servers → zones and scopes → subnets → addresses</span>
    </a>
    <a class="idx-card" href="TROUBLESHOOTING.html">
      <span class="idx-card-num">3</span>
      <span class="idx-card-title">Troubleshooting</span>
      <span class="idx-card-desc">Recovery recipes: deleted agent rows, password reset, refused subnet deletes, and more</span>
    </a>
  </div>
  <p class="idx-alt">
    Running containers you manage yourself? Start at
    <a href="deployment/DOCKER.html">Docker Compose</a> or
    <a href="deployment/KUBERNETES.html">Kubernetes</a> instead of step 1.
  </p>
</section>


<section class="idx-section" id="architecture" markdown="0">
  <header class="idx-section-head">
    <span class="idx-section-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
           stroke-linecap="round" stroke-linejoin="round"><path d="M3 21h18M5 21V7l7-4 7 4v14M9 21v-6h6v6"/></svg>
    </span>
    <div>
      <h2>Architecture &amp; design</h2>
      <p>How the control plane, agents and data model fit together, and the conventions every surface follows.</p>
    </div>
  </header>
  <div class="idx-grid">
    <a class="idx-card" href="ARCHITECTURE.html">
      <span class="idx-card-title">Architecture</span>
      <span class="idx-card-desc">System topology, component relationships, HA design</span>
    </a>
    <a class="idx-card" href="deployment/TOPOLOGIES.html">
      <span class="idx-card-title">Deployment Topologies</span>
      <span class="idx-card-desc">Six reference production layouts with sizing notes</span>
    </a>
    <a class="idx-card" href="DATA_MODEL.html">
      <span class="idx-card-title">Data Model</span>
      <span class="idx-card-desc">Database models, relationships, field definitions</span>
    </a>
    <a class="idx-card" href="API.html">
      <span class="idx-card-title">API Conventions</span>
      <span class="idx-card-desc">REST conventions, pagination, error format, versioning</span>
    </a>
    <a class="idx-card" href="PERMISSIONS.html">
      <span class="idx-card-title">Permissions</span>
      <span class="idx-card-desc">RBAC grammar, builtin roles, scope delegation</span>
    </a>
    <a class="idx-card" href="OBSERVABILITY.html">
      <span class="idx-card-title">Observability</span>
      <span class="idx-card-desc">Logging, metrics, health dashboard, alerting</span>
    </a>
    <a class="idx-card" href="design/FLEET_FIREWALL.html">
      <span class="idx-card-title">Fleet Firewall Design</span>
      <span class="idx-card-desc">Per-role appliance firewall policy compiled to nftables</span>
    </a>
    <a class="idx-card" href="SHIPPED.html">
      <span class="idx-card-title">Shipped Roadmap</span>
      <span class="idx-card-desc">The design context behind every feature that has landed</span>
    </a>
  </div>
</section>


<section class="idx-section" id="features" markdown="0">
  <header class="idx-section-head">
    <span class="idx-section-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
           stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16v16H4zM8 8h8M8 12h8M8 16h5"/></svg>
    </span>
    <div>
      <h2>Feature specs</h2>
      <p>One page per subsystem — the authoritative description of what each does and why it was built that way.</p>
    </div>
  </header>
  <div class="idx-grid">
    <a class="idx-card" href="features/IPAM.html">
      <span class="idx-card-title">IPAM</span>
      <span class="idx-card-desc">Spaces, blocks, subnets, addresses, VLANs, custom fields, import and export</span>
    </a>
    <a class="idx-card" href="features/DNS.html">
      <span class="idx-card-title">DNS</span>
      <span class="idx-card-desc">Zones, records, views, server groups, blocking lists, DNSSEC, DoT / DoH, Windows DNS</span>
    </a>
    <a class="idx-card" href="features/DHCP.html">
      <span class="idx-card-title">DHCP</span>
      <span class="idx-card-desc">Servers, scopes, pools, reservations, leases, DDNS, Windows DHCP</span>
    </a>
    <a class="idx-card" href="features/AUTH.html">
      <span class="idx-card-title">Auth &amp; Permissions</span>
      <span class="idx-card-desc">LDAP, OIDC, SAML, RADIUS, TACACS+, roles, API tokens</span>
    </a>
    <a class="idx-card" href="features/ACME.html">
      <span class="idx-card-title">ACME DNS-01 Provider</span>
      <span class="idx-card-desc">acme-dns-compatible endpoint for public-CA certificate issuance</span>
    </a>
    <a class="idx-card" href="features/MIGRATION.html">
      <span class="idx-card-title">Migration</span>
      <span class="idx-card-desc">One-shot DNS, DHCP and NetBox importers, plus the guided Windows cutover</span>
    </a>
    <a class="idx-card" href="features/INTEGRATIONS.html">
      <span class="idx-card-title">Integrations</span>
      <span class="idx-card-desc">Read-only mirrors of Kubernetes, Docker, Proxmox, Tailscale, cloud and firewalls into IPAM</span>
    </a>
    <a class="idx-card" href="features/LOOKING_GLASS.html">
      <span class="idx-card-title">BGP Looking Glass</span>
      <span class="idx-card-desc">Receive-only GoBGP collector: sessions, routes, RPKI status at ingest</span>
    </a>
    <a class="idx-card" href="features/VERTICALS.html">
      <span class="idx-card-title">Vertical Network Awareness</span>
      <span class="idx-card-desc">AV-over-IP, BACnet/IP, industrial OT and DICOM registries, plus the do-not-probe flag</span>
    </a>
    <a class="idx-card" href="features/E911.html">
      <span class="idx-card-title">E911 Dispatchable Location</span>
      <span class="idx-card-desc">A Location Information Server: ERLs, port and subnet bindings, HELD and DHCP delivery</span>
    </a>
    <a class="idx-card" href="features/SYSTEM_ADMIN.html">
      <span class="idx-card-title">System Admin</span>
      <span class="idx-card-desc">Config, health dashboard, notifications, backup and restore, service control</span>
    </a>
  </div>
</section>


<section class="idx-section" id="deployment" markdown="0">
  <header class="idx-section-head">
    <span class="idx-section-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
           stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8l-9-5-9 5v8l9 5 9-5zM3 8l9 5 9-5M12 13v8"/></svg>
    </span>
    <div>
      <h2>Deployment</h2>
      <p>Every supported way to run it, from a single Compose host to a multi-node appliance cluster.</p>
    </div>
  </header>
  <div class="idx-grid">
    <a class="idx-card" href="deployment/APPLIANCE_INSTALL.html">
      <span class="idx-card-title">Install the OS Appliance</span>
      <span class="idx-card-desc">Step by step: the ISO, the installer, first boot, first login, adding nodes</span>
    </a>
    <a class="idx-card" href="deployment/DOCKER.html">
      <span class="idx-card-title">Docker Compose</span>
      <span class="idx-card-desc">Quick start, profiles, TLS, HA</span>
    </a>
    <a class="idx-card" href="deployment/KUBERNETES.html">
      <span class="idx-card-title">Kubernetes</span>
      <span class="idx-card-desc">Umbrella Helm chart, HPA, Ingress / LoadBalancer, CloudNativePG + Redis Sentinel HA</span>
    </a>
    <a class="idx-card" href="deployment/APPLIANCE.html">
      <span class="idx-card-title">OS Appliance Design</span>
      <span class="idx-card-desc">Why k3s, the A/B slot layout, the fleet firewall, control-plane HA internals, the build pipeline</span>
    </a>
    <a class="idx-card" href="deployment/BAREMETAL.html">
      <span class="idx-card-title">Bare Metal</span>
      <span class="idx-card-desc">Compose on a host and the appliance path (the Compose Patroni overlay is unsupported in 1.0)</span>
    </a>
    <a class="idx-card" href="deployment/WINDOWS.html">
      <span class="idx-card-title">Windows Server</span>
      <span class="idx-card-desc">WinRM, service accounts, firewall — the Windows-side checklist for DNS and DHCP</span>
    </a>
    <a class="idx-card" href="deployment/DNS_AGENT.html">
      <span class="idx-card-title">DNS Agent</span>
      <span class="idx-card-desc">Agent protocol, auto-registration, config sync</span>
    </a>
  </div>
</section>


<section class="idx-section" id="internals" markdown="0">
  <header class="idx-section-head">
    <span class="idx-section-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
           stroke-linecap="round" stroke-linejoin="round"><path d="M8 6L2 12l6 6M16 6l6 6-6 6"/></svg>
    </span>
    <div>
      <h2>Internals &amp; development</h2>
      <p>Driver internals for anyone reading the code, and how to build, test and contribute.</p>
    </div>
  </header>
  <div class="idx-grid">
    <a class="idx-card" href="drivers/DNS_DRIVERS.html">
      <span class="idx-card-title">DNS Drivers</span>
      <span class="idx-card-desc">BIND9, PowerDNS, Technitium and Windows DNS driver internals</span>
    </a>
    <a class="idx-card" href="drivers/DHCP_DRIVERS.html">
      <span class="idx-card-title">DHCP Drivers</span>
      <span class="idx-card-desc">Kea and Windows DHCP driver internals</span>
    </a>
    <a class="idx-card" href="DEVELOPMENT.html">
      <span class="idx-card-title">Development Guide</span>
      <span class="idx-card-desc">Coding standards, test requirements, CI pipeline</span>
    </a>
    <a class="idx-card" href="PERFORMANCE_TESTING.html">
      <span class="idx-card-title">Performance Testing</span>
      <span class="idx-card-desc">The 24-hour university-scale load and soak plan behind the <code>perf/</code> suite</span>
    </a>
    <a class="idx-card" href="PERF_APPLIANCE_SETUP.html">
      <span class="idx-card-title">Perf Appliance Setup</span>
      <span class="idx-card-desc">Preparing a clean single-node appliance for the suite to drive</span>
    </a>
  </div>
</section>


<section class="idx-section" id="project" markdown="0">
  <header class="idx-section-head">
    <span class="idx-section-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"
           stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l3 6 7 1-5 5 1 7-6-3-6 3 1-7-5-5 7-1z"/></svg>
    </span>
    <div>
      <h2>Project</h2>
      <p>Policies, licences, and where the project lives.</p>
    </div>
  </header>
  <div class="idx-grid">
    <a class="idx-card" href="PRIVACY.html">
      <span class="idx-card-title">Privacy</span>
      <span class="idx-card-desc">No telemetry, no analytics, no phone-home — every outbound connection, what it sends, how to turn it off</span>
    </a>
    <a class="idx-card" href="THIRD_PARTY.html">
      <span class="idx-card-title">Third-Party Components</span>
      <span class="idx-card-desc">Every bundled engine, library and OS package, with its licence and the artifact it ships in</span>
    </a>
    <a class="idx-card" href="{{ site.links.github }}/blob/main/CHANGELOG.md">
      <span class="idx-card-title">Changelog</span>
      <span class="idx-card-desc">What changed in each release, including upgrade notes</span>
    </a>
    <a class="idx-card" href="{{ site.links.github }}">
      <span class="idx-card-title">Source, Releases &amp; Issues</span>
      <span class="idx-card-desc">The project on GitHub</span>
    </a>
    <a class="idx-card" href="{{ site.links.discord }}">
      <span class="idx-card-title">Community</span>
      <span class="idx-card-desc">Questions and discussion on Discord</span>
    </a>
  </div>
</section>


<p class="idx-foot">
  Source for these pages lives in the
  <a href="{{ site.links.github }}/tree/main/docs"><code>docs/</code> directory</a>
  of the main repository and is republished on every push to <code>main</code>.
</p>
