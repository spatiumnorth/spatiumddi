---
layout: default
title: Web exposure detection
---

# Web exposure detection

Issue [#3651](https://github.com/spatiumnorth/spatiumddi/issues/3651).

An install that is reachable from the internet looks exactly like one that is
not. This feature answers one question, "is my control plane reachable from
outside my networks?", with a **verdict and its evidence**, raises one alert,
and offers a few opt-in responses built on controls the product already has.

It is deliberately **not** a WAF, not fail2ban, not geo-blocking and not an
intrusion detection system. It makes **no outbound connection** of any kind
(no geo database, no reputation feed; see [PRIVACY.md](../PRIVACY.md) section
7).

## Off by default

Detection is the feature module **Web exposure detection**
(`security.web_exposure`, group Security). It ships **off**: enable it under
Features & Integrations. Every mitigation is a further, separate, default-off
setting. Turning the module on arms nothing.

## What counts as "internal"

A client address is classified, in this order:

| Class | Meaning |
|---|---|
| `trusted` | Inside the **trusted networks** list (Settings > Security > Reachability). Empty by default. |
| `internal` | Private address space: RFC 1918, CGNAT `100.64.0.0/10`, ULA `fc00::/7`, loopback, link-local. |
| `external` | Anything else. |

"Internal" is **not** inferred from IPAM. An operator who numbers their LAN
from public space (a university, an ISP, a VPN that hands out public
addresses) lists those ranges as trusted networks; that list is the only
escape hatch. It is a classification list, not an allow-list: nothing is
refused because of it.

Every signal is keyed on the spoofing-resistant client address
(`get_trusted_client_ip`: `X-Real-IP` is believed only from a trusted proxy
peer, `X-Forwarded-For` never; see
[REVERSE_PROXY.md](../deployment/REVERSE_PROXY.md)). Sources are aggregated by
bucket (IPv4 /24, IPv6 /48) so a scanner walking one /24 reads as one source.

## Signals

Counted only for `external` sources:

| Signal | Source |
|---|---|
| Login page loaded | unauthenticated `GET /api/v1/settings/public` |
| Unauthenticated api hit | 401 / 403 on `/api/v1/*` (not the sign-in route) |
| Version fetch | `GET /api/v1/version` (recorded, never reaches the threshold alone) |
| Failed sign-in | every failed `/auth/login`, with a count of distinct usernames tried |
| Host refusal | a request refused by `TRUSTED_HOSTS` |

Excluded from every signal, as maintenance mode exempts them (agents must
keep working): the DNS / DHCP agent and supervisor routes, health, metrics, and
the ACME and HELD routes that are reachable from outside by design.

A proxy that sends `X-Forwarded-For` but no `X-Real-IP` makes every client look
like the proxy. That is reported as an **attribution warning** (exposure cannot
be judged until the proxy is trusted) rather than silently counted as internal.

Scanner-path signals (`/wp-login.php`, `/.env`) are not collected: on Compose
and Helm those requests are answered by the frontend's nginx and never reach
the api.

## The verdict

Over the evaluation window (default 24 h):

* **exposed**: at least *threshold* (default 3) distinct external networks
  loaded the login page or got a 401, **or** any failed sign-in from an
  external network, **or** any refused Host header from one.
* **reached from outside**: some external traffic, below that. A remote admin or
  a poller. Shown on the Security tab only; no alert.
* **not observed**: nothing from outside. Honest, not "safe": nobody may simply
  have tried.
* **unknown**: the counters could not be read.

Severity: `warning` for reachability, `critical` when the same window carries
failed sign-ins or a username spray (five or more distinct usernames). The
**intentional** acknowledgement demotes reachability to `info` but keeps the
attack-evidence escalation. "Exposed" means reachable and probed, never
"breached".

Each verdict carries its evidence: which outside networks, how many requests,
first and last seen, which endpoints (login page versus other api paths), and
a fix for the detected deployment shape (appliance, Compose, Kubernetes).

## Where it shows

* **Security dashboard tab**, a Reachability card (counts for everyone who can
  see the tab, the per-network rows for callers who may read the audit log,
  exact sample addresses for superadmins).
* **Alert rule** `web_ui_exposed` (enabled, inert while the module is off; the
  distinct-network threshold is editable). It rides every existing channel.
  The event text carries networks and counts, never exact addresses.
* **Settings > Security > Reachability**: trusted networks, the intentional
  flag, window and threshold, the evidence table with a one-click "this is
  ours", and the mitigations.
* **Copilot (MCP)**: `get_web_exposure_verdict` and `find_web_access_sources`,
  read-only, superadmin, enabled by default (same data the Security tab shows a
  superadmin). There is **no** `propose_*` tool for any setting: every
  mitigation can lock an operator out, and the pre-flights depend on which
  address the human is sitting at, which a chat window does not know.

## Storage

Redis only, bounded by construction: one hash per hour (expires after eight
days) capped at a fixed number of fields, an in-process buffer capped at 256
networks, flushed every few seconds in one pipeline. A scanner cannot grow it.
If Redis is down the counters are dropped, never spooled to disk. Submitted
usernames are stored only as hashes inside a HyperLogLog.

## Mitigations (all default off)

Nothing turns on because of a verdict. **A source that classifies as `trusted`
or `internal` is never subject to any tier**, whatever the settings say, so a
wrong threshold cannot touch your own networks. Redis trouble fails open.

| Tier | Effect | You will not be locked out because |
|---|---|---|
| **1a** stricter throttle | a second per-network sign-in budget for external sources (default 5 per 60 s per /24 or /48), same 429 + `Retry-After` | internal / trusted sources are exempt; a remote admin waits out the window; fails open |
| **1b** temporary ban | after N failed sign-ins (default 10 in 15 min) from one external network, refuse sign-in from it for 15 min, doubling to a cap (default 24 h). Listed and clearable in Settings; at most 200 bans; Redis only so a restart clears it; each ban and clear is audited | internal / trusted sources are never banned; bans expire by themselves; clear any ban from an internal address. A remote admin sharing a network with an attacker is banned too: that is the trade |
| **2** second factor from outside | a **local** account without TOTP is refused at sign-in from an external network, after the password was verified, with a message to enrol from inside. TOTP-enrolled users, SSO / LDAP / RADIUS / TACACS+ users and API tokens are unaffected | enabling it is refused (422) unless you are connecting from an internal / trusted address or your own account has TOTP; the refusal names every local superadmin without TOTP. There is no acknowledgement path |
| **3a** appliance allow-list | one click writes the trusted networks plus private space into the existing Web UI source restriction (nftables 80 / 443 and `loadBalancerSourceRanges`) | it goes through the existing endpoint and its guards: refused unless your own address stays covered, console-only pre-flight, the console recovers it |

**Not built: tier 3b**, an application-layer allow-list for Compose / Helm. It
is the only mitigation that could strand an operator with no second door, and
whether to ship it at all is undecided. On Compose or Kubernetes the finding
prints the network-layer fix instead (bind `HTTP_PORT` to the LAN interface;
`frontend.loadBalancerSourceRanges`).

### Break glass

If you cannot reach Settings, set `WEB_EXPOSURE_MITIGATIONS=off` in the api
environment and restart the api (Compose: `docker compose up -d api`; Helm:
`api.extraEnv`). Every tier is disabled whatever is stored, and Settings says
so. Remove the variable to re-enable them. A Redis flush also clears all bans.
