import axios, {
  AxiosError,
  type AxiosInstance,
  type AxiosResponse,
} from "axios";
import { getAccessToken, setAccessToken } from "@/lib/authToken";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api/v1";

function createClient(): AxiosInstance {
  const client = axios.create({
    baseURL: API_BASE,
    headers: { "Content-Type": "application/json" },
    // Serialise array query params as ``?tag=foo&tag=bar`` (repeated
    // key without brackets) — that's the form FastAPI's
    // ``Query(default_factory=list)`` parses natively. axios 1.x
    // would otherwise emit ``?tag[]=foo`` which FastAPI ignores.
    // ``indexes: null`` is the documented opt-in for "no brackets,
    // no indices, just repeat the key".
    paramsSerializer: { indexes: null },
  });

  // Attach the in-memory Bearer token on every request (#484 / #400 L1).
  // The access token lives ONLY in JS memory (lib/authToken.ts); the refresh
  // token is an HttpOnly cookie the browser sends automatically on the
  // path-scoped /auth/refresh + /auth/logout calls — never readable here.
  client.interceptors.request.use((config) => {
    const token = getAccessToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  });

  // On 401, attempt token refresh once then redirect to login.
  //
  // Two deadlock traps to avoid:
  //
  //   1. The ``/auth/refresh`` call itself goes through this same
  //      interceptor. A 401 from refresh must NOT be treated as
  //      "try to refresh again" — otherwise it queues on itself and
  //      the outer ``await`` never resolves, the ``catch`` block
  //      never runs, and the user is never redirected.
  //
  //   2. If refresh fails, we must reject every queued request too
  //      — not just the current one. Otherwise any concurrent
  //      requests that were already queued hang forever.
  // NOTE: isRefreshing + refreshQueue are closure-local to this
  // createClient() call. That's correct here because createClient() is
  // invoked exactly once and the single instance is exported as `api`
  // below — so there is one shared refresh lock + queue process-wide. If
  // this module were ever evaluated twice (e.g. a test that re-imports a
  // fresh copy), each copy would get its own lock and two concurrent 401s
  // could trigger two parallel refreshes. Keep createClient() a singleton.
  let isRefreshing = false;
  let refreshQueue: Array<{
    resolve: (token: string) => void;
    reject: (err: unknown) => void;
  }> = [];

  // A 401 from a credential endpoint (login / login/mfa / refresh) means bad
  // credentials or a dead refresh token — NOT an expired access token. It must
  // never trigger the refresh-and-retry path below: retrying a wrong-password
  // /auth/login would double-count the failed-login audit row + lockout/
  // rate-limit budget, and retrying /auth/refresh would loop on itself (#484).
  function isCredentialEndpoint(url: string | undefined): boolean {
    const path = url ? url.replace(/^[^/]*\/\//, "") : "";
    return path.includes("/auth/login") || path.includes("/auth/refresh");
  }

  function forceLogin(): void {
    setAccessToken(null);
    // Skip redirect if we're already on /login so the user doesn't
    // see a white flash when an expired session fires first.
    if (!window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
  }

  client.interceptors.response.use(
    (res) => res,
    async (err: AxiosError) => {
      const originalRequest = err.config as typeof err.config & {
        _retry?: boolean;
      };

      // 401 on a credential endpoint (login / login/mfa / refresh) = bad
      // credentials or a dead refresh token. Surface the original error so the
      // caller's ``catch`` branch runs its cleanup + redirect. Don't refresh:
      // the refresh call would loop on itself, and a login retry would
      // double-charge the lockout/audit budget.
      if (
        err.response?.status === 401 &&
        isCredentialEndpoint(originalRequest?.url)
      ) {
        return Promise.reject(err);
      }

      if (err.response?.status === 401 && !originalRequest?._retry) {
        if (isRefreshing) {
          return new Promise((resolve, reject) => {
            refreshQueue.push({
              resolve: (token: string) => {
                if (originalRequest?.headers)
                  originalRequest.headers.Authorization = `Bearer ${token}`;
                resolve(client(originalRequest!));
              },
              reject,
            });
          });
        }

        originalRequest._retry = true;
        isRefreshing = true;
        try {
          // The refresh token rides the HttpOnly cookie automatically; the
          // rotated refresh token comes back as a new Set-Cookie and the fresh
          // access token in the JSON body (#484). ``withCredentials`` lets the
          // cookie flow on a cross-ORIGIN (but same-site) API host when CORS
          // credentials are enabled; the cookie is SameSite=Strict, so a
          // genuinely cross-SITE SPA/API split is not supported by design.
          const res = await client.post<RefreshResponse>(
            "/auth/refresh",
            {},
            { withCredentials: true },
          );
          const { access_token } = res.data;
          setAccessToken(access_token);
          refreshQueue.forEach(({ resolve }) => resolve(access_token));
          refreshQueue = [];
          if (originalRequest?.headers)
            originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return client(originalRequest!);
        } catch (refreshErr) {
          // Refresh failed — reject every queued request so their
          // awaits resolve, then clear storage + redirect.
          refreshQueue.forEach(({ reject }) => reject(refreshErr));
          refreshQueue = [];
          forceLogin();
          return Promise.reject(err);
        } finally {
          isRefreshing = false;
        }
      }
      return Promise.reject(err);
    },
  );

  return client;
}

export const api = createClient();

/**
 * Normalise whatever shape an API error arrives in into a single string
 * suitable for React children (issue #31) and operator-readable toasts
 * / inline form errors (issue #186).
 *
 * FastAPI returns three common shapes:
 *   - 4xx HTTPException:   `{"detail": "some message"}`
 *   - 422 validation:      `{"detail": [{"type", "loc", "msg", "input", "ctx"}, ...]}`
 *   - Unhandled 500:       `{"detail": "Internal Server Error"}` or no body
 *
 * Use this **everywhere** an error gets rendered — including
 * ``{(mutation.error as Error).message}``-style sites. Axios's default
 * ``.message`` is just ``"Request failed with status code N"`` which
 * hides the backend's actual detail; this helper pulls the right field
 * for each shape. Original use case was issue #31 (avoid React error
 * "Objects are not valid as a React child" when the 422 path returned
 * an array); issue #186 extended adoption across every error-render
 * site in the app.
 */
export function formatApiError(err: unknown, fallback = "Error"): string {
  const anyErr = err as {
    response?: { data?: { detail?: unknown } };
    message?: string;
  };
  const detail = anyErr?.response?.data?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    // Pydantic v2 validation errors.
    const parts = detail
      .map((e) => {
        if (!e || typeof e !== "object") return String(e);
        const rec = e as { msg?: unknown; loc?: unknown };
        const loc = Array.isArray(rec.loc)
          ? rec.loc.filter((s) => s !== "body").join(".")
          : "";
        const msg = typeof rec.msg === "string" ? rec.msg : JSON.stringify(e);
        return loc ? `${loc}: ${msg}` : msg;
      })
      .filter(Boolean);
    if (parts.length) return parts.join("; ");
  }
  if (detail && typeof detail === "object") {
    // A structured 422 that names the offending field, e.g. the DNS view
    // address-match-list validator (#876):
    //   {"field": "match_clients", "value": "10.0.0.300", "message": "…"}
    // Without this the operator was shown the raw JSON, which buries the
    // one sentence that tells them what to fix.
    const rec = detail as { message?: unknown; field?: unknown };
    if (typeof rec.message === "string" && rec.message.trim()) {
      return typeof rec.field === "string" && rec.field
        ? `${rec.field}: ${rec.message}`
        : rec.message;
    }
    // Unexpected shape — stringify defensively so we never render an object.
    try {
      return JSON.stringify(detail);
    } catch {
      return fallback;
    }
  }
  if (typeof anyErr?.message === "string" && anyErr.message)
    return anyErr.message;
  return fallback;
}

// Typed API helpers

export type DdnsHostnamePolicy =
  | "client_provided"
  | "client_or_generated"
  | "always_generate"
  | "disabled";

export interface IPSpace {
  id: string;
  name: string;
  description: string;
  is_default: boolean;
  tags: Record<string, unknown>;
  color: string | null;
  dns_group_ids: string[];
  dns_zone_id: string | null;
  dns_additional_zone_ids: string[];
  dhcp_server_group_id?: string | null;
  // DDNS defaults — root of the block → subnet inheritance chain. Descendants
  // use these when their own `ddns_inherit_settings` is True.
  ddns_enabled?: boolean;
  ddns_hostname_policy?: DdnsHostnamePolicy;
  ddns_domain_override?: string | null;
  ddns_ttl?: number | null;
  // Fragile-device probe suppression (#722). ORs down the
  // space → block → subnet chain — any level setting it suppresses
  // every level below, and a descendant cannot un-set it. Reason
  // travels with the flag and is quoted back in every refusal.
  do_not_probe?: boolean;
  do_not_probe_reason?: string;
  // VRF / routing annotation — pure metadata; address allocation
  // ignores these. ``route_targets`` is an array of strings so the
  // operator can encode the inline import:A:B; export:C:D convention
  // until first-class import / export columns land.
  vrf_id?: string | null;
  vrf_name?: string | null;
  route_distinguisher?: string | null;
  route_targets?: string[] | null;
  asn_id?: string | null;
  // Logical ownership (issue #91). NULL = unassigned.
  customer_id?: string | null;
  created_at?: string;
  modified_at?: string;
}

export interface IPBlock {
  id: string;
  space_id: string;
  parent_block_id: string | null;
  network: string;
  name: string;
  description: string;
  utilization_percent: number;
  allocated_ips?: number;
  total_ips?: number;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  dns_group_ids: string[] | null;
  dns_zone_id: string | null;
  dns_additional_zone_ids: string[] | null;
  dns_inherit_settings: boolean;
  // Issue #25 — block-level split-horizon flag, inheritable to
  // descendant subnets via the existing dns_inherit_settings walk.
  dns_split_horizon?: boolean;
  dhcp_server_group_id?: string | null;
  dhcp_inherit_settings?: boolean;
  // DDNS inheritance. When `ddns_inherit_settings` is True, the four
  // fields above it are ignored and the effective config comes from the
  // parent block chain → space.
  ddns_enabled?: boolean;
  ddns_hostname_policy?: DdnsHostnamePolicy;
  ddns_domain_override?: string | null;
  ddns_ttl?: number | null;
  ddns_inherit_settings?: boolean;
  // Fragile-device probe suppression (#722). ORs down the
  // space → block → subnet chain — any level setting it suppresses
  // every level below, and a descendant cannot un-set it. Reason
  // travels with the flag and is quoted back in every refusal.
  do_not_probe?: boolean;
  do_not_probe_reason?: string;
  vrf_id?: string | null;
  asn_id?: string | null;
  customer_id?: string | null;
  site_id?: string | null;
  applied_template_id?: string | null;
  created_at?: string;
  modified_at?: string;
}

export interface FreeCidrRange {
  network: string;
  first: string;
  last: string;
  size: number;
  prefix_len: number;
}

export interface PlanRequestItem {
  count: number;
  prefix_len: number;
}

export interface PlannedSubnet {
  prefix_len: number;
  network: string;
  first: string;
  last: string;
  size: number;
}

export interface UnfulfilledItem {
  prefix_len: number;
  requested: number;
  allocated: number;
}

export interface AggregationSuggestion {
  supernet: string;
  prefix_len: number;
  total_size: number;
  subnet_ids: string[];
  subnet_networks: string[];
  // Stable hash that ties the suggestion to a snooze entry. The popover
  // sends this back when the operator snoozes or dismisses the candidate.
  candidate_key: string;
  // ISO timestamp (snoozed-until) or the literal ``"permanent"`` when
  // dismissed. ``null`` for live, un-acted-on candidates.
  snoozed_until: string | null;
}

export interface PlanAllocationResponse {
  block_network: string;
  block_prefix_len: number;
  allocations: PlannedSubnet[];
  unfulfilled: UnfulfilledItem[];
  remaining_free: FreeCidrRange[];
}

// ── Subnet plans (multi-level CIDR designs) ─────────────────────────────

export interface PlanNode {
  id: string;
  network: string;
  name: string;
  description: string;
  existing_block_id?: string | null;
  kind: "block" | "subnet";
  // Optional resource bindings — null/undefined = inherit from parent.
  dns_group_id?: string | null;
  dns_zone_id?: string | null;
  dhcp_server_group_id?: string | null;
  vlan_ref_id?: string | null;
  gateway?: string | null;
  children: PlanNode[];
}

export interface SubnetPlanRead {
  id: string;
  name: string;
  description: string;
  space_id: string;
  tree: PlanNode | null;
  applied_at: string | null;
  applied_resource_ids: { block_ids: string[]; subnet_ids: string[] } | null;
  created_by_user_id: string | null;
  created_at: string;
  modified_at: string;
}

export interface SubnetPlanCreate {
  name: string;
  description?: string;
  space_id: string;
  tree: PlanNode;
}

export interface SubnetPlanUpdate {
  name?: string;
  description?: string;
  tree?: PlanNode;
}

export interface PlanValidationConflict {
  node_id: string;
  network: string;
  kind:
    | "overlap_existing"
    | "out_of_parent"
    | "sibling_overlap"
    | "duplicate_id"
    | "missing_block";
  message: string;
}

export interface PlanValidationResult {
  ok: boolean;
  conflicts: PlanValidationConflict[];
  summary: { block_count: number; subnet_count: number };
}

export interface PlanApplyResult {
  block_ids: string[];
  subnet_ids: string[];
  applied_at: string;
}

/** Effective fragile-device probe verdict for a subnet (#722).
 *
 * ``inherited`` distinguishes "this subnet is flagged" from "an ancestor
 * flagged it" — i.e. whether clearing the subnet's own checkbox would
 * actually re-enable probing. */
export interface ProbePolicy {
  do_not_probe: boolean;
  reason: string;
  /** ``subnet:<id>`` / ``block:<id>`` / ``space:<id>``; null when
   *  nothing is suppressing. */
  source: string | null;
  scope: string | null;
  inherited: boolean;
}

export interface EffectiveDns {
  dns_group_ids: string[];
  dns_zone_id: string | null;
  dns_additional_zone_ids: string[];
  inherited_from_block_id: string | null;
}

export interface EffectiveDhcp {
  dhcp_server_group_id: string | null;
  inherited_from_block_id: string | null;
  inherited_from_space: boolean;
}

export interface DnsSyncMissing {
  ip_id: string;
  ip_address: string;
  hostname: string;
  record_type: "A" | "AAAA" | "PTR";
  expected_name: string;
  expected_value: string;
  zone_id: string;
  zone_name: string;
}

export interface DnsSyncMismatch {
  record_id: string;
  ip_id: string;
  ip_address: string;
  record_type: "A" | "AAAA" | "PTR";
  zone_id: string;
  zone_name: string;
  current_name: string;
  current_value: string;
  expected_name: string;
  expected_value: string;
}

export interface DnsSyncStale {
  record_id: string;
  record_type: string;
  zone_id: string;
  zone_name: string;
  name: string;
  value: string;
  reason: string;
}

export interface DnsSyncPreview {
  subnet_id: string;
  forward_zone_id: string | null;
  forward_zone_name: string | null;
  reverse_zone_id: string | null;
  reverse_zone_name: string | null;
  missing: DnsSyncMissing[];
  mismatched: DnsSyncMismatch[];
  stale: DnsSyncStale[];
}

export interface DnsSyncCommitResult {
  created: number;
  updated: number;
  deleted: number;
  errors: string[];
}

export interface DnsSyncSummary {
  subnet_id: string;
  missing: number;
  mismatched: number;
  stale: number;
  total: number;
  has_drift: boolean;
}

export interface SubnetVLANRef {
  id: string;
  router_id: string;
  router_name: string | null;
  vlan_id: number;
  name: string;
}

export type SubnetRole = "data" | "voice" | "management" | "guest";

export const SUBNET_ROLES: readonly SubnetRole[] = [
  "data",
  "voice",
  "management",
  "guest",
] as const;

export const SUBNET_ROLE_LABELS: Record<SubnetRole, string> = {
  data: "Data",
  voice: "Voice",
  management: "Management",
  guest: "Guest",
};

export interface SubnetUtilizationPoint {
  sampled_at: string;
  allocated_ips: number;
  total_ips: number;
  utilization_percent: number;
}

export interface Subnet {
  id: string;
  space_id: string;
  block_id: string;
  network: string;
  name: string;
  description: string;
  /**
   * Auto-detected from the CIDR on create:
   *   - ``"unicast"`` (default) — endpoints + per-IP allocation
   *   - ``"multicast"`` — stream-identity range (224.0.0.0/4 v4 /
   *     ff00::/8 v6); IPAM allocation endpoints refuse, multicast
   *     groups are managed under /multicast/groups instead.
   */
  kind?: string;
  // Auto-derived server-side (issue #42): true when ``network`` sits
  // inside CGNAT space (RFC 6598, 100.64.0.0/10). Read-only — drives
  // the "CGNAT" badge. Carrier-grade NAT space that overlays like
  // Tailscale allocate, so it's worth flagging vs a normal LAN.
  is_cgnat?: boolean;
  vlan_id: number | null;
  vxlan_id: number | null;
  vlan_ref_id?: string | null;
  vlan?: SubnetVLANRef | null;
  gateway: string | null;
  status: string;
  skip_auto_addresses?: boolean;
  utilization_percent: number;
  total_ips: number;
  allocated_ips: number;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  dns_group_ids: string[] | null;
  dns_zone_id: string | null;
  dns_additional_zone_ids: string[] | null;
  dns_inherit_settings: boolean;
  // Issue #25 — when true the IP picker becomes a multi-select
  // grouped by DNS server group; ``IPAddress.extra_zone_ids``
  // carries the extras. Off = single-zone publishing (current).
  dns_split_horizon?: boolean;
  dhcp_server_group_id?: string | null;
  dhcp_inherit_settings?: boolean;
  // DDNS — dynamic DNS reconciliation from DHCP leases. Subnet-level
  // opt-in; when enabled, lease-mirrored IPAM rows get an A/AAAA + PTR
  // per ``ddns_hostname_policy``. See docs/features/DNS.md §7.
  ddns_enabled?: boolean;
  ddns_hostname_policy?:
    | "client_provided"
    | "client_or_generated"
    | "always_generate"
    | "disabled";
  ddns_domain_override?: string | null;
  ddns_ttl?: number | null;
  // When True, the four fields above are ignored and the effective DDNS
  // config is resolved from the containing block / space.
  ddns_inherit_settings?: boolean;
  // Device profiling — opt-in auto-nmap on new DHCP leases. See
  // CLAUDE.md "Device profiling" entry. Default off because nmap is
  // loud (corporate IDS will flag the source IP); operators must
  // authorise + enable per subnet. ``auto_profile_refresh_days`` is
  // the dedupe window so churning Wi-Fi clients don't re-trigger.
  auto_profile_on_dhcp_lease?: boolean;
  auto_profile_preset?:
    | "quick"
    | "service_version"
    | "os_fingerprint"
    | "service_and_os"
    | "default_scripts"
    | "udp_top1000"
    | "aggressive";
  auto_profile_refresh_days?: number;
  // IP discovery (issue #23) — opt-in scheduled ping/ARP sweep.
  discovery_enabled?: boolean;
  discovery_interval_minutes?: number;
  last_discovery_at?: string | null;
  // Fragile-device probe suppression (#722). This is the subnet's OWN
  // flag — an ancestor block / space can suppress a subnet whose own
  // flag is false. Resolve the effective answer with
  // ``ipamApi.probePolicy(subnetId)``.
  do_not_probe?: boolean;
  do_not_probe_reason?: string;
  // Compliance / classification flags. First-class booleans (rather
  // than freeform tags) so auditor queries — "show me every PCI
  // subnet" — are clean indexed predicates. Default false on every
  // subnet; flip via the Edit modal. Surfaces on the Compliance
  // dashboard at /admin/compliance.
  pci_scope?: boolean;
  hipaa_scope?: boolean;
  internet_facing?: boolean;
  // Planned decommission date (issue #46). ISO date (YYYY-MM-DD) or
  // null when no decom is scheduled. Drives the ``decom_expiring``
  // alert + the dashboard decom-awareness widget.
  decom_date?: string | null;
  // Network-role classification (issue #112 phase 2). NULL means
  // unspecified; values are ``data`` / ``voice`` / ``management`` /
  // ``guest``. Drives the IPAM filter chip + VLAN-page voice tag +
  // voice-segment conformity / alert rules.
  subnet_role?: SubnetRole | null;
  dns_servers?: string[] | null;
  domain_name?: string | null;
  applied_template_id?: string | null;
  // Logical ownership (issue #91). NULL = unassigned.
  customer_id?: string | null;
  site_id?: string | null;
  created_at?: string;
  modified_at?: string;
}

/** One IP row in a reconciliation bucket (issue #23). */
export interface ReconciliationEntry {
  id: string;
  address: string;
  status: string;
  hostname: string | null;
  mac_address: string | null;
  last_seen_at: string | null;
  last_seen_method: string | null;
}

/** IP-discovery reconciliation report for a subnet (issue #23). */
export interface SubnetReconciliation {
  subnet_id: string;
  network: string;
  generated_at: string;
  stale_minutes: number;
  last_discovery_at: string | null;
  counts: {
    in_ipam_not_seen: number;
    discovered_not_allocated: number;
    status_mismatch: number;
  };
  in_ipam_not_seen: ReconciliationEntry[];
  discovered_not_allocated: ReconciliationEntry[];
  status_mismatch: ReconciliationEntry[];
}

/** One stale allocated IP in the address-space hygiene report (issue #45). */
export interface StaleIPEntry {
  id: string;
  address: string;
  status: string;
  hostname: string | null;
  mac_address: string | null;
  last_seen_at: string | null;
  last_seen_method: string | null;
  days_stale: number | null;
  subnet_id: string;
  subnet_network: string | null;
  subnet_name: string | null;
}

/** Stale-IP report — allocated IPs nothing has seen in N days (issue #45). */
export interface StaleIPReport {
  generated_at: string;
  stale_days: number;
  include_never_seen: boolean;
  total: number;
  limit: number;
  offset: number;
  entries: StaleIPEntry[];
}

export interface StaleIPReportParams {
  stale_days?: number;
  include_never_seen?: boolean;
  space_id?: string;
  block_id?: string;
  subnet_id?: string;
  limit?: number;
  offset?: number;
}

export interface StaleIPDeprecateRequest {
  ip_ids?: string[];
  all_matching?: boolean;
  stale_days?: number;
  include_never_seen?: boolean;
  space_id?: string;
  block_id?: string;
  subnet_id?: string;
}

export interface StaleIPDeprecateResponse {
  batch_id: string;
  deprecated_count: number;
  skipped: string[];
  capped: boolean;
}

/** Optional role tag, orthogonal to ``status``. Roles in
 *  ``IP_ROLES_SHARED`` (anycast / vip / vrrp) are intentionally
 *  shared across multiple devices — the API skips MAC-collision
 *  warnings for them. */
export type IPRole =
  | "host"
  | "loopback"
  | "anycast"
  | "vip"
  | "vrrp"
  | "secondary"
  | "gateway"
  | "bmc";

export const IP_ROLE_OPTIONS: IPRole[] = [
  "host",
  "loopback",
  "anycast",
  "vip",
  "vrrp",
  "secondary",
  "gateway",
  // Baseboard management controller — iDRAC / iLO / IPMI / Redfish
  // (#722). A management-plane endpoint on a fragile embedded stack,
  // and a routine casualty of ping sweeps: naming the class is what
  // lets an operator find them all and decide whether their subnet
  // belongs behind the do-not-probe flag.
  "bmc",
];

export const IP_ROLES_SHARED: ReadonlySet<IPRole> = new Set([
  "anycast",
  "vip",
  "vrrp",
]);

export interface IPAddress {
  id: string;
  subnet_id: string;
  address: string;
  status: string;
  /** Curated role tag — null = no specific role. See ``IP_ROLE_OPTIONS``. */
  role?: IPRole | null;
  /** TTL on a ``status='reserved'`` row. The Celery sweep task flips
   *  the row back to ``available`` after this passes. */
  reserved_until?: string | null;
  /** Planned decommission date (issue #46). ISO date (YYYY-MM-DD) or
   *  null when no decom is scheduled. */
  decom_date?: string | null;
  hostname: string | null;
  fqdn: string | null;
  description: string;
  mac_address: string | null;
  owner_user_id?: string | null;
  last_seen_at?: string | null;
  last_seen_method?: string | null;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  // Linkage (§3) — populated by Wave 3 DDNS/DHCP integration.
  forward_zone_id?: string | null;
  // Issue #25 — additional zones to publish A/AAAA records into
  // beyond the singular primary. Each entry is a zone UUID. Empty
  // list = current behaviour (one record). Operator-edited via the
  // multi-zone picker on the IP create / edit modal when the
  // subnet's ``dns_split_horizon`` is on.
  extra_zone_ids?: string[];
  reverse_zone_id?: string | null;
  dns_record_id?: string | null;
  dhcp_lease_id?: string | null;
  static_assignment_id?: string | null;
  // True when this row is a dynamic-lease mirror created by the DHCP
  // lease-pull task. Such rows are read-only in the UI — the DHCP server
  // owns their state and any edit would get overwritten on the next pull.
  auto_from_lease?: boolean;
  // User-added CNAME/A aliases on this IP (excludes the primary A).
  alias_count?: number;
  // Count of NAT mappings referencing this IP (as either internal or
  // external endpoint). Populated by /ipam/subnets/{id}/addresses;
  // defaults to 0 elsewhere. Surfaced as a small "NAT" badge in the
  // IP-row of IPAMPage with a tooltip listing the matching mapping
  // names.
  nat_mapping_count?: number;
  // IEEE OUI vendor for this MAC (populated when OUI lookup is enabled).
  vendor?: string | null;
  // ``true`` when ``vendor`` matches the curated VoIP-phone vendor list
  // (issue #112 phase 3). Drives the Phone icon next to the MAC in the
  // IP detail modal + IPAM table. Always false when vendor is null.
  is_voip_phone?: boolean;
  // Device profile (active-layer Phase 1). ``last_profiled_at`` is the
  // finished_at of the most recent successful nmap profile scan;
  // ``last_profile_scan_id`` deep-links to the NmapScan row. Surfaced
  // in the IP detail modal's "Device profile" section.
  last_profiled_at?: string | null;
  last_profile_scan_id?: string | null;
  // Device profile (passive-layer Phase 2). Populated by the
  // fingerbank lookup task off DHCP option-55/option-60 captures
  // pushed by the agent's scapy sniffer. Null while the sniffer is
  // disabled or no fingerprint has been observed for the row's MAC.
  device_type?: string | null;
  device_class?: string | null;
  device_manufacturer?: string | null;
  created_at?: string;
  modified_at?: string;
}

/** A cross-subnet search hit (issue #520). Extends {@link IPAddress}
 *  with the joined subnet + space identity so the UI can render + group
 *  results that span many subnets. Returned by ``GET
 *  /ipam/addresses/search``. */
export interface IPAddressSearchItem extends IPAddress {
  subnet_cidr: string;
  subnet_name: string | null;
  space_id: string;
  space_name: string | null;
}

/** Envelope for ``GET /ipam/addresses/search`` (issue #520). */
export interface AddressSearchResponse {
  items: IPAddressSearchItem[];
  total: number;
  limit: number;
  offset: number;
}

/** Envelope for ``GET /ipam/addresses/search/ids`` — used by the
 *  "select all N matches" cross-subnet bulk flow. ``ids`` is capped at
 *  5000 server-side; ``capped`` is true when ``total`` exceeded that. */
export interface AddressSearchIdsResponse {
  ids: string[];
  total: number;
  capped: boolean;
}

/** Optional query params for the per-subnet address list + the
 *  cross-subnet search (issue #517 / #519 / #520). All fields are
 *  optional; an empty object reproduces the legacy full-list behavior. */
export interface AddressQueryParams {
  q?: string;
  hostname?: string;
  mac?: string;
  status_filter?: string;
  /** Repeatable ``k:v`` tag filters. */
  tag?: string[];
  sort?:
    | "address"
    | "hostname"
    | "status"
    | "mac"
    | "last_seen"
    | "description";
  order?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

/** Cross-subnet search params — {@link AddressQueryParams} plus the
 *  scope narrowers. */
export interface AddressSearchParams extends AddressQueryParams {
  space_id?: string;
  block_id?: string;
  subnet_id?: string;
}

/** Joined view of the ``dhcp_fingerprint`` row (passive-layer Phase 2)
 *  that matches an IP's MAC. Surfaced in the IP detail modal's "Device
 *  profile" section under a "Raw signature" disclosure. */
export interface DHCPFingerprintResponse {
  mac_address: string;
  option_55: string | null;
  option_60: string | null;
  option_77: string | null;
  client_id: string | null;
  fingerbank_device_id: number | null;
  fingerbank_device_name: string | null;
  fingerbank_device_class: string | null;
  fingerbank_manufacturer: string | null;
  fingerbank_score: number | null;
  fingerbank_last_lookup_at: string | null;
  fingerbank_last_error: string | null;
  first_seen_at: string;
  last_seen_at: string;
}

/** One observation in an IP's MAC history. ``vendor`` is best-effort
 *  via the OUI lookup feature. */
export interface MacHistoryEntry {
  id: string;
  mac_address: string;
  first_seen: string;
  last_seen: string;
  vendor?: string | null;
}

export interface SubnetAlias {
  id: string;
  zone_id: string;
  name: string;
  record_type: string;
  value: string;
  fqdn: string;
  ip_address_id: string;
  ip_address: string;
  ip_hostname: string | null;
}

export interface SubnetDomain {
  id: string;
  subnet_id: string;
  dns_zone_id: string;
  is_primary: boolean;
  zone_name: string | null;
}

export interface EffectiveFields {
  subnet_id: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  tag_sources: Record<string, string>;
  custom_field_sources: Record<string, string>;
}

export interface BlockEffectiveFields {
  block_id: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  tag_sources: Record<string, string>;
  custom_field_sources: Record<string, string>;
}

export interface SubnetBulkEditChanges {
  name?: string;
  description?: string;
  status?: string;
  vlan_id?: number;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface SubnetBulkEditResponse {
  batch_id: string;
  updated_count: number;
  not_found: string[];
}

// ── Resize (grow-only) ─────────────────────────────────────────────────────
//
// Two-phase contract (preview → commit). Preview is a pure read; commit
// takes a pg advisory lock and re-validates before mutating. Shrinking is
// explicitly out of scope — the backend returns 422 if the new prefix
// length is >= the current one.

export interface ResizeConflict {
  type: string;
  detail: string;
}

export interface SubnetResizePlaceholder {
  ip: string;
  hostname: string;
}

export interface SubnetResizePreviewRequest {
  new_cidr: string;
  move_gateway_to_first_usable?: boolean;
}

export interface SubnetResizePreviewResponse {
  old_cidr: string;
  new_cidr: string;
  network_address_shifts: boolean;
  old_network_ip: string;
  new_network_ip: string;
  old_broadcast_ip: string | null;
  new_broadcast_ip: string | null;
  total_ips_before: number;
  total_ips_after: number;
  gateway_current: string | null;
  gateway_suggested_new_first_usable: string | null;
  placeholders_default_named: SubnetResizePlaceholder[];
  placeholders_renamed: SubnetResizePlaceholder[];
  affected_ip_addresses_total: number;
  affected_dhcp_scopes: number;
  affected_dhcp_pools: number;
  affected_dhcp_static_assignments: number;
  affected_dns_records_auto: number;
  affected_active_leases: number;
  reverse_zones_existing: string[];
  reverse_zones_will_be_created: string[];
  conflicts: ResizeConflict[];
  warnings: string[];
}

export interface SubnetResizeCommitRequest {
  new_cidr: string;
  move_gateway_to_first_usable?: boolean;
  replace_default_placeholders?: boolean;
}

export interface SubnetResizeCommitResponse {
  subnet: Subnet;
  old_cidr: string;
  new_cidr: string;
  placeholders_deleted: number;
  placeholders_created: number;
  dhcp_servers_notified: number;
  summary: string[];
}

export interface BlockResizeChildRow {
  id: string;
  network: string;
  name: string;
}

export interface BlockResizePreviewRequest {
  new_cidr: string;
}

export interface BlockResizePreviewResponse {
  old_cidr: string;
  new_cidr: string;
  network_address_shifts: boolean;
  old_network_ip: string;
  new_network_ip: string;
  total_ips_before: number;
  total_ips_after: number;
  child_blocks_count: number;
  child_blocks: BlockResizeChildRow[];
  child_subnets_count: number;
  child_subnets: BlockResizeChildRow[];
  descendant_ip_addresses_total: number;
  conflicts: ResizeConflict[];
  warnings: string[];
}

export interface BlockResizeCommitRequest {
  new_cidr: string;
}

export interface BlockResizeCommitResponse {
  block: IPBlock;
  old_cidr: string;
  new_cidr: string;
  summary: string[];
}

// ── Block move (issue #27) ───────────────────────────────────────────────
//
// Operator-driven relocation of an IPBlock + everything under it
// (descendant blocks, subnets, addresses) into a different IPSpace.
// Preview is a pure read of the blast radius; commit takes a per-block
// advisory lock and refuses if any descendant is owned by an integration
// reconciler (kubernetes / docker / proxmox / tailscale FK set).

export interface BlockMovePreviewRequest {
  target_space_id: string;
  target_parent_id?: string | null;
}

export interface BlockMoveIntegrationBlocker {
  kind: "block" | "subnet" | "ip_address";
  resource_id: string;
  network: string;
  integration: "kubernetes" | "docker" | "proxmox" | "tailscale";
}

export interface BlockMovePreviewResponse {
  block_id: string;
  block_network: string;
  source_space_id: string;
  target_space_id: string;
  target_parent_id: string | null;
  descendant_blocks_count: number;
  descendant_subnets_count: number;
  descendant_ip_addresses_total: number;
  reparent_chain_block_ids: string[];
  integration_blockers: BlockMoveIntegrationBlocker[];
  warnings: string[];
}

export interface BlockMoveCommitRequest {
  target_space_id: string;
  target_parent_id?: string | null;
  confirmation_cidr: string;
}

export interface BlockMoveCommitResponse {
  block: IPBlock;
  source_space_id: string;
  target_space_id: string;
  target_parent_id: string | null;
  blocks_moved: number;
  subnets_moved: number;
  addresses_in_moved_subtree: number;
  reparented_block_ids: string[];
}

// ── Free-space finder ──────────────────────────────────────────────────────
//
// Sweep an IPSpace (or one block subtree) for unused CIDRs of the
// requested prefix length. Empty space yields HTTP 200 with
// `summary.warning="space has no blocks"` so the UI can render a
// "create a block first" nudge instead of an error.

export interface FindFreeRequest {
  prefix_length: number;
  address_family?: 4 | 6;
  count?: number;
  min_free_addresses?: number | null;
  parent_block_id?: string | null;
}

export interface FindFreeCandidate {
  cidr: string;
  parent_block_id: string;
  parent_block_cidr: string;
  free_addresses?: number | null;
}

export interface FindFreeResponse {
  candidates: FindFreeCandidate[];
  summary: Record<string, string | number>;
}

// ── Subnet split ───────────────────────────────────────────────────────────

export interface SplitChildPreview {
  cidr: string;
  allocations_count: number;
  placeholders_default_named: number;
  placeholders_renamed: number;
  dhcp_scope_id: string | null;
  dhcp_pool_count: number;
  dhcp_static_count: number;
  dns_record_count: number;
}

export interface SplitSubnetPreviewRequest {
  new_prefix_length: number;
}

export interface SplitSubnetPreviewResponse {
  parent_cidr: string;
  new_prefix_length: number;
  children: SplitChildPreview[];
  conflicts: ResizeConflict[];
  warnings: string[];
}

export interface SplitSubnetCommitRequest {
  new_prefix_length: number;
  confirm_cidr: string;
}

export interface SplitSubnetCommitResponse {
  parent_cidr: string;
  children: Subnet[];
  summary: string[];
}

// ── Subnet merge ───────────────────────────────────────────────────────────

export interface MergeSourceRow {
  id: string;
  cidr: string;
}

export interface MergeSubnetPreviewRequest {
  sibling_subnet_ids: string[];
}

export interface MergeSubnetPreviewResponse {
  merged_cidr: string | null;
  source_subnets: MergeSourceRow[];
  surviving_dhcp_scope_id: string | null;
  conflicts: ResizeConflict[];
  warnings: string[];
}

export interface MergeSubnetCommitRequest {
  sibling_subnet_ids: string[];
  confirm_cidr: string;
}

export interface MergeSubnetCommitResponse {
  merged_subnet: Subnet;
  deleted_subnet_ids: string[];
  summary: string[];
}

// ── Bulk allocate (subnet-level) ──────────────────────────────────────────
//
// Stamp a contiguous IP range with name templating in one shot. Token
// language is mirrored client-side in BulkAllocateModal for live preview;
// keep the regex in sync with the backend `_BULK_TEMPLATE_RE`.

export interface BulkAllocateItem {
  address: string;
  hostname: string;
  fqdn: string | null;
  in_use: boolean;
  in_dynamic_pool: boolean;
  fqdn_collision: boolean;
}

export interface BulkAllocateRequest {
  range_start: string;
  range_end: string;
  hostname_template: string;
  template_start?: number;
  status?: string;
  description?: string | null;
  dns_zone_id?: string | null;
  create_dns_records?: boolean;
  on_collision?: "skip" | "abort";
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface BulkAllocatePreviewResponse {
  total: number;
  will_create: number;
  conflicts_in_use: number;
  conflicts_in_pool: number;
  conflicts_fqdn: number;
  sample: BulkAllocateItem[];
  warnings: string[];
}

export interface BulkAllocateCommitResponse {
  created: number;
  skipped_in_use: number;
  skipped_in_pool: number;
  skipped_fqdn_collision: number;
  sample_created: string[];
  summary: string[];
}

// ── IPAM Templates (issue #26) ────────────────────────────────────────

export type IPAMTemplateAppliesTo = "block" | "subnet";

export interface IPAMTemplateChildLayoutEntry {
  prefix: number;
  name_template: string;
  description?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface IPAMTemplateChildLayout {
  children: IPAMTemplateChildLayoutEntry[];
}

export interface IPAMTemplate {
  id: string;
  name: string;
  description: string;
  applies_to: IPAMTemplateAppliesTo;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  dns_group_id: string | null;
  dns_zone_id: string | null;
  dns_additional_zone_ids: string[] | null;
  dhcp_group_id: string | null;
  ddns_enabled: boolean;
  ddns_hostname_policy: DdnsHostnamePolicy;
  ddns_domain_override: string | null;
  ddns_ttl: number | null;
  child_layout: IPAMTemplateChildLayout | null;
  applied_count: number;
  created_at: string;
  modified_at: string;
}

export interface IPAMTemplateCreate {
  name: string;
  description?: string;
  applies_to: IPAMTemplateAppliesTo;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
  dns_group_id?: string | null;
  dns_zone_id?: string | null;
  dns_additional_zone_ids?: string[];
  dhcp_group_id?: string | null;
  ddns_enabled?: boolean;
  ddns_hostname_policy?: DdnsHostnamePolicy;
  ddns_domain_override?: string | null;
  ddns_ttl?: number | null;
  child_layout?: IPAMTemplateChildLayout | null;
}

export interface IPAMTemplateUpdate {
  name?: string;
  description?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
  dns_group_id?: string | null;
  dns_zone_id?: string | null;
  dns_additional_zone_ids?: string[] | null;
  dhcp_group_id?: string | null;
  ddns_enabled?: boolean;
  ddns_hostname_policy?: DdnsHostnamePolicy;
  ddns_domain_override?: string | null;
  ddns_ttl?: number | null;
  child_layout?: IPAMTemplateChildLayout | null;
  clear_dns_group_id?: boolean;
  clear_dhcp_group_id?: boolean;
  clear_dns_zone_id?: boolean;
  clear_dns_additional_zone_ids?: boolean;
  clear_child_layout?: boolean;
  clear_ddns_domain_override?: boolean;
  clear_ddns_ttl?: boolean;
}

export interface TemplateApplyRequest {
  block_id?: string;
  subnet_id?: string;
  force?: boolean;
  carve_children?: boolean;
}

export interface TemplateApplyResponse {
  template_id: string;
  target_kind: "block" | "subnet";
  target_id: string;
  fields_written: string[];
  children_carved: { cidr: string; name: string; skipped: boolean }[];
}

export interface TemplateReapplyAllResponse {
  template_id: string;
  target_kind: "block" | "subnet";
  instances_total: number;
  instances_processed: number;
  instances_skipped: number;
  cap_reached: boolean;
}

export const ipamApi = {
  listSpaces: () => api.get<IPSpace[]>("/ipam/spaces").then((r) => r.data),
  getSpace: (id: string) =>
    api.get<IPSpace>(`/ipam/spaces/${id}`).then((r) => r.data),
  createSpace: (data: Partial<IPSpace>) =>
    api.post<IPSpace>("/ipam/spaces", data).then((r) => r.data),
  updateSpace: (id: string, data: Partial<IPSpace>) =>
    api.put<IPSpace>(`/ipam/spaces/${id}`, data).then((r) => r.data),
  // #62 two-person approval: when the ``governance.approvals`` module is on
  // and a policy matches, this returns **202** with a ``ChangeRequestQueued``
  // body (queued, NOT deleted) instead of 204. Returns the FULL axios
  // response on purpose — do NOT chain ``.then((r) => r.data)`` here or the
  // 202 status is invisible. Callers pass the response to
  // ``handleApprovalQueued`` (``@/lib/approvalQueue``); see deleteBlock /
  // deleteSubnet below + dnsApi/dhcpApi delete methods.
  deleteSpace: (id: string) => api.delete(`/ipam/spaces/${id}`),

  listBlocks: (spaceId?: string) =>
    api
      .get<IPBlock[]>("/ipam/blocks", {
        params: spaceId ? { space_id: spaceId } : undefined,
      })
      .then((r) => r.data),
  createBlock: (data: Partial<IPBlock> & { template_id?: string | null }) =>
    api.post<IPBlock>("/ipam/blocks", data).then((r) => r.data),
  updateBlock: (
    id: string,
    data: Partial<
      Pick<
        IPBlock,
        | "name"
        | "description"
        | "parent_block_id"
        | "tags"
        | "custom_fields"
        | "dns_group_ids"
        | "dns_zone_id"
        | "dns_additional_zone_ids"
        | "dns_inherit_settings"
        | "dhcp_server_group_id"
        | "dhcp_inherit_settings"
        | "asn_id"
        | "vrf_id"
        | "customer_id"
        | "site_id"
        | "do_not_probe"
        | "do_not_probe_reason"
      >
    >,
  ) => api.put<IPBlock>(`/ipam/blocks/${id}`, data).then((r) => r.data),
  // #62: returns the full axios response (may be 202 queued-for-approval —
  // see deleteSpace). Do NOT add ``.then((r) => r.data)``.
  deleteBlock: (id: string) => api.delete(`/ipam/blocks/${id}`),
  availableSubnets: (blockId: string, prefixLen: number) =>
    api
      .get<string[]>(`/ipam/blocks/${blockId}/available-subnets`, {
        params: { prefix_len: prefixLen },
      })
      .then((r) => r.data),
  blockFreeSpace: (blockId: string) =>
    api
      .get<FreeCidrRange[]>(`/ipam/blocks/${blockId}/free-space`)
      .then((r) => r.data),
  blockAggregationSuggestions: (
    blockId: string,
    params?: { include_snoozed?: boolean },
  ) =>
    api
      .get<
        AggregationSuggestion[]
      >(`/ipam/blocks/${blockId}/aggregation-suggestions`, { params })
      .then((r) => r.data),
  snoozeAggregationCandidate: (candidate_key: string, days: number = 30) =>
    api
      .post<void>(`/ipam/aggregation-snoozes/snooze`, { candidate_key, days })
      .then((r) => r.data),
  dismissAggregationCandidate: (candidate_key: string) =>
    api
      .post<void>(`/ipam/aggregation-snoozes/dismiss`, { candidate_key })
      .then((r) => r.data),
  clearAggregationSnooze: (candidate_key: string) =>
    api
      .post<void>(`/ipam/aggregation-snoozes/clear`, { candidate_key })
      .then((r) => r.data),
  planBlockAllocation: (blockId: string, items: PlanRequestItem[]) =>
    api
      .post<PlanAllocationResponse>(`/ipam/blocks/${blockId}/plan-allocation`, {
        items,
      })
      .then((r) => r.data),

  // Subnet plans
  listSubnetPlans: (spaceId?: string) =>
    api
      .get<SubnetPlanRead[]>(`/ipam/plans`, {
        params: spaceId ? { space_id: spaceId } : undefined,
      })
      .then((r) => r.data),
  getSubnetPlan: (id: string) =>
    api.get<SubnetPlanRead>(`/ipam/plans/${id}`).then((r) => r.data),
  createSubnetPlan: (body: SubnetPlanCreate) =>
    api.post<SubnetPlanRead>(`/ipam/plans`, body).then((r) => r.data),
  updateSubnetPlan: (id: string, body: SubnetPlanUpdate) =>
    api.patch<SubnetPlanRead>(`/ipam/plans/${id}`, body).then((r) => r.data),
  deleteSubnetPlan: (id: string) =>
    api.delete<void>(`/ipam/plans/${id}`).then((r) => r.data),
  validateSubnetPlan: (id: string) =>
    api
      .post<PlanValidationResult>(`/ipam/plans/${id}/validate`)
      .then((r) => r.data),
  validateSubnetPlanTree: (body: SubnetPlanCreate) =>
    api
      .post<PlanValidationResult>(`/ipam/plans/validate-tree`, body)
      .then((r) => r.data),
  applySubnetPlan: (id: string) =>
    api.post<PlanApplyResult>(`/ipam/plans/${id}/apply`).then((r) => r.data),
  reopenSubnetPlan: (id: string) =>
    api.post<SubnetPlanRead>(`/ipam/plans/${id}/reopen`).then((r) => r.data),
  // Effective do-not-probe verdict for a subnet (#722). A separate call
  // rather than a field on the list rows: resolving it walks the block
  // chain, which is cheap once but N walks on a list page.
  getSubnetProbePolicy: (subnetId: string) =>
    api
      .get<ProbePolicy>(`/ipam/subnets/${subnetId}/probe-policy`)
      .then((r) => r.data),
  getEffectiveBlockDns: (blockId: string) =>
    api
      .get<EffectiveDns>(`/ipam/blocks/${blockId}/effective-dns`)
      .then((r) => r.data),
  getEffectiveSubnetDns: (subnetId: string) =>
    api
      .get<EffectiveDns>(`/ipam/subnets/${subnetId}/effective-dns`)
      .then((r) => r.data),
  getEffectiveSpaceDns: (spaceId: string) =>
    api
      .get<EffectiveDns>(`/ipam/spaces/${spaceId}/effective-dns`)
      .then((r) => r.data),
  getEffectiveBlockDhcp: (blockId: string) =>
    api
      .get<EffectiveDhcp>(`/ipam/blocks/${blockId}/effective-dhcp`)
      .then((r) => r.data),
  getEffectiveSubnetDhcp: (subnetId: string) =>
    api
      .get<EffectiveDhcp>(`/ipam/subnets/${subnetId}/effective-dhcp`)
      .then((r) => r.data),
  getEffectiveSpaceDhcp: (spaceId: string) =>
    api
      .get<EffectiveDhcp>(`/ipam/spaces/${spaceId}/effective-dhcp`)
      .then((r) => r.data),

  listSubnets: (params?: {
    // ``space_id`` accepts a single id or an array — axios serialises an
    // array as repeated ``?space_id=<uuid>&space_id=<uuid>`` thanks to the
    // ``indexes: null`` paramsSerializer config.
    space_id?: string | string[];
    block_id?: string;
    vlan_ref_id?: string;
    pci_scope?: boolean;
    hipaa_scope?: boolean;
    internet_facing?: boolean;
    // Multi-value (e.g. ``["voice", "management"]``). axios serialises
    // arrays as repeated keys so the FastAPI ``list[str]`` parses them
    // natively.
    subnet_role?: SubnetRole | SubnetRole[];
    tag?: string[];
  }) => api.get<Subnet[]>("/ipam/subnets", { params }).then((r) => r.data),
  getSubnet: (id: string) =>
    api.get<Subnet>(`/ipam/subnets/${id}`).then((r) => r.data),
  // Per-subnet utilization history — daily snapshots for the trend chart (#44).
  getUtilizationHistory: (id: string, days = 90) =>
    api
      .get<
        SubnetUtilizationPoint[]
      >(`/ipam/subnets/${id}/utilization-history`, { params: { days } })
      .then((r) => r.data),
  // IP discovery reconciliation report (issue #23).
  getReconciliation: (id: string, staleMinutes?: number) =>
    api
      .get<SubnetReconciliation>(`/ipam/subnets/${id}/reconciliation`, {
        params: staleMinutes ? { stale_minutes: staleMinutes } : undefined,
      })
      .then((r) => r.data),
  // Queue an on-demand discovery sweep (independent of the schedule).
  triggerDiscovery: (id: string) =>
    api
      .post<{
        status: string;
        subnet_id: string;
      }>(`/ipam/subnets/${id}/discover`)
      .then((r) => r.data),
  // Stale-IP report + one-click bulk-deprecate (issue #45).
  getStaleIPs: (params?: StaleIPReportParams) =>
    api
      .get<StaleIPReport>("/ipam/reports/stale-ips", { params })
      .then((r) => r.data),
  deprecateStaleIPs: (body: StaleIPDeprecateRequest) =>
    api
      .post<StaleIPDeprecateResponse>("/ipam/reports/stale-ips/deprecate", body)
      .then((r) => r.data),
  createSubnet: (data: Partial<Subnet> & { template_id?: string | null }) =>
    api.post<Subnet>("/ipam/subnets", data).then((r) => r.data),
  // Atomic carve-and-create (#372): pick the lowest free child CIDR of
  // ``prefix_len`` and create it in one locked call. Race-safe — preferred
  // over availableSubnets()-then-createSubnet() for the "Find by size" flow.
  allocateSubnet: (
    blockId: string,
    data: { prefix_len: number } & Partial<Subnet> & {
        template_id?: string | null;
      },
  ) =>
    api
      .post<Subnet>(`/ipam/blocks/${blockId}/allocate-subnet`, data)
      .then((r) => r.data),
  updateSubnet: (
    id: string,
    data: Partial<Subnet> & { manage_auto_addresses?: boolean },
  ) => api.put<Subnet>(`/ipam/subnets/${id}`, data).then((r) => r.data),
  // ``force`` cascades the delete: the backend refuses by default if
  // the subnet still has user-owned IP rows or attached DHCP scopes.
  // The UI's two confirmation modals already make the cascade
  // explicit ("…and all IP address records will be permanently
  // deleted") so they pass force=true; the bare-id callable shape is
  // kept for any future "soft" call site.
  // #62: returns the full axios response (may be 202 queued-for-approval —
  // see deleteSpace). Do NOT add ``.then((r) => r.data)``.
  deleteSubnet: (id: string, force: boolean = false) =>
    api.delete(`/ipam/subnets/${id}${force ? "?force=true" : ""}`),

  // Resize (grow-only) — preview is a pure read; commit takes a pg
  // advisory lock and returns 423 Locked if another resize is in flight
  // for the same subnet / block.
  resizeSubnetPreview: (subnetId: string, body: SubnetResizePreviewRequest) =>
    api
      .post<SubnetResizePreviewResponse>(
        `/ipam/subnets/${subnetId}/resize/preview`,
        body,
      )
      .then((r) => r.data),
  resizeSubnetCommit: (subnetId: string, body: SubnetResizeCommitRequest) =>
    api
      .post<SubnetResizeCommitResponse>(
        `/ipam/subnets/${subnetId}/resize`,
        body,
      )
      .then((r) => r.data),
  resizeBlockPreview: (blockId: string, body: BlockResizePreviewRequest) =>
    api
      .post<BlockResizePreviewResponse>(
        `/ipam/blocks/${blockId}/resize/preview`,
        body,
      )
      .then((r) => r.data),
  resizeBlockCommit: (blockId: string, body: BlockResizeCommitRequest) =>
    api
      .post<BlockResizeCommitResponse>(`/ipam/blocks/${blockId}/resize`, body)
      .then((r) => r.data),

  // ── Block move (issue #27) ───────────────────────────────────────────
  moveBlockPreview: (blockId: string, body: BlockMovePreviewRequest) =>
    api
      .post<BlockMovePreviewResponse>(
        `/ipam/blocks/${blockId}/move/preview`,
        body,
      )
      .then((r) => r.data),
  moveBlockCommit: (blockId: string, body: BlockMoveCommitRequest) =>
    api
      .post<BlockMoveCommitResponse>(
        `/ipam/blocks/${blockId}/move/commit`,
        body,
      )
      .then((r) => r.data),

  // ── Free-space finder ───────────────────────────────────────────────
  findFreeSpace: (spaceId: string, body: FindFreeRequest) =>
    api
      .post<FindFreeResponse>(`/ipam/spaces/${spaceId}/find-free`, body)
      .then((r) => r.data),

  // ── Subnet split / merge ────────────────────────────────────────────
  splitSubnetPreview: (subnetId: string, body: SplitSubnetPreviewRequest) =>
    api
      .post<SplitSubnetPreviewResponse>(
        `/ipam/subnets/${subnetId}/split/preview`,
        body,
      )
      .then((r) => r.data),
  splitSubnetCommit: (subnetId: string, body: SplitSubnetCommitRequest) =>
    api
      .post<SplitSubnetCommitResponse>(
        `/ipam/subnets/${subnetId}/split/commit`,
        body,
      )
      .then((r) => r.data),
  mergeSubnetPreview: (subnetId: string, body: MergeSubnetPreviewRequest) =>
    api
      .post<MergeSubnetPreviewResponse>(
        `/ipam/subnets/${subnetId}/merge/preview`,
        body,
      )
      .then((r) => r.data),
  mergeSubnetCommit: (subnetId: string, body: MergeSubnetCommitRequest) =>
    api
      .post<MergeSubnetCommitResponse>(
        `/ipam/subnets/${subnetId}/merge/commit`,
        body,
      )
      .then((r) => r.data),

  bulkAllocatePreview: (subnetId: string, body: BulkAllocateRequest) =>
    api
      .post<BulkAllocatePreviewResponse>(
        `/ipam/subnets/${subnetId}/bulk-allocate/preview`,
        body,
      )
      .then((r) => r.data),
  bulkAllocateCommit: (subnetId: string, body: BulkAllocateRequest) =>
    api
      .post<BulkAllocateCommitResponse>(
        `/ipam/subnets/${subnetId}/bulk-allocate`,
        body,
      )
      .then((r) => r.data),

  dnsSyncPreview: (subnetId: string) =>
    api
      .get<DnsSyncPreview>(`/ipam/subnets/${subnetId}/dns-sync/preview`)
      .then((r) => r.data),
  dnsSyncSummary: (subnetId: string) =>
    api
      .get<DnsSyncSummary>(`/ipam/subnets/${subnetId}/dns-sync/summary`)
      .then((r) => r.data),
  dnsSyncCommit: (
    subnetId: string,
    body: {
      create_for_ip_ids?: string[];
      update_record_ids?: string[];
      delete_stale_record_ids?: string[];
    },
  ) =>
    api
      .post<DnsSyncCommitResult>(
        `/ipam/subnets/${subnetId}/dns-sync/commit`,
        body,
      )
      .then((r) => r.data),

  dnsSyncPreviewBlock: (blockId: string) =>
    api
      .get<DnsSyncPreview>(`/ipam/blocks/${blockId}/dns-sync/preview`)
      .then((r) => r.data),
  dnsSyncCommitBlock: (
    blockId: string,
    body: {
      create_for_ip_ids?: string[];
      update_record_ids?: string[];
      delete_stale_record_ids?: string[];
    },
  ) =>
    api
      .post<DnsSyncCommitResult>(
        `/ipam/blocks/${blockId}/dns-sync/commit`,
        body,
      )
      .then((r) => r.data),

  dnsSyncPreviewSpace: (spaceId: string) =>
    api
      .get<DnsSyncPreview>(`/ipam/spaces/${spaceId}/dns-sync/preview`)
      .then((r) => r.data),
  dnsSyncCommitSpace: (
    spaceId: string,
    body: {
      create_for_ip_ids?: string[];
      update_record_ids?: string[];
      delete_stale_record_ids?: string[];
    },
  ) =>
    api
      .post<DnsSyncCommitResult>(
        `/ipam/spaces/${spaceId}/dns-sync/commit`,
        body,
      )
      .then((r) => r.data),

  listAddresses: (subnetId: string, params?: AddressQueryParams) =>
    api
      .get<IPAddress[]>(`/ipam/subnets/${subnetId}/addresses`, {
        params,
      })
      .then((r) => r.data),
  /** Cross-subnet IP search (issue #520). Results are permission-scoped
   *  server-side — only IPs in subnets the caller can read come back. */
  searchAddresses: (params: AddressSearchParams) =>
    api
      .get<AddressSearchResponse>(`/ipam/addresses/search`, { params })
      .then((r) => r.data),
  /** Gather the ids of every match (capped at 5000) for the "select all
   *  N matches → bulk edit/delete" flow. */
  searchAddressIds: (
    params: Omit<AddressSearchParams, "sort" | "order" | "limit" | "offset">,
  ) =>
    api
      .get<AddressSearchIdsResponse>(`/ipam/addresses/search/ids`, { params })
      .then((r) => r.data),
  createAddress: (
    data: Partial<IPAddress> & {
      hostname: string;
      dns_zone_id?: string | null;
      aliases?: { name: string; record_type: "CNAME" | "A" }[];
      /** Re-submit flag after the user confirms a 409 collision warning. */
      force?: boolean;
    },
  ) =>
    api
      .post<IPAddress>(`/ipam/subnets/${data.subnet_id}/addresses`, data)
      .then((r) => r.data),
  updateAddress: (
    id: string,
    data: Partial<IPAddress> & {
      dns_zone_id?: string | null;
      /** Re-submit flag after the user confirms a 409 collision warning. */
      force?: boolean;
    },
  ) => api.put<IPAddress>(`/ipam/addresses/${id}`, data).then((r) => r.data),
  deleteAddress: (id: string, permanent = false) =>
    api.delete(`/ipam/addresses/${id}`, {
      params: permanent ? { permanent: true } : undefined,
    }),
  /** Operator-triggered "Re-profile now" — bypasses the subnet's
   *  refresh-window dedupe but still respects the per-subnet
   *  concurrency cap (returns 429 when full). */
  profileAddress: (id: string, preset?: string) =>
    api
      .post<{
        scan_id: string;
        preset: string;
        status: string;
      }>(`/ipam/addresses/${id}/profile`, { preset: preset ?? null })
      .then((r) => r.data),
  /** Wake-on-LAN (#533) — send a magic packet to this IP's MAC. The
   *  broadcast target is derived server-side from the IP's subnet. Omit
   *  the vantage to send from the control plane; pass an appliance target
   *  to originate the packet on that appliance's segment.
   *
   *  Pass `verify: true` (#596) to arm a post-wake liveness check: after
   *  `verifyWaitSeconds` the server probes the host with `verifyMethod` and
   *  re-wakes it up to `verifyRetries` times. The attempt is recorded as an
   *  `adhoc` run in Wake Schedules → History. Requires the
   *  `tools.wake_scheduler` module (422 otherwise). */
  wakeAddress: (
    id: string,
    opts?: {
      port?: number;
      target?: { kind: "server" | "appliance"; id?: string };
      verify?: boolean;
      verifyWaitSeconds?: number;
      verifyRetries?: number;
      verifyMethod?: WolVerifyMethod;
    },
  ) =>
    api
      .post<{
        mac: string;
        broadcast: string;
        port: number;
        sent: boolean;
        ran_from: string;
        error: string | null;
      }>(`/ipam/addresses/${id}/wake`, {
        port: opts?.port ?? 9,
        target: opts?.target ?? null,
        verify: opts?.verify ?? false,
        verify_wait_seconds: opts?.verifyWaitSeconds ?? 60,
        verify_retries: opts?.verifyRetries ?? 1,
        verify_method: opts?.verifyMethod ?? "auto",
      })
      .then((r) => r.data),
  /** Fetch the passive DHCP fingerprint joined to this IP's MAC.
   *  404 when the IP has no MAC or no fingerprint has been captured
   *  yet — callers should swallow that and treat it as "no data". */
  getDhcpFingerprint: (id: string) =>
    api
      .get<DHCPFingerprintResponse>(`/ipam/addresses/${id}/dhcp-fingerprint`)
      .then((r) => r.data),
  listAliases: (addressId: string) =>
    api
      .get<
        {
          id: string;
          name: string;
          record_type: string;
          value: string;
          zone_id: string;
          fqdn: string;
        }[]
      >(`/ipam/addresses/${addressId}/aliases`)
      .then((r) => r.data),
  /** Pull every distinct MAC ever observed on this IP, newest-first. */
  listMacHistory: (addressId: string) =>
    api
      .get<MacHistoryEntry[]>(`/ipam/addresses/${addressId}/mac-history`)
      .then((r) => r.data),
  addAlias: (
    addressId: string,
    data: { name: string; record_type: "CNAME" | "A" },
  ) =>
    api
      .post<{
        id: string;
        name: string;
        record_type: string;
        value: string;
        zone_id: string;
        fqdn: string;
      }>(`/ipam/addresses/${addressId}/aliases`, data)
      .then((r) => r.data),
  deleteAlias: (addressId: string, recordId: string) =>
    api.delete(`/ipam/addresses/${addressId}/aliases/${recordId}`),
  listSubnetAliases: (subnetId: string) =>
    api
      .get<SubnetAlias[]>(`/ipam/subnets/${subnetId}/aliases`)
      .then((r) => r.data),
  bulkDeleteAddresses: (data: { ip_ids: string[]; permanent?: boolean }) =>
    api
      .post<{
        deleted_count: number;
        not_found: string[];
        skipped: string[];
      }>(`/ipam/addresses/bulk-delete`, data)
      .then((r) => r.data),
  bulkEditAddresses: (data: {
    ip_ids: string[];
    changes: {
      status?: string;
      description?: string;
      tags?: Record<string, unknown>;
      custom_fields?: Record<string, unknown>;
      /** New forward-zone for every selected IP. Empty string clears. */
      dns_zone_id?: string;
      /** Curated role tag. Empty string clears (= no specific role). */
      role?: IPRole | "" | null;
      /** TTL on reservations. ``null`` clears, ISO 8601 string sets. */
      reserved_until?: string | null;
    };
  }) =>
    api
      .post<{
        batch_id: string;
        updated_count: number;
        not_found: string[];
        skipped: string[];
      }>(`/ipam/addresses/bulk-edit`, data)
      .then((r) => r.data),
  backfillReverseZonesSpace: (spaceId: string) =>
    api
      .post<{
        created: { subnet: string; zone: string }[];
        skipped: number;
      }>(`/ipam/spaces/${spaceId}/reverse-zones/backfill`)
      .then((r) => r.data),
  backfillReverseZonesBlock: (blockId: string) =>
    api
      .post<{
        created: { subnet: string; zone: string }[];
        skipped: number;
      }>(`/ipam/blocks/${blockId}/reverse-zones/backfill`)
      .then((r) => r.data),
  backfillReverseZonesSubnet: (subnetId: string) =>
    api
      .post<{
        created: { subnet: string; zone: string }[];
        skipped: number;
      }>(`/ipam/subnets/${subnetId}/reverse-zones/backfill`)
      .then((r) => r.data),
  purgeOrphans: (subnetId: string, ipIds: string[]) =>
    api
      .post<{ purged: number }>(`/ipam/subnets/${subnetId}/orphans/purge`, {
        ip_ids: ipIds,
      })
      .then((r) => r.data),
  nextAddress: (
    subnetId: string,
    data: {
      hostname: string;
      status?: string;
      mac_address?: string;
      description?: string;
      custom_fields?: Record<string, unknown>;
      dns_zone_id?: string | null;
      /** Issue #25 — additional zones to publish A/AAAA records into. */
      extra_zone_ids?: string[];
      aliases?: { name: string; record_type: "CNAME" | "A" }[];
      role?: IPRole;
      reserved_until?: string;
      /** Re-submit flag after the user confirms a 409 collision warning. */
      force?: boolean;
    },
  ) =>
    api
      .post<IPAddress>(`/ipam/subnets/${subnetId}/next`, data)
      .then((r) => r.data),
  previewNextIp: (
    subnetId: string,
    strategy: "sequential" | "random" = "sequential",
  ) =>
    api
      .get<{
        address: string | null;
        strategy: string;
      }>(`/ipam/subnets/${subnetId}/next-ip-preview`, { params: { strategy } })
      .then((r) => r.data),

  // Subnet ↔ DNS domain associations (§11)
  listSubnetDomains: (subnetId: string) =>
    api
      .get<SubnetDomain[]>(`/ipam/subnets/${subnetId}/domains`)
      .then((r) => r.data),
  addSubnetDomain: (
    subnetId: string,
    data: { dns_zone_id: string; is_primary?: boolean },
  ) =>
    api
      .post<SubnetDomain>(`/ipam/subnets/${subnetId}/domains`, data)
      .then((r) => r.data),
  removeSubnetDomain: (subnetId: string, domainId: string) =>
    api.delete(`/ipam/subnets/${subnetId}/domains/${domainId}`),

  // Effective (inherited) tags + custom_fields (§11)
  effectiveFields: (subnetId: string) =>
    api
      .get<EffectiveFields>(`/ipam/subnets/${subnetId}/effective-fields`)
      .then((r) => r.data),
  effectiveBlockFields: (blockId: string) =>
    api
      .get<BlockEffectiveFields>(`/ipam/blocks/${blockId}/effective-fields`)
      .then((r) => r.data),

  // Bulk edit multiple subnets in one transaction (§11)
  bulkEditSubnets: (subnet_ids: string[], changes: SubnetBulkEditChanges) =>
    api
      .post<SubnetBulkEditResponse>("/ipam/subnets/bulk-edit", {
        subnet_ids,
        changes,
      })
      .then((r) => r.data),

  // ── IPAM templates (issue #26) ────────────────────────────────────
  listTemplates: (params?: {
    applies_to?: IPAMTemplateAppliesTo;
    search?: string;
  }) =>
    api.get<IPAMTemplate[]>("/ipam/templates", { params }).then((r) => r.data),
  getTemplate: (id: string) =>
    api.get<IPAMTemplate>(`/ipam/templates/${id}`).then((r) => r.data),
  createTemplate: (body: IPAMTemplateCreate) =>
    api.post<IPAMTemplate>("/ipam/templates", body).then((r) => r.data),
  updateTemplate: (id: string, body: IPAMTemplateUpdate) =>
    api.put<IPAMTemplate>(`/ipam/templates/${id}`, body).then((r) => r.data),
  deleteTemplate: (id: string) =>
    api.delete<void>(`/ipam/templates/${id}`).then((r) => r.data),
  applyTemplate: (id: string, body: TemplateApplyRequest) =>
    api
      .post<TemplateApplyResponse>(`/ipam/templates/${id}/apply`, body)
      .then((r) => r.data),
  reapplyAllTemplate: (id: string) =>
    api
      .post<TemplateReapplyAllResponse>(`/ipam/templates/${id}/reapply-all`, {})
      .then((r) => r.data),
};

// ── Address sets (#103) ────────────────────────────────────────────────────────
//
// A named, RBAC-scoped slice of a subnet's address space. Granting
// ``admin`` on a single ``address_set`` id (via a role permission entry
// ``{action:"admin", resource_type:"address_set", resource_id:<id>}``)
// lets a delegated admin edit just their range of a subnet without
// holding subnet-wide write. The CRUD surface lives at the top-level
// ``/address-sets`` endpoint (list is filterable by ``subnet_id``).

export type AddressSetRangeKind = "contiguous" | "explicit";

export interface AddressSet {
  id: string;
  name: string;
  description: string;
  subnet_id: string;
  customer_id: string | null;
  site_id: string | null;
  range_kind: AddressSetRangeKind;
  // Contiguous span — both set when ``range_kind === "contiguous"``.
  start_address: string | null;
  end_address: string | null;
  // Arbitrary host list — non-empty when ``range_kind === "explicit"``.
  explicit_addresses: string[];
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface AddressSetCreate {
  name: string;
  description?: string;
  subnet_id: string;
  customer_id?: string | null;
  site_id?: string | null;
  range_kind?: AddressSetRangeKind;
  start_address?: string | null;
  end_address?: string | null;
  explicit_addresses?: string[];
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface AddressSetUpdate {
  name?: string;
  description?: string;
  customer_id?: string | null;
  site_id?: string | null;
  range_kind?: AddressSetRangeKind;
  start_address?: string | null;
  end_address?: string | null;
  explicit_addresses?: string[];
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export const addressSetsApi = {
  // ``list`` returns a bare array (ordered by name), matching the
  // sibling subnet sub-resources (aliases) rather than the paginated
  // ``{items,total,...}`` envelope customers/sites use.
  list: (params?: {
    subnet_id?: string;
    customer_id?: string;
    site_id?: string;
    search?: string;
    limit?: number;
  }) => api.get<AddressSet[]>("/address-sets", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<AddressSet>(`/address-sets/${id}`).then((r) => r.data),
  create: (data: AddressSetCreate) =>
    api.post<AddressSet>("/address-sets", data).then((r) => r.data),
  update: (id: string, data: AddressSetUpdate) =>
    api.put<AddressSet>(`/address-sets/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/address-sets/${id}`),
};

// ── IPAM Import / Export ───────────────────────────────────────────────────────

export interface ImportDiffRow {
  kind: "subnet" | "block" | "address";
  action: "create" | "update" | "conflict" | "skip" | "error";
  network: string;
  name?: string;
  reason?: string | null;
  details?: Record<string, unknown>;
}

export interface ImportPreviewResponse {
  space_id: string;
  space_name: string;
  summary: {
    creates: number;
    updates: number;
    conflicts: number;
    errors: number;
  };
  creates: ImportDiffRow[];
  updates: ImportDiffRow[];
  conflicts: ImportDiffRow[];
  errors: ImportDiffRow[];
}

export interface ImportCommitResponse {
  space_id: string;
  created_subnets: number;
  updated_subnets: number;
  skipped: number;
  auto_created_blocks: number;
  errors: string[];
}

export interface AddressImportCommitResponse {
  subnet_id: string;
  created: number;
  updated: number;
  skipped: number;
  dns_synced: number;
  errors: string[];
}

export type ImportStrategy = "skip" | "overwrite" | "fail";

function _buildImportForm(
  file: File,
  opts: { space_id?: string; space_name?: string; strategy: ImportStrategy },
): FormData {
  const form = new FormData();
  form.append("file", file);
  if (opts.space_id) form.append("space_id", opts.space_id);
  if (opts.space_name) form.append("space_name", opts.space_name);
  form.append("strategy", opts.strategy);
  return form;
}

export const ipamIoApi = {
  preview: (
    file: File,
    opts: { space_id?: string; space_name?: string; strategy: ImportStrategy },
  ) =>
    api
      .post<ImportPreviewResponse>(
        "/ipam/import/preview",
        _buildImportForm(file, opts),
        {
          headers: { "Content-Type": "multipart/form-data" },
        },
      )
      .then((r) => r.data),

  commit: (
    file: File,
    opts: { space_id?: string; space_name?: string; strategy: ImportStrategy },
  ) =>
    api
      .post<ImportCommitResponse>(
        "/ipam/import/commit",
        _buildImportForm(file, opts),
        {
          headers: { "Content-Type": "multipart/form-data" },
        },
      )
      .then((r) => r.data),

  previewAddresses: (
    file: File,
    opts: { subnet_id: string; strategy: ImportStrategy },
  ) => {
    const form = new FormData();
    form.append("file", file);
    form.append("subnet_id", opts.subnet_id);
    form.append("strategy", opts.strategy);
    return api
      .post<ImportPreviewResponse>("/ipam/import/addresses/preview", form, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      .then((r) => r.data);
  },

  commitAddresses: (
    file: File,
    opts: { subnet_id: string; strategy: ImportStrategy },
  ) => {
    const form = new FormData();
    form.append("file", file);
    form.append("subnet_id", opts.subnet_id);
    form.append("strategy", opts.strategy);
    return api
      .post<AddressImportCommitResponse>(
        "/ipam/import/addresses/commit",
        form,
        {
          headers: { "Content-Type": "multipart/form-data" },
        },
      )
      .then((r) => r.data);
  },

  exportUrl: (params: {
    space_id?: string;
    block_id?: string;
    subnet_id?: string;
    format: "csv" | "json" | "xlsx";
    include_addresses?: boolean;
  }) => {
    const qs = new URLSearchParams();
    if (params.space_id) qs.set("space_id", params.space_id);
    if (params.block_id) qs.set("block_id", params.block_id);
    if (params.subnet_id) qs.set("subnet_id", params.subnet_id);
    qs.set("format", params.format);
    if (params.include_addresses) qs.set("include_addresses", "true");
    return `/ipam/export?${qs.toString()}`;
  },

  /** Download an export using the caller's auth token. */
  download: async (params: {
    space_id?: string;
    block_id?: string;
    subnet_id?: string;
    format: "csv" | "json" | "xlsx";
    include_addresses?: boolean;
  }) => {
    const res = await api.get(ipamIoApi.exportUrl(params), {
      responseType: "blob",
    });
    const disp = (res.headers["content-disposition"] as string) || "";
    const match = disp.match(/filename="?([^";]+)"?/i);
    // UTC YYYYMMDD-HHMMSS matches the backend's export filename convention
    // so the fallback (no Content-Disposition) sorts alongside real exports.
    const ts = new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[-:]/g, "")
      .replace("T", "-");
    const filename = match ? match[1] : `ipam-export-${ts}.${params.format}`;
    const blob = new Blob([res.data as BlobPart]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  /** Print / PDF export (#82) — the handover deliverable, as opposed to the
   *  machine-readable formats above. A `subnet_id` scope renders the subnet
   *  detail report (always includes its addresses); a `space_id` / `block_id`
   *  scope renders the tree report. */
  downloadPdf: async (params: {
    space_id?: string;
    block_id?: string;
    subnet_id?: string;
    include_addresses?: boolean;
  }) => {
    const qs = new URLSearchParams();
    if (params.space_id) qs.set("space_id", params.space_id);
    if (params.block_id) qs.set("block_id", params.block_id);
    if (params.subnet_id) qs.set("subnet_id", params.subnet_id);
    if (params.include_addresses) qs.set("include_addresses", "true");
    let res;
    try {
      res = await api.get(`/ipam/export.pdf?${qs.toString()}`, {
        responseType: "blob",
      });
    } catch (err) {
      // With responseType "blob" an error body arrives as a Blob too, so the
      // usual `response.data.detail` is unreadable — unwrap it to text and
      // re-throw something the caller can actually display.
      const data = (err as { response?: { data?: unknown } })?.response?.data;
      if (data instanceof Blob) {
        const text = await data.text();
        let detail = text || "PDF export failed";
        try {
          const parsed = JSON.parse(text)?.detail;
          // FastAPI returns a string for HTTPException but an *array* of
          // {loc, msg, type} objects for a 422 validation error. Passing
          // that array to new Error() stringifies to "[object Object]",
          // so flatten it into something an operator can read.
          if (typeof parsed === "string") {
            detail = parsed;
          } else if (Array.isArray(parsed)) {
            detail =
              parsed
                .map((d) => (typeof d === "string" ? d : d?.msg))
                .filter(Boolean)
                .join("; ") || detail;
          }
        } catch {
          // body wasn't JSON — fall back to the raw text
        }
        throw new Error(detail);
      }
      throw err;
    }
    const disp = (res.headers["content-disposition"] as string) || "";
    const match = disp.match(/filename="?([^";]+)"?/i);
    const ts = new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[-:]/g, "")
      .replace("T", "-");
    const filename = match ? match[1] : `spatiumddi-ipam-${ts}.pdf`;
    const blob = new Blob([res.data as BlobPart], { type: "application/pdf" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },
};

export interface LoginResponse {
  // Set when MFA is NOT required — normal token issuance. The refresh token
  // is delivered out-of-band as an HttpOnly cookie (#484), never in this body.
  access_token: string | null;
  token_type: string;
  force_password_change: boolean;
  // Set when the user has TOTP enabled (issue #69). The frontend
  // routes the operator into a TOTP prompt + posts to /auth/login/mfa
  // with this challenge token + the second factor.
  mfa_required?: boolean;
  mfa_token?: string | null;
}

// Mirrors the backend `RefreshResponse` (#484): /auth/refresh returns a fresh
// access token plus `token_type` + `force_password_change` (the rotated refresh
// token rides the HttpOnly cookie), but NONE of LoginResponse's MFA/login-only
// fields. Typed separately so a refresh caller can't accidentally depend on
// `mfa_required` / `mfa_token`.
export interface RefreshResponse {
  access_token: string;
  token_type: string;
  force_password_change: boolean;
}

export interface MfaStatusResponse {
  enabled: boolean;
  enrolment_pending: boolean;
  recovery_codes_remaining: number;
}

export interface MfaEnrolBeginResponse {
  secret: string;
  otpauth_uri: string;
  recovery_codes: string[];
}

export interface AppUser {
  id: string;
  username: string;
  email: string;
  display_name: string;
  is_active: boolean;
  is_superadmin: boolean;
  force_password_change: boolean;
  auth_source: string;
  last_login_at: string | null;
  /** Lockout state (issue #71). ``locked`` is the live time check;
   *  ``failed_login_locked_until`` is the wall-clock target so the UI
   *  can render a relative "unlocks in 12 m" hint without recomputing
   *  the rule. */
  failed_login_count?: number;
  failed_login_locked_until?: string | null;
  locked?: boolean;
}

export const usersApi = {
  list: () => api.get<AppUser[]>("/users").then((r) => r.data),
  get: (id: string) => api.get<AppUser>(`/users/${id}`).then((r) => r.data),
  create: (data: {
    username: string;
    email: string;
    display_name: string;
    password: string;
    is_superadmin: boolean;
    force_password_change: boolean;
  }) => api.post<AppUser>("/users", data).then((r) => r.data),
  update: (
    id: string,
    data: Partial<
      Pick<
        AppUser,
        | "display_name"
        | "email"
        | "is_active"
        | "is_superadmin"
        | "force_password_change"
      >
    >,
  ) => api.put<AppUser>(`/users/${id}`, data).then((r) => r.data),
  resetPassword: (id: string, newPassword: string) =>
    api.post(`/users/${id}/reset-password`, { new_password: newPassword }),
  /** Clear lockout state on a user account (issue #71). */
  unlock: (id: string) => api.post(`/users/${id}/unlock`),
  delete: (id: string) => api.delete(`/users/${id}`),
};

// ── Sessions (issue #72) ────────────────────────────────────────────

export interface UserSessionRow {
  id: string;
  user_id: string;
  username: string;
  display_name: string;
  auth_source: string;
  source_ip: string | null;
  user_agent: string | null;
  created_at: string;
  last_seen_at: string | null;
  expires_at: string;
  revoked: boolean;
  is_current: boolean;
}

// ── Tag autocomplete (issue #104 phase 2) ───────────────────────────

export interface TagKeysResponse {
  keys: string[];
}

export interface TagValuesResponse {
  key: string;
  values: string[];
}

export const tagsApi = {
  /** Distinct tag keys across every tagged resource type. ``prefix``
   *  is a case-insensitive substring filter for typeahead.
   *  ``staleTime`` on the React Query consumer should be generous
   *  (10–30s) — the result set turns over slowly as operators rarely
   *  invent new keys. */
  listKeys: (prefix?: string, limit = 200) => {
    const qs = new URLSearchParams();
    if (prefix) qs.set("prefix", prefix);
    qs.set("limit", String(limit));
    return api.get<TagKeysResponse>(`/tags/keys?${qs}`).then((r) => r.data);
  },
  /** Distinct values for a specific tag key, across every tagged
   *  resource type. Used after the operator has picked a key in the
   *  chip and is choosing the value side. */
  listValues: (key: string, prefix?: string, limit = 200) => {
    const qs = new URLSearchParams();
    qs.set("key", key);
    if (prefix) qs.set("prefix", prefix);
    qs.set("limit", String(limit));
    return api.get<TagValuesResponse>(`/tags/values?${qs}`).then((r) => r.data);
  },
};

export const sessionsApi = {
  /** Sessions owned by the current user. Useful even for non-admins —
   *  spot a session you don't recognise and revoke it. */
  listMine: (includeExpired = false) =>
    api
      .get<UserSessionRow[]>("/sessions/me", {
        params: { include_expired: includeExpired },
      })
      .then((r) => r.data),
  /** All sessions across every user (superadmin only). */
  listAll: (includeExpired = false) =>
    api
      .get<UserSessionRow[]>("/sessions", {
        params: { include_expired: includeExpired },
      })
      .then((r) => r.data),
  /** Force-logout. Returns 204; the in-flight access token using
   *  this session's jti will start 401-ing on its next call. */
  revoke: (id: string) => api.delete(`/sessions/${id}`),
};

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  user_display_name: string;
  auth_source: string;
  action: string;
  resource_type: string;
  resource_id: string;
  resource_display: string;
  result: string;
  source_ip: string | null;
}

export interface AuditLogPage {
  total: number;
  items: AuditLogEntry[];
}

export interface AuditChainBreak {
  seq: number;
  audit_id: string;
  expected_hash: string;
  actual_hash: string;
  reason: "row_hash_mismatch" | "prev_hash_mismatch";
}

export interface AuditIntegrity {
  ok: boolean;
  rows_checked: number;
  breaks: AuditChainBreak[];
}

// ── AI tool catalog (issue #101 follow-up) ──────────────────────────

export interface AIToolCatalogEntry {
  name: string;
  description: string;
  category: string;
  writes: boolean;
  parameters_schema: Record<string, unknown>;
  default_enabled: boolean;
  enabled: boolean;
}

export interface AIToolCatalog {
  tools: AIToolCatalogEntry[];
  total: number;
  /** Raw setting: ``null`` = registry per-tool defaults, list = explicit. */
  platform_override: string[] | null;
}

export const aiToolCatalogApi = {
  list: () => api.get<AIToolCatalog>("/ai/tools").then((r) => r.data),
  /** Pass null to revert to registry defaults; pass an explicit list
   *  to pin the platform allowlist. */
  update: (enabled: string[] | null) =>
    api
      .put<AIToolCatalog>("/ai/tools/catalog", { enabled })
      .then((r) => r.data),
};

// ── Feature modules ──────────────────────────────────────────────────
//
// Operator-controlled visibility for whole sidebar / REST / MCP
// surfaces. The sidebar + Cmd-K palette query this on mount so a
// disabled module disappears entirely. Toggling is superadmin-only.
export interface FeatureModuleEntry {
  id: string;
  label: string;
  group: string;
  description: string;
  default_enabled: boolean;
  /**
   * This module's OWN state. A module whose `requires` chain is broken
   * resolves disabled everywhere else (routers, sidebar, copilot tools)
   * while still reporting `enabled: true` here — see #1068.
   */
  enabled: boolean;
  /** Module ids this one is meaningless without (#1068). */
  requires: string[];
}

// #62 break-glass: force a weakening control change immediately (the 5 kinds
// the backend ``ModifyApprovalControlArgs.kind`` accepts).
export type ApprovalControlKind =
  | "disable_module"
  | "disable_policy"
  | "delete_policy"
  | "lower_superadmin_gate"
  | "unlock";

export interface BreakGlassBody {
  kind: ApprovalControlKind;
  policy_id?: string | null;
  password?: string | null;
  totp_code?: string | null;
  confirm_phrase: string;
}

export const featureModulesApi = {
  list: () =>
    api.get<FeatureModuleEntry[]>("/admin/feature-modules").then((r) => r.data),
  // Toggle a module. Returns the FULL axios response (no trailing
  // ``.then(r => r.data)``) so the #62 self-governance lock's 202
  // approval-queue envelope is observable: disabling ``governance.approvals``
  // while the lock is on returns 202 + a ``ChangeRequestQueued`` body instead
  // of the FeatureModuleEntry. Callers route the response through
  // ``handleApprovalQueued`` (``@/lib/approvalQueue``) and read ``.data`` for
  // the inline 200 case. ``protectControls`` is only honoured by the backend
  // when enabling ``governance.approvals`` (strengthening → single-person).
  toggle: (id: string, enabled: boolean, protectControls?: boolean) =>
    api.patch<FeatureModuleEntry | ChangeRequestQueued>(
      `/admin/feature-modules/${id}`,
      { enabled, protect_controls: protectControls },
    ),
  // #62 self-governance lock state. ON ⇒ disabling/weakening the approval
  // control requires a second superadmin (or break-glass).
  getApprovalsLock: () =>
    api
      .get<{
        approvals_protect_controls: boolean;
      }>("/admin/feature-modules/approvals-lock")
      .then((r) => r.data),
  // Turn the lock on (strengthen → inline 200) or off (weaken → 202 gated
  // when currently on). Full response so the 202 envelope is observable.
  setApprovalsLock: (enabled: boolean) =>
    api.post<{ approvals_protect_controls: boolean } | ChangeRequestQueued>(
      "/admin/feature-modules/approvals-lock",
      { enabled },
    ),
  // #62 break-glass — force a protected control change IMMEDIATELY, bypassing
  // the two-person gate. Superadmin-only; the backend re-confirms password /
  // TOTP + the typed phrase, writes a HIGH-severity audit row, and fires the
  // ``governance.break_glass`` event.
  breakGlass: (body: BreakGlassBody) =>
    api
      .post<{
        forced: boolean;
        kind: string;
      }>("/admin/feature-modules/break-glass", body)
      .then((r) => r.data),
};

// ── Saved views (issue #77) ──────────────────────────────────────────
//
// Per-user, per-page named filter/sort/column presets. ``payload`` is
// opaque JSON shaped by each page; the SavedViewsMenu just stores and
// restores it via the page's apply callback. Gated by the
// ``ui.saved_views`` feature module.
export interface SavedView {
  id: string;
  page: string;
  name: string;
  payload: Record<string, unknown>;
  is_default: boolean;
  created_at: string;
  modified_at: string;
}

export interface SavedViewCreate {
  page: string;
  name: string;
  payload: Record<string, unknown>;
  is_default?: boolean;
}

export interface SavedViewUpdate {
  name?: string;
  payload?: Record<string, unknown>;
  is_default?: boolean;
}

export const savedViewsApi = {
  list: (page?: string) =>
    api
      .get<SavedView[]>("/saved-views", { params: page ? { page } : undefined })
      .then((r) => r.data),
  create: (body: SavedViewCreate) =>
    api.post<SavedView>("/saved-views", body).then((r) => r.data),
  update: (id: string, body: SavedViewUpdate) =>
    api.patch<SavedView>(`/saved-views/${id}`, body).then((r) => r.data),
  remove: (id: string) => api.delete(`/saved-views/${id}`),
};

export const auditApi = {
  list: (params?: {
    limit?: number;
    offset?: number;
    action?: string;
    resource_type?: string;
    user_display_name?: string;
    resource_display?: string;
    result?: string;
    source_ip?: string;
  }) => api.get<AuditLogPage>("/audit", { params }).then((r) => r.data),
  /** Walk the chain and report any tampering (issue #73). The
   *  ``max_rows`` cap is for huge tables — leave unset for a full
   *  sweep. */
  integrity: (maxRows?: number) =>
    api
      .get<AuditIntegrity>("/audit/integrity", {
        params: maxRows ? { max_rows: maxRows } : undefined,
      })
      .then((r) => r.data),
  /** Compliance / change report PDF (#48) — auditor-facing rollup of every
   *  audit-log mutation in a date range, grouped by user / type / action.
   *  Defaults to the last 30 days; pass ISO ``since``/``until`` to narrow. */
  exportPdf: async (params?: {
    since?: string;
    until?: string;
  }): Promise<void> => {
    let res;
    try {
      res = await api.get<Blob>("/audit/export.pdf", {
        params,
        responseType: "blob",
      });
    } catch (err) {
      // With responseType: "blob" the error body also arrives as a Blob, so
      // the usual response.data.detail is unreadable — unwrap it to text
      // first and re-throw a real Error the caller can show inline.
      const data = (err as { response?: { data?: unknown } })?.response?.data;
      if (data instanceof Blob) {
        const text = await data.text();
        let detail = text || "PDF export failed";
        try {
          detail = JSON.parse(text)?.detail || detail;
        } catch {
          // body wasn't JSON — fall back to the raw text
        }
        throw new Error(detail);
      }
      throw err;
    }
    const disp = (res.headers["content-disposition"] as string) || "";
    const match = disp.match(/filename="?([^";]+)"?/i);
    const ts = new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[-:]/g, "")
      .replace("T", "-");
    const filename = match ? match[1] : `spatiumddi-change-report-${ts}.pdf`;
    const blob = new Blob([res.data as BlobPart], { type: "application/pdf" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },
};

// ── Backup + restore (issue #117 Phase 1a) ────────────────────────────────────

export interface BackupManifest {
  format?: string;
  format_version?: number;
  app_version?: string;
  schema_version?: string | null;
  hostname?: string;
  created_at?: string;
  included_sections?: string[];
  secret_passphrase_hint?: string;
}

export interface BackupRestoreResponse {
  success: boolean;
  pre_restore_safety_path: string | null;
  duration_ms: number;
  manifest: BackupManifest;
  secrets_payload_keys: string[];
  note: string;
  selective?: boolean;
  restored_sections?: string[] | null;
  // Operator-actionable post-restore advisories (issue #127 Phase 4d) —
  // currently surfaces the PowerDNS DNSSEC re-sign / re-publish caveat.
  warnings?: string[];
}

export interface BackupSection {
  key: string;
  label: string;
  description: string;
  table_count: number;
  volatile: boolean;
  selectable: boolean;
}

export interface BackupManifestPreviewResponse {
  manifest: BackupManifest;
  archive_bytes: number;
  format_recognised: boolean;
}

export const backupApi = {
  /**
   * Build a backup archive on the backend and download it as a zip.
   * Synchronous from the operator's perspective — the server holds
   * the response open until ``pg_dump`` + zip assembly finish, then
   * streams the file with ``Content-Disposition: attachment``.
   * Mirrors the conformity PDF export shape.
   */
  createAndDownload: async (
    passphrase: string,
    passphraseHint: string,
    excludeSecrets: boolean = false,
  ): Promise<void> => {
    const fd = new FormData();
    fd.append("passphrase", passphrase);
    fd.append("passphrase_hint", passphraseHint);
    if (excludeSecrets) fd.append("exclude_secrets", "true");
    let res;
    try {
      res = await api.post<Blob>("/backup/create-and-download", fd, {
        responseType: "blob",
        // Override the global ``Content-Type: application/json`` so
        // axios fills in the multipart boundary correctly.
        headers: { "Content-Type": "multipart/form-data" },
      });
    } catch (err) {
      // ``responseType: blob`` makes axios wrap the JSON error body
      // in a Blob, which renders as a useless
      // "Request failed with status code 422" string. Read it as
      // text so the operator sees the actual validation message.
      throw await _unwrapBlobError(err);
    }
    const disp = (res.headers["content-disposition"] as string) || "";
    const match = disp.match(/filename="?([^";]+)"?/i);
    const ts = new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[-:]/g, "")
      .replace("T", "-");
    const fallback = `spatiumddi-backup-${ts}.zip`;
    const filename = match ? match[1] : fallback;
    const blob = new Blob([res.data as BlobPart], { type: "application/zip" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  /** Inspect an archive's manifest before committing to a restore.
   *  The operator uploads the file, the server unpacks just
   *  ``manifest.json``, and the UI shows them which install + when
   *  this archive was taken. */
  previewManifest: async (
    file: File,
  ): Promise<BackupManifestPreviewResponse> => {
    const fd = new FormData();
    fd.append("archive", file);
    const res = await api.post<BackupManifestPreviewResponse>(
      "/backup/manifest-preview",
      fd,
      { headers: { "Content-Type": "multipart/form-data" } },
    );
    return res.data;
  },

  /** Apply a backup archive to the running install. Hard overwrite
   *  by default; pass a non-empty ``sections`` list for selective
   *  restore (Phase 2b). Operator must type
   *  ``RESTORE-FROM-BACKUP`` in ``confirmationPhrase``. */
  restore: async (
    file: File,
    passphrase: string,
    confirmationPhrase: string,
    sections?: string[],
  ): Promise<BackupRestoreResponse> => {
    const fd = new FormData();
    fd.append("archive", file);
    fd.append("passphrase", passphrase);
    fd.append("confirmation_phrase", confirmationPhrase);
    if (sections && sections.length > 0) {
      fd.append("sections", sections.join(","));
    }
    const res = await api.post<BackupRestoreResponse>("/backup/restore", fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return res.data;
  },

  /** Backup-section catalog (Phase 2a). Drives the selective-
   *  restore checklist. */
  listSections: () =>
    api
      .get<{ sections: BackupSection[] }>("/backup/sections")
      .then((r) => r.data.sections),
};

// ── Backup targets (issue #117 Phase 1b) ──────────────────────────────────────

export interface BackupTargetConfigField {
  name: string;
  label: string;
  type: string;
  required: boolean;
  description: string | null;
  secret: boolean;
}

export interface BackupTargetKind {
  kind: string;
  label: string;
  config_fields: BackupTargetConfigField[];
  /**
   * True when the kind has no listing and no delete at all (`https_put`),
   * as opposed to a kind whose credential merely lacks delete permission.
   * The API forces `write_only` on for these, so the form renders the
   * switch as checked and disabled rather than offering a choice the
   * server will override.
   */
  inherently_write_only: boolean;
}

export interface BackupTarget {
  id: string;
  name: string;
  description: string;
  kind: string;
  enabled: boolean;
  config: Record<string, unknown>;
  passphrase_set: boolean;
  passphrase_hint: string;
  schedule_cron: string | null;
  retention_keep_last_n: number | null;
  retention_keep_days: number | null;
  /**
   * Write-only destination (#989). Retention is skipped, archive delete
   * is refused, pull-mode download answers 409, and the restore drill
   * reports `cannot_drill` — recovery readiness is UNVERIFIED, never
   * healthy.
   */
  write_only: boolean;
  last_run_status: string;
  last_run_at: string | null;
  last_run_filename: string | null;
  last_run_bytes: number | null;
  last_run_duration_ms: number | null;
  last_run_error: string | null;
  next_run_at: string | null;
  drill_enabled: boolean;
  drill_cron: string | null;
  drill_next_run_at: string | null;
  drill_last_status: string;
  drill_last_at: string | null;
  created_at: string;
  modified_at: string;
}

export interface BackupTargetCreate {
  name: string;
  description?: string;
  kind: string;
  enabled?: boolean;
  config: Record<string, unknown>;
  passphrase: string;
  passphrase_hint?: string;
  schedule_cron?: string | null;
  retention_keep_last_n?: number | null;
  retention_keep_days?: number | null;
  write_only?: boolean;
}

export interface BackupTargetUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  config?: Record<string, unknown>;
  passphrase?: string;
  passphrase_hint?: string;
  schedule_cron?: string | null;
  retention_keep_last_n?: number | null;
  retention_keep_days?: number | null;
  write_only?: boolean;
  drill_enabled?: boolean;
  drill_cron?: string | null;
}

/** One check inside a restore drill's verdict (issue #702). */
export interface RestoreDrillAssertion {
  name: string;
  /** "pass" | "fail" | "skip" */
  status: string;
  detail: string;
}

export interface RestoreDrill {
  id: string;
  target_id: string;
  target_name: string | null;
  /** "running" | "passed" | "failed" | "error" */
  state: string;
  triggered_by: string;
  filename: string | null;
  archive_bytes: number | null;
  manifest: Record<string, unknown> | null;
  scratch_db: string | null;
  assertions: RestoreDrillAssertion[];
  error: string | null;
  started_at: string;
  finished_at: string | null;
  duration_ms: number | null;
}

/** One target's recovery-readiness row (issue #702). */
export interface RestoreDrillReadinessTarget {
  target_id: string;
  target_name: string;
  kind: string;
  enabled: boolean;
  /** #989 — a write-only destination cannot be read back. */
  write_only: boolean;
  /**
   * Why this target cannot be drilled at all, or null when it can.
   * Non-null forces `verified` false: an unverifiable backup is an
   * unknown, not a pass.
   */
  undrillable_reason: string | null;
  drills_scheduled: boolean;
  drill_cron: string | null;
  /** Raw latest status, including "error" / "in_progress" / "cannot_drill". */
  latest_verdict: string;
  /** Latest terminal verdict, i.e. "passed" | "failed" | null. */
  latest_finished_verdict: string | null;
  latest_drill_at: string | null;
  last_passed_at: string | null;
  hours_since_last_pass: number | null;
  /** Has passed at some point AND the latest finished verdict isn't a failure. */
  verified: boolean;
}

export interface RestoreDrillReadiness {
  targets: RestoreDrillReadinessTarget[];
  total_targets: number;
  verified_targets: number;
  unverified_targets: number;
}

export interface BackupArchiveListing {
  filename: string;
  size_bytes: number;
  created_at: string;
}

export interface BackupRunNowOutcome {
  success: boolean;
  filename: string | null;
  bytes: number | null;
  duration_ms: number | null;
  deleted: number;
  error: string | null;
}

export interface BackupTestOutcome {
  ok: boolean;
  detail?: string;
  error?: string;
}

export const backupTargetsApi = {
  listKinds: () =>
    api
      .get<{ kinds: BackupTargetKind[] }>("/backup/targets/kinds")
      .then((r) => r.data.kinds),
  list: () => api.get<BackupTarget[]>("/backup/targets").then((r) => r.data),
  get: (id: string) =>
    api.get<BackupTarget>(`/backup/targets/${id}`).then((r) => r.data),
  create: (body: BackupTargetCreate) =>
    api.post<BackupTarget>("/backup/targets", body).then((r) => r.data),
  update: (id: string, body: BackupTargetUpdate) =>
    api.patch<BackupTarget>(`/backup/targets/${id}`, body).then((r) => r.data),
  remove: (id: string) =>
    api.delete<void>(`/backup/targets/${id}`).then((r) => r.data),
  runNow: (id: string) =>
    api
      .post<BackupRunNowOutcome>(`/backup/targets/${id}/run-now`)
      .then((r) => r.data),
  test: (id: string) =>
    api
      .post<BackupTestOutcome>(`/backup/targets/${id}/test`)
      .then((r) => r.data),
  listArchives: (id: string) =>
    api
      .get<BackupArchiveListing[]>(`/backup/targets/${id}/archives`)
      .then((r) => r.data),
  /**
   * Restore-verification drills (issue #702) — replay this target's
   * newest archive into a throwaway database and assert against the
   * result. Synchronous like ``runNow``; the request is held open
   * for the whole replay.
   */
  runDrill: (id: string) =>
    api.post<RestoreDrill>(`/backup/drills/run/${id}`).then((r) => r.data),
  listDrills: (params?: {
    target_id?: string;
    state?: string;
    limit?: number;
  }) =>
    api.get<RestoreDrill[]>("/backup/drills", { params }).then((r) => r.data),
  /**
   * Per-target recovery readiness. Backed by the same server-side
   * computation the Operator Copilot uses, so the UI and the assistant
   * can't disagree about whether a backup is proven — and so
   * "last proven" doesn't depend on how far back the drill history
   * page happens to reach.
   */
  drillReadiness: () =>
    api
      .get<RestoreDrillReadiness>("/backup/drills/readiness")
      .then((r) => r.data),
  deleteArchive: (id: string, filename: string) =>
    api
      .delete<void>(
        `/backup/targets/${id}/archives/${encodeURIComponent(filename)}`,
      )
      .then((r) => r.data),
  /**
   * Stream an archive back from any destination (local volume /
   * S3 / SCP / Azure Blob) to the operator's browser as a zip
   * download. The api proxies the fetch — operators don't need
   * direct credentials for the underlying destination. Same shape
   * as ``backupApi.createAndDownload``: blob response, parse
   * ``Content-Disposition`` for the filename, synthetic anchor
   * click.
   */
  downloadArchive: async (id: string, filename: string): Promise<void> => {
    let res;
    try {
      res = await api.get<Blob>(
        `/backup/targets/${id}/archives/${encodeURIComponent(filename)}/download`,
        { responseType: "blob" },
      );
    } catch (err) {
      throw await _unwrapBlobError(err);
    }
    const disp = (res.headers["content-disposition"] as string) || "";
    const match = disp.match(/filename="?([^";]+)"?/i);
    const downloadName = match ? match[1] : filename;
    const blob = new Blob([res.data as BlobPart], {
      type: "application/zip",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = downloadName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },
  restoreFromArchive: (
    id: string,
    body: {
      filename: string;
      passphrase: string;
      confirmation_phrase: string;
      sections?: string[] | null;
    },
  ) =>
    api
      .post<{
        success: boolean;
        filename: string;
        duration_ms: number;
        manifest: BackupManifest;
        pre_restore_safety_path: string | null;
        selective?: boolean;
        restored_sections?: string[] | null;
      }>(`/backup/targets/${id}/archives/restore`, body)
      .then((r) => r.data),
};

// Read a blob-shaped error body and re-throw with the actual
// ``detail`` (or whatever JSON the backend returned) attached so
// the operator sees the real validation message instead of the
// generic axios "Request failed with status code N".
async function _unwrapBlobError(err: unknown): Promise<Error> {
  const axiosErr = err as {
    response?: { status?: number; data?: Blob | unknown };
    message?: string;
  };
  const data = axiosErr?.response?.data;
  if (data instanceof Blob) {
    try {
      const text = await data.text();
      try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === "object") {
          const detail = (parsed as { detail?: unknown }).detail;
          if (typeof detail === "string") {
            return new Error(detail);
          }
          // FastAPI 422 returns a list under ``detail``; fall back
          // to the JSON-stringified version.
          return new Error(JSON.stringify(parsed));
        }
      } catch {
        // Body wasn't JSON — surface as plain text.
      }
      if (text) return new Error(text);
    } catch {
      // Couldn't read the blob — fall through to the generic.
    }
  }
  return new Error(axiosErr?.message || "Request failed");
}

// ── BGP enrichment — RIPEstat + PeeringDB (issue #122) ───────────────────────

export interface BgpAnnouncedPrefix {
  prefix: string;
  first_seen: string | null;
  last_seen: string | null;
}

export interface BgpAnnouncedPrefixesResponse {
  available: boolean;
  asn: number;
  prefixes?: BgpAnnouncedPrefix[];
  ipv4_count?: number;
  ipv6_count?: number;
  error?: string;
}

export interface BgpPrefixOriginResponse {
  available: boolean;
  resource: string;
  prefix?: string;
  is_less_specific?: boolean;
  asns?: { asn: number; holder: string | null }[];
  block?: Record<string, unknown> | null;
  announced?: boolean;
  error?: string;
}

export interface BgpRoutingHistoryEvent {
  asn: number;
  starttime: string | null;
  endtime: string | null;
}

export interface BgpRoutingHistoryResponse {
  available: boolean;
  resource: string;
  events?: BgpRoutingHistoryEvent[];
  error?: string;
}

export interface BgpIxpRow {
  ix_name: string | null;
  city: string | null;
  speed_mbit: number | null;
  ipv4: string | null;
  ipv6: string | null;
  is_rs_peer: boolean;
  operational: boolean;
}

export interface BgpIxpsResponse {
  available: boolean;
  asn: number;
  ixps?: BgpIxpRow[];
  ixp_count?: number;
  error?: string;
}

export interface BgpPeeringProfileResponse {
  available: boolean;
  asn: number;
  found?: boolean;
  name?: string | null;
  aka?: string | null;
  info_type?: string | null;
  info_traffic?: string | null;
  info_scope?: string | null;
  policy_general?: string | null;
  policy_locations?: string | null;
  irr_as_set?: string | null;
  looking_glass?: string | null;
  website?: string | null;
  error?: string;
}

export const bgpApi = {
  announcedPrefixes: (asn: number) =>
    api
      .get<BgpAnnouncedPrefixesResponse>(`/bgp/asn/${asn}/announced-prefixes`)
      .then((r) => r.data),
  asnNetwork: (asn: number) =>
    api
      .get<BgpPeeringProfileResponse>(`/bgp/asn/${asn}/network`)
      .then((r) => r.data),
  asnIxps: (asn: number) =>
    api.get<BgpIxpsResponse>(`/bgp/asn/${asn}/ixps`).then((r) => r.data),
  prefixOrigin: (resource: string) =>
    api
      .get<BgpPrefixOriginResponse>("/bgp/prefix/origin", {
        params: { resource },
      })
      .then((r) => r.data),
  prefixRoutingHistory: (resource: string) =>
    api
      .get<BgpRoutingHistoryResponse>("/bgp/prefix/routing-history", {
        params: { resource },
      })
      .then((r) => r.data),
};

// ── Diagnostics — uncaught exceptions (issue #123) ────────────────────────────

export interface InternalErrorListItem {
  id: string;
  timestamp: string;
  service: string;
  kind: string;
  route_or_task: string | null;
  exception_class: string;
  message: string;
  fingerprint: string;
  occurrence_count: number;
  last_seen_at: string;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  suppressed_until: string | null;
}

export interface InternalErrorDetail extends InternalErrorListItem {
  request_id: string | null;
  traceback: string;
  context_json: Record<string, unknown>;
}

export interface InternalErrorStats {
  total: number;
  unacknowledged: number;
  noisy_unacked: number;
}

export const diagnosticsApi = {
  list: (params?: {
    service?: string;
    acknowledged?: "yes" | "no";
    since_hours?: number;
    exception_class?: string;
    limit?: number;
  }) =>
    api
      .get<InternalErrorListItem[]>("/diagnostics/errors", { params })
      .then((r) => r.data),
  get: (id: string) =>
    api
      .get<InternalErrorDetail>(`/diagnostics/errors/${id}`)
      .then((r) => r.data),
  stats: () =>
    api
      .get<InternalErrorStats>("/diagnostics/errors/stats")
      .then((r) => r.data),
  acknowledge: (id: string) =>
    api
      .post<InternalErrorDetail>(`/diagnostics/errors/${id}/acknowledge`)
      .then((r) => r.data),
  suppress: (id: string, hours = 24) =>
    api
      .post<InternalErrorDetail>(`/diagnostics/errors/${id}/suppress`, {
        hours,
      })
      .then((r) => r.data),
  delete: (id: string) =>
    api.delete<void>(`/diagnostics/errors/${id}`).then((r) => r.data),
};

// ── Search ─────────────────────────────────────────────────────────────────────

/** Every type `app/services/search/providers.py` can emit. Keep in step
 *  with the `PROVIDERS` registry there — a type missing here still returns
 *  from the API, it just renders with the fallback icon and label. */
export type SearchResultType =
  | "ip_address"
  | "subnet"
  | "block"
  | "space"
  | "dns_group"
  | "dns_zone"
  | "dns_record"
  | "dns_server"
  | "dns_view"
  | "dns_blocklist"
  | "dhcp_scope"
  | "dhcp_reservation"
  | "dhcp_server"
  | "vlan"
  | "device"
  | "site"
  | "circuit"
  | "user"
  | "group"
  | "appliance";

export interface SearchResult {
  type: SearchResultType;
  id: string;
  display: string;
  name: string | null;
  status: string | null;
  description: string | null;
  hostname: string | null;
  mac_address: string | null;
  // IPAM breadcrumb
  subnet_id: string | null;
  subnet_network: string | null;
  block_id: string | null;
  space_id: string | null;
  space_name: string | null;
  // DNS context
  dns_group_id: string | null;
  dns_group_name: string | null;
  dns_zone_id: string | null;
  dns_zone_name: string | null;
  dns_record_type: string | null;
  dns_record_value: string | null;
  /** Free-form breadcrumb for types with no shared parent shape. */
  context?: string | null;
  /** Path to navigate to. Present for every type added in #879; the
   *  original seven are dispatched client-side because they pass
   *  react-router state rather than a path. */
  route?: string | null;
  matched_field?: string | null;
  /** Relevance: match quality plus type weight. Higher is better. */
  score?: number;
}

/** A type the calling user is permitted to search, used for scope chips. */
export interface SearchTypeInfo {
  type: SearchResultType;
  label: string;
  /** Scope chip this type belongs to: ipam | dns | dhcp | network | admin. */
  group: string;
}

export interface SearchResponse {
  query: string;
  total: number;
  results: SearchResult[];
  searched_types: SearchTypeInfo[];
}

export const searchApi = {
  search: (q: string, types?: string, limit = 25) =>
    api
      .get<SearchResponse>("/search", { params: { q, types, limit } })
      .then((r) => r.data),
  /** Types this caller may search — permission- and module-filtered. */
  types: () => api.get<SearchTypeInfo[]>("/search/types").then((r) => r.data),
};

// ── Settings ───────────────────────────────────────────────────────────────────

export type EnvBannerPosition = "top" | "bottom" | "both";

/** The deliberately-public slice of PlatformSettings, served unauthenticated
 *  so the login page can render branding before anyone has a session
 *  (issues #885 / #886 / #887 / #888). Never add a field here that an
 *  anonymous visitor shouldn't see. */
export interface PublicSettings {
  app_title: string;
  login_banner: {
    enabled: boolean;
    title: string;
    text: string;
    require_ack: boolean;
  };
  env_banner: {
    enabled: boolean;
    text: string;
    bg: string;
    fg: string;
    position: EnvBannerPosition;
  };
  /** sha256 of the operator-uploaded logo, or null when none is set (the
   *  frontend then falls back to the bundled asset). Doubles as the
   *  cache-buster in the logo URL. */
  logo_sha256: string | null;
}

export interface BrandingLogoInfo {
  sha256: string;
  byte_size: number;
  media_type: string;
}

export interface PlatformSettings {
  app_title: string;
  app_base_url: string;
  // Login-screen acceptable-use banner — issue #885.
  login_banner_enabled: boolean;
  login_banner_title: string;
  login_banner_text: string;
  login_banner_require_ack: boolean;
  // Environment banner ("you are on the DEV box") — issue #887.
  env_banner_enabled: boolean;
  env_banner_text: string;
  env_banner_bg: string;
  env_banner_fg: string;
  env_banner_position: EnvBannerPosition;
  dns_auto_sync_enabled: boolean;
  dns_auto_sync_interval_minutes: number;
  dns_auto_sync_delete_stale: boolean;
  dns_auto_sync_last_run_at: string | null;
  // Reverse-DNS (PTR) auto-population — issue #41.
  reverse_dns_enabled: boolean;
  reverse_dns_interval_minutes: number;
  reverse_dns_resolvers: string[] | null;
  reverse_dns_last_run_at: string | null;
  dns_pull_from_server_enabled: boolean;
  dns_pull_from_server_interval_minutes: number;
  dns_pull_from_server_last_run_at: string | null;
  dhcp_pull_leases_enabled: boolean;
  dhcp_pull_leases_interval_seconds: number;
  dhcp_pull_leases_last_run_at: string | null;
  audit_forward_syslog_enabled: boolean;
  audit_forward_syslog_host: string;
  audit_forward_syslog_port: number;
  audit_forward_syslog_protocol: string;
  audit_forward_syslog_facility: number;
  audit_forward_webhook_enabled: boolean;
  audit_forward_webhook_url: string;
  audit_forward_webhook_auth_header: string;
  ip_allocation_strategy: string;
  session_timeout_minutes: number;
  auto_logout_minutes: number;
  utilization_warn_threshold: number;
  utilization_critical_threshold: number;
  utilization_max_prefix_ipv4: number;
  utilization_max_prefix_ipv6: number;
  subnet_tree_default_expanded_depth: number;
  github_release_check_enabled: boolean;
  dns_default_ttl: number;
  dns_default_zone_type: string;
  dns_default_dnssec_validation: string;
  dns_recursive_by_default: boolean;
  dhcp_default_dns_servers: string[];
  dhcp_default_domain_name: string;
  dhcp_default_domain_search: string[];
  dhcp_default_ntp_servers: string[];
  dhcp_default_lease_time: number;
  oui_lookup_enabled: boolean;
  oui_update_interval_hours: number;
  oui_last_updated_at: string | null;
  integration_kubernetes_enabled: boolean;
  integration_docker_enabled: boolean;
  integration_proxmox_enabled: boolean;
  integration_tailscale_enabled: boolean;
  integration_unifi_enabled: boolean;
  integration_cloud_enabled: boolean;
  integration_opnsense_enabled: boolean;
  integration_panos_enabled: boolean;
  integration_fortinet_enabled: boolean;
  integration_meraki_enabled: boolean;
  integration_netbird_enabled: boolean;
  /** Domain WHOIS refresh cadence (hours). Beat ticks hourly; the
   *  task itself reads this on every fire so cadence changes take
   *  effect on the next tick without restarting beat. 1–168 h range
   *  enforced server-side. */
  domain_whois_interval_hours: number;
  tls_cert_check_interval_hours: number;
  asn_whois_interval_hours: number;
  rpki_roa_source: string;
  rpki_roa_refresh_interval_hours: number;
  vrf_strict_rd_validation: boolean;
  /** Read-only — true when an encrypted fingerbank API key is on file.
   *  The plaintext is never returned. Submit a value via
   *  ``fingerbank_api_key`` on the update payload to set or clear it
   *  (empty string clears). */
  fingerbank_api_key_set: boolean;
  /** Write-only — Fernet-encrypted server-side. Set to a non-empty
   *  string to store; set to "" to clear; omit to leave unchanged. */
  fingerbank_api_key?: string;
  /** Operator Copilot daily digest (issue #90 Phase 2). When true,
   *  a Celery cron at 08:00 UTC rolls up the prior 24 h, sends to
   *  the highest-priority enabled AI provider for an executive
   *  summary, and dispatches via the audit-forward targets. */
  ai_daily_digest_enabled: boolean;
  /** Password policy (issue #70). 0 disables history / max-age; the
   *  complexity flags are independently toggleable. */
  password_min_length: number;
  password_require_uppercase: boolean;
  password_require_lowercase: boolean;
  password_require_digit: boolean;
  password_require_symbol: boolean;
  password_history_count: number;
  password_max_age_days: number;
  /** Account lockout (issue #71). 0 disables. */
  lockout_threshold: number;
  lockout_duration_minutes: number;
  lockout_reset_minutes: number;
  /** Appliance SNMP (issue #153). Toggle + version pick + sysContact /
   *  sysLocation are straightforward; community + v3 user passes are
   *  redacted on the wire (``*_set`` booleans), with write-only
   *  ``snmp_community`` + per-user ``auth_pass`` / ``priv_pass`` on
   *  the update payload. ``snmp_v3_users`` carries the read shape
   *  on response, write shape on update. */
  snmp_enabled: boolean;
  snmp_version: SnmpVersion;
  snmp_community_set: boolean;
  /** Write-only — Fernet-encrypted server-side. Set to a non-empty
   *  string to store; set to "" to clear; omit to leave unchanged. */
  snmp_community?: string;
  /** Read shape on response; on update, send the new full list with
   *  per-user ``auth_pass`` / ``priv_pass`` semantics (None = leave,
   *  "" = clear, non-empty = encrypt + replace). */
  snmp_v3_users: SnmpV3User[];
  snmp_allowed_sources: string[];
  snmp_sys_contact: string;
  snmp_sys_location: string;
  /** Appliance NTP / chrony (issue #154). No secrets — server
   *  hostnames are not sensitive, so the read shape and the write
   *  shape match (no ``*_set`` redaction). */
  ntp_source_mode: NtpSourceMode;
  ntp_pool_servers: string[];
  ntp_custom_servers: NtpCustomServer[];
  ntp_allow_clients: boolean;
  ntp_allow_client_networks: string[];
  // Issue #165 — operator-set IANA timezone. Empty = no override
  // (host falls back to install-time default).
  timezone: string;
  /** Appliance console mode (#393): "dashboard" (default) = quiet boot +
   *  the Talos console dashboard; "verbose_dashboard" = verbose kernel /
   *  systemd boot output, then the dashboard takes over; "text_console" =
   *  verbose boot + a plain getty login (no dashboard). Appliance hosts only;
   *  applies on the next reboot (grubenv-driven). */
  console_mode: "dashboard" | "verbose_dashboard" | "text_console";
  /** Supervisor (appliance) registration gate (#170 Wave A / #407).
   *  When false, a remote supervisor cannot pair (register 404s).
   *  OS-appliance control-plane installs self-enable this on first boot;
   *  generic Kubernetes/Helm control planes must flip it on (here or via
   *  the Fleet → Pairing toggle) before an appliance can register. */
  supervisor_registration_enabled: boolean;
  /** Maintenance mode (issue #57). System-wide read-only switch.
   *  ``maintenance_started_at`` is server-managed (stamped on enable /
   *  cleared on disable) and is therefore read-only — not sent on PUT. */
  maintenance_mode_enabled: boolean;
  maintenance_message: string;
  maintenance_started_at: string | null;
  /** Appliance LLDP (issue #343). No secrets — LLDP advertises public
   *  identity, so read + write shapes match. ``lldp_protocols`` enables
   *  reception of CDP/EDP/FDP/SONMP alongside LLDP. */
  lldp_enabled: boolean;
  lldp_tx_interval: number;
  lldp_tx_hold: number;
  lldp_protocols: LldpProtocol[];
  lldp_interface_pattern: string;
  lldp_management_pattern: string;
  lldp_sys_name: string;
  lldp_sys_description: string;
  lldp_med_location: Record<string, unknown>;
  lldp_snmp_agentx: boolean;
  /** Appliance syslog forwarding (issue #156). Per-target ``ca_cert_pem``
   *  is redacted to a ``ca_cert_set`` boolean on the read shape; on
   *  update send the full ``SyslogTargetWrite[]`` list with per-target
   *  ``ca_cert_pem`` semantics (None/omit = leave, "" = clear, non-empty
   *  = encrypt + replace, keyed by host:port). */
  syslog_enabled: boolean;
  syslog_targets: SyslogTarget[];
  syslog_filter: string;
  syslog_buffer_disk: boolean;
  /** Appliance SSH (issue #157). Public keys are NOT secrets — the
   *  authorized-keys list is returned verbatim (no redaction). Send the
   *  full list on update (atomic replace). ``ssh_password_auth_enabled``
   *  defaults true; disabling it with zero keys is refused server-side
   *  (lockout safety). ``ssh_port`` < 1024 is rejected except 22. */
  ssh_authorized_keys: SshAuthorizedKey[];
  ssh_password_auth_enabled: boolean;
  ssh_allow_root_login: boolean;
  ssh_port: number;
  ssh_allowed_source_networks: string[];
  /** #1009 — whether the allowlist above is ENFORCED. Off, the host
   *  firewall keeps its unconditional port-22 floor and the list is
   *  inert; on, that floor is retired and the scope applies. */
  ssh_lockdown: boolean;
  /** Write-only acknowledgement for the self-lockout pre-flight —
   *  never returned by the API. */
  ssh_lockdown_force?: boolean;
  /** Accept losing EVERY remote door, leaving only the console (#1013). */
  acknowledge_console_only?: boolean;
  /** Appliance DNS resolver (issue #158). No secrets — resolver IPs /
   *  search domains are not sensitive, so read + write shapes match.
   *  ``automatic`` defers to per-link NetworkManager / DHCP DNS;
   *  ``override`` pins the global ``resolver_servers`` (which win over
   *  per-link resolvers via a route-only ``~.`` default domain). The
   *  rendered drop-in NEVER touches DNSStubListener (BIND9 binds host
   *  :53). */
  resolver_mode: ResolverMode;
  resolver_servers: string[];
  resolver_fallback_servers: string[];
  resolver_search_domains: string[];
  resolver_dnssec: ResolverDnssec;
  resolver_dns_over_tls: ResolverDoT;
  // ── Appliance APT (issue #155) ───────────────────────────────────
  apt_managed: boolean;
  apt_sources: AptSource[];
  apt_gpg_keys: AptGpgKeyRedacted[];
  apt_proxy_http: string;
  apt_proxy_https: string;
  apt_proxy_no_proxy: string;
  apt_auth: AptAuthRedacted[];
  apt_unattended_upgrades_enabled: boolean;
  // Issue #164 — unattended-upgrades policy (the WHEN/HOW of auto-applying).
  apt_unattended_origins: string[];
  apt_unattended_blocklist: string[];
  apt_unattended_automatic_reboot: boolean;
  apt_unattended_reboot_time: string;
}

/** One managed APT repo. No secrets — the armoured key lives in
 *  ``apt_gpg_keys`` and is referenced by ``signed_by_key_id``. */
export interface AptSource {
  name: string;
  uri: string;
  suites: string;
  components: string;
  signed_by_key_id: string;
  enabled: boolean;
}

/** Read shape of a GPG key — the armoured text is redacted to a bool. */
export interface AptGpgKeyRedacted {
  key_id: string;
  comment: string;
  armoured_text_set: boolean;
}

/** Write shape — ``armoured_text`` null preserves, "" clears, else sets. */
export interface AptGpgKeyUpdate {
  key_id: string;
  comment?: string;
  armoured_text?: string | null;
}

/** Read shape of a private-mirror credential — password redacted. */
export interface AptAuthRedacted {
  machine: string;
  login: string;
  password_set: boolean;
}

/** Write shape — ``password`` null preserves, "" clears, else sets. */
export interface AptAuthUpdate {
  machine: string;
  login: string;
  password?: string | null;
}

/** PUT /settings body for the APT block — carries the write shapes for
 *  the secret-bearing fields (gpg keys / auth) that the redacted
 *  PlatformSettings read type can't express. */
export interface AptSettingsUpdate {
  apt_managed?: boolean;
  apt_sources?: AptSource[];
  apt_gpg_keys?: AptGpgKeyUpdate[];
  apt_proxy_http?: string;
  apt_proxy_https?: string;
  apt_proxy_no_proxy?: string;
  apt_auth?: AptAuthUpdate[];
  apt_unattended_upgrades_enabled?: boolean;
  // Issue #164 — unattended-upgrades policy.
  apt_unattended_origins?: string[];
  apt_unattended_blocklist?: string[];
  apt_unattended_automatic_reboot?: boolean;
  apt_unattended_reboot_time?: string;
}

export interface AptValidateRequest {
  apt_sources: AptSource[];
  apt_gpg_key_ids?: string[];
  apt_proxy_http?: string;
  apt_proxy_https?: string;
}

export interface AptValidateResponse {
  valid: boolean;
  errors: string[];
  warnings: string[];
  sources_list_preview: string;
}

export type ResolverMode = "automatic" | "override";
export type ResolverDnssec = "yes" | "no" | "allow-downgrade";
export type ResolverDoT = "yes" | "opportunistic" | "no";

/** One authorized SSH key. ``public_key`` is a single OpenSSH public-key
 *  line; ``name`` is an operator label, ``comment`` an optional note.
 *  Public keys are not secrets, so the same shape is used for read +
 *  write. */
export interface SshAuthorizedKey {
  name: string;
  public_key: string;
  comment: string;
}

export type NtpSourceMode = "pool" | "servers" | "mixed";
export type SyslogProtocol = "udp" | "tcp" | "tls";
export type SyslogFormat = "rfc5424" | "rfc3164" | "json";

/** Read shape — the server never returns the CA PEM ciphertext. */
export interface SyslogTarget {
  host: string;
  port: number;
  protocol: SyslogProtocol;
  format: SyslogFormat;
  ca_cert_set: boolean;
}

/** Write shape — ``ca_cert_pem`` is plaintext on the wire (TLS); None /
 *  omit preserves the existing ciphertext for the same host:port; ""
 *  clears; required (non-empty) when protocol is "tls". */
export interface SyslogTargetWrite {
  host: string;
  port: number;
  protocol: SyslogProtocol;
  format: SyslogFormat;
  ca_cert_pem?: string | null;
}
export type LldpProtocol = "cdp" | "edp" | "fdp" | "sonmp";

export interface NtpCustomServer {
  host: string;
  iburst: boolean;
  prefer: boolean;
}

export type SnmpVersion = "v2c" | "v3";
export type SnmpAuthProtocol = "none" | "MD5" | "SHA";
export type SnmpPrivProtocol = "none" | "DES" | "AES";

/** Read shape — the server never returns the ciphertext. */
export interface SnmpV3User {
  username: string;
  auth_protocol: SnmpAuthProtocol;
  auth_pass_set: boolean;
  priv_protocol: SnmpPrivProtocol;
  priv_pass_set: boolean;
}

/** Write shape — passes are plaintext on the wire (TLS); None / omit
 *  preserves the existing ciphertext for the same username; "" clears. */
export interface SnmpV3UserWrite {
  username: string;
  auth_protocol: SnmpAuthProtocol;
  auth_pass?: string | null;
  priv_protocol: SnmpPrivProtocol;
  priv_pass?: string | null;
}

export interface PasswordPolicy {
  min_length: number;
  require_uppercase: boolean;
  require_lowercase: boolean;
  require_digit: boolean;
  require_symbol: boolean;
  history_count: number;
  max_age_days: number;
}

export interface OUIStatus {
  enabled: boolean;
  interval_hours: number;
  last_updated_at: string | null;
  vendor_count: number;
}

export interface OUITaskStatus {
  task_id: string;
  state: string; // "PENDING" | "STARTED" | "SUCCESS" | "FAILURE" | "RETRY"
  ready: boolean;
  result:
    | ({
        status?: string; // "ran" | "disabled" | "skipped" | "error"
        total?: number;
        added?: number;
        updated?: number;
        removed?: number;
        unchanged?: number;
        forced?: boolean;
        reason?: string;
        detail?: string;
      } & Record<string, unknown>)
    | null;
  error: string | null;
}

// ── InfluxDB push export (issue #889) ─────────────────────────────────────────

/** Three declared versions, two wire dialects: ``v3`` reuses the v2
 *  write endpoint with bearer auth and bucket=database naming. */
export type InfluxDBVersion = "v1" | "v2" | "v3";

export interface InfluxDBTarget {
  id: string;
  name: string;
  enabled: boolean;
  version: InfluxDBVersion;
  url: string;
  verify_tls: boolean;
  timeout_seconds: number;
  database: string;
  username: string;
  /** Secrets are write-only — the server reports presence, never value. */
  password_set: boolean;
  org: string;
  bucket: string;
  token_set: boolean;
  measurement_prefix: string;
  push_interval_seconds: number;
  push_dns_metrics: boolean;
  push_dhcp_metrics: boolean;
  push_subnet_utilization: boolean;
  push_dhcp_scope_leases: boolean;
  last_push_at: string | null;
  last_push_points: number;
  last_push_error: string | null;
  last_dns_bucket_at: string | null;
  last_dhcp_bucket_at: string | null;
  created_at: string;
  modified_at: string;
}

export interface InfluxDBTargetWrite {
  name: string;
  enabled: boolean;
  version: InfluxDBVersion;
  url: string;
  verify_tls: boolean;
  timeout_seconds: number;
  database: string;
  username: string;
  /** ``null`` = keep what is stored, ``""`` = clear, else replace. */
  password?: string | null;
  org: string;
  bucket: string;
  token?: string | null;
  measurement_prefix: string;
  push_interval_seconds: number;
  push_dns_metrics: boolean;
  push_dhcp_metrics: boolean;
  push_subnet_utilization: boolean;
  push_dhcp_scope_leases: boolean;
}

export interface InfluxDBTestResult {
  ok: boolean;
  message: string;
  points: number;
}

export type AuditForwardKind = "syslog" | "webhook" | "smtp";
export type AuditForwardWebhookFlavor =
  | "generic"
  | "slack"
  | "teams"
  | "discord";
export type AuditForwardSmtpSecurity = "none" | "starttls" | "ssl";
export type AuditForwardFormat =
  | "rfc5424_json"
  | "rfc5424_cef"
  | "rfc5424_leef"
  | "rfc3164"
  | "json_lines";
export type AuditForwardProtocol = "udp" | "tcp" | "tls";
export type AuditForwardSeverity = "info" | "warn" | "error" | "denied";

export interface AuditForwardTarget {
  id: string;
  name: string;
  enabled: boolean;
  kind: AuditForwardKind;
  format: AuditForwardFormat;
  host: string;
  port: number;
  protocol: AuditForwardProtocol;
  facility: number;
  ca_cert_pem: string | null;
  url: string;
  auth_header_set: boolean;
  webhook_flavor: AuditForwardWebhookFlavor;
  smtp_host: string;
  smtp_port: number;
  smtp_security: AuditForwardSmtpSecurity;
  smtp_username: string;
  // Server returns only a boolean (the password is Fernet-encrypted at rest).
  smtp_password_set: boolean;
  smtp_from_address: string;
  smtp_to_addresses: string[] | null;
  smtp_reply_to: string;
  min_severity: AuditForwardSeverity | null;
  resource_types: string[] | null;
  created_at: string;
  modified_at: string;
}

export interface AuditForwardTargetWrite {
  name: string;
  enabled: boolean;
  kind: AuditForwardKind;
  format: AuditForwardFormat;
  host?: string;
  port?: number;
  protocol?: AuditForwardProtocol;
  facility?: number;
  ca_cert_pem?: string | null;
  url?: string;
  auth_header?: string;
  webhook_flavor?: AuditForwardWebhookFlavor;
  smtp_host?: string;
  smtp_port?: number;
  smtp_security?: AuditForwardSmtpSecurity;
  smtp_username?: string;
  // ``null`` keeps the existing encrypted password, ``""`` clears it,
  // any other string is sent in plaintext and encrypted server-side.
  smtp_password?: string | null;
  smtp_from_address?: string;
  smtp_to_addresses?: string[] | null;
  smtp_reply_to?: string;
  min_severity?: AuditForwardSeverity | null;
  resource_types?: string[] | null;
}

/** Unauthenticated branding reads (issues #885–#888). Kept separate from
 *  ``settingsApi`` because these are the only settings calls that work
 *  without a session — the login page depends on that. */
export const publicSettingsApi = {
  get: () => api.get<PublicSettings>("/settings/public").then((r) => r.data),
  /** Direct URL — the browser fetches the bytes itself, so no auth header
   *  is available; the route is public for exactly that reason. Built from
   *  ``API_BASE`` rather than a hardcoded ``/api/v1`` so a deployment that
   *  overrides ``VITE_API_BASE_URL`` (split-origin / sub-path) still points
   *  at the real API. The sha busts the cache on re-upload. */
  logoUrl: (sha256: string) =>
    `${API_BASE.replace(/\/$/, "")}/settings/public/logo?v=${sha256}`,
};

export const settingsApi = {
  get: () => api.get<PlatformSettings>("/settings").then((r) => r.data),
  update: (data: Partial<PlatformSettings>) =>
    api.put<PlatformSettings>("/settings", data).then((r) => r.data),
  /** Issue #886 — upload the branding logo (PNG, ≤512 KB). Superadmin
   *  only, audited server-side. */
  uploadLogo: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return api
      .put<BrandingLogoInfo>("/settings/branding/logo", fd, {
        // Axios picks the multipart boundary itself when the body is a
        // FormData; an explicit Content-Type would strip it.
        headers: { "Content-Type": undefined },
      })
      .then((r) => r.data);
  },
  /** Issue #886 — remove the custom logo and fall back to the bundled one. */
  deleteLogo: () => api.delete("/settings/branding/logo"),
  getDefaults: () =>
    api
      .get<Partial<PlatformSettings>>("/settings/defaults")
      .then((r) => r.data),
  /** Issue #41 — queue an on-demand reverse-DNS (PTR) sweep, bypassing
   *  the enabled-gate + interval. */
  runReverseDns: () =>
    api
      .post<{
        status: string;
        task_id: string | null;
      }>("/settings/reverse-dns/run")
      .then((r) => r.data),
  /** Issue #153 — reveal the configured SNMP v2c community after a
   *  password re-verify. Superadmin + local-auth only; every reveal
   *  is audit-logged. ``community`` is null when nothing is
   *  configured (in which case ``configured`` is false). */
  revealSnmpCommunity: (password?: string, totpCode?: string) =>
    api
      .post<{
        configured: boolean;
        community: string | null;
      }>("/settings/snmp/reveal-community", {
        password,
        totp_code: totpCode,
      })
      .then((r) => r.data),
  /** Issue #155 — PUT the APT host-config block (carries write shapes
   *  for the secret-bearing gpg-key / auth fields). */
  updateApt: (data: AptSettingsUpdate) =>
    api.put<PlatformSettings>("/settings", data).then((r) => r.data),
  /** Issue #155 — structural pre-apply check for a candidate APT config
   *  (no save). The host runner does the real apt-get-update validation;
   *  this catches the structural mistakes before Save. */
  validateApt: (req: AptValidateRequest) =>
    api
      .post<AptValidateResponse>("/settings/apt/validate", req)
      .then((r) => r.data),
  getOUIStatus: () =>
    api.get<OUIStatus>("/settings/oui/status").then((r) => r.data),
  refreshOUI: () =>
    api
      .post<{ status: string; task_id: string | null }>("/settings/oui/refresh")
      .then((r) => r.data),
  getOUIRefreshStatus: (taskId: string) =>
    api
      .get<OUITaskStatus>(`/settings/oui/refresh/${taskId}`)
      .then((r) => r.data),
  listAuditTargets: () =>
    api
      .get<AuditForwardTarget[]>("/settings/audit-forward-targets")
      .then((r) => r.data),
  createAuditTarget: (body: AuditForwardTargetWrite) =>
    api
      .post<AuditForwardTarget>("/settings/audit-forward-targets", body)
      .then((r) => r.data),
  updateAuditTarget: (id: string, body: AuditForwardTargetWrite) =>
    api
      .put<AuditForwardTarget>(`/settings/audit-forward-targets/${id}`, body)
      .then((r) => r.data),
  deleteAuditTarget: (id: string) =>
    api.delete(`/settings/audit-forward-targets/${id}`),
  testAuditTarget: (id: string) =>
    api
      .post<{
        status: string;
        target: string;
      }>(`/settings/audit-forward-targets/${id}/test`)
      .then((r) => r.data),
  /** Issue #889 — InfluxDB push-export targets. Superadmin-only server
   *  side; secrets are write-only (the row carries `*_set` booleans). */
  listInfluxTargets: () =>
    api.get<InfluxDBTarget[]>("/settings/influxdb-targets").then((r) => r.data),
  createInfluxTarget: (body: InfluxDBTargetWrite) =>
    api
      .post<InfluxDBTarget>("/settings/influxdb-targets", body)
      .then((r) => r.data),
  updateInfluxTarget: (id: string, body: InfluxDBTargetWrite) =>
    api
      .put<InfluxDBTarget>(`/settings/influxdb-targets/${id}`, body)
      .then((r) => r.data),
  deleteInfluxTarget: (id: string) =>
    api.delete(`/settings/influxdb-targets/${id}`),
  /** Writes one synthetic point — a real write, because a reachable URL
   *  with the wrong bucket / org / token still answers a plain GET. */
  testInfluxTarget: (id: string) =>
    api
      .post<InfluxDBTestResult>(`/settings/influxdb-targets/${id}/test`)
      .then((r) => r.data),
};

// ── Auth Providers ─────────────────────────────────────────────────────────────

export type AuthProviderType = "ldap" | "oidc" | "saml" | "radius" | "tacacs";

export interface AuthProvider {
  id: string;
  name: string;
  type: AuthProviderType;
  is_enabled: boolean;
  priority: number;
  config: Record<string, unknown>;
  has_secrets: boolean;
  auto_create_users: boolean;
  auto_update_users: boolean;
  mapping_count: number;
  created_at: string;
  modified_at: string;
}

export interface AuthProviderCreate {
  name: string;
  type: AuthProviderType;
  is_enabled?: boolean;
  priority?: number;
  config?: Record<string, unknown>;
  secrets?: Record<string, unknown> | null;
  auto_create_users?: boolean;
  auto_update_users?: boolean;
}

export interface AuthProviderUpdate {
  name?: string;
  is_enabled?: boolean;
  priority?: number;
  config?: Record<string, unknown>;
  /** undefined = leave stored secrets untouched. {} = clear. */
  secrets?: Record<string, unknown> | null;
  auto_create_users?: boolean;
  auto_update_users?: boolean;
}

export interface AuthGroupMapping {
  id: string;
  provider_id: string;
  external_group: string;
  internal_group_id: string;
  internal_group_name: string;
  priority: number;
  created_at: string;
  modified_at: string;
}

export interface AuthGroupMappingCreate {
  external_group: string;
  internal_group_id: string;
  priority?: number;
}

export interface AuthGroupMappingUpdate {
  external_group?: string;
  internal_group_id?: string;
  priority?: number;
}

export interface AuthProviderTestResult {
  ok: boolean;
  message: string;
  details: Record<string, unknown>;
}

export interface InternalGroup {
  id: string;
  name: string;
  description: string;
  auth_source: string;
  external_dn?: string | null;
  role_ids?: string[];
  user_ids?: string[];
}

export interface InternalGroupCreate {
  name: string;
  description?: string;
  auth_source?: string;
  external_dn?: string | null;
  role_ids?: string[];
  user_ids?: string[];
}

export interface InternalGroupUpdate {
  name?: string;
  description?: string;
  external_dn?: string | null;
  role_ids?: string[];
  user_ids?: string[];
}

export const groupsApi = {
  list: () => api.get<InternalGroup[]>("/groups").then((r) => r.data),
  get: (id: string) =>
    api.get<InternalGroup>(`/groups/${id}`).then((r) => r.data),
  create: (body: InternalGroupCreate) =>
    api.post<InternalGroup>("/groups", body).then((r) => r.data),
  update: (id: string, body: InternalGroupUpdate) =>
    api.put<InternalGroup>(`/groups/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/groups/${id}`),
};

// ── Time-bound grants (#65) ─────────────────────────────────────────────────

export interface TimeBoundGrant {
  id: string;
  group_id: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  expires_at: string;
  revoked_at?: string | null;
  reason: string;
  granted_by_user_id?: string | null;
  is_active: boolean;
  created_at: string;
}

export interface TimeBoundGrantCreate {
  group_id: string;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  expires_at: string;
  reason?: string;
}

export const timeBoundGrantsApi = {
  list: (groupId?: string, includeExpired?: boolean) => {
    const params = new URLSearchParams();
    if (groupId) params.set("group_id", groupId);
    if (includeExpired) params.set("include_expired", "true");
    const qs = params.toString();
    return api
      .get<TimeBoundGrant[]>(`/groups/time-bound-grants${qs ? `?${qs}` : ""}`)
      .then((r) => r.data);
  },
  create: (body: TimeBoundGrantCreate) =>
    api
      .post<TimeBoundGrant>("/groups/time-bound-grants", body)
      .then((r) => r.data),
  revoke: (id: string) =>
    api
      .delete<TimeBoundGrant>(`/groups/time-bound-grants/${id}`)
      .then((r) => r.data),
};

// ── Roles ─────────────────────────────────────────────────────────────────────

export interface PermissionEntry {
  action: string;
  resource_type: string;
  resource_id?: string | null;
}

export interface AppRole {
  id: string;
  name: string;
  description: string;
  is_builtin: boolean;
  permissions: PermissionEntry[];
}

export interface RoleCreate {
  name: string;
  description?: string;
  permissions?: PermissionEntry[];
}

export interface RoleUpdate {
  name?: string;
  description?: string;
  permissions?: PermissionEntry[];
}

export const rolesApi = {
  list: () => api.get<AppRole[]>("/roles").then((r) => r.data),
  get: (id: string) => api.get<AppRole>(`/roles/${id}`).then((r) => r.data),
  create: (body: RoleCreate) =>
    api.post<AppRole>("/roles", body).then((r) => r.data),
  update: (id: string, body: RoleUpdate) =>
    api.put<AppRole>(`/roles/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/roles/${id}`),
  clone: (id: string, name: string) =>
    api.post<AppRole>(`/roles/${id}/clone`, { name }).then((r) => r.data),
};

export const authProvidersApi = {
  list: () => api.get<AuthProvider[]>("/auth-providers").then((r) => r.data),
  test: (id: string, body: { username?: string; password?: string }) =>
    api
      .post<AuthProviderTestResult>(`/auth-providers/${id}/test`, body)
      .then((r) => r.data),
  // Dry-run test against an unsaved provider config. Nothing is persisted —
  // lets admins iterate on config + secrets before committing a row.
  testUnsaved: (body: {
    type: AuthProviderType;
    config: Record<string, unknown>;
    secrets: Record<string, unknown>;
    username?: string;
    password?: string;
  }) =>
    api
      .post<AuthProviderTestResult>("/auth-providers/test", body)
      .then((r) => r.data),
  get: (id: string) =>
    api.get<AuthProvider>(`/auth-providers/${id}`).then((r) => r.data),
  create: (body: AuthProviderCreate) =>
    api.post<AuthProvider>("/auth-providers", body).then((r) => r.data),
  update: (id: string, body: AuthProviderUpdate) =>
    api.put<AuthProvider>(`/auth-providers/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/auth-providers/${id}`),
  revealSecrets: (id: string) =>
    api
      .get<Record<string, unknown>>(`/auth-providers/${id}/secrets`)
      .then((r) => r.data),
  listMappings: (id: string) =>
    api
      .get<AuthGroupMapping[]>(`/auth-providers/${id}/mappings`)
      .then((r) => r.data),
  createMapping: (id: string, body: AuthGroupMappingCreate) =>
    api
      .post<AuthGroupMapping>(`/auth-providers/${id}/mappings`, body)
      .then((r) => r.data),
  updateMapping: (
    id: string,
    mappingId: string,
    body: AuthGroupMappingUpdate,
  ) =>
    api
      .put<AuthGroupMapping>(
        `/auth-providers/${id}/mappings/${mappingId}`,
        body,
      )
      .then((r) => r.data),
  deleteMapping: (id: string, mappingId: string) =>
    api.delete(`/auth-providers/${id}/mappings/${mappingId}`),
};

// ── AI Providers (issue #90 — Operator Copilot) ────────────────────────────────

export type AIProviderKind =
  | "openai_compat"
  | "anthropic"
  | "google"
  | "azure_openai";

export const AI_PROVIDER_KIND_LABELS: Record<AIProviderKind, string> = {
  openai_compat: "OpenAI-compatible (OpenAI / Ollama / vLLM / OpenWebUI / …)",
  anthropic: "Anthropic Claude",
  google: "Google Gemini",
  azure_openai: "Azure OpenAI",
};

// Short labels for table cells (the verbose ``AI_PROVIDER_KIND_LABELS``
// fits in a form picker but pushes the table too wide on narrow viewports).
export const AI_PROVIDER_KIND_SHORT: Record<AIProviderKind, string> = {
  openai_compat: "OpenAI-compat",
  anthropic: "Claude",
  google: "Gemini",
  azure_openai: "Azure OpenAI",
};

// Drivers currently shipping. All four kinds are registered after the
// Phase 2 Azure + Gemini bundle landed.
export const AI_PROVIDER_KIND_AVAILABLE: AIProviderKind[] = [
  "openai_compat",
  "anthropic",
  "azure_openai",
  "google",
];

export interface AIProvider {
  id: string;
  name: string;
  kind: AIProviderKind;
  base_url: string;
  has_api_key: boolean;
  default_model: string;
  is_enabled: boolean;
  priority: number;
  options: Record<string, unknown>;
  /** null = use the baked-in default Operator Copilot system prompt. */
  system_prompt_override: string | null;
  /** null = all registered tools enabled (default). [] = no tools.
   *  list = exactly those tool names (unknown names skipped at runtime). */
  enabled_tools: string[] | null;
  created_at: string;
  modified_at: string;
}

export interface AIProviderCreate {
  name: string;
  kind: AIProviderKind;
  base_url?: string;
  api_key?: string | null;
  default_model?: string;
  is_enabled?: boolean;
  priority?: number;
  options?: Record<string, unknown>;
  system_prompt_override?: string | null;
  enabled_tools?: string[] | null;
}

export interface AIProviderUpdate {
  name?: string;
  base_url?: string;
  api_key?: string | null;
  default_model?: string;
  is_enabled?: boolean;
  priority?: number;
  options?: Record<string, unknown>;
  /** null = leave override unchanged; "" = clear (revert to default). */
  system_prompt_override?: string | null;
  /** null sentinel = revert to "all enabled". Field omitted = no change. */
  enabled_tools?: string[] | null;
}

export interface AIToolCatalogEntry {
  name: string;
  description: string;
  category: string;
  writes: boolean;
}

export interface AITestConnectionResult {
  ok: boolean;
  detail: string;
  latency_ms: number | null;
  sample_models: string[];
}

export interface AIModelInfo {
  id: string;
  owned_by: string;
  context_window: number | null;
}

export const aiApi = {
  listProviders: () =>
    api.get<AIProvider[]>("/ai/providers").then((r) => r.data),
  getProvider: (id: string) =>
    api.get<AIProvider>(`/ai/providers/${id}`).then((r) => r.data),
  createProvider: (body: AIProviderCreate) =>
    api.post<AIProvider>("/ai/providers", body).then((r) => r.data),
  updateProvider: (id: string, body: AIProviderUpdate) =>
    api.put<AIProvider>(`/ai/providers/${id}`, body).then((r) => r.data),
  deleteProvider: (id: string) =>
    api.delete<void>(`/ai/providers/${id}`).then((r) => r.data),
  testProvider: (id: string) =>
    api
      .post<AITestConnectionResult>(`/ai/providers/${id}/test`, {})
      .then((r) => r.data),
  testUnsaved: (body: {
    kind: AIProviderKind;
    base_url?: string;
    api_key?: string | null;
    default_model?: string;
    options?: Record<string, unknown>;
  }) =>
    api
      .post<AITestConnectionResult>("/ai/providers/test", body)
      .then((r) => r.data),
  listModels: (id: string) =>
    api
      .get<{ models: AIModelInfo[] }>(`/ai/providers/${id}/models`)
      .then((r) => r.data.models),
  getDefaultSystemPrompt: () =>
    api
      .get<{ prompt: string }>("/ai/providers/default-system-prompt")
      .then((r) => r.data.prompt),
  getToolCatalog: () =>
    api
      .get<{ tools: AIToolCatalogEntry[] }>("/ai/providers/tools")
      .then((r) => r.data.tools),

  // ── Chat sessions (Wave 3) ───────────────────────────────────────
  listSessions: (includeArchived = false) =>
    api
      .get<AIChatSessionSummary[]>("/ai/sessions", {
        params: { include_archived: includeArchived },
      })
      .then((r) => r.data),
  getSession: (id: string) =>
    api.get<AIChatSessionDetail>(`/ai/sessions/${id}`).then((r) => r.data),
  updateSession: (id: string, body: { name?: string; archived?: boolean }) =>
    api
      .put<AIChatSessionSummary>(`/ai/sessions/${id}`, body)
      .then((r) => r.data),
  deleteSession: (id: string) =>
    api.delete<void>(`/ai/sessions/${id}`).then((r) => r.data),
  // Catalog of registered tools (admin-only). Wave 3 surface uses this
  // for the "what can the copilot do?" panel inside the chat drawer.
  listTools: () =>
    api
      .get<{ tools: AIToolEntry[]; total: number }>("/ai/tools")
      .then((r) => r.data),

  // ── Usage observability (Wave 4) ────────────────────────────────
  myUsage: () => api.get<AIUsageSnapshot>("/ai/usage/me").then((r) => r.data),
  adminUsage: () => api.get<AIAdminUsage>("/ai/usage").then((r) => r.data),

  // ── Prompt library (Phase 2) ────────────────────────────────────
  listPrompts: () => api.get<AIPrompt[]>("/ai/prompts").then((r) => r.data),
  getPrompt: (id: string) =>
    api.get<AIPrompt>(`/ai/prompts/${id}`).then((r) => r.data),
  createPrompt: (body: AIPromptCreate) =>
    api.post<AIPrompt>("/ai/prompts", body).then((r) => r.data),
  updatePrompt: (id: string, body: AIPromptUpdate) =>
    api.put<AIPrompt>(`/ai/prompts/${id}`, body).then((r) => r.data),
  deletePrompt: (id: string) =>
    api.delete<void>(`/ai/prompts/${id}`).then((r) => r.data),

  // ── Operation proposals (Phase 2 — write-tool preview/apply) ──
  listProposals: (pendingOnly = true) =>
    api
      .get<AIProposal[]>("/ai/proposals", {
        params: { pending_only: pendingOnly },
      })
      .then((r) => r.data),
  getProposal: (id: string) =>
    api.get<AIProposal>(`/ai/proposals/${id}`).then((r) => r.data),
  applyProposal: (id: string) =>
    api
      .post<AIProposalApplyResponse>(`/ai/proposals/${id}/apply`, {})
      .then((r) => r.data),
  discardProposal: (id: string) =>
    api.post<AIProposal>(`/ai/proposals/${id}/discard`, {}).then((r) => r.data),
};

// ── AI usage observability types ─────────────────────────────────────

export interface AIUsageSnapshot {
  messages: number;
  tokens_in: number;
  tokens_out: number;
  // Returned as a string to preserve Decimal precision.
  cost_usd: string;
  cap_token: number | null;
  cap_cost_usd: string | null;
}

export interface AIAdminUsageTopUser {
  user_id: string;
  username: string;
  messages: number;
  tokens_in: number;
  tokens_out: number;
  cost_usd: string;
}

export interface AIAdminUsage {
  today: AIUsageSnapshot;
  last_7d: AIUsageSnapshot;
  last_30d: AIUsageSnapshot;
  top_users_today: AIAdminUsageTopUser[];
}

// ── AI prompts library types (Phase 2) ───────────────────────────────

export interface AIPrompt {
  id: string;
  name: string;
  description: string;
  prompt_text: string;
  is_shared: boolean;
  created_by_user_id: string | null;
  created_at: string;
  modified_at: string;
  is_owner: boolean;
}

export interface AIPromptCreate {
  name: string;
  description?: string;
  prompt_text: string;
  is_shared?: boolean;
}

export interface AIPromptUpdate {
  name?: string;
  description?: string;
  prompt_text?: string;
  is_shared?: boolean;
}

// ── AI write-operation proposal types (Phase 2) ──────────────────────

export interface AIProposal {
  id: string;
  operation: string;
  args: Record<string, unknown>;
  preview_text: string;
  expires_at: string;
  applied_at: string | null;
  discarded_at: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
  created_at: string;
}

export interface AIProposalApplyResponse {
  ok: boolean;
  detail: string;
  result: Record<string, unknown> | null;
  proposal: AIProposal;
}

// ── AI chat types ────────────────────────────────────────────────────

export type AIChatRole = "system" | "user" | "assistant" | "tool";

export interface AIChatToolCall {
  id: string;
  name: string;
  arguments: string;
}

export interface AIChatMessage {
  id: string;
  role: AIChatRole;
  content: string;
  tool_calls: AIChatToolCall[] | null;
  tool_call_id: string | null;
  name: string | null;
  tokens_in: number | null;
  tokens_out: number | null;
  latency_ms: number | null;
  created_at: string;
}

export interface AIChatSessionSummary {
  id: string;
  name: string;
  provider_id: string | null;
  model: string;
  archived_at: string | null;
  created_at: string;
  modified_at: string;
  message_count: number;
}

export interface AIChatSessionDetail extends AIChatSessionSummary {
  system_prompt: string;
  messages: AIChatMessage[];
}

export interface AIToolEntry {
  name: string;
  description: string;
  category: string;
  writes: boolean;
  parameters_schema: Record<string, unknown>;
}

/**
 * Stream a chat turn. Uses ``fetch`` rather than ``EventSource`` because
 * EventSource doesn't support custom headers (Authorization). Yields one
 * parsed SSE event at a time. Cancel via the ``AbortSignal``.
 */
export async function* streamChatTurn(
  body: {
    message: string;
    session_id?: string;
    provider_id?: string;
    model?: string;
    initial_context?: string;
  },
  signal?: AbortSignal,
): AsyncIterable<{ event: string; data: Record<string, unknown> }> {
  const token = getAccessToken();
  const res = await fetch("/api/v1/ai/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      Accept: "text/event-stream",
    },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok || !res.body) {
    let detail = "";
    try {
      detail = (await res.json())?.detail ?? "";
    } catch {
      detail = await res.text();
    }
    throw new Error(`chat request failed (${res.status}): ${detail}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    // SSE frames are separated by blank lines.
    const frames = buffer.split("\n\n");
    buffer = frames.pop() ?? "";
    for (const frame of frames) {
      if (!frame.trim()) continue;
      let event = "message";
      let data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("event: ")) event = line.slice(7).trim();
        else if (line.startsWith("data: ")) data += line.slice(6);
      }
      if (!data) continue;
      try {
        yield { event, data: JSON.parse(data) };
      } catch {
        // Skip malformed frames silently — keep the stream alive.
      }
    }
  }
}

// ── Custom Fields ──────────────────────────────────────────────────────────────

export interface CustomField {
  id: string;
  resource_type: string;
  name: string;
  label: string;
  field_type: string;
  options: string[] | null;
  is_required: boolean;
  is_searchable: boolean;
  default_value: string | null;
  display_order: number;
  description: string;
}

export const customFieldsApi = {
  list: (resource_type?: string) =>
    api
      .get<CustomField[]>("/custom-fields", {
        params: resource_type ? { resource_type } : undefined,
      })
      .then((r) => r.data),
  create: (data: Omit<CustomField, "id">) =>
    api.post<CustomField>("/custom-fields", data).then((r) => r.data),
  update: (
    id: string,
    data: Partial<
      Omit<CustomField, "id" | "resource_type" | "name" | "field_type">
    >,
  ) => api.put<CustomField>(`/custom-fields/${id}`, data).then((r) => r.data),
  delete: (id: string) => api.delete(`/custom-fields/${id}`),
};

// ── DNS ────────────────────────────────────────────────────────────────────

/** #935 — what moving a zone to another group would do. Returned by both
 *  the preview and the commit, so the UI can show the same figures after
 *  the fact. */
export interface ZoneMovePreview {
  zone_id: string;
  zone_name: string;
  source_group_id: string;
  source_group_name: string;
  target_group_id: string;
  target_group_name: string;
  source_has_views: boolean;
  target_has_views: boolean;
  /** kept_none | remapped | cleared_widening | cleared_inert */
  zone_view_action: string;
  zone_view_from: string | null;
  records_total: number;
  records_remapped: number;
  /** Records whose view scoping is lost while the TARGET renders views —
   *  they go from answering in one view to answering in every one. */
  records_widened: number;
  records_cleared_inert: number;
  records_widened_by_view: Record<string, number>;
  acl_rows_remapped: number;
  acl_keys_lost: string[];
  pools_repointed: number;
  zone_state_rows: number;
  pending_ops: number;
  dnssec_signed: boolean;
  dnssec_key_count: number;
  acme_accounts: number;
  source_drivers: string[];
  target_drivers: string[];
  name_collision: boolean;
  /** Target drivers that cannot sign, when the zone is signed. Non-empty
   *  means the commit refuses — not waivable by acknowledgement. */
  dnssec_unsupported_drivers: string[];
  acl_names_remapped: string[];
  /** Named ACLs the zone cites that the target group doesn't define.
   *  Non-empty means the commit refuses: an undefined symbol makes BIND
   *  reject the whole file, stopping the entire target group. */
  acl_names_lost: string[];
  warnings: string[];
  /** Keys the commit will demand: view_widening | dnssec_rollover |
   *  lost_update_grants. */
  required_acknowledgements: string[];
  target_tsig_key_generated?: boolean;
}

export interface DNSServerGroup {
  id: string;
  name: string;
  description: string;
  group_type: string;
  default_view: string | null;
  is_recursive: boolean;
  // RFC 9432 BIND9 catalog zones — distribute zones via one catalog
  // instead of per-server config push. Producer is the group's primary
  // bind9 server; consumers auto-pull members.
  catalog_zones_enabled: boolean;
  catalog_zone_name: string;
  // Issue #25 — flag this group as exposed to the public internet.
  // The IPAM safety guard returns ``requires_confirmation`` when an
  // operator binds a private IP into a zone in this group, forcing a
  // typed-CIDR confirm.
  is_public_facing?: boolean;
  /** Distinct drivers of the servers currently in this group (#934
   *  follow-up). Empty = an empty group, compatible with anything. A group
   *  is single-driver, so one entry is normal; two or more means the group
   *  was mixed through the create path, which doesn't enforce homogeneity.
   *  Lets the move picker tell which groups a server can actually go to. */
  server_drivers?: string[];
  created_at: string;
  modified_at: string;
}

export interface WindowsDNSCredentials {
  username: string;
  password: string;
  winrm_port?: number;
  // Kerberos is not offered: the images carry no GSSAPI stack (#1128).
  transport?: "ntlm" | "basic" | "credssp";
  use_tls?: boolean;
  verify_tls?: boolean;
}

export interface DNSZoneSyncItem {
  zone: string;
  imported: number;
  pushed: number;
  server_records: number;
  push_errors: string[];
  error: string | null;
}

export interface DNSServerSyncResult {
  zones_attempted: number;
  zones_succeeded: number;
  zones_failed: number;
  total_imported: number;
  total_pushed: number;
  total_push_errors: number;
  /** Zones listed on the server via WinRM — windows_dns Path B only.
   * Empty for BIND9 and windows_dns without credentials. */
  zones_on_server: string[];
  /** Subset of zones_on_server that aren't tracked in SpatiumDDI yet. */
  new_zones_on_server: string[];
  /** Zones that were auto-imported into SpatiumDDI during this sync
   * (when the caller passed import_new_zones=true, the default). */
  zones_imported: string[];
  /** Zones on the server that were skipped because they look like a
   * Windows system zone (TrustAnchors, single-label names, …). */
  zones_skipped_system: string[];
  /** Zones that existed in SpatiumDDI but not on the Windows server
   * — pushed over WinRM during this sync. */
  zones_pushed_to_server: string[];
  /** Per-zone error strings when the DB→server zone push failed. */
  zones_push_to_server_errors: string[];
  items: DNSZoneSyncItem[];
}

export interface DNSPerServerSyncItem {
  server_id: string;
  server_name: string;
  driver: string;
  error: string | null;
  result: DNSServerSyncResult | null;
}

export interface DNSGroupSyncResult {
  servers_attempted: number;
  servers_succeeded: number;
  total_imported: number;
  total_pushed: number;
  total_push_errors: number;
  total_zones_imported: number;
  total_zones_pushed_to_server: number;
  items: DNSPerServerSyncItem[];
}

export interface DNSPerServerZoneStateEntry {
  zone_id: string;
  zone_name: string;
  zone_type: string;
  target_serial: number;
  current_serial: number | null;
  reported_at: string | null;
  in_sync: boolean;
}

export interface DNSPerServerZoneStateResponse {
  server_id: string;
  server_name: string;
  zones: DNSPerServerZoneStateEntry[];
  summary: {
    total: number;
    in_sync: number;
    drift: number;
    not_reported: number;
  };
}

export interface DNSPendingOpEntry {
  op_id: string;
  zone_name: string;
  op: string;
  state: string;
  record: Record<string, unknown>;
  target_serial: number | null;
  attempts: number;
  last_error: string | null;
  created_at: string;
  applied_at: string | null;
}

export interface DNSPendingOpsResponse {
  server_id: string;
  counts: Record<string, number>;
  items: DNSPendingOpEntry[];
}

export interface DNSServerEventEntry {
  id: string;
  timestamp: string;
  user_display_name: string;
  action: string;
  resource_type: string;
  resource_display: string;
  result: string;
}

export interface DNSServerEventsResponse {
  server_id: string;
  items: DNSServerEventEntry[];
}

// Latest agent-pushed snapshot of the on-disk rendered config tree.
// One entry per text file under the agent's rendered/ directory:
// "named.conf" + every "zones/<name>.db". `rendered_at` is null when
// the agent hasn't pushed yet (fresh server, never reloaded).
export interface DNSRenderedConfigFile {
  path: string;
  content: string;
}
export interface DNSRenderedConfigResponse {
  server_id: string;
  rendered_at: string | null;
  files: DNSRenderedConfigFile[];
}

// Latest agent-pushed `rndc status` output. Confirms the daemon is
// running + which zones are loaded without needing SSH access.
export interface DNSRndcStatusResponse {
  server_id: string;
  observed_at: string | null;
  text: string | null;
}

export interface DNSPoolMember {
  id: string;
  pool_id: string;
  address: string;
  weight: number;
  enabled: boolean;
  // Geo / topology-aware steering scope (issue #530). Empty CIDRs + null
  // site ⇒ default target served to everyone.
  serving_cidrs: string[];
  site_id: string | null;
  last_check_state: "unknown" | "healthy" | "unhealthy";
  last_check_at: string | null;
  last_check_error: string | null;
  consecutive_failures: number;
  consecutive_successes: number;
  created_at: string;
  modified_at: string;
}

export interface DNSPoolMemberWrite {
  address: string;
  weight?: number;
  enabled?: boolean;
  serving_cidrs?: string[];
  site_id?: string | null;
}

export interface DNSPool {
  id: string;
  group_id: string;
  zone_id: string;
  name: string;
  description: string;
  record_name: string;
  record_type: "A" | "AAAA";
  ttl: number;
  enabled: boolean;
  hc_type: "none" | "tcp" | "http" | "https" | "icmp";
  hc_target_port: number | null;
  hc_path: string;
  hc_method: string;
  hc_verify_tls: boolean;
  hc_expected_status_codes: number[];
  hc_interval_seconds: number;
  hc_timeout_seconds: number;
  hc_unhealthy_threshold: number;
  hc_healthy_threshold: number;
  next_check_at: string | null;
  last_checked_at: string | null;
  members: DNSPoolMember[];
  created_at: string;
  modified_at: string;
}

export interface DNSPoolListEntry {
  id: string;
  group_id: string;
  group_name: string;
  zone_id: string;
  zone_name: string;
  name: string;
  description: string;
  record_name: string;
  record_type: "A" | "AAAA";
  ttl: number;
  enabled: boolean;
  hc_type: "none" | "tcp" | "http" | "https" | "icmp";
  hc_target_port: number | null;
  hc_interval_seconds: number;
  next_check_at: string | null;
  last_checked_at: string | null;
  member_count: number;
  healthy_count: number;
  enabled_count: number;
  live_count: number;
  created_at: string;
  modified_at: string;
}

export interface DNSPoolWrite {
  name: string;
  description?: string;
  record_name: string;
  record_type?: "A" | "AAAA";
  ttl?: number;
  enabled?: boolean;
  hc_type?: "none" | "tcp" | "http" | "https" | "icmp";
  hc_target_port?: number | null;
  hc_path?: string;
  hc_method?: string;
  hc_verify_tls?: boolean;
  hc_expected_status_codes?: number[];
  hc_interval_seconds?: number;
  hc_timeout_seconds?: number;
  hc_unhealthy_threshold?: number;
  hc_healthy_threshold?: number;
  members?: DNSPoolMemberWrite[];
}

/**
 * Last config-apply verdict an agent reported (#882).
 *
 * `null` means the agent has never reported one — a pre-#882 agent, or an
 * agentless driver (Windows DNS, the cloud DNS providers, `technitium_api`)
 * that has no apply loop at all. Render that as unknown, never as healthy.
 */
export type ConfigApplyStatus =
  | "ok"
  /** The saved config failed; the agent rolled back and is serving the previous one. */
  | "reverted"
  /** The saved config failed AND the rollback failed. Running state unknown. */
  | "revert_failed"
  /** Failed with no previously-working config to fall back to. */
  | "no_previous";

/** One stream of an agent's durable push spool (#1077). */
export interface AgentSpoolStreamStatus {
  enabled: boolean;
  entries: number;
  bytes: number;
  cap_bytes: number;
  oldest_at: string | null;
  trimmed_entries_total: number;
  trimmed_bytes_total: number;
  last_trim_at: string | null;
  expired_entries_total: number;
  rejected_entries_total: number;
  write_failures_total: number;
}

/**
 * An agent's durable push spool as last reported on its heartbeat (#1077):
 * pushes the control plane has not acknowledged yet, queued on the agent's
 * disk and replayed in order on reconnect. The `*_total` counters are
 * cumulative across agent restarts.
 *
 * `null` on the server row means the agent has never reported one — a
 * pre-#1077 agent or an agentless driver. That is unknown, not "empty".
 */
export interface AgentSpoolStatus {
  enabled: boolean;
  cap_bytes: number;
  bytes: number;
  entries: number;
  oldest_at: string | null;
  trimmed_entries_total: number;
  trimmed_bytes_total: number;
  last_trim_at: string | null;
  expired_entries_total: number;
  streams: Record<string, AgentSpoolStreamStatus>;
}

/** Config-apply fields shared by DNS servers, DHCP servers and LG collectors. */
export interface ConfigApplyFields {
  config_apply_status: ConfigApplyStatus | null;
  config_apply_error: string | null;
  config_failed_etag: string | null;
  config_apply_at: string | null;
}

/**
 * Daemon state an agent reported on its heartbeat (#1067), shared by DNS and
 * DHCP servers.
 *
 * `daemon_status` is the agent's own word: `ok` while the daemon is up,
 * `degraded` otherwise — a DNS agent waiting for its first bundle, a Kea
 * whose control socket is unreachable, or either agent echoing a failed
 * config apply (#882). `null` means the agent has never reported one — a
 * pre-#1061 agent, or an agentless driver — and renders as unknown, never as
 * healthy. `daemon_status_since` is when the CURRENT state began; a repeated
 * report never moves it.
 *
 * `daemon_not_serving` is the server's one reading of the three, and the
 * field to render from: `true` when the daemon is not serving; `false` on
 * `ok`, or when the `degraded` is a config-apply echo (the config-apply chip
 * already shows that, at #882's severity, and a reverted daemon IS serving);
 * `null` when never reported. Re-deriving "not serving" from `daemon_status`
 * is what put a red chip on every routine revert while the alert, which
 * reads the same classification as this field, stayed quiet.
 */
export interface DaemonStateFields {
  daemon_status: string | null;
  daemon_reason: string | null;
  daemon_status_since: string | null;
  daemon_not_serving: boolean | null;
}

export interface DNSServer {
  id: string;
  group_id: string;
  name: string;
  driver: string;
  host: string;
  port: number;
  api_port: number | null;
  roles: string[];
  status: string;
  /** User-controlled pause. When false, health sweeps, the bi-directional
   * sync job, and record-op writes all skip this server. Separate from
   * ``status`` which is automatically set by the health probe. */
  is_enabled: boolean;
  last_sync_at: string | null;
  last_health_check_at: string | null;
  notes: string;
  /** True when stored Fernet-encrypted WinRM credentials exist. Used by
   * the UI to show "Credentials set" / "Clear" and gate the Path B
   * affordances without exposing the password. */
  has_credentials: boolean;
  /** True when the driver runs from the control plane (no agent). Used
   * by the UI to hide approval / agent-registration affordances. */
  is_agentless: boolean;
  /** Agent-state fields surfaced for the Server Detail modal. */
  agent_id: string | null;
  last_seen_at: string | null;
  /** Source IP of the most recent agent heartbeat — operator-visible
   *  to identify which host an agent is on (the operator-set ``host``
   *  is just a label; doesn't reflect NAT / distributed deployments). */
  last_seen_ip: string | null;
  config_apply_status: ConfigApplyStatus | null;
  config_apply_error: string | null;
  config_failed_etag: string | null;
  config_apply_at: string | null;
  /** #1077 — push spool as last reported; `null` = never reported. */
  spool_status: AgentSpoolStatus | null;
  daemon_status: string | null;
  daemon_reason: string | null;
  daemon_status_since: string | null;
  /** #1067 — derived; render from this, see `DaemonStateFields`. */
  daemon_not_serving: boolean | null;
  last_config_etag: string | null;
  pending_approval: boolean;
  is_primary: boolean;
  /** Per-server maintenance mode (issue #182). When true the control
   * plane skips shipping pending DNSRecordOp rows + suppresses the
   * heartbeat-stale alert; the UI renders an amber Maintenance chip. */
  maintenance_mode: boolean;
  maintenance_started_at: string | null;
  maintenance_reason: string | null;
  created_at: string;
  modified_at: string;
}

export interface DNSServerOptions {
  id: string;
  group_id: string;
  forwarders: string[];
  forward_policy: string;
  recursion_enabled: boolean;
  allow_recursion: string[];
  dnssec_validation: string;
  gss_tsig_enabled: boolean;
  gss_tsig_keytab_path: string | null;
  gss_tsig_realm: string | null;
  gss_tsig_principal: string | null;
  notify_enabled: string;
  also_notify: string[];
  allow_notify: string[];
  allow_query: string[];
  allow_query_cache: string[];
  allow_transfer: string[];
  blackhole: string[];
  query_log_enabled: boolean;
  /** Per-query RCODE logging (#914). BIND9 only; requires query_log_enabled. */
  response_log_enabled: boolean;
  query_log_channel: string;
  query_log_file: string;
  query_log_severity: string;
  query_log_print_category: boolean;
  query_log_print_severity: boolean;
  query_log_print_time: boolean;
  // Response Rate Limiting + amplification defenses (issue #146)
  rrl_enabled: boolean;
  rrl_responses_per_second: number;
  rrl_window: number;
  rrl_slip: number;
  rrl_qps_scale: number | null;
  rrl_exempt_clients: string[];
  rrl_log_only: boolean;
  minimal_responses: boolean;
  tcp_clients: number | null;
  clients_per_query: number | null;
  max_clients_per_query: number | null;
  // dnsdist front for PowerDNS (issue #146 Phase 2)
  dnsdist_enabled: boolean;
  dnsdist_max_qps_per_client: number | null;
  dnsdist_action: string;
  dnsdist_dynblock_qps: number | null;
  dnsdist_dynblock_seconds: number;
  // Encrypted transports (issue #50, extended by #741). Inbound listeners
  // are additive — plain Do53 on :53 is unaffected.
  //
  // forward_transport is "do53" | "tls" | "https" | "quic". BIND has no
  // client-side HTTP or QUIC transport, so the API gates https/quic (and
  // DoQ) to Technitium-only groups and 422s otherwise.
  dot_enabled: boolean;
  dot_port: number;
  doh_enabled: boolean;
  doh_port: number;
  // Technitium serves DoH on a fixed /dns-query and ignores this.
  doh_path: string;
  // DNS-over-QUIC (#741) — Technitium only. UDP, so doq_port may share a
  // number with dot_port without colliding.
  doq_enabled: boolean;
  doq_port: number;
  tls_certificate_id: string | null;
  forward_transport: string;
  forward_tls_hostname: string | null;
  forward_tls_verify: boolean;
  trust_anchors: DNSTrustAnchor[];
  modified_at: string;
}

/** A curated public upstream resolver (issue #877). ``tls_hostname`` is the
 *  name the provider's certificate presents — with DoT verification on, a
 *  mismatch fails closed, so the address set and the hostname travel
 *  together rather than being typed independently. */
export interface ResolverPreset {
  id: string;
  name: string;
  provider: string;
  description: string;
  ipv4: string[];
  ipv6: string[];
  tls_hostname: string;
  /** What the upstream filters by default, for an honest picker label. */
  filtering: string;
  /** How a blocked name is answered: none | nxdomain | refused |
   *  forged_address. A forged address for a signed name is bogus data, so
   *  a DNSSEC-validating resolver downstream turns the block into
   *  SERVFAIL — worth warning about. */
  blocking_method: string;
  /** True for upstreams that refuse plaintext 53 (Mullvad). */
  requires_encrypted: boolean;
  homepage: string;
  notes: string | null;
}

export interface ResolverPresetCatalog {
  version: string;
  presets: ResolverPreset[];
}

export interface DNSTrustAnchor {
  id: string;
  zone_name: string;
  algorithm: number;
  key_tag: number;
  public_key: string;
  is_initial_key: boolean;
  added_at: string;
}

export interface DNSAclEntry {
  id: string;
  value: string;
  negate: boolean;
  order: number;
}

export interface DNSAcl {
  id: string;
  group_id: string | null;
  name: string;
  description: string;
  entries: DNSAclEntry[];
  created_at: string;
  modified_at: string;
}

export interface DNSView {
  id: string;
  group_id: string;
  name: string;
  description: string;
  match_clients: string[];
  match_destinations: string[];
  recursion: boolean;
  order: number;
  allow_query: string[] | null;
  allow_query_cache: string[] | null;
  created_at: string;
  modified_at: string;
}

/**
 * TLD scope of a zone name (#986). Derived server-side at serialisation
 * from the IANA root-zone list — never stored, so it can change under a
 * zone when the operator refreshes the TLD registry.
 */
export type ZoneNameScope = "public" | "reserved" | "undelegated" | "reverse";

export interface ZoneNameScopeDetail {
  scope: ZoneNameScope;
  /** One line explaining the classification, shown as the pill tooltip. */
  reason: string;
  /** The special-use entry or TLD the decision rests on. */
  matched_suffix: string | null;
  /** RFC or ICANN action that reserved the suffix, when there is one. */
  rfc: string | null;
  /** `.local` only — an authoritative zone here collides with mDNS. */
  mdns_conflict: boolean;
}

export interface TldRegistryInfo {
  origin: "bundled" | "snapshot";
  version: string;
  fetched_at: string | null;
  source: string;
  count: number;
  age_days: number | null;
  stale: boolean;
  bundled_version: string;
  bundled_count: number;
  snapshot_version: string | null;
  snapshot_fetched_at: string | null;
  snapshot_count: number | null;
}

export interface DNSZone {
  id: string;
  group_id: string;
  view_id: string | null;
  name: string;
  zone_type: string;
  kind: string;
  ttl: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
  primary_ns: string;
  admin_email: string;
  is_auto_generated: boolean;
  linked_subnet_id: string | null;
  domain_id?: string | null;
  dnssec_enabled: boolean;
  auto_tls_probe?: boolean;
  dnssec_policy_id?: string | null;
  // Dynamic-update (RFC 2136) ACL toggle (issue #641). ACL rows are
  // managed via getZoneUpdateAcl / replaceZoneUpdateAcl.
  dynamic_update_enabled?: boolean;
  dnssec_ds_records: string[] | null;
  dnssec_synced_at: string | null;
  color: string | null;
  last_serial: number;
  last_pushed_at: string | null;
  allow_query: string[] | null;
  allow_transfer: string[] | null;
  also_notify: string[] | null;
  notify_enabled: string | null;
  // Conditional-forwarder config. Meaningful only when zone_type==="forward".
  forwarders: string[];
  forward_only: boolean;
  // Secondary / stub primaries (issue #336). The master server IPs this
  // zone transfers FROM (ip or ip@port). Required when
  // zone_type==="secondary" | "stub"; empty otherwise.
  masters: string[];
  // Non-null when the zone was synthesised by the Tailscale Phase 2
  // reconciler. The UI shows a read-only badge and disables edit /
  // delete controls on the zone + its records.
  tailscale_tenant_id: string | null;
  // Logical ownership (issue #91). NULL = unassigned.
  customer_id: string | null;
  // #986 — TLD scope of the zone name. Optional in the type because the
  // importer preview and a few older cached payloads carry the bare zone
  // shape; every live read from /dns/groups/{id}/zones sets both.
  name_scope?: ZoneNameScope;
  name_scope_detail?: ZoneNameScopeDetail | null;
  created_at: string;
  modified_at: string;
}

// ── Zone server-state (per-server serial reporting) ──────────────────────────

export interface ZoneServerStateEntry {
  server_id: string;
  server_name: string;
  server_status: string;
  // `null` means the agent hasn't reported back yet (freshly-registered
  // server, or the zone was only just created).
  current_serial: number | null;
  reported_at: string | null;
}

export interface ZoneServerState {
  zone_id: string;
  zone_name: string;
  target_serial: number;
  servers: ZoneServerStateEntry[];
  // `false` while any server hasn't reported or is on a different serial.
  in_sync: boolean;
}

// ── Zone config drift (#61) ──────────────────────────────────────────────────
//
// Record-level diff between the DB (source of truth) and what each server in
// the group is actually serving, obtained by AXFR / driver pull. Strictly
// read-only — the report never applies anything. Distinct from
// `ZoneServerState` above, which compares SOA *serials* only: a server can sit
// on the right serial and still be serving the wrong records if someone edited
// the host by hand.

export interface ZoneDriftRecord {
  name: string;
  record_type: string;
  value: string;
  ttl: number | null;
}

export interface ZoneDriftServer {
  server_id: string;
  server_name: string;
  driver: string;
  // "ok" — pulled and diffed. "error" — the pull failed (unreachable, paused,
  // AXFR refused); counts are meaningless. "unsupported" — the driver has no
  // `pull_zone_records`, so drift can't be computed for it at all.
  status: "ok" | "error" | "unsupported";
  error: string | null;
  in_sync: number;
  // `extra_on_server.length + missing_on_server.length` — the backend derives
  // it, so don't recompute it in the UI.
  drift_count: number;
  // Served by the host but absent from the DB — typically a manual on-host edit.
  extra_on_server: ZoneDriftRecord[];
  // In the DB but not being served — the change never reached this host.
  missing_on_server: ZoneDriftRecord[];
}

export interface ZoneDrift {
  zone_id: string;
  zone_name: string;
  db_record_count: number;
  servers: ZoneDriftServer[];
  // Caveats that make the diff less trustworthy — chiefly split-horizon
  // views, where an AXFR is answered by whichever view matches the control
  // plane's source address rather than the one this zone row belongs to.
  warnings: string[];
}

// Pending records the delegation wizard would land in the parent zone.
// `existing_*` lists are already-present rows the wizard would skip on apply.
export interface DelegationRecord {
  name: string;
  record_type: string;
  value: string;
  ttl: number | null;
}

export interface DelegationPreview {
  has_parent: true;
  parent_zone_id: string;
  parent_zone_name: string;
  child_zone_id: string;
  child_zone_name: string;
  child_label: string;
  ns_records_to_create: DelegationRecord[];
  glue_records_to_create: DelegationRecord[];
  existing_ns_records: DelegationRecord[];
  existing_glue_records: DelegationRecord[];
  warnings: string[];
  child_apex_ns_count: number;
}

export type DelegationPreviewResponse =
  | { has_parent: false }
  | DelegationPreview;

// Zone-template wizard catalog. Templates carry a parameter manifest
// the UI renders into a form; submission returns a fully-built zone.
export interface ZoneTemplateParameter {
  key: string;
  label: string;
  type: string;
  required: boolean;
  default: string | null;
  placeholder: string | null;
  hint: string | null;
}

export interface ZoneTemplate {
  id: string;
  name: string;
  category: string;
  description: string;
  parameters: ZoneTemplateParameter[];
  record_count: number;
}

export interface ZoneTemplateCatalog {
  templates: ZoneTemplate[];
}

export interface FromTemplateRequest {
  template_id: string;
  zone_name: string;
  params: Record<string, string>;
  view_id?: string | null;
  zone_type?: string;
  kind?: string;
}

// Operator-managed named TSIG keys for RFC 2136 / AXFR auth. Distinct
// from the legacy single key auto-generated on DNSServerGroup which is
// reserved for the agent's own loopback updates.
export interface DNSTSIGKey {
  id: string;
  group_id: string;
  name: string;
  algorithm: string;
  purpose: string | null;
  notes: string;
  last_rotated_at: string | null;
  created_at: string;
  modified_at: string;
  // Plaintext secret. Populated on the create / rotate responses *only*.
  // Read endpoints (list / get) leave this null.
  secret: string | null;
}

export interface TSIGKeyCreate {
  name: string;
  algorithm?: string;
  secret?: string | null;
  purpose?: string | null;
  notes?: string;
}

export interface TSIGKeyUpdate {
  name?: string;
  algorithm?: string;
  purpose?: string | null;
  notes?: string;
}

// ── Dynamic-update (RFC 2136) ACLs (issue #641) ──────────────────────────────

export interface DynamicUpdateCaps {
  supports_ip_acl: boolean;
  supports_tsig_acl: boolean;
  supports_name_scoping: boolean;
  supports_per_type: boolean;
  coarse_enum_only: boolean;
  // false ⇒ the group's driver has no RFC 2136 surface; the feature 422s.
  supported: boolean;
}

export interface UpdateAclEntry {
  id: string;
  seq: number;
  action: "grant" | "deny";
  match_kind: "tsig_key" | "ip";
  ip_cidr: string | null;
  tsig_key_id: string | null;
  tsig_key_name: string | null;
  name_scope: string | null;
  name_pattern: string | null;
  record_types: string[] | null;
}

export interface UpdateAclEntryInput {
  match_kind: "tsig_key" | "ip";
  action?: "grant" | "deny";
  ip_cidr?: string | null;
  tsig_key_id?: string | null;
  name_scope?: string | null;
  name_pattern?: string | null;
  record_types?: string[] | null;
}

export interface ZoneUpdateAcl {
  zone_id: string;
  dynamic_update_enabled: boolean;
  driver_names: string[];
  caps: DynamicUpdateCaps;
  entries: UpdateAclEntry[];
  warnings: string[];
}

export interface ZoneUpdateAclReplace {
  dynamic_update_enabled?: boolean | null;
  entries: UpdateAclEntryInput[];
}

// Generic server-side pagination envelope (#455). Matches the backend
// `app.api.pagination.Page[T]` shape; adopted by list endpoints that can grow
// unbounded (DNS records, DHCP leases, …) so the UI pages instead of pulling
// the whole table.
export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface DNSRecord {
  id: string;
  zone_id: string;
  view_id: string | null;
  name: string;
  fqdn: string;
  record_type: string;
  value: string;
  ttl: number | null;
  priority: number | null;
  weight: number | null;
  port: number | null;
  auto_generated: boolean;
  // Non-null when the record was synthesised by Tailscale Phase 2.
  tailscale_tenant_id: string | null;
  // Non-null when the record is rendered by the DNS pool health-check
  // pipeline. Operator edits / deletes are blocked while non-null.
  pool_member_id: string | null;
  created_at: string;
  modified_at: string;
}

export interface DNSGroupRecord {
  id: string;
  zone_id: string;
  zone_name: string;
  view_id: string | null;
  view_name: string | null;
  name: string;
  fqdn: string;
  // Synthesised by Tailscale Phase 2 → write paths blocked.
  tailscale_tenant_id?: string | null;
  // Managed by a DNS pool → write paths blocked.
  pool_member_id?: string | null;
  record_type: string;
  value: string;
  ttl: number | null;
  priority: number | null;
  weight: number | null;
  port: number | null;
  auto_generated: boolean;
  created_at: string;
  modified_at: string;
}

export interface ResolverInfo {
  name: string;
  address: string;
}

export interface PropagationResolverResult {
  resolver: string;
  name: string | null;
  status: "ok" | "nxdomain" | "timeout" | "error";
  rtt_ms: number | null;
  answers: string[];
  error: string | null;
}

export interface PropagationCheckResult {
  name: string;
  record_type: string;
  queried_at_ms: number;
  results: PropagationResolverResult[];
}

/** One DNSSEC key's public state (issue #49). No private material. */
export interface DNSKeyState {
  key_tag: number;
  key_type: "ksk" | "zsk" | "csk";
  algorithm: number;
  state: string;
  ds_records: string[];
  timing?: Record<string, string>;
  reported_at?: string | null;
}

/** Zone DNSSEC posture for the zone-edit DNSSEC card. */
export interface ZoneDnssecInfo {
  zone_id: string;
  zone_name: string;
  dnssec_enabled: boolean;
  dnssec_policy_id: string | null;
  dnssec_ds_records: string[];
  dnssec_synced_at: string | null;
  keys: DNSKeyState[];
}

/** A reusable BIND9 dnssec-policy definition (issue #49). */
export interface DNSSECPolicy {
  id: string;
  name: string;
  description: string;
  is_builtin: boolean;
  algorithm: string;
  ksk_lifetime_days: number;
  zsk_lifetime_days: number;
  nsec3: boolean;
  nsec3_iterations: number;
  nsec3_salt_length: number;
  nsec3_optout: boolean;
  created_at: string;
  modified_at: string;
}

export const dnsApi = {
  // Server groups
  listGroups: () =>
    api.get<DNSServerGroup[]>("/dns/groups").then((r) => r.data),
  // Multi-resolver propagation check
  checkPropagation: (body: {
    name: string;
    record_type?: string;
    resolvers?: string[];
    timeout_seconds?: number;
  }) =>
    api
      .post<PropagationCheckResult>(`/dns/tools/propagation-check`, body)
      .then((r) => r.data),
  defaultResolvers: () =>
    api.get<ResolverInfo[]>(`/dns/tools/default-resolvers`).then((r) => r.data),
  createGroup: (data: Partial<DNSServerGroup>) =>
    api.post<DNSServerGroup>("/dns/groups", data).then((r) => r.data),
  updateGroup: (id: string, data: Partial<DNSServerGroup>) =>
    api.put<DNSServerGroup>(`/dns/groups/${id}`, data).then((r) => r.data),
  // #62: returns the full axios response (may be 202 queued-for-approval —
  // see ipamApi.deleteSpace). Do NOT add ``.then((r) => r.data)`` or the
  // 202 envelope is lost; callers pass it to ``handleApprovalQueued``.
  deleteGroup: (id: string) => api.delete(`/dns/groups/${id}`),

  // Servers
  listServers: (groupId: string) =>
    api.get<DNSServer[]>(`/dns/groups/${groupId}/servers`).then((r) => r.data),
  createServer: (
    groupId: string,
    data: Partial<DNSServer> & {
      api_key?: string;
      windows_credentials?: WindowsDNSCredentials | Record<string, never>;
      // Credentialed agentless driver credentials — the cloud providers
      // (issue #37) and self-hosted technitium_api (issue #810).
      // Driver-specific dict (e.g. {api_token} for cloudflare,
      // {api_url, api_token, verify_tls} for technitium_api);
      // Fernet-encrypted server-side. Booleans are allowed because
      // verify_tls is a real boolean, not the string "false".
      cloud_credentials?: Record<string, string | boolean>;
    },
  ) =>
    api
      .post<DNSServer>(`/dns/groups/${groupId}/servers`, data)
      .then((r) => r.data),
  updateServer: (
    groupId: string,
    serverId: string,
    data: Partial<DNSServer> & {
      api_key?: string;
      windows_credentials?:
        | Partial<WindowsDNSCredentials>
        | Record<string, never>;
      // None = leave alone, {} = clear, dict = replace.
      cloud_credentials?:
        | Record<string, string | boolean>
        | Record<string, never>;
    },
  ) =>
    api
      .put<DNSServer>(`/dns/groups/${groupId}/servers/${serverId}`, data)
      .then((r) => r.data),
  // #935 — move a zone to another server group. Preview is a pure read
  // and safe to call repeatedly; commit demands the typed zone name plus
  // an acknowledgement for each consequence the preview flagged.
  previewZoneMove: (groupId: string, zoneId: string, targetGroupId: string) =>
    api
      .post<ZoneMovePreview>(
        `/dns/groups/${groupId}/zones/${zoneId}/move/preview`,
        { target_group_id: targetGroupId },
      )
      .then((r) => r.data),
  commitZoneMove: (
    groupId: string,
    zoneId: string,
    body: {
      target_group_id: string;
      confirmation_zone_name: string;
      acknowledgements: string[];
    },
  ) =>
    api
      .post<ZoneMovePreview>(
        `/dns/groups/${groupId}/zones/${zoneId}/move/commit`,
        body,
      )
      .then((r) => r.data),

  deleteServer: (groupId: string, serverId: string) =>
    api.delete(`/dns/groups/${groupId}/servers/${serverId}`),
  // Issue #182: per-server maintenance mode.
  pauseServer: (groupId: string, serverId: string, reason?: string) =>
    api
      .post<DNSServer>(`/dns/groups/${groupId}/servers/${serverId}/pause`, {
        reason: reason ?? null,
      })
      .then((r) => r.data),
  resumeServer: (groupId: string, serverId: string) =>
    api
      .post<DNSServer>(`/dns/groups/${groupId}/servers/${serverId}/resume`)
      .then((r) => r.data),

  testWindowsCredentials: (body: {
    host: string;
    credentials?: Partial<WindowsDNSCredentials>;
    server_id?: string;
  }) =>
    api
      .post<{
        ok: boolean;
        message: string;
      }>("/dns/test-windows-credentials", body)
      .then((r) => r.data),

  // Probe a saved credentialed agentless server (cloud providers +
  // technitium_api, issue #810) with its STORED credentials. Post-save only —
  // there is no plaintext-credential mode, unlike the Windows endpoint.
  testServerConnection: (groupId: string, serverId: string) =>
    api
      .post<{
        ok: boolean;
        message: string;
      }>(`/dns/groups/${groupId}/servers/${serverId}/test-connection`)
      .then((r) => r.data),

  pullZonesFromServer: (groupId: string, serverId: string) =>
    api
      .post<{
        zones: Array<Record<string, unknown>>;
      }>(`/dns/groups/${groupId}/servers/${serverId}/pull-zones-from-server`)
      .then((r) => r.data),

  syncFromServer: (groupId: string, serverId: string) =>
    api
      .post<DNSServerSyncResult>(
        `/dns/groups/${groupId}/servers/${serverId}/sync-from-server`,
      )
      .then((r) => r.data),

  // Per-server detail (powers the Server Detail modal)
  getServerZoneState: (serverId: string) =>
    api
      .get<DNSPerServerZoneStateResponse>(`/dns/servers/${serverId}/zone-state`)
      .then((r) => r.data),
  getServerPendingOps: (serverId: string, limit = 50) =>
    api
      .get<DNSPendingOpsResponse>(
        `/dns/servers/${serverId}/pending-ops?limit=${limit}`,
      )
      .then((r) => r.data),
  getServerRecentEvents: (serverId: string, limit = 50) =>
    api
      .get<DNSServerEventsResponse>(
        `/dns/servers/${serverId}/recent-events?limit=${limit}`,
      )
      .then((r) => r.data),
  getServerRenderedConfig: (serverId: string) =>
    api
      .get<DNSRenderedConfigResponse>(
        `/dns/servers/${serverId}/rendered-config`,
      )
      .then((r) => r.data),
  getServerRndcStatus: (serverId: string) =>
    api
      .get<DNSRndcStatusResponse>(`/dns/servers/${serverId}/rndc-status`)
      .then((r) => r.data),

  // DNS pools (GSLB-lite)
  listAllPools: (groupId?: string) =>
    api
      .get<DNSPoolListEntry[]>(`/dns/pools`, {
        params: groupId ? { group_id: groupId } : undefined,
      })
      .then((r) => r.data),
  listPools: (groupId: string, zoneId: string) =>
    api
      .get<DNSPool[]>(`/dns/groups/${groupId}/zones/${zoneId}/pools`)
      .then((r) => r.data),
  createPool: (groupId: string, zoneId: string, data: DNSPoolWrite) =>
    api
      .post<DNSPool>(`/dns/groups/${groupId}/zones/${zoneId}/pools`, data)
      .then((r) => r.data),
  getPool: (poolId: string) =>
    api.get<DNSPool>(`/dns/pools/${poolId}`).then((r) => r.data),
  updatePool: (poolId: string, data: Partial<DNSPoolWrite>) =>
    api.put<DNSPool>(`/dns/pools/${poolId}`, data).then((r) => r.data),
  deletePool: (poolId: string) => api.delete(`/dns/pools/${poolId}`),
  checkPoolNow: (poolId: string) =>
    api.post<DNSPool>(`/dns/pools/${poolId}/check-now`).then((r) => r.data),
  addPoolMember: (poolId: string, data: DNSPoolMemberWrite) =>
    api
      .post<DNSPoolMember>(`/dns/pools/${poolId}/members`, data)
      .then((r) => r.data),
  updatePoolMember: (
    memberId: string,
    data: {
      address?: string;
      weight?: number;
      enabled?: boolean;
      // Geo / topology-aware steering scope (issue #530). `[]` clears
      // the CIDR list; `null` clears the Site link.
      serving_cidrs?: string[];
      site_id?: string | null;
    },
  ) =>
    api
      .put<DNSPoolMember>(`/dns/pool-members/${memberId}`, data)
      .then((r) => r.data),
  deletePoolMember: (memberId: string) =>
    api.delete(`/dns/pool-members/${memberId}`),

  syncGroupWithServers: (groupId: string) =>
    api
      .post<DNSGroupSyncResult>(`/dns/groups/${groupId}/sync-with-servers`)
      .then((r) => r.data),

  // Server options
  getOptions: (groupId: string) =>
    api
      .get<DNSServerOptions>(`/dns/groups/${groupId}/options`)
      .then((r) => r.data),
  updateOptions: (groupId: string, data: Partial<DNSServerOptions>) =>
    api
      .put<DNSServerOptions>(`/dns/groups/${groupId}/options`, data)
      .then((r) => r.data),
  /** Issue #877 — curated public upstream resolvers, each carrying the DoT
   *  hostname its certificate presents. Served from the backend so the
   *  picker and the server-side conflict check read one table. */
  forwarderPresets: () =>
    api
      .get<ResolverPresetCatalog>("/dns/forwarder-presets")
      .then((r) => r.data),
  addTrustAnchor: (
    groupId: string,
    data: Omit<DNSTrustAnchor, "id" | "added_at">,
  ) =>
    api
      .post<DNSTrustAnchor>(
        `/dns/groups/${groupId}/options/trust-anchors`,
        data,
      )
      .then((r) => r.data),
  deleteTrustAnchor: (groupId: string, anchorId: string) =>
    api.delete(`/dns/groups/${groupId}/options/trust-anchors/${anchorId}`),

  // ACLs
  listAcls: (groupId: string) =>
    api.get<DNSAcl[]>(`/dns/groups/${groupId}/acls`).then((r) => r.data),
  createAcl: (groupId: string, data: Partial<DNSAcl>) =>
    api.post<DNSAcl>(`/dns/groups/${groupId}/acls`, data).then((r) => r.data),
  updateAcl: (groupId: string, aclId: string, data: Partial<DNSAcl>) =>
    api
      .put<DNSAcl>(`/dns/groups/${groupId}/acls/${aclId}`, data)
      .then((r) => r.data),
  deleteAcl: (groupId: string, aclId: string) =>
    api.delete(`/dns/groups/${groupId}/acls/${aclId}`),

  // Views
  listViews: (groupId: string) =>
    api.get<DNSView[]>(`/dns/groups/${groupId}/views`).then((r) => r.data),
  createView: (groupId: string, data: Partial<DNSView>) =>
    api.post<DNSView>(`/dns/groups/${groupId}/views`, data).then((r) => r.data),
  updateView: (groupId: string, viewId: string, data: Partial<DNSView>) =>
    api
      .put<DNSView>(`/dns/groups/${groupId}/views/${viewId}`, data)
      .then((r) => r.data),
  deleteView: (groupId: string, viewId: string) =>
    api.delete(`/dns/groups/${groupId}/views/${viewId}`),

  // TLD registry (#986) — the IANA root-zone list behind zone name_scope.
  // Read by anyone who can read DNS; refresh is superadmin-only and is the
  // only outbound call in this router (see docs/PRIVACY.md §3.2).
  getTldRegistry: () =>
    api.get<TldRegistryInfo>("/dns/tld-registry").then((r) => r.data),
  refreshTldRegistry: () =>
    api.post<TldRegistryInfo>("/dns/tld-registry/refresh").then((r) => r.data),
  /**
   * Classify a candidate zone name (live hint in the create / edit modal).
   * Server-side on purpose — a TypeScript copy of the rules would drift
   * from the one that decides the pill in the table.
   */
  classifyZoneName: (name: string) =>
    api
      .get<ZoneNameScopeDetail>("/dns/tld-registry/classify", {
        params: { name },
      })
      .then((r) => r.data),

  // Zones
  listZones: (groupId: string, params?: { tag?: string[] }) =>
    api
      .get<DNSZone[]>(`/dns/groups/${groupId}/zones`, { params })
      .then((r) => r.data),
  createZone: (groupId: string, data: Partial<DNSZone>) =>
    api.post<DNSZone>(`/dns/groups/${groupId}/zones`, data).then((r) => r.data),
  updateZone: (groupId: string, zoneId: string, data: Partial<DNSZone>) =>
    api
      .put<DNSZone>(`/dns/groups/${groupId}/zones/${zoneId}`, data)
      .then((r) => r.data),
  // #62: returns the full axios response (may be 202 queued-for-approval —
  // see ipamApi.deleteSpace). Do NOT add ``.then((r) => r.data)``.
  deleteZone: (groupId: string, zoneId: string) =>
    api.delete(`/dns/groups/${groupId}/zones/${zoneId}`),
  getZoneServerState: (groupId: string, zoneId: string) =>
    api
      .get<ZoneServerState>(
        `/dns/groups/${groupId}/zones/${zoneId}/server-state`,
      )
      .then((r) => r.data),
  // #61 — AXFRs every server in the group and diffs it against the DB.
  // One request fans out to every host, so this is slow and deliberately
  // NOT auto-fetched; the Drift tab loads it on demand.
  getZoneDrift: (groupId: string, zoneId: string) =>
    api
      .get<ZoneDrift>(`/dns/groups/${groupId}/zones/${zoneId}/drift`)
      .then((r) => r.data),

  // DNSSEC — PowerDNS online signing (#127) + BIND9 inline-signing (#49)
  // (types declared above `dnsApi`; see DNSKeyState / ZoneDnssecInfo / DNSSECPolicy)
  getZoneDnssecInfo: (groupId: string, zoneId: string) =>
    api
      .get<ZoneDnssecInfo>(`/dns/groups/${groupId}/zones/${zoneId}/dnssec/info`)
      .then((r) => r.data),
  // policyId undefined ⇒ omit (backend leaves the zone's policy unchanged);
  // null ⇒ reset to built-in default; a UUID ⇒ set that policy.
  signZoneDnssec: (groupId: string, zoneId: string, policyId?: string | null) =>
    api
      .post<DNSZone>(
        `/dns/groups/${groupId}/zones/${zoneId}/dnssec/sign`,
        policyId === undefined ? {} : { policy_id: policyId },
      )
      .then((r) => r.data),
  unsignZoneDnssec: (groupId: string, zoneId: string) =>
    api
      .post<DNSZone>(`/dns/groups/${groupId}/zones/${zoneId}/dnssec/unsign`)
      .then((r) => r.data),
  rolloverZoneDnssecKey: (groupId: string, zoneId: string, keyTag: number) =>
    api
      .post<{
        status: string;
        zone_id: string;
        key_tag: number;
      }>(`/dns/groups/${groupId}/zones/${zoneId}/dnssec/rollover`, {
        key_tag: keyTag,
      })
      .then((r) => r.data),
  // DNSSEC policies (issue #49)
  listDnssecPolicies: () =>
    api.get<DNSSECPolicy[]>("/dns/dnssec-policies").then((r) => r.data),
  createDnssecPolicy: (data: Partial<DNSSECPolicy>) =>
    api.post<DNSSECPolicy>("/dns/dnssec-policies", data).then((r) => r.data),
  updateDnssecPolicy: (id: string, data: Partial<DNSSECPolicy>) =>
    api
      .put<DNSSECPolicy>(`/dns/dnssec-policies/${id}`, data)
      .then((r) => r.data),
  deleteDnssecPolicy: (id: string) => api.delete(`/dns/dnssec-policies/${id}`),

  // Delegation wizard
  getDelegationPreview: (groupId: string, zoneId: string) =>
    api
      .get<DelegationPreviewResponse>(
        `/dns/groups/${groupId}/zones/${zoneId}/delegation-preview`,
      )
      .then((r) => r.data),
  applyDelegation: (groupId: string, zoneId: string) =>
    api
      .post<
        DNSRecord[]
      >(`/dns/groups/${groupId}/zones/${zoneId}/delegate-from-parent`)
      .then((r) => r.data),

  // Zone templates (starter zones with parameterised records)
  listZoneTemplates: () =>
    api.get<ZoneTemplateCatalog>(`/dns/zone-templates`).then((r) => r.data),
  createZoneFromTemplate: (groupId: string, body: FromTemplateRequest) =>
    api
      .post<DNSZone>(`/dns/groups/${groupId}/zones/from-template`, body)
      .then((r) => r.data),

  // TSIG keys (operator-managed named keys for RFC 2136 / AXFR auth)
  listTSIGKeys: (groupId: string) =>
    api
      .get<DNSTSIGKey[]>(`/dns/groups/${groupId}/tsig-keys`)
      .then((r) => r.data),
  createTSIGKey: (groupId: string, body: TSIGKeyCreate) =>
    api
      .post<DNSTSIGKey>(`/dns/groups/${groupId}/tsig-keys`, body)
      .then((r) => r.data),
  updateTSIGKey: (groupId: string, keyId: string, body: TSIGKeyUpdate) =>
    api
      .put<DNSTSIGKey>(`/dns/groups/${groupId}/tsig-keys/${keyId}`, body)
      .then((r) => r.data),
  rotateTSIGKey: (groupId: string, keyId: string) =>
    api
      .post<DNSTSIGKey>(`/dns/groups/${groupId}/tsig-keys/${keyId}/rotate`)
      .then((r) => r.data),
  deleteTSIGKey: (groupId: string, keyId: string) =>
    api.delete(`/dns/groups/${groupId}/tsig-keys/${keyId}`),
  generateTSIGSecret: (groupId: string, algorithm: string) =>
    api
      .get<{
        algorithm: string;
        secret: string;
      }>(`/dns/groups/${groupId}/tsig-keys/generate-secret`, {
        params: { algorithm },
      })
      .then((r) => r.data),

  // Dynamic-update (RFC 2136) ACLs (issue #641)
  getGroupDynamicUpdateCaps: (groupId: string) =>
    api
      .get<DynamicUpdateCaps>(`/dns/groups/${groupId}/dynamic-update-caps`)
      .then((r) => r.data),
  getZoneUpdateAcl: (groupId: string, zoneId: string) =>
    api
      .get<ZoneUpdateAcl>(`/dns/groups/${groupId}/zones/${zoneId}/update-acl`)
      .then((r) => r.data),
  replaceZoneUpdateAcl: (
    groupId: string,
    zoneId: string,
    body: ZoneUpdateAclReplace,
  ) =>
    api
      .put<ZoneUpdateAcl>(
        `/dns/groups/${groupId}/zones/${zoneId}/update-acl`,
        body,
      )
      .then((r) => r.data),

  // Records — server-side paginated (#455)
  listGroupRecords: (
    groupId: string,
    params?: {
      search?: string;
      record_type?: string;
      page?: number;
      page_size?: number;
    },
  ) =>
    api
      .get<Page<DNSGroupRecord>>(`/dns/groups/${groupId}/records`, { params })
      .then((r) => r.data),
  listRecords: (
    groupId: string,
    zoneId: string,
    params?: {
      tag?: string[];
      search?: string;
      record_type?: string;
      page?: number;
      page_size?: number;
    },
  ) =>
    api
      .get<Page<DNSRecord>>(`/dns/groups/${groupId}/zones/${zoneId}/records`, {
        params,
      })
      .then((r) => r.data),
  createRecord: (groupId: string, zoneId: string, data: Partial<DNSRecord>) =>
    api
      .post<DNSRecord>(`/dns/groups/${groupId}/zones/${zoneId}/records`, data)
      .then((r) => r.data),
  updateRecord: (
    groupId: string,
    zoneId: string,
    recordId: string,
    data: Partial<DNSRecord>,
  ) =>
    api
      .put<DNSRecord>(
        `/dns/groups/${groupId}/zones/${zoneId}/records/${recordId}`,
        data,
      )
      .then((r) => r.data),
  deleteRecord: (groupId: string, zoneId: string, recordId: string) =>
    api.delete(`/dns/groups/${groupId}/zones/${zoneId}/records/${recordId}`),

  // Soft-deletes by default (#963) — the whole selection shares one
  // deletion_batch_id, so it restores from Admin → Trash in one action.
  // ``permanent`` is superadmin-only server-side, same as deleteRecord.
  bulkDeleteRecords: (
    groupId: string,
    zoneId: string,
    recordIds: string[],
    opts?: { permanent?: boolean },
  ) =>
    api
      .post<{
        deleted: number;
        skipped: { record_id: string; reason: string }[];
        deletion_batch_id: string | null;
      }>(
        `/dns/groups/${groupId}/zones/${zoneId}/records/bulk-delete`,
        { record_ids: recordIds },
        { params: opts?.permanent ? { permanent: true } : undefined },
      )
      .then((r) => r.data),

  // Bulk zone file import / export
  importZonePreview: (
    groupId: string,
    zoneId: string,
    data: { zone_file: string; zone_name?: string; view_id?: string | null },
  ) =>
    api
      .post<DNSImportPreview>(
        `/dns/groups/${groupId}/zones/${zoneId}/import/preview`,
        data,
      )
      .then((r) => r.data),
  importZoneCommit: (
    groupId: string,
    zoneId: string,
    data: {
      zone_file: string;
      zone_name?: string;
      view_id?: string | null;
      conflict_strategy: "merge" | "replace" | "append";
    },
  ) =>
    api
      .post<DNSImportCommit>(
        `/dns/groups/${groupId}/zones/${zoneId}/import/commit`,
        data,
      )
      .then((r) => r.data),
  exportZone: (groupId: string, zoneId: string) =>
    api
      .get<string>(`/dns/groups/${groupId}/zones/${zoneId}/export`, {
        responseType: "text",
        transformResponse: (d) => d,
      })
      .then((r) => ({
        data: r.data,
        // Prefer the backend's Content-Disposition filename — it carries the
        // UTC timestamp suffix. Callers must not fabricate their own.
        filename: _parseContentDispositionFilename(
          r.headers["content-disposition"],
        ),
      })),
  syncZoneWithServer: (groupId: string, zoneId: string, apply = true) =>
    api
      .post<{
        server_records: number;
        existing_in_db: number;
        imported: number;
        skipped_unsupported: number;
        imported_records: {
          name: string;
          fqdn: string;
          record_type: string;
          value: string;
          ttl: number | null;
        }[];
        push_candidates: number;
        pushed: number;
        pushed_records: {
          name: string;
          fqdn: string;
          record_type: string;
          value: string;
          ttl: number | null;
        }[];
        push_errors: string[];
      }>(`/dns/groups/${groupId}/zones/${zoneId}/sync-with-server`, { apply })
      .then((r) => r.data),
  exportAllZones: (groupId: string, viewId?: string | null) =>
    api
      .get<Blob>(`/dns/groups/${groupId}/zones/export`, {
        params: viewId ? { view_id: viewId } : {},
        responseType: "blob",
      })
      .then((r) => ({
        data: r.data,
        filename: _parseContentDispositionFilename(
          r.headers["content-disposition"],
        ),
      })),
};

function _parseContentDispositionFilename(
  header: string | undefined,
): string | null {
  if (!header) return null;
  const match = header.match(/filename="?([^";]+)"?/i);
  return match ? match[1] : null;
}

export interface DNSRecordChange {
  op: "create" | "update" | "delete" | "unchanged";
  name: string;
  record_type: string;
  value: string;
  ttl: number | null;
  priority: number | null;
  weight: number | null;
  port: number | null;
  existing_id: string | null;
}

export interface DNSImportPreview {
  zone_id: string | null;
  zone_name: string;
  to_create: DNSRecordChange[];
  to_update: DNSRecordChange[];
  to_delete: DNSRecordChange[];
  unchanged: DNSRecordChange[];
  soa_detected: boolean;
  record_count: number;
}

export interface DNSImportCommit {
  zone_id: string;
  batch_id: string;
  created: number;
  updated: number;
  deleted: number;
  unchanged: number;
  conflict_strategy: string;
}

// ── DNS Blocking Lists ─────────────────────────────────────────────────────

export interface DNSBlockList {
  id: string;
  name: string;
  description: string;
  category: string;
  source_type: string;
  feed_url: string | null;
  feed_format: string;
  update_interval_hours: number;
  block_mode: string;
  sinkhole_ip: string | null;
  /** Whether feed-sourced entries block subdomains too (#894). */
  feed_entries_are_wildcard: boolean;
  enabled: boolean;
  last_synced_at: string | null;
  last_sync_status: string | null;
  last_sync_error: string | null;
  entry_count: number;
  created_at: string;
  modified_at: string;
  applied_group_ids: string[];
  applied_view_ids: string[];
}

export interface DNSBlockListEntry {
  id: string;
  list_id: string;
  domain: string;
  entry_type: string;
  target: string | null;
  source: string;
  is_wildcard: boolean;
  reason: string;
  added_at: string;
}

export interface DNSBlockListEntryPage {
  total: number;
  items: DNSBlockListEntry[];
}

export interface DNSBlockListException {
  id: string;
  list_id: string;
  domain: string;
  reason: string;
  created_at: string;
}

export interface BlocklistCatalogSource {
  id: string;
  name: string;
  description: string;
  category: string;
  feed_url: string;
  feed_format: string;
  license: string;
  homepage: string | null;
  recommended: boolean;
  /** Whether this feed's entries should block subdomains (#894). */
  entries_are_wildcard: boolean;
}

/** One provider's rewrite set inside a template (issue #878). */
export interface BlocklistTemplateGroup {
  id: string;
  name: string;
  /** Where this group's domains are rewritten to. */
  target: string;
  domain_count: number;
  default: boolean;
  note: string | null;
  /** Sibling group ids this one cannot be combined with. */
  conflicts_with: string[];
}

export interface BlocklistTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  block_mode: string;
  groups: BlocklistTemplateGroup[];
}

export interface BlocklistProfile {
  id: string;
  name: string;
  description: string;
  source_ids: string[];
  template_ids: string[];
  note: string | null;
}

export interface BlocklistCatalogResponse {
  version: string;
  comment: string;
  sources: BlocklistCatalogSource[];
  templates: BlocklistTemplate[];
  profiles: BlocklistProfile[];
}

export interface BlocklistFromTemplateRequest {
  template_id: string;
  name?: string;
  /** Omit for the template's default groups. */
  group_ids?: string[];
  block_mode?: string;
  enabled?: boolean;
}

export interface BlocklistProfileAppliedItem {
  kind: "source" | "template";
  catalog_id: string;
  name: string;
  list_id: string | null;
  status: "created" | "skipped_existing" | "skipped_missing";
}

export interface BlocklistApplyProfileResponse {
  profile_id: string;
  created: number;
  skipped: number;
  items: BlocklistProfileAppliedItem[];
}

// ── DNS configuration importer (issue #128) ─────────────────────────

export type DNSImportSource =
  | "bind9"
  | "windows_dns"
  | "powerdns"
  | "technitium";
export type DNSImportConflictAction = "skip" | "overwrite" | "rename";

export interface DNSImportedRecord {
  name: string;
  record_type: string;
  value: string;
  ttl: number | null;
  priority: number | null;
  weight: number | null;
  port: number | null;
}

export interface DNSImportedSOA {
  primary_ns: string;
  admin_email: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
  ttl: number;
}

export interface DNSImportedZone {
  name: string;
  zone_type: string;
  kind: string;
  soa: DNSImportedSOA | null;
  records: DNSImportedRecord[];
  view_name: string | null;
  forwarders: string[];
  skipped_record_types: Record<string, number>;
  parse_warnings: string[];
  /**
   * #986 — TLD scope of the incoming name. Optional because this same
   * shape is posted back on commit, where it is ignored server-side.
   */
  name_scope?: ZoneNameScope;
}

export interface DNSImportZoneConflict {
  zone_name: string;
  existing_zone_id: string;
  existing_record_count: number;
  action: DNSImportConflictAction;
  rename_to: string | null;
}

export interface DNSImportPreview {
  source: DNSImportSource;
  zones: DNSImportedZone[];
  conflicts: DNSImportZoneConflict[];
  warnings: string[];
  total_records: number;
  record_type_histogram: Record<string, number>;
}

export interface DNSImportConflictDecision {
  action: DNSImportConflictAction;
  rename_to?: string | null;
}

export interface DNSImportCommitResultZone {
  zone_name: string;
  action_taken: "created" | "overwrote" | "renamed" | "skipped" | "failed";
  zone_id: string | null;
  records_created: number;
  records_deleted: number;
  error: string | null;
}

export interface DNSImportCommitResult {
  target_group_id: string;
  zones: DNSImportCommitResultZone[];
  warnings: string[];
  total_zones_created: number;
  total_zones_overwrote: number;
  total_zones_renamed: number;
  total_zones_skipped: number;
  total_zones_failed: number;
  total_records_created: number;
}

export interface WindowsDNSServerOption {
  id: string;
  name: string;
  host: string;
  group_id: string;
  group_name: string;
  has_credentials: boolean;
}

// Cloud DNS import (issue #37, Part B). One row in the cloud-DNS server
// picker — filtered to cloud-driver rows (cloudflare/route53/azure_dns/
// google_dns). Mirrors WindowsDNSServerOption but carries the driver
// name instead of a host.
export interface CloudDNSServerOption {
  id: string;
  name: string;
  driver: string;
  group_id: string;
  group_name: string;
  has_credentials: boolean;
}

export const dnsImportApi = {
  bind9Preview: (
    file: File,
    target_group_id: string,
    target_view_id?: string,
  ) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("target_group_id", target_group_id);
    if (target_view_id) fd.append("target_view_id", target_view_id);
    return api
      .post<DNSImportPreview>("/dns/import/bind9/preview", fd)
      .then((r) => r.data);
  },
  bind9Commit: (body: {
    target_group_id: string;
    target_view_id?: string | null;
    plan: DNSImportPreview;
    conflict_actions: Record<string, DNSImportConflictDecision>;
  }) =>
    api
      .post<DNSImportCommitResult>("/dns/import/bind9/commit", body)
      .then((r) => r.data),

  // Windows DNS — server-side live pull.
  windowsDNSServers: () =>
    api
      .get<WindowsDNSServerOption[]>("/dns/import/windows-dns/servers")
      .then((r) => r.data),
  windowsDNSPreview: (body: {
    server_id: string;
    target_group_id: string;
    target_view_id?: string | null;
  }) =>
    api
      .post<DNSImportPreview>("/dns/import/windows-dns/preview", body)
      .then((r) => r.data),
  windowsDNSCommit: (body: {
    target_group_id: string;
    target_view_id?: string | null;
    plan: DNSImportPreview;
    conflict_actions: Record<string, DNSImportConflictDecision>;
  }) =>
    api
      .post<DNSImportCommitResult>("/dns/import/windows-dns/commit", body)
      .then((r) => r.data),

  // PowerDNS — REST API live pull.
  powerDNSTestConnection: (body: {
    api_url: string;
    api_key: string;
    server_name?: string;
  }) =>
    api
      .post<PowerDNSConnectionInfo>("/dns/import/powerdns/test-connection", {
        ...body,
        server_name: body.server_name || "localhost",
      })
      .then((r) => r.data),
  powerDNSPreview: (body: {
    api_url: string;
    api_key: string;
    server_name?: string;
    target_group_id: string;
    target_view_id?: string | null;
  }) =>
    api
      .post<DNSImportPreview>("/dns/import/powerdns/preview", {
        ...body,
        server_name: body.server_name || "localhost",
      })
      .then((r) => r.data),
  powerDNSCommit: (body: {
    target_group_id: string;
    target_view_id?: string | null;
    plan: DNSImportPreview;
    conflict_actions: Record<string, DNSImportConflictDecision>;
  }) =>
    api
      .post<DNSImportCommitResult>("/dns/import/powerdns/commit", body)
      .then((r) => r.data),

  // Technitium — REST API live pull (issue #744). Only Primary zones are
  // imported; the rest come back as preview warnings.
  technitiumTestConnection: (body: { api_url: string; api_token: string }) =>
    api
      .post<TechnitiumConnectionInfo>(
        "/dns/import/technitium/test-connection",
        body,
      )
      .then((r) => r.data),
  technitiumPreview: (body: {
    api_url: string;
    api_token: string;
    target_group_id: string;
    target_view_id?: string | null;
  }) =>
    api
      .post<DNSImportPreview>("/dns/import/technitium/preview", body)
      .then((r) => r.data),
  technitiumCommit: (body: {
    target_group_id: string;
    target_view_id?: string | null;
    plan: DNSImportPreview;
    conflict_actions: Record<string, DNSImportConflictDecision>;
  }) =>
    api
      .post<DNSImportCommitResult>("/dns/import/technitium/commit", body)
      .then((r) => r.data),

  // Cloud DNS (issue #37, Part B) — live pull of hosted zones + records
  // from a cloud DNS provider. Also the engine behind "Sync from
  // provider" on a cloud DNS server.
  cloudDNSServers: () =>
    api
      .get<CloudDNSServerOption[]>("/dns/import/cloud/servers")
      .then((r) => r.data),
  cloudDNSPreview: (body: {
    server_id: string;
    target_group_id: string;
    target_view_id?: string | null;
  }) =>
    api
      .post<DNSImportPreview>("/dns/import/cloud/preview", body)
      .then((r) => r.data),
  cloudDNSCommit: (body: {
    target_group_id: string;
    target_view_id?: string | null;
    plan: DNSImportPreview;
    conflict_actions: Record<string, DNSImportConflictDecision>;
  }) =>
    api
      .post<DNSImportCommitResult>("/dns/import/cloud/commit", body)
      .then((r) => r.data),
};

export interface PowerDNSConnectionInfo {
  type: string;
  id: string;
  daemon_type: string;
  version: string;
  url: string;
}

export interface TechnitiumConnectionInfo {
  ok: boolean;
  zone_count: number;
  // Only Primary zones can be imported — a server that is mostly
  // secondaries has far less to migrate than its raw zone count suggests.
  importable_zone_count: number;
}

// ── DHCP configuration importer (issue #129) ────────────────────────

export type DHCPImportSource = "kea" | "windows_dhcp" | "isc_dhcp";
export type DHCPImportConflictAction = "skip" | "overwrite";

export interface DHCPImportedReservation {
  ip_address: string;
  mac_address: string;
  hostname: string;
  client_id: string | null;
  options: Record<string, unknown>;
}

export interface DHCPImportedPool {
  start_ip: string;
  end_ip: string;
  pool_type: string;
  name: string;
  class_restriction: string | null;
}

export interface DHCPImportedClientClass {
  name: string;
  match_expression: string;
  description: string;
  options: Record<string, unknown>;
  supported: boolean;
  warning: string | null;
}

export interface DHCPImportedScope {
  subnet_cidr: string;
  address_family: string;
  name: string;
  description: string;
  lease_time: number;
  min_lease_time: number | null;
  max_lease_time: number | null;
  is_active: boolean;
  options: Record<string, unknown>;
  pools: DHCPImportedPool[];
  reservations: DHCPImportedReservation[];
  ddns_enabled: boolean;
  ddns_hostname_policy: string;
  v6_address_mode: string;
  skipped_options: Record<string, unknown>;
  ha_info: string | null;
  parse_warnings: string[];
}

export interface DHCPImportScopeConflict {
  subnet_cidr: string;
  existing_scope_id: string | null;
  existing_subnet_id: string | null;
  existing_subnet_name: string | null;
  existing_pool_count: number;
  existing_reservation_count: number;
  soft_deleted: boolean;
  action: DHCPImportConflictAction;
}

export interface DHCPImportPreview {
  source: DHCPImportSource;
  scopes: DHCPImportedScope[];
  client_classes: DHCPImportedClientClass[];
  conflicts: DHCPImportScopeConflict[];
  warnings: string[];
  unsupported: string[];
  total_pools: number;
  total_reservations: number;
  address_family_histogram: Record<string, number>;
}

export interface DHCPImportConflictDecision {
  action: DHCPImportConflictAction;
}

export interface DHCPImportCommitScope {
  subnet_cidr: string;
  action_taken: "created" | "overwrote" | "skipped" | "failed";
  scope_id: string | null;
  subnet_id: string | null;
  subnet_created: boolean;
  pools_created: number;
  reservations_created: number;
  error: string | null;
}

export interface DHCPImportCommitResult {
  target_group_id: string;
  scopes: DHCPImportCommitScope[];
  client_classes_created: number;
  warnings: string[];
  total_scopes_created: number;
  total_scopes_overwrote: number;
  total_scopes_skipped: number;
  total_scopes_failed: number;
  total_subnets_created: number;
  total_pools_created: number;
  total_reservations_created: number;
}

export interface WindowsDHCPServerOption {
  id: string;
  name: string;
  host: string;
  group_id: string | null;
  group_name: string | null;
  has_credentials: boolean;
}

interface DHCPImportCommitBody {
  target_group_id: string;
  ipam_space_id?: string | null;
  ipam_block_id?: string | null;
  plan: DHCPImportPreview;
  conflict_actions: Record<string, DHCPImportConflictDecision>;
}

export const dhcpImportApi = {
  // Kea — JSON config file upload.
  keaPreview: (file: File, target_group_id: string, ipam_space_id?: string) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("target_group_id", target_group_id);
    if (ipam_space_id) fd.append("ipam_space_id", ipam_space_id);
    return api
      .post<DHCPImportPreview>("/dhcp/import/kea/preview", fd)
      .then((r) => r.data);
  },
  keaCommit: (body: DHCPImportCommitBody) =>
    api
      .post<DHCPImportCommitResult>("/dhcp/import/kea/commit", body)
      .then((r) => r.data),

  // ISC — dhcpd.conf file upload.
  iscPreview: (file: File, target_group_id: string, ipam_space_id?: string) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("target_group_id", target_group_id);
    if (ipam_space_id) fd.append("ipam_space_id", ipam_space_id);
    return api
      .post<DHCPImportPreview>("/dhcp/import/isc/preview", fd)
      .then((r) => r.data);
  },
  iscCommit: (body: DHCPImportCommitBody) =>
    api
      .post<DHCPImportCommitResult>("/dhcp/import/isc/commit", body)
      .then((r) => r.data),

  // Windows DHCP — server-side live pull.
  windowsServers: () =>
    api
      .get<WindowsDHCPServerOption[]>("/dhcp/import/windows/servers")
      .then((r) => r.data),
  windowsPreview: (body: {
    server_id: string;
    target_group_id: string;
    ipam_space_id?: string | null;
  }) =>
    api
      .post<DHCPImportPreview>("/dhcp/import/windows/preview", body)
      .then((r) => r.data),
  windowsCommit: (body: DHCPImportCommitBody) =>
    api
      .post<DHCPImportCommitResult>("/dhcp/import/windows/commit", body)
      .then((r) => r.data),
};

// ── NetBox read-only one-shot IPAM importer (issue #36) ─────────────────
//
// A live-API migration tool: the operator pastes a NetBox base_url + token
// per request (creds read-once, never persisted), tests the connection,
// previews the would-create canonical IR across every entity type, then
// commits the unmodified previewed plan. Stateless between preview + commit
// — the UI hands the same PreviewOut straight back as CommitIn.plan. Mirrors
// the dnsImportApi (connection-test shape) + dhcpImportApi (IPAM-target
// shape). Wire shapes match backend/app/api/v1/netbox_import/router.py.

export type NetBoxSpaceStrategy = "per_vrf" | "single";
export type NetBoxImportConflictAction = "skip" | "overwrite";

// Shared connection fields (test-connection + preview bodies).
export interface NetBoxConnIn {
  base_url: string;
  token: string;
  verify_tls?: boolean;
}

// Optional scope slice forwarded to the prefix / address / vrf / tenant
// pulls so the operator can import a slice of a large NetBox.
export interface NetBoxPreviewFilters {
  vrf_id?: number | null;
  tenant_id?: number | null;
  status?: string | null;
  family?: 4 | 6 | null;
  within_include?: string | null;
}

export interface NetBoxTestOut {
  ok: boolean;
  netbox_version: string | null;
  api_version: string | null;
  counts: Record<string, number> | null;
}

// ── The 8 Imported*Out canonical-IR row shapes ───────────────────────
export interface NetBoxImportedCustomer {
  name: string;
  notes: string;
  custom_fields: Record<string, unknown>;
  tags: Record<string, unknown>;
  netbox_id: number | null;
}

export interface NetBoxImportedSite {
  name: string;
  code: string | null;
  parent_code: string | null;
  kind: string;
  region: string | null;
  notes: string;
  tags: Record<string, unknown>;
  netbox_id: number | null;
}

export interface NetBoxImportedVRF {
  name: string;
  rd: string | null;
  import_targets: string[];
  export_targets: string[];
  description: string;
  customer_name: string | null;
  custom_fields: Record<string, unknown>;
  tags: Record<string, unknown>;
  netbox_id: number | null;
}

export interface NetBoxImportedSpace {
  name: string;
  vrf_name: string | null;
  is_default: boolean;
  customer_name: string | null;
  description: string;
  tags: Record<string, unknown>;
}

export interface NetBoxImportedVLAN {
  vid: number;
  name: string;
  description: string;
  netbox_id: number | null;
}

export interface NetBoxImportedBlock {
  network: string;
  name: string;
  description: string;
  space_name: string | null;
  parent_cidr: string | null;
  customer_name: string | null;
  site_code: string | null;
  custom_fields: Record<string, unknown>;
  tags: Record<string, unknown>;
  netbox_id: number | null;
}

export interface NetBoxImportedSubnet {
  network: string;
  name: string;
  description: string;
  space_name: string | null;
  status: string;
  vlan_vid: number | null;
  customer_name: string | null;
  site_code: string | null;
  subnet_role: string | null;
  kind: string;
  custom_fields: Record<string, unknown>;
  tags: Record<string, unknown>;
  netbox_id: number | null;
}

export interface NetBoxImportedAddress {
  address: string;
  status: string;
  role: string | null;
  hostname: string | null;
  fqdn: string | null;
  description: string;
  subnet_cidr: string | null;
  space_name: string | null;
  custom_fields: Record<string, unknown>;
  tags: Record<string, unknown>;
  netbox_id: number | null;
}

export interface NetBoxEntityConflict {
  kind: string;
  key: string;
  existing_id: string;
  reason: string;
  action: NetBoxImportConflictAction;
}

// PreviewOut — also the commit request payload's ``plan`` field, so the
// UI hands back the same shape it received.
export interface NetBoxImportPreview {
  source: "netbox";
  customers: NetBoxImportedCustomer[];
  sites: NetBoxImportedSite[];
  vrfs: NetBoxImportedVRF[];
  spaces: NetBoxImportedSpace[];
  vlans: NetBoxImportedVLAN[];
  blocks: NetBoxImportedBlock[];
  subnets: NetBoxImportedSubnet[];
  addresses: NetBoxImportedAddress[];
  conflicts: NetBoxEntityConflict[];
  warnings: string[];
  counts: Record<string, number>;
}

export interface NetBoxImportConflictDecision {
  action: NetBoxImportConflictAction;
}

export interface NetBoxCommitEntity {
  kind: string;
  key: string;
  action_taken: "created" | "overwrote" | "skipped" | "failed";
  entity_id: string | null;
  error: string | null;
}

export interface NetBoxImportCommitResult {
  source: string;
  entities: NetBoxCommitEntity[];
  warnings: string[];
  customers_created: number;
  sites_created: number;
  vrfs_created: number;
  spaces_created: number;
  vlans_created: number;
  blocks_created: number;
  subnets_created: number;
  addresses_created: number;
  total_created: number;
  total_overwrote: number;
  total_skipped: number;
  total_failed: number;
}

export const netboxImportApi = {
  // Connection probe — base URL + token; token read-once, never persisted.
  testConnection: (body: NetBoxConnIn) =>
    api
      .post<NetBoxTestOut>("/ipam/import/netbox/test-connection", body)
      .then((r) => r.data),
  preview: (
    body: NetBoxConnIn & {
      space_strategy: NetBoxSpaceStrategy;
      target_space_id?: string | null;
      filters?: NetBoxPreviewFilters | null;
    },
  ) =>
    api
      .post<NetBoxImportPreview>("/ipam/import/netbox/preview", body)
      .then((r) => r.data),
  commit: (body: {
    plan: NetBoxImportPreview;
    conflict_actions: Record<string, NetBoxImportConflictDecision>;
    space_strategy: NetBoxSpaceStrategy;
    target_space_id?: string | null;
    default_router_name?: string;
  }) =>
    api
      .post<NetBoxImportCommitResult>("/ipam/import/netbox/commit", body)
      .then((r) => r.data),
};

// ── Windows → SpatiumDDI cutover (issue #756) ──────────────────────────
//
// The migration family's guided workflow: a plan holds one item per Windows
// zone / scope and walks it through four phases — parity (does SpatiumDDI
// hold what Windows holds?), parallel run (do both sides answer the same?),
// the switch (TTL pre-flight / DHCP lease handover / cut over / roll back),
// and the decommission checklist. Every endpoint is superadmin-gated and
// lives behind the ``migration.cutover`` feature module.
//
// Wire shapes match backend/app/api/v1/cutover/router.py; the JSONB payloads
// that ride inside the item columns (last_parity, last_shadow, …) match the
// ``as_dict()`` of the dataclasses in
// backend/app/services/cutover/canonical.py.

export type CutoverItemKind = "dns_zone" | "dhcp_scope";

/** ``block`` refuses the switch outright; ``warn`` can be acknowledged with
 *  ``force``. Messages are written to state the fix — render them verbatim. */
export interface CutoverBlocker {
  code: string;
  severity: "block" | "warn";
  message: string;
}

/** One explained difference between SpatiumDDI and the live Windows object.
 *  ``classification`` is a DiffClass: in_sync | value_mismatch |
 *  drifted_since_import | never_imported | intentionally_diverged. */
export interface CutoverParityDifference {
  classification: string;
  name: string;
  detail: string;
  source_value: string | null;
  target_value: string | null;
  record_type: string | null;
}

export interface CutoverParityReport {
  kind: string;
  source_ref: string;
  // ok | unmatched | error | unverified
  status: string;
  error: string | null;
  in_sync: number;
  not_compared: number;
  difference_count: number;
  is_parity: boolean;
  counts_by_class: Record<string, number>;
  differences: CutoverParityDifference[];
  warnings: string[];
}

export interface CutoverShadowSample {
  name: string;
  qtype: string;
  source_answers: string[];
  // Keyed by target server label.
  target_answers: Record<string, string[]>;
  // match | mismatch | source_error | target_error
  verdict: string;
  error: string | null;
}

export interface CutoverShadowReport {
  zone_name: string;
  source: string;
  targets: string[];
  // "query_log" = replayed production traffic; "zone_records" = our own rows.
  sample_source: string;
  sampled: number;
  matched: number;
  mismatched: number;
  errors: number;
  samples: CutoverShadowSample[];
  warnings: string[];
}

export interface CutoverTTLRecordChange {
  record_id: string;
  name: string;
  record_type: string;
  current_ttl: number | null;
  new_ttl: number;
}

export interface CutoverTTLPreflightPlan {
  target_ttl: number;
  zone_current: Record<string, number>;
  zone_after: Record<string, number>;
  records: CutoverTTLRecordChange[];
  changed: number;
  unchanged: number;
  warnings: string[];
  // PowerShell the operator runs on the Windows side — SpatiumDDI never
  // writes TTLs there, and an unexplained one-sided drop is worse than none.
  source_side_instructions: string;
}

export interface CutoverLeaseEntry {
  ip_address: string;
  mac_address: string;
  hostname: string;
  action: "create" | "skip" | "conflict";
  reason: string;
  // Set on commit: created | skipped | failed.
  result: string | null;
  error: string | null;
}

/** What ``CutoverItem.lease_handover`` actually holds after a commit. */
export interface CutoverLeaseHandoverSummary {
  created: number;
  skipped: number;
  failed: number;
  at: string;
}

export interface CutoverLeaseHandoverPlan {
  scope_cidr: string;
  source_scope_id: string;
  entries: CutoverLeaseEntry[];
  create_count: number;
  skip_count: number;
  conflict_count: number;
  created: number;
  skipped: number;
  failed: number;
  warnings: string[];
}

export interface CutoverItem {
  id: string;
  plan_id: string;
  kind: string;
  source_ref: string;
  zone_id: string | null;
  scope_id: string | null;
  // pending | parity_checked | preflight_done | cut_over | rolled_back
  stage: string;
  blockers: CutoverBlocker[];
  last_parity: CutoverParityReport | null;
  last_parity_at: string | null;
  last_shadow: CutoverShadowReport | null;
  last_shadow_at: string | null;
  ttl_snapshot: Record<string, unknown> | null;
  ttl_lowered_at: string | null;
  /**
   * The persisted *summary* of the last handover, NOT a full plan — the backend
   * stores only ``{created, skipped, failed, at}`` on the item
   * (``services/cutover/leases.commit_lease_handover``). Typing it as the full
   * plan would let a component reach for ``.entries`` / ``.warnings`` that are
   * never there.
   */
  lease_handover: CutoverLeaseHandoverSummary | null;
  cut_over_at: string | null;
  rolled_back_at: string | null;
  notes: string;
}

export interface CutoverPlan {
  id: string;
  name: string;
  description: string;
  // draft | verifying | parallel | cutting_over | completed | rolled_back |
  // abandoned
  status: string;
  source_dns_server_id: string | null;
  source_dhcp_server_id: string | null;
  target_dns_group_id: string | null;
  target_dhcp_group_id: string | null;
  notes: string;
  created_at: string;
  modified_at: string;
  completed_at: string | null;
  rolled_back_at: string | null;
  item_count: number;
  stage_counts: Record<string, number>;
  blocked_count: number;
}

export interface CutoverPlanDetail extends CutoverPlan {
  items: CutoverItem[];
}

export interface CutoverPlanCreate {
  name: string;
  description?: string;
  source_dns_server_id?: string | null;
  source_dhcp_server_id?: string | null;
  target_dns_group_id?: string | null;
  target_dhcp_group_id?: string | null;
  notes?: string;
}

export interface CutoverChecklistItem {
  key: string;
  // dns | dhcp | ad | general
  category: string;
  label: string;
  description: string;
  applies_to: string;
  is_done: boolean;
  done_at: string | null;
  notes: string;
  sort_order: number;
  // ok | attention | not_applicable | manual — advisory only, never ticks.
  auto_state: string;
  auto_detail: string;
}

export interface CutoverEvent {
  id: string;
  item_id: string | null;
  at: string;
  kind: string;
  summary: string;
  detail: Record<string, unknown> | null;
  user_display_name: string;
}

export interface CutoverCandidate {
  kind: CutoverItemKind;
  source_ref: string;
  display_name: string;
  matched_id: string | null;
  matched_display: string | null;
  already_in_plan: boolean;
  blockers: CutoverBlocker[];
  source: Record<string, unknown>;
}

// One half of the discover result. ``available: false`` means the plan simply
// has no source server of that kind — a DNS-only plan is not an error state.
export interface CutoverDiscoverSide {
  available: boolean;
  error: string | null;
  source_server: string | null;
  target_group_id: string | null;
  candidates: CutoverCandidate[];
}

export interface CutoverDiscoverResult {
  dns: CutoverDiscoverSide;
  dhcp: CutoverDiscoverSide;
}

export interface CutoverItemIn {
  kind: CutoverItemKind;
  source_ref: string;
  zone_id?: string | null;
  scope_id?: string | null;
  notes?: string;
}

// Per-item row of the whole-plan parity run: the report fields inlined, or
// ``status: "error"`` with the wiring problem that stopped it.
export type CutoverPlanParityRow = Partial<CutoverParityReport> & {
  item_id: string;
  source_ref: string;
  kind: string;
  status: string;
  error?: string | null;
};

export interface CutoverPlanParityResult {
  items: CutoverPlanParityRow[];
  in_parity: number;
  total: number;
}

// Result of a cutover / rollback. ``actions`` is what SpatiumDDI did;
// ``instructions`` is what the operator still has to do (for DNS, the
// delegation change — which lives outside SpatiumDDI entirely).
export interface CutoverSwitchResult {
  kind: string;
  source_ref: string;
  stage: string;
  cut_over_at?: string;
  rolled_back_at?: string;
  actions: string[];
  instructions: string[];
  recovery_estimate_seconds: number | null;
  acknowledged_warnings?: CutoverBlocker[];
  records_restored?: number;
  ttl_lowered_at?: string | null;
  warnings?: string[];
}

// 409 body of POST …/cutover — ``CutoverBlocked.as_dict()``. Note the key is
// ``error``, not ``message``.
export interface CutoverBlockedDetail {
  error: string;
  blockers: CutoverBlocker[];
}

const CUTOVER_BASE = "/migration/cutover";

export const cutoverApi = {
  listPlans: () =>
    api.get<CutoverPlan[]>(`${CUTOVER_BASE}/plans`).then((r) => r.data),
  createPlan: (body: CutoverPlanCreate) =>
    api
      .post<CutoverPlanDetail>(`${CUTOVER_BASE}/plans`, body)
      .then((r) => r.data),
  getPlan: (planId: string) =>
    api
      .get<CutoverPlanDetail>(`${CUTOVER_BASE}/plans/${planId}`)
      .then((r) => r.data),
  updatePlan: (
    planId: string,
    body: Partial<CutoverPlanCreate> & {
      status?: string;
    },
  ) =>
    api
      .patch<CutoverPlanDetail>(`${CUTOVER_BASE}/plans/${planId}`, body)
      .then((r) => r.data),
  deletePlan: (planId: string) => api.delete(`${CUTOVER_BASE}/plans/${planId}`),

  // Live WinRM pull of the source estate — read-only, matches each Windows
  // object against the target group and pre-computes its blockers.
  discover: (planId: string) =>
    api
      .post<CutoverDiscoverResult>(`${CUTOVER_BASE}/plans/${planId}/discover`)
      .then((r) => r.data),
  addItems: (planId: string, items: CutoverItemIn[]) =>
    api
      .post<CutoverItem[]>(`${CUTOVER_BASE}/plans/${planId}/items`, { items })
      .then((r) => r.data),
  deleteItem: (planId: string, itemId: string) =>
    api.delete(`${CUTOVER_BASE}/plans/${planId}/items/${itemId}`),

  // Phase 1 — parity.
  runItemParity: (planId: string, itemId: string) =>
    api
      .post<{
        report: CutoverParityReport;
        blockers: CutoverBlocker[];
      }>(`${CUTOVER_BASE}/plans/${planId}/items/${itemId}/parity`)
      .then((r) => r.data),
  runPlanParity: (planId: string) =>
    api
      .post<CutoverPlanParityResult>(`${CUTOVER_BASE}/plans/${planId}/parity`)
      .then((r) => r.data),

  // Phase 2 — parallel run (DNS items only; a dhcp_scope item 422s).
  runShadow: (planId: string, itemId: string, sampleSize: number) =>
    api
      .post<CutoverShadowReport>(
        `${CUTOVER_BASE}/plans/${planId}/items/${itemId}/shadow`,
        { sample_size: sampleSize },
      )
      .then((r) => r.data),

  // Phase 3a — TTL pre-flight (DNS items only).
  previewTtl: (planId: string, itemId: string, targetTtl: number) =>
    api
      .post<CutoverTTLPreflightPlan>(
        `${CUTOVER_BASE}/plans/${planId}/items/${itemId}/ttl-preflight/preview`,
        { target_ttl: targetTtl },
      )
      .then((r) => r.data),
  commitTtl: (planId: string, itemId: string, targetTtl: number) =>
    api
      .post<CutoverTTLPreflightPlan>(
        `${CUTOVER_BASE}/plans/${planId}/items/${itemId}/ttl-preflight/commit`,
        { target_ttl: targetTtl },
      )
      .then((r) => r.data),
  restoreTtl: (planId: string, itemId: string) =>
    api
      .post<{
        records_restored: number;
        zone: string;
      }>(
        `${CUTOVER_BASE}/plans/${planId}/items/${itemId}/ttl-preflight/restore`,
      )
      .then((r) => r.data),

  // Phase 3b — DHCP lease handover (DHCP items only). Stateless between
  // preview and commit: the previewed entries are handed straight back, and
  // the server re-classifies every one against live DB state.
  previewLeases: (planId: string, itemId: string) =>
    api
      .post<CutoverLeaseHandoverPlan>(
        `${CUTOVER_BASE}/plans/${planId}/items/${itemId}/lease-handover/preview`,
      )
      .then((r) => r.data),
  commitLeases: (
    planId: string,
    itemId: string,
    entries: CutoverLeaseEntry[],
  ) =>
    api
      .post<CutoverLeaseHandoverPlan>(
        `${CUTOVER_BASE}/plans/${planId}/items/${itemId}/lease-handover/commit`,
        { entries },
      )
      .then((r) => r.data),

  // Phase 3c — the switch. 409 carries CutoverBlockedDetail; ``force`` only
  // ever acknowledges warn-severity blockers.
  cutOver: (planId: string, itemId: string, force = false) =>
    api
      .post<CutoverSwitchResult>(
        `${CUTOVER_BASE}/plans/${planId}/items/${itemId}/cutover`,
        { force },
      )
      .then((r) => r.data),
  rollback: (planId: string, itemId: string) =>
    api
      .post<CutoverSwitchResult>(
        `${CUTOVER_BASE}/plans/${planId}/items/${itemId}/rollback`,
      )
      .then((r) => r.data),

  // Phase 4 — decommission checklist. The GET seeds on first read.
  getChecklist: (planId: string) =>
    api
      .get<CutoverChecklistItem[]>(`${CUTOVER_BASE}/plans/${planId}/checklist`)
      .then((r) => r.data),
  patchChecklistItem: (
    planId: string,
    key: string,
    body: { is_done?: boolean; notes?: string },
  ) =>
    api
      .patch<CutoverChecklistItem>(
        `${CUTOVER_BASE}/plans/${planId}/checklist/${key}`,
        body,
      )
      .then((r) => r.data),

  listEvents: (planId: string, params?: { limit?: number; offset?: number }) =>
    api
      .get<CutoverEvent[]>(`${CUTOVER_BASE}/plans/${planId}/events`, { params })
      .then((r) => r.data),
  runbook: (planId: string) =>
    api
      .get<{ markdown: string }>(`${CUTOVER_BASE}/plans/${planId}/runbook`)
      .then((r) => r.data),
};

export const dnsBlocklistApi = {
  list: () => api.get<DNSBlockList[]>("/dns/blocklists").then((r) => r.data),
  catalog: () =>
    api
      .get<BlocklistCatalogResponse>("/dns/blocklists/catalog")
      .then((r) => r.data),
  subscribeFromCatalog: (body: {
    source_id: string;
    name?: string;
    update_interval_hours?: number;
    block_mode?: string;
    enabled?: boolean;
  }) =>
    api
      .post<DNSBlockList>("/dns/blocklists/from-catalog", body)
      .then((r) => r.data),
  createFromTemplate: (body: BlocklistFromTemplateRequest) =>
    api
      .post<DNSBlockList>("/dns/blocklists/from-template", body)
      .then((r) => r.data),
  applyProfile: (body: { profile_id: string; enabled?: boolean }) =>
    api
      .post<BlocklistApplyProfileResponse>(
        "/dns/blocklists/apply-profile",
        body,
      )
      .then((r) => r.data),
  get: (id: string) =>
    api.get<DNSBlockList>(`/dns/blocklists/${id}`).then((r) => r.data),
  create: (data: Partial<DNSBlockList>) =>
    api.post<DNSBlockList>("/dns/blocklists", data).then((r) => r.data),
  update: (id: string, data: Partial<DNSBlockList>) =>
    api.put<DNSBlockList>(`/dns/blocklists/${id}`, data).then((r) => r.data),
  delete: (id: string) => api.delete(`/dns/blocklists/${id}`),

  updateAssignments: (
    id: string,
    data: { server_group_ids?: string[]; view_ids?: string[] },
  ) =>
    api
      .put<DNSBlockList>(`/dns/blocklists/${id}/assignments`, data)
      .then((r) => r.data),

  refresh: (id: string) =>
    api
      .post<{
        list_id: string;
        task_id: string | null;
        status: string;
      }>(`/dns/blocklists/${id}/refresh`)
      .then((r) => r.data),

  listEntries: (
    id: string,
    params?: { q?: string; limit?: number; offset?: number },
  ) =>
    api
      .get<DNSBlockListEntryPage>(`/dns/blocklists/${id}/entries`, { params })
      .then((r) => r.data),
  addEntry: (id: string, data: Partial<DNSBlockListEntry>) =>
    api
      .post<DNSBlockListEntry>(`/dns/blocklists/${id}/entries`, data)
      .then((r) => r.data),
  bulkAddEntries: (id: string, domains: string[]) =>
    api
      .post<{
        added: number;
        skipped: number;
        total: number;
      }>(`/dns/blocklists/${id}/entries/bulk`, { domains })
      .then((r) => r.data),
  updateEntry: (
    id: string,
    entryId: string,
    data: Partial<DNSBlockListEntry>,
  ) =>
    api
      .put<DNSBlockListEntry>(`/dns/blocklists/${id}/entries/${entryId}`, data)
      .then((r) => r.data),
  deleteEntry: (id: string, entryId: string) =>
    api.delete(`/dns/blocklists/${id}/entries/${entryId}`),

  listExceptions: (id: string) =>
    api
      .get<DNSBlockListException[]>(`/dns/blocklists/${id}/exceptions`)
      .then((r) => r.data),
  addException: (id: string, data: { domain: string; reason?: string }) =>
    api
      .post<DNSBlockListException>(`/dns/blocklists/${id}/exceptions`, data)
      .then((r) => r.data),
  updateException: (
    id: string,
    exceptionId: string,
    data: { domain?: string; reason?: string },
  ) =>
    api
      .put<DNSBlockListException>(
        `/dns/blocklists/${id}/exceptions/${exceptionId}`,
        data,
      )
      .then((r) => r.data),
  deleteException: (id: string, exceptionId: string) =>
    api.delete(`/dns/blocklists/${id}/exceptions/${exceptionId}`),
};

// ── VLANs ────────────────────────────────────────────────────────────────────

export interface Router {
  id: string;
  name: string;
  description: string;
  location: string;
  management_ip: string | null;
  vendor: string | null;
  model: string | null;
  notes: string;
  created_at: string;
  modified_at: string;
}

export interface VLAN {
  id: string;
  router_id: string;
  vlan_id: number;
  name: string;
  description: string;
  created_at: string;
  modified_at: string;
}

// ── VRFs ─────────────────────────────────────────────────────────────────────

export interface VRF {
  id: string;
  name: string;
  description: string;
  asn_id: string | null;
  route_distinguisher: string | null;
  import_targets: string[];
  export_targets: string[];
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  customer_id: string | null;
  created_at: string;
  modified_at: string;
  space_count: number;
  block_count: number;
}

export interface VRFCreate {
  name: string;
  description?: string;
  asn_id?: string | null;
  route_distinguisher?: string | null;
  import_targets?: string[];
  export_targets?: string[];
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
  customer_id?: string | null;
}

export type VRFUpdate = Partial<VRFCreate>;

export interface VRFBulkDeleteResponse {
  deleted: number;
  detached_spaces: number;
  detached_blocks: number;
  not_found: string[];
  refused: {
    id: string;
    name: string;
    linked_spaces: number;
    linked_blocks: number;
  }[];
}

export const vrfsApi = {
  list: (params?: { search?: string; asn_id?: string; tag?: string[] }) =>
    api.get<VRF[]>("/vrfs", { params }).then((r) => r.data),
  get: (id: string) => api.get<VRF>(`/vrfs/${id}`).then((r) => r.data),
  create: (body: VRFCreate) => api.post<VRF>("/vrfs", body).then((r) => r.data),
  update: (id: string, body: VRFUpdate) =>
    api.put<VRF>(`/vrfs/${id}`, body).then((r) => r.data),
  delete: (id: string, force = false) =>
    api.delete(`/vrfs/${id}`, { params: { force } }),
  bulkDelete: (ids: string[], force = false) =>
    api
      .post<VRFBulkDeleteResponse>("/vrfs/bulk-delete", { ids, force })
      .then((r) => r.data),
};

export const vlansApi = {
  listRouters: () => api.get<Router[]>("/vlans/routers").then((r) => r.data),
  getRouter: (id: string) =>
    api.get<Router>(`/vlans/routers/${id}`).then((r) => r.data),
  createRouter: (data: Partial<Router>) =>
    api.post<Router>("/vlans/routers", data).then((r) => r.data),
  updateRouter: (id: string, data: Partial<Router>) =>
    api.put<Router>(`/vlans/routers/${id}`, data).then((r) => r.data),
  deleteRouter: (id: string) => api.delete(`/vlans/routers/${id}`),

  listVlans: (routerId: string) =>
    api.get<VLAN[]>(`/vlans/routers/${routerId}/vlans`).then((r) => r.data),
  createVlan: (
    routerId: string,
    data: { vlan_id: number; name: string; description?: string },
  ) =>
    api
      .post<VLAN>(`/vlans/routers/${routerId}/vlans`, data)
      .then((r) => r.data),
  getVlan: (id: string) =>
    api.get<VLAN>(`/vlans/vlans/${id}`).then((r) => r.data),
  updateVlan: (
    id: string,
    data: { vlan_id?: number; name?: string; description?: string },
  ) => api.put<VLAN>(`/vlans/vlans/${id}`, data).then((r) => r.data),
  deleteVlan: (id: string) => api.delete(`/vlans/vlans/${id}`),
};

// ── DHCP ───────────────────────────────────────────────────────────────────

export interface DHCPServerGroupMember {
  id: string;
  name: string;
  driver: string;
  host: string;
  status: string;
  ha_state: string | null;
  ha_peer_url: string;
  agent_approved: boolean;
}

export interface DHCPServerGroup {
  id: string;
  name: string;
  description: string;
  // mode is the HA mode when the group has ≥ 2 Kea members:
  //   "hot-standby" | "load-balancing" | "standalone".
  mode: string;
  // #170 Wave C2 — supervisor-side container networking mode.
  // "host" = container shares host netns for L2 broadcasts (default).
  // "bridged" = container listens on host UDP/67 only (relayed
  // unicast deployments). Surfaces in the role-assignment UI on
  // the Approvals tab so the operator knows what they're picking.
  network_mode?: string;
  // #365 — Kea dhcp-socket-type selector. "direct" → raw sockets (hears
  // broadcast DISCOVERs from directly-attached clients; the default),
  // "relay" → udp sockets (relay-only). Per-daemon, so it lives on the
  // group and applies to every member Kea.
  dhcp_socket_mode?: "direct" | "relay";
  heartbeat_delay_ms: number;
  max_response_delay_ms: number;
  max_ack_delay_ms: number;
  max_unacked_clients: number;
  auto_failover: boolean;
  /** #637 — Kea lease cache. 0.0 = disabled (every renewal writes through,
   * the pre-Kea-3.0 behaviour). > 0 reuses leases without a DB write, which
   * suppresses the lease-events that drive DDNS + the IPAM lease mirror. */
  lease_cache_threshold: number;
  lease_cache_max_age: number | null;
  /** #980 — Kea `multi-threading.thread-pool-size`. 1 (the default) measured
   *  1.7x-2.9x more packets served than Kea's own auto-sizing, which starts
   *  one worker per HOST cpu regardless of the container's cgroup share and
   *  leaves them competing with the thread that drains the receive socket.
   *  0 hands sizing back to Kea. */
  kea_thread_pool_size: number;
  /** #980 — true (the default, and today's behaviour) logs every packet
   *  received and sent. False raises only `kea-dhcpN.packets` to WARN, worth
   *  ~1.3x more packets served on a constrained node, at the cost of the two
   *  log codes that carry the source address and receiving interface. */
  kea_packet_logging: boolean;
  // Number of Kea servers currently in the group. ≥ 2 means HA is
  // rendered into every peer's Kea config via libdhcp_ha.so.
  kea_member_count: number;
  // Member servers (rolled up by the /server-groups response).
  servers: DHCPServerGroupMember[];
  created_at: string;
  modified_at: string;
}

export interface DHCPServerGroupCreate {
  name: string;
  description?: string;
  mode?: "standalone" | "hot-standby" | "load-balancing";
  dhcp_socket_mode?: "direct" | "relay";
  heartbeat_delay_ms?: number;
  max_response_delay_ms?: number;
  max_ack_delay_ms?: number;
  max_unacked_clients?: number;
  auto_failover?: boolean;
  lease_cache_threshold?: number;
  lease_cache_max_age?: number | null;
  kea_thread_pool_size?: number;
  kea_packet_logging?: boolean;
}

export interface DHCPServer {
  id: string;
  server_group_id: string | null;
  name: string;
  description: string;
  driver: string;
  host: string;
  port: number;
  roles: string[];
  status: string;
  last_sync_at: string | null;
  last_health_check_at: string | null;
  agent_registered: boolean;
  agent_approved: boolean;
  agent_last_seen: string | null;
  /** Source IP of the most recent agent heartbeat — operator-visible
   *  to identify which host an agent runs on (the operator-set ``host``
   *  is just a label; doesn't reflect NAT / distributed deployments). */
  last_seen_ip: string | null;
  config_apply_status: ConfigApplyStatus | null;
  config_apply_error: string | null;
  config_failed_etag: string | null;
  config_apply_at: string | null;
  /** #1077 — push spool as last reported; `null` = never reported. */
  spool_status: AgentSpoolStatus | null;
  daemon_status: string | null;
  daemon_reason: string | null;
  daemon_status_since: string | null;
  /** #1067 — derived; render from this, see `DaemonStateFields`. */
  daemon_not_serving: boolean | null;
  agent_version: string | null;
  config_etag: string | null;
  config_pushed_at: string | null;
  // This server's OWN HA listener URL — empty for standalone servers.
  // The partner in the same group calls this URL for heartbeats +
  // lease updates. Rendered into the peer URL of Kea's HA hook.
  ha_peer_url?: string;
  // Populated by the agent's periodic status-get poll. Null for
  // standalone servers (group size < 2). Kea state names:
  // waiting / syncing / ready / normal / communications-interrupted /
  // partner-down / hot-standby / load-balancing / backup /
  // passive-backup / terminated.
  ha_state?: string | null;
  ha_last_heartbeat_at?: string | null;
  // True once Windows admin credentials have been stored on this server.
  // The password itself is never returned — set via `windows_credentials`
  // on the create/update body.
  has_credentials: boolean;
  // Driver runs from the control plane without a co-located agent
  // (windows_dhcp). Drives lease-pull visibility.
  is_agentless: boolean;
  // Driver only supports reads — UI hides config-push actions.
  is_read_only: boolean;
  // Non-secret FortiGate VDOM echoed back for cloud drivers so the edit
  // modal can show / change it without re-entering the token. Null for
  // non-cloud drivers.
  vdom?: string | null;
  // Non-secret TLS-verify flag echoed for cloud drivers so the edit modal
  // seeds the checkbox from the stored value instead of resetting it (which
  // would silently re-disable verification). Null for non-cloud drivers.
  verify_tls?: boolean | null;
  // Per-server maintenance mode (issue #182). When true the control
  // plane skips shipping pending DHCPConfigOp rows + suppresses the
  // heartbeat-stale alert; the UI renders an amber Maintenance chip.
  maintenance_mode: boolean;
  maintenance_started_at: string | null;
  maintenance_reason: string | null;
  created_at: string;
  modified_at: string;
}

export interface WindowsDHCPCredentials {
  username: string;
  password: string;
  winrm_port?: number;
  // Kerberos is not offered: the images carry no GSSAPI stack (#1128).
  transport?: "ntlm" | "basic" | "credssp";
  use_tls?: boolean;
  verify_tls?: boolean;
}

// FortiGate (driver='fortigate') agentless credentials — API token + VDOM.
// The token is never returned by the API; only `has_credentials` + the
// non-secret `vdom` come back. Sent via `cloud_credentials` on the
// create/update body.
export interface FortiGateCredentials {
  api_token?: string;
  vdom?: string;
  verify_tls?: boolean;
  // Optional PEM chain to pin a private-CA FortiGate without disabling
  // verification. Merged into the stored credential blob.
  ca_bundle_pem?: string;
}

// One FortiGate L3 interface + which managed scope its CIDR matches
// (preflight before a sync). From GET /dhcp/servers/{id}/fortigate-interfaces.
export interface FortiGateExistingDHCPServer {
  mkey: number | null;
  ip_range_count: number;
  reserved_count: number;
  option_count: number;
  // True when SpatiumDDI already owns this object (adopting is a no-op);
  // false means a plain sync would clobber operator-managed config.
  managed: boolean;
}

export interface FortiGateInterface {
  name: string;
  cidr: string;
  ip: string;
  netmask: string;
  status: string;
  alias: string;
  matched_subnet_id: string | null;
  matched_scope_id: string | null;
  // A pre-existing DHCP server on this interface, or null if none. Surfaced so
  // the operator sees the clobber risk before an adopt-and-sync.
  existing_dhcp_server: FortiGateExistingDHCPServer | null;
}

export interface DHCPLeaseSyncResult {
  server_leases: number;
  imported: number;
  refreshed: number;
  removed: number;
  ipam_created: number;
  ipam_refreshed: number;
  ipam_revoked: number;
  out_of_scope: number;
  scopes_imported: number;
  scopes_refreshed: number;
  scopes_skipped_no_subnet: number;
  pools_synced: number;
  statics_synced: number;
  pools_removed?: number;
  statics_removed?: number;
  mac_blocks_added?: number;
  mac_blocks_removed?: number;
  /** #1110 — scopes this server holds whose import belongs to another
   *  Windows member of its group (one member imports a shared scope). */
  scopes_deferred?: number;
  errors: string[];
  /** #1110 — standing conditions, not failures of this sync: a scope two
   *  Windows members serve uncoordinated, failover partners whose
   *  configuration drifted, a failover read that was denied. */
  warnings?: string[];
  // Present on the agent-based (Kea) no-op path: explains that leases stream
  // live and config converges via the agent, so there was nothing to pull.
  note?: string | null;
}

/** #1110 — how a group's Windows DHCP members serve one scope. Values of
 *  `services.dhcp.windows_failover.Verdict`, plus `no_windows_members`. */
export type DHCPServingVerdict =
  | "not_on_windows"
  | "single_server"
  | "failover"
  | "failover_one_sided"
  | "split_scope"
  | "uncoordinated"
  | "unknown"
  | "no_windows_members";

export interface DHCPScopeServingServer {
  server_id: string;
  server_name: string;
  /** null = this member's scopes have never been read — unknown, not "no". */
  holds: boolean | null;
  is_active: boolean | null;
  relationship_name: string | null;
  /** Several holders: does this member's config match the imported view? */
  in_sync: boolean | null;
  observed_at: string | null;
  stale: boolean;
  /** This member's view is the one the topology poll imports. */
  reconcile_owner: boolean;
}

export interface DHCPScopeServing {
  scope_id: string | null;
  cidr: string;
  verdict: DHCPServingVerdict;
  /** No two servers can hand out the same address under this verdict. */
  safe: boolean;
  detail: string;
  relationship_name: string | null;
  relationship_mode: string | null;
  drift: boolean | null;
  servers: DHCPScopeServingServer[];
}

export interface DHCPFailoverMember {
  server_id: string;
  server_name: string;
  host: string;
  scopes_observed_at: string | null;
  /** Last SUCCESSFUL failover read — null means never read, not "none". */
  failover_observed_at: string | null;
  failover_error: string | null;
  fresh: boolean;
  relationship_count: number;
}

export interface DHCPFailoverSide {
  server_id: string;
  server_name: string;
  partner_server: string;
  partner_server_id: string | null;
  server_role: string | null;
  state: string | null;
  load_balance_percent: number | null;
  reserve_percent: number | null;
  modified_at: string;
}

export interface DHCPFailoverRelationship {
  name: string;
  mode: string | null;
  max_client_lead_time_seconds: number | null;
  state_switch_interval_seconds: number | null;
  auto_state_transition: boolean | null;
  enable_auth: boolean | null;
  scope_ids: string[];
  sides: DHCPFailoverSide[];
  complete: boolean;
  partner_outside_group: string | null;
}

export interface DHCPGroupFailover {
  group_id: string;
  windows_member_count: number;
  /** Kea members of the same group — non-empty means a mixed group, where
   *  every active scope a Windows member also holds is served twice. */
  kea_members: string[];
  members: DHCPFailoverMember[];
  relationships: DHCPFailoverRelationship[];
  scopes: DHCPScopeServing[];
}

/** #1110 Phase 2 — relationship management. Every action runs one cmdlet on
 *  one member, which reaches the partner from there: the member's WinRM
 *  transport must be CredSSP, or the API answers 422. */
export type DHCPFailoverMode = "LoadBalance" | "HotStandby";

export interface DHCPFailoverTuning {
  server_role?: "Active" | "Standby" | null;
  load_balance_percent?: number | null;
  reserve_percent?: number | null;
  max_client_lead_time_seconds?: number | null;
  auto_state_transition?: boolean | null;
  state_switch_interval_seconds?: number | null;
  /** Sent to Windows, never stored or returned. */
  shared_secret?: string | null;
}

export interface DHCPFailoverRelationshipCreate extends DHCPFailoverTuning {
  name: string;
  server_id: string;
  partner_server_id: string;
  mode: DHCPFailoverMode;
  scope_ids: string[];
}

export interface DHCPFailoverRelationshipUpdate extends DHCPFailoverTuning {
  mode?: DHCPFailoverMode | null;
  /** The side the change runs on — required with a share or a role, which
   *  Windows applies to that server (the partner gets the complement). */
  server_id?: string | null;
}

export interface DHCPFailoverActionResult {
  action:
    | "create"
    | "update"
    | "delete"
    | "add_scopes"
    | "remove_scopes"
    | "replicate";
  relationship: string;
  ran_on_server_id: string;
  ran_on_server_name: string;
  partner_server_id: string | null;
  partner_server_name: string | null;
  scope_ids: string[];
  /** The action happened; re-reading a server afterwards did not. */
  warnings: string[];
  failover: DHCPGroupFailover;
}

export interface DHCPOption {
  code: number;
  name?: string;
  value: string | string[];
}

export interface DHCPScope {
  id: string;
  subnet_id: string;
  // Scopes belong to groups, not individual servers — every member of
  // the group renders the same Kea subnet4 config from this row.
  group_id: string;
  name: string;
  description: string;
  enabled: boolean;
  lease_time: number;
  min_lease_time: number | null;
  max_lease_time: number | null;
  /** #637 — per-scope Kea lease-cache override. null = inherit the group's
   * value. 0 is meaningful: caching explicitly disabled for this scope. */
  lease_cache_threshold: number | null;
  lease_cache_max_age: number | null;
  ddns_enabled: boolean;
  ddns_hostname_policy: string | null;
  // #784 — no ddns_domain_override. It never existed as a column; the DDNS
  // domain is resolved from the IPAM chain, most-specific-first: the
  // subnet, then up through its blocks, then the IP space.
  hostname_sync_mode: string;
  // When false, this scope's dynamic-pool lease mirrors are excluded from the
  // IPAM↔DNS drift check, so ephemeral pulled leases don't read as "out of sync".
  dns_track_dynamic_leases?: boolean;
  // "ipv4" → Kea Dhcp4; "ipv6" → Kea Dhcp6. Inferred from subnet CIDR.
  address_family?: "ipv4" | "ipv6";
  // DHCPv6 operating mode (issue #52). Only meaningful for ipv6 scopes.
  // "stateful" = DHCP hands out addresses; "stateless" = options only
  // (clients SLAAC their address); "slaac" = no DHCP address service.
  // ra_managed_flag / ra_other_flag are the intended Router-Advertisement
  // M/O flags — configured on the upstream router, not pushed by Kea.
  v6_address_mode?: "stateful" | "stateless" | "slaac";
  ra_managed_flag?: boolean;
  ra_other_flag?: boolean;
  // IPv6 Router Advertisement management (issue #524). When ra_enabled,
  // the DHCP ConfigBundle carries a rendered radvd.conf so the agent runs
  // radvd and actually emits RAs. M/O flags default-derived from
  // v6_address_mode unless ra_mo_override uses ra_managed_flag/ra_other_flag.
  ra_enabled?: boolean;
  ra_mo_override?: boolean;
  ra_router_lifetime?: number;
  ra_max_interval?: number;
  ra_prefix_valid_lifetime?: number;
  ra_prefix_preferred_lifetime?: number;
  ra_prefix_on_link?: boolean;
  ra_prefix_autonomous?: boolean;
  ra_interface?: string;
  // DHCP relay-agent (giaddr) IPs (issue #337). When non-empty, Kea
  // renders relay.ip-addresses on the subnet so a centralized server
  // selects this scope for relayed traffic from a remote, non-attached
  // subnet. Empty = direct-attach subnet selection (default).
  relay_addresses?: string[];
  options: DHCPOption[];
  // PXE / iPXE profile binding (issue #51). Null = no PXE on this
  // scope. Bound profile renders one Kea client-class per arch-match
  // on the next ConfigBundle push.
  pxe_profile_id?: string | null;
  created_at: string;
  modified_at: string;
}

// ── PXE / iPXE profiles (issue #51) ─────────────────────────────
//
// Group-scoped reusable provisioning profiles. Each profile carries
// ``next_server`` + N arch-matches. Operators bind a profile to a
// scope via ``DHCPScope.pxe_profile_id``; the Kea driver renders one
// client-class per arch-match.

/** DHCP option-93 (Client Architecture Type) lookup. Surfaced in
 * the UI's arch-codes multi-select. */
export const DHCP_PXE_ARCH_LABELS: Record<number, string> = {
  0: "BIOS / Legacy x86",
  6: "UEFI x86 (32-bit)",
  7: "UEFI x86-64",
  9: "UEFI x86-64 (alt)",
  10: "ARM 32-bit UEFI",
  11: "ARM 64-bit UEFI",
  15: "HTTP boot UEFI",
  16: "HTTP boot UEFI x86-64",
};

export type PXEMatchKind = "first_stage" | "ipxe_chain";

export interface PXEArchMatch {
  id: string;
  profile_id: string;
  priority: number;
  match_kind: PXEMatchKind;
  vendor_class_match: string | null;
  arch_codes: number[] | null;
  boot_filename: string;
  boot_file_url_v6: string | null;
  created_at: string;
  modified_at: string;
}

export interface PXEArchMatchInput {
  priority?: number;
  match_kind?: PXEMatchKind;
  vendor_class_match?: string | null;
  arch_codes?: number[] | null;
  boot_filename: string;
  boot_file_url_v6?: string | null;
}

export interface PXEProfile {
  id: string;
  group_id: string;
  name: string;
  description: string;
  next_server: string;
  enabled: boolean;
  tags: Record<string, unknown>;
  matches: PXEArchMatch[];
  created_at: string;
  modified_at: string;
}

export interface PXEProfileCreate {
  name: string;
  description?: string;
  next_server: string;
  enabled?: boolean;
  tags?: Record<string, unknown>;
  matches?: PXEArchMatchInput[];
}

export interface PXEProfileUpdate {
  name?: string;
  description?: string;
  next_server?: string;
  enabled?: boolean;
  tags?: Record<string, unknown>;
  matches?: PXEArchMatchInput[];
}

// ── VoIP phone profiles (issue #112 phase 1) ────────────────────────────

export interface VoIPVendorOption {
  code: number;
  name: string;
  kind: string;
  use: string;
}

export interface VoIPVendor {
  vendor: string;
  match_hint: string;
  description: string;
  options: VoIPVendorOption[];
}

export interface PhoneOption {
  code: number;
  name?: string | null;
  value: string;
}

export interface PhoneProfile {
  id: string;
  group_id: string;
  name: string;
  description: string;
  enabled: boolean;
  vendor: string | null;
  vendor_class_match: string | null;
  option_set: PhoneOption[];
  tags: Record<string, unknown>;
  scope_ids: string[];
  created_at: string;
  modified_at: string;
}

export interface PhoneProfileCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  vendor?: string | null;
  vendor_class_match?: string | null;
  option_set?: PhoneOption[];
  tags?: Record<string, unknown>;
  scope_ids?: string[];
}

export interface PhoneProfileUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  vendor?: string | null;
  vendor_class_match?: string | null;
  option_set?: PhoneOption[];
  tags?: Record<string, unknown>;
}

// ── DHCP ServerDetailModal payloads (issue #181) ────────────────────────────
// Mirrors the DNS side's per-server detail interfaces. The shapes match
// the DNS equivalents close enough that the modal's tab components feel
// identical to a DNS-familiar operator.
export interface DHCPPendingOpEntry {
  op_id: string;
  op_type: string;
  status: string;
  attempts: number;
  error_msg: string | null;
  created_at: string;
  acked_at: string | null;
}

export interface DHCPPendingOpsResponse {
  server_id: string;
  counts: Record<string, number>;
  items: DHCPPendingOpEntry[];
}

export interface DHCPServerEventEntry {
  id: string;
  timestamp: string;
  user_display_name: string;
  action: string;
  resource_type: string;
  resource_display: string;
  result: string;
}

export interface DHCPServerEventsResponse {
  server_id: string;
  items: DHCPServerEventEntry[];
}

export interface DHCPRenderedConfigResponse {
  server_id: string;
  driver: string;
  etag: string;
  rendered_at: string;
  config: string;
}

// Per-server lease-rate stats for the ServerDetailModal Stats tab (#195).
export type DHCPStatsRange = "1h" | "6h" | "24h" | "7d";

export interface DHCPRateBucket {
  ts: string;
  discover: number;
  offer: number;
  request: number;
  ack: number;
  nak: number;
  decline: number;
  release: number;
  /** #980 — packets lost, and where. `socket_drop` is the kernel dropping
   *  datagrams before the server could read them (its receive buffer filled;
   *  the node is short of CPU). `receive_drop` is the server reading a packet
   *  and discarding it. `null` means the agent did not measure it — too old,
   *  or unable to read /proc/net/udp — and must render as "not measured",
   *  never as 0. Zero is a measurement; null is the absence of one. */
  receive_drop: number | null;
  socket_drop: number | null;
}

export interface DHCPServerStatsResponse {
  leases_active: number;
  range: DHCPStatsRange;
  bucket_seconds: number;
  rate_buckets: DHCPRateBucket[];
}

export const dhcpApi = {
  listGroups: () =>
    api.get<DHCPServerGroup[]>("/dhcp/server-groups").then((r) => r.data),
  getGroup: (id: string) =>
    api.get<DHCPServerGroup>(`/dhcp/server-groups/${id}`).then((r) => r.data),
  createGroup: (data: DHCPServerGroupCreate) =>
    api.post<DHCPServerGroup>("/dhcp/server-groups", data).then((r) => r.data),
  updateGroup: (id: string, data: Partial<DHCPServerGroupCreate>) =>
    api
      .put<DHCPServerGroup>(`/dhcp/server-groups/${id}`, data)
      .then((r) => r.data),
  // #62: returns the full axios response (may be 202 queued-for-approval —
  // see ipamApi.deleteSpace). Do NOT add ``.then((r) => r.data)`` or the
  // 202 envelope is lost; callers pass it to ``handleApprovalQueued``.
  deleteGroup: (id: string) => api.delete(`/dhcp/server-groups/${id}`),
  // #1110 — Windows failover as the group's members report it (stored
  // observations from the topology poll, never a live read).
  getGroupFailover: (id: string) =>
    api
      .get<DHCPGroupFailover>(`/dhcp/server-groups/${id}/failover`)
      .then((r) => r.data),
  getScopeFailover: (scopeId: string) =>
    api
      .get<DHCPScopeServing>(`/dhcp/scopes/${scopeId}/failover`)
      .then((r) => r.data),
  createFailoverRelationship: (
    groupId: string,
    body: DHCPFailoverRelationshipCreate,
  ) =>
    api
      .post<DHCPFailoverActionResult>(
        `/dhcp/server-groups/${groupId}/failover/relationships`,
        body,
      )
      .then((r) => r.data),
  updateFailoverRelationship: (
    groupId: string,
    name: string,
    body: DHCPFailoverRelationshipUpdate,
  ) =>
    api
      .patch<DHCPFailoverActionResult>(
        `/dhcp/server-groups/${groupId}/failover/relationships/${encodeURIComponent(name)}`,
        body,
      )
      .then((r) => r.data),
  deleteFailoverRelationship: (
    groupId: string,
    name: string,
    keepServerId?: string,
  ) =>
    api
      .delete<DHCPFailoverActionResult>(
        `/dhcp/server-groups/${groupId}/failover/relationships/${encodeURIComponent(name)}`,
        { params: keepServerId ? { keep_server_id: keepServerId } : {} },
      )
      .then((r) => r.data),
  addFailoverScopes: (groupId: string, name: string, scopeIds: string[]) =>
    api
      .post<DHCPFailoverActionResult>(
        `/dhcp/server-groups/${groupId}/failover/relationships/${encodeURIComponent(name)}/scopes`,
        { scope_ids: scopeIds },
      )
      .then((r) => r.data),
  removeFailoverScope: (
    groupId: string,
    name: string,
    scopeId: string,
    keepServerId?: string,
  ) =>
    api
      .delete<DHCPFailoverActionResult>(
        `/dhcp/server-groups/${groupId}/failover/relationships/${encodeURIComponent(name)}/scopes/${encodeURIComponent(scopeId)}`,
        { params: keepServerId ? { keep_server_id: keepServerId } : {} },
      )
      .then((r) => r.data),
  replicateFailover: (
    groupId: string,
    name: string,
    sourceServerId: string,
    scopeIds: string[] = [],
  ) =>
    api
      .post<DHCPFailoverActionResult>(
        `/dhcp/server-groups/${groupId}/failover/relationships/${encodeURIComponent(name)}/replicate`,
        { source_server_id: sourceServerId, scope_ids: scopeIds },
      )
      .then((r) => r.data),

  listServers: (groupId?: string) =>
    api
      .get<DHCPServer[]>("/dhcp/servers")
      .then((r) =>
        groupId ? r.data.filter((s) => s.server_group_id === groupId) : r.data,
      ),
  getServer: (id: string) =>
    api.get<DHCPServer>(`/dhcp/servers/${id}`).then((r) => r.data),
  createServer: (data: Partial<DHCPServer>) =>
    api.post<DHCPServer>("/dhcp/servers", data).then((r) => r.data),
  updateServer: (id: string, data: Partial<DHCPServer>) =>
    api.put<DHCPServer>(`/dhcp/servers/${id}`, data).then((r) => r.data),
  deleteServer: (id: string) => api.delete(`/dhcp/servers/${id}`),
  // `adoptExisting` (cloud/FortiGate only) opts in to overwriting a
  // pre-existing provider DHCP object SpatiumDDI never created; without it a
  // clobber-risk sync returns 409.
  syncServer: (id: string, adoptExisting = false) =>
    api
      .post<{
        status: string;
        op_id: string;
        etag: string;
      }>(
        `/dhcp/servers/${id}/sync${adoptExisting ? "?adopt_existing=true" : ""}`,
      )
      .then((r) => r.data),
  syncLeasesNow: (id: string) =>
    api
      .post<DHCPLeaseSyncResult>(`/dhcp/servers/${id}/sync-leases`)
      .then((r) => r.data),
  testWindowsCredentials: (body: {
    host: string;
    credentials?: WindowsDHCPCredentials;
    server_id?: string;
  }) =>
    api
      .post<{
        ok: boolean;
        message: string;
      }>("/dhcp/servers/test-windows-credentials", body)
      .then((r) => r.data),
  testFortigateCredentials: (body: {
    host?: string;
    port?: number;
    credentials?: FortiGateCredentials;
    server_id?: string;
  }) =>
    api
      .post<{
        ok: boolean;
        message: string;
      }>("/dhcp/servers/test-fortigate-credentials", body)
      .then((r) => r.data),
  getFortigateInterfaces: (id: string) =>
    api
      .get<FortiGateInterface[]>(`/dhcp/servers/${id}/fortigate-interfaces`)
      .then((r) => r.data),
  approveServer: (id: string) =>
    api.post<DHCPServer>(`/dhcp/servers/${id}/approve`).then((r) => r.data),
  // Issue #182: per-server maintenance mode. ``reason`` is optional but
  // strongly encouraged so the audit trail captures *why* a server
  // went offline. ``resumeServer`` takes no body — that path is
  // single-purpose.
  pauseServer: (id: string, reason?: string) =>
    api
      .post<DHCPServer>(`/dhcp/servers/${id}/pause`, {
        reason: reason ?? null,
      })
      .then((r) => r.data),
  resumeServer: (id: string) =>
    api.post<DHCPServer>(`/dhcp/servers/${id}/resume`).then((r) => r.data),
  getLeases: (
    id: string,
    params?: {
      search?: string;
      state?: string;
      device_class?: string;
      page?: number;
      page_size?: number;
    },
  ) =>
    api
      .get<Page<DHCPLease>>(`/dhcp/servers/${id}/leases`, { params })
      .then((r) => r.data),
  // Delete a single lease + its auto_from_lease IPAM mirror (SuperAdmin, #478).
  // A still-live lease may be re-learned on the next poll — durable only once
  // its scope/device is gone (the scope-delete path handles that automatically).
  deleteLease: (serverId: string, leaseId: string) =>
    api.delete(`/dhcp/servers/${serverId}/leases/${leaseId}`),

  // Per-server detail (powers the DHCP ServerDetailModal — issue #181)
  getServerPendingOps: (serverId: string, limit = 50) =>
    api
      .get<DHCPPendingOpsResponse>(
        `/dhcp/servers/${serverId}/pending-ops?limit=${limit}`,
      )
      .then((r) => r.data),
  getServerRecentEvents: (serverId: string, limit = 50) =>
    api
      .get<DHCPServerEventsResponse>(
        `/dhcp/servers/${serverId}/recent-events?limit=${limit}`,
      )
      .then((r) => r.data),
  getServerRenderedConfig: (serverId: string) =>
    api
      .get<DHCPRenderedConfigResponse>(
        `/dhcp/servers/${serverId}/rendered-config`,
      )
      .then((r) => r.data),
  // Lease-rate timeseries + active lease count for the Stats tab (#195).
  serverStats: (serverId: string, range: DHCPStatsRange = "1h") =>
    api
      .get<DHCPServerStatsResponse>(`/dhcp/servers/${serverId}/stats`, {
        params: { range },
      })
      .then((r) => r.data),

  listScopesBySubnet: (subnetId: string, params?: { tag?: string[] }) =>
    api
      .get<DHCPScope[]>(`/dhcp/subnets/${subnetId}/dhcp-scopes`, { params })
      .then((r) => r.data),
  listScopesByGroup: (groupId: string, params?: { tag?: string[] }) =>
    api
      .get<DHCPScope[]>(`/dhcp/server-groups/${groupId}/scopes`, { params })
      .then((r) => r.data),
  getScope: (id: string) =>
    api.get<DHCPScope>(`/dhcp/scopes/${id}`).then((r) => r.data),
  // `adoptExisting` (cloud/FortiGate groups only, #865) opts in to
  // overwriting a provider DHCP object SpatiumDDI never created; without it
  // such a save 409s with an X-Adoption-Required header (see
  // isAdoptionRequired) so the modal can offer an adopt-and-retry.
  createScope: (
    subnetId: string,
    data: Partial<DHCPScope>,
    adoptExisting = false,
  ) =>
    api
      .post<DHCPScope>(
        `/dhcp/subnets/${subnetId}/dhcp-scopes${adoptExisting ? "?adopt_existing=true" : ""}`,
        data,
      )
      .then((r) => r.data),
  updateScope: (id: string, data: Partial<DHCPScope>, adoptExisting = false) =>
    api
      .put<DHCPScope>(
        `/dhcp/scopes/${id}${adoptExisting ? "?adopt_existing=true" : ""}`,
        data,
      )
      .then((r) => r.data),
  // #62: returns the full axios response (may be 202 queued-for-approval —
  // see ipamApi.deleteSpace). Do NOT add ``.then((r) => r.data)``.
  deleteScope: (id: string) => api.delete(`/dhcp/scopes/${id}`),

  listPools: (scopeId: string) =>
    api.get<DHCPPool[]>(`/dhcp/scopes/${scopeId}/pools`).then((r) => r.data),
  createPool: (scopeId: string, data: Partial<DHCPPool>) =>
    api
      .post<DHCPPool>(`/dhcp/scopes/${scopeId}/pools`, data)
      .then((r) => r.data),
  updatePool: (_scopeId: string, poolId: string, data: Partial<DHCPPool>) =>
    api.put<DHCPPool>(`/dhcp/pools/${poolId}`, data).then((r) => r.data),
  deletePool: (_scopeId: string, poolId: string) =>
    api.delete(`/dhcp/pools/${poolId}`),

  // Live pool occupancy (#913). Assigned unions active leases with in-pool
  // static reservations, so a reserved-but-offline address counts as taken.
  // Dynamic pools only: the scope call omits every other type and the
  // per-pool one 422s, because a percentage full is not a fact about an
  // excluded range, a reserved range is supposed to fill up, and a pd
  // pool's start/end are placeholders rather than a range.
  poolOccupancy: (poolId: string) =>
    api
      .get<DHCPPoolOccupancy>(`/dhcp/pools/${poolId}/occupancy`)
      .then((r) => r.data),
  scopePoolOccupancy: (scopeId: string) =>
    api
      .get<DHCPPoolOccupancy[]>(`/dhcp/scopes/${scopeId}/pools/occupancy`)
      .then((r) => r.data),
  // Fleet-wide, fullest first (#942) — one round trip whose cost does not
  // grow with the number of scopes. Same dynamic-only filter as above.
  fleetPoolOccupancy: (limit = 10) =>
    api
      .get<DHCPFleetPoolOccupancy>("/dhcp/pools/occupancy", {
        params: { limit },
      })
      .then((r) => r.data),

  // Rogue-DHCP observed responders (#370).
  listResponders: (groupId: string, classification?: string) =>
    api
      .get<DHCPObservedResponder[]>(`/dhcp/groups/${groupId}/responders`, {
        params: classification ? { classification } : undefined,
      })
      .then((r) => r.data),
  acknowledgeResponder: (groupId: string, responderId: string, note = "") =>
    api
      .post<DHCPObservedResponder>(
        `/dhcp/groups/${groupId}/responders/${responderId}/acknowledge`,
        { note },
      )
      .then((r) => r.data),

  // IPv6 Router Advertisements + rogue-RA (#524).
  raConfigPreview: (groupId: string) =>
    api
      .get<RAConfigPreview>(`/dhcp/ra/groups/${groupId}/ra-config`)
      .then((r) => r.data),
  listObservedRARouters: (groupId: string, classification?: string) =>
    api
      .get<RAObservedRouter[]>(`/dhcp/ra/groups/${groupId}/observed-routers`, {
        params: classification ? { classification } : undefined,
      })
      .then((r) => r.data),
  acknowledgeRARouter: (groupId: string, routerId: string, note = "") =>
    api
      .post<RAObservedRouter>(
        `/dhcp/ra/groups/${groupId}/observed-routers/${routerId}/acknowledge`,
        { note },
      )
      .then((r) => r.data),
  listRAAllowlist: (groupId: string) =>
    api
      .get<RARouterAllowlist[]>(`/dhcp/ra/groups/${groupId}/ra-allowlist`)
      .then((r) => r.data),
  createRAAllowlist: (
    groupId: string,
    body: { source_ip?: string; source_mac?: string; note?: string },
  ) =>
    api
      .post<RARouterAllowlist>(`/dhcp/ra/groups/${groupId}/ra-allowlist`, body)
      .then((r) => r.data),
  deleteRAAllowlist: (groupId: string, entryId: string) =>
    api.delete(`/dhcp/ra/groups/${groupId}/ra-allowlist/${entryId}`),

  listStatics: (scopeId: string, params?: { tag?: string[] }) =>
    api
      .get<DHCPStaticAssignment[]>(`/dhcp/scopes/${scopeId}/statics`, {
        params,
      })
      .then((r) => r.data),
  createStatic: (scopeId: string, data: DHCPStaticAssignmentWrite) =>
    api
      .post<DHCPStaticAssignment>(`/dhcp/scopes/${scopeId}/statics`, data)
      .then((r) => r.data),
  updateStatic: (
    _scopeId: string,
    staticId: string,
    data: DHCPStaticAssignmentWrite,
  ) =>
    api
      .put<DHCPStaticAssignment>(`/dhcp/statics/${staticId}`, data)
      .then((r) => r.data),
  deleteStatic: (_scopeId: string, staticId: string) =>
    api.delete(`/dhcp/statics/${staticId}`),

  listClientClasses: (groupId: string) =>
    api
      .get<DHCPClientClass[]>(`/dhcp/server-groups/${groupId}/client-classes`)
      .then((r) => r.data),
  createClientClass: (groupId: string, data: Partial<DHCPClientClass>) =>
    api
      .post<DHCPClientClass>(
        `/dhcp/server-groups/${groupId}/client-classes`,
        data,
      )
      .then((r) => r.data),
  updateClientClass: (
    _groupId: string,
    classId: string,
    data: Partial<DHCPClientClass>,
  ) =>
    api
      .put<DHCPClientClass>(`/dhcp/client-classes/${classId}`, data)
      .then((r) => r.data),
  deleteClientClass: (_groupId: string, classId: string) =>
    api.delete(`/dhcp/client-classes/${classId}`),

  // #700 — fingerprint-driven device policies. These COMPILE INTO client
  // classes; they are not a parallel mechanism. The preview call is what
  // keeps the generated match expression from being a black box.
  listDevicePolicies: (groupId: string) =>
    api
      .get<DHCPDevicePolicy[]>(`/dhcp/server-groups/${groupId}/device-policies`)
      .then((r) => r.data),
  createDevicePolicy: (groupId: string, data: Partial<DHCPDevicePolicy>) =>
    api
      .post<DHCPDevicePolicy>(
        `/dhcp/server-groups/${groupId}/device-policies`,
        data,
      )
      .then((r) => r.data),
  updateDevicePolicy: (policyId: string, data: Partial<DHCPDevicePolicy>) =>
    api
      .put<DHCPDevicePolicy>(`/dhcp/device-policies/${policyId}`, data)
      .then((r) => r.data),
  deleteDevicePolicy: (policyId: string) =>
    api.delete(`/dhcp/device-policies/${policyId}`),
  previewDevicePolicy: (policyId: string) =>
    api
      .get<DHCPDevicePolicyPreview>(`/dhcp/device-policies/${policyId}/preview`)
      .then((r) => r.data),
  listDeviceObservations: (groupId: string) =>
    api
      .get<DHCPDeviceObservations>(
        `/dhcp/server-groups/${groupId}/device-observations`,
      )
      .then((r) => r.data),

  listOptionCodes: (q?: string) =>
    api
      .get<DHCPOptionCodeDef[]>("/dhcp/option-codes", {
        params: q ? { q } : undefined,
      })
      .then((r) => r.data),

  listOptionTemplates: (groupId: string) =>
    api
      .get<
        DHCPOptionTemplate[]
      >(`/dhcp/server-groups/${groupId}/option-templates`)
      .then((r) => r.data),
  createOptionTemplate: (groupId: string, data: DHCPOptionTemplateWrite) =>
    api
      .post<DHCPOptionTemplate>(
        `/dhcp/server-groups/${groupId}/option-templates`,
        data,
      )
      .then((r) => r.data),
  updateOptionTemplate: (
    _groupId: string,
    templateId: string,
    data: Partial<DHCPOptionTemplateWrite>,
  ) =>
    api
      .put<DHCPOptionTemplate>(`/dhcp/option-templates/${templateId}`, data)
      .then((r) => r.data),
  deleteOptionTemplate: (_groupId: string, templateId: string) =>
    api.delete(`/dhcp/option-templates/${templateId}`),
  applyOptionTemplate: (
    scopeId: string,
    data: { template_id: string; mode?: "merge" | "replace" },
  ) =>
    api
      .post<DHCPApplyTemplateResponse>(
        `/dhcp/scopes/${scopeId}/apply-option-template`,
        data,
      )
      .then((r) => r.data),

  // ── PXE / iPXE profiles (issue #51) ──────────────────────────────
  listPxeProfiles: (groupId: string) =>
    api
      .get<PXEProfile[]>(`/dhcp/server-groups/${groupId}/pxe-profiles`)
      .then((r) => r.data),
  getPxeProfile: (profileId: string) =>
    api.get<PXEProfile>(`/dhcp/pxe-profiles/${profileId}`).then((r) => r.data),
  createPxeProfile: (groupId: string, body: PXEProfileCreate) =>
    api
      .post<PXEProfile>(`/dhcp/server-groups/${groupId}/pxe-profiles`, body)
      .then((r) => r.data),
  updatePxeProfile: (profileId: string, body: PXEProfileUpdate) =>
    api
      .put<PXEProfile>(`/dhcp/pxe-profiles/${profileId}`, body)
      .then((r) => r.data),
  deletePxeProfile: (profileId: string) =>
    api.delete(`/dhcp/pxe-profiles/${profileId}`),

  // ── VoIP phone profiles (issue #112 phase 1) ────────────────────────
  listVoipVendors: () =>
    api.get<VoIPVendor[]>(`/dhcp/voip-options`).then((r) => r.data),
  listPhoneProfiles: (groupId: string) =>
    api
      .get<PhoneProfile[]>(`/dhcp/server-groups/${groupId}/phone-profiles`)
      .then((r) => r.data),
  createPhoneProfile: (groupId: string, body: PhoneProfileCreate) =>
    api
      .post<PhoneProfile>(`/dhcp/server-groups/${groupId}/phone-profiles`, body)
      .then((r) => r.data),
  updatePhoneProfile: (profileId: string, body: PhoneProfileUpdate) =>
    api
      .put<PhoneProfile>(`/dhcp/phone-profiles/${profileId}`, body)
      .then((r) => r.data),
  deletePhoneProfile: (profileId: string) =>
    api.delete(`/dhcp/phone-profiles/${profileId}`),
  setPhoneProfileScopes: (profileId: string, scope_ids: string[]) =>
    api
      .put<PhoneProfile>(`/dhcp/phone-profiles/${profileId}/scopes`, {
        scope_ids,
      })
      .then((r) => r.data),
  seedPhoneProfileStarterPack: (groupId: string) =>
    api
      .post<
        PhoneProfile[]
      >(`/dhcp/server-groups/${groupId}/phone-profiles/seed-starter-pack`)
      .then((r) => r.data),

  listMacBlocks: (groupId: string) =>
    api
      .get<DHCPMACBlock[]>(`/dhcp/server-groups/${groupId}/mac-blocks`)
      .then((r) => r.data),
  createMacBlock: (groupId: string, data: DHCPMACBlockWrite) =>
    api
      .post<DHCPMACBlock>(`/dhcp/server-groups/${groupId}/mac-blocks`, data)
      .then((r) => r.data),
  updateMacBlock: (
    _groupId: string,
    blockId: string,
    data: Partial<DHCPMACBlockWrite>,
  ) =>
    api
      .put<DHCPMACBlock>(`/dhcp/mac-blocks/${blockId}`, data)
      .then((r) => r.data),
  deleteMacBlock: (_groupId: string, blockId: string) =>
    api.delete(`/dhcp/mac-blocks/${blockId}`),
};

// ── New-device watch (issue #459) ──────────────────────────────────────
// arpwatch-style first-seen MAC tracking. The whole surface is gated by
// the (default-off) ``security.new_device_watch`` feature module — every
// endpoint 404s when the module is off, so callers must gate their
// queries on ``useFeatureModules().enabled("security.new_device_watch")``.

export type NewDeviceClassification = "new" | "acknowledged" | "known";
export type NewDeviceSource = "dhcp_lease" | "snmp" | "sweep" | "l2_sniff";

export interface NewDeviceSummary {
  new_count: number;
  new_randomized_count: number;
  new_last_24h: number;
  acknowledged_count: number;
  known_count: number;
  allowlist_count: number;
}

export interface NewDeviceSighting {
  id: string;
  ip_address_id: string;
  ip_address: string;
  subnet_id: string | null;
  subnet_name: string | null;
  mac_address: string;
  oui_vendor: string | null;
  classification: NewDeviceClassification;
  source: NewDeviceSource;
  is_randomized: boolean;
  first_seen: string;
  last_seen: string;
  acknowledged_at: string | null;
}

export interface NewDeviceAllowlistEntry {
  id: string;
  mac_address: string | null;
  oui_prefix: string | null;
  note: string;
  is_builtin: boolean;
  created_at: string;
}

export interface NewDeviceAllowlistResult {
  entry: NewDeviceAllowlistEntry;
  reclassified_count: number;
}

export interface NewDeviceBlockResult {
  mac_address: string;
  blocked_group_ids: string[];
  already_blocked_group_ids: string[];
  // #601 — set when ``block_upstream`` also pushed an L2 quarantine into
  // the active block-sync set (or queued it for two-person approval).
  upstream_block_created: boolean;
  upstream_change_request_id: string | null;
}

export const newDeviceApi = {
  summary: () =>
    api.get<NewDeviceSummary>("/new-devices/summary").then((r) => r.data),

  listSightings: (params?: {
    classification?: NewDeviceClassification;
    subnet_id?: string;
    since_hours?: number;
    include_randomized?: boolean;
    search?: string;
    page?: number;
    page_size?: number;
  }) =>
    api
      .get<Page<NewDeviceSighting>>("/new-devices/sightings", { params })
      .then((r) => r.data),

  acknowledge: (sightingId: string, note?: string) =>
    api
      .post<NewDeviceSighting>(
        `/new-devices/sightings/${sightingId}/acknowledge`,
        {
          note,
        },
      )
      .then((r) => r.data),

  baseline: () =>
    api
      .post<{ reclassified_count: number }>("/new-devices/baseline")
      .then((r) => r.data),

  listAllowlist: () =>
    api
      .get<NewDeviceAllowlistEntry[]>("/new-devices/allowlist")
      .then((r) => r.data),

  addAllowlist: (data: {
    mac_address?: string;
    oui_prefix?: string;
    note?: string;
  }) =>
    api
      .post<NewDeviceAllowlistResult>("/new-devices/allowlist", data)
      .then((r) => r.data),

  addVirtDefaults: () =>
    api
      .post<{
        added: number;
        skipped: number;
      }>("/new-devices/allowlist/virt-defaults")
      .then((r) => r.data),

  deleteAllowlist: (id: string) => api.delete(`/new-devices/allowlist/${id}`),

  block: (data: {
    mac_address: string;
    group_id?: string;
    reason?: string;
    description?: string;
    // #601 — also push an L2 quarantine to armed UniFi block-sync targets.
    // Only meaningful when the ``security.block_sync`` module is enabled.
    block_upstream?: boolean;
  }) =>
    api
      .post<NewDeviceBlockResult>("/new-devices/block", data)
      .then((r) => r.data),
};

/** Live occupancy of one address-range DHCP pool (#913). */
export interface DHCPPoolOccupancy {
  pool_id: string;
  scope_id: string;
  pool_name: string;
  start_ip: string;
  end_ip: string;
  pool_type: string;
  total: number;
  assigned: number;
  free: number;
  percent: number;
  /** Derived from mirrored lease rows, so its freshness follows the last lease pull. */
  computed_at: string;
}

/** One row of the fleet-wide occupancy rollup (#942) — a pool plus the
 *  context needed to identify it without a follow-up call. */
export interface DHCPFleetPoolOccupancyRow extends DHCPPoolOccupancy {
  scope_name: string;
  scope_is_active: boolean;
  subnet_network: string | null;
  group_id: string;
  group_name: string;
}

export interface DHCPFleetPoolOccupancy {
  computed_at: string;
  /** Every dynamic pool considered, not just the returned slice. */
  pool_count: number;
  pools_warning: number;
  pools_critical: number;
  /** Distinct (scope, address) pairs on an active lease, fleet-wide. */
  active_lease_count: number;
  pools: DHCPFleetPoolOccupancyRow[];
}

export interface DHCPPool {
  id: string;
  scope_id: string;
  name: string;
  start_ip: string;
  end_ip: string;
  pool_type: string; // "dynamic" | "excluded" | "reserved" | "pd"
  class_restriction: string | null;
  lease_time_override: number | null;
  options_override: Record<string, unknown> | null;
  // DHCPv6 prefix delegation (#368) — only set for pool_type === "pd".
  pd_prefix?: string | null;
  delegated_length?: number | null;
  excluded_prefix?: string | null;
  // Populated by create/update only: IPs already allocated inside this
  // range, so the modal can surface a confirmation before overwriting.
  existing_ips_in_range?:
    | {
        address: string;
        status: string;
        hostname: string;
      }[]
    | null;
  created_at: string;
  modified_at: string;
}

/**
 * Fields the reservation create/update API actually accepts.
 *
 * Deliberately NOT `Partial<DHCPStaticAssignment>`: that includes `scope_id`,
 * which the API refuses. A reservation cannot be re-pointed at another scope —
 * the scope is part of its identity (uniqueness is keyed on it, and Kea renders
 * the reservation nested inside the scope's subnet stanza). The backend used to
 * drop a stray `scope_id` silently; it now 422s (#619), so the payload type has
 * to be honest about what is sendable.
 */
export type DHCPStaticAssignmentWrite = Partial<
  Pick<
    DHCPStaticAssignment,
    | "ip_address"
    | "mac_address"
    | "hostname"
    | "description"
    | "client_id"
    | "duid"
    | "options_override"
    | "ip_address_id"
  >
> & { tags?: Record<string, unknown> };

export interface DHCPStaticAssignment {
  id: string;
  scope_id: string;
  ip_address: string;
  mac_address: string;
  hostname: string;
  description: string;
  client_id: string | null;
  // DHCPv6 DUID (#368) — keys the reservation on a v6 scope.
  duid?: string | null;
  options_override: Record<string, unknown> | null;
  ip_address_id: string | null;
  created_at: string;
  modified_at: string;
}

/** A DHCP server observed answering on a managed segment (#370). */
export interface DHCPObservedResponder {
  id: string;
  group_id: string;
  server_identifier: string;
  source_ip: string;
  source_mac: string | null;
  giaddr: string | null;
  offered_ip: string | null;
  classification: string; // "expected" | "acknowledged" | "rogue"
  first_seen_at: string;
  last_seen_at: string;
}

/** An IPv6 router observed emitting a Router Advertisement (#524). */
export interface RAObservedRouter {
  id: string;
  group_id: string;
  source_ip: string;
  source_mac: string | null;
  prefixes: string[];
  managed_flag: boolean;
  other_flag: boolean;
  router_lifetime: number | null;
  iface: string | null;
  classification: string; // "expected" | "acknowledged" | "rogue"
  first_seen_at: string;
  last_seen_at: string;
}

/** An operator-approved expected RA source router (#524). */
export interface RARouterAllowlist {
  id: string;
  group_id: string;
  source_ip: string | null;
  source_mac: string | null;
  note: string;
}

/** One RA-enabled scope's resolved radvd config (#524). */
export interface RAScopeConfig {
  scope_id: string;
  subnet_id: string;
  subnet_cidr: string;
  interface: string;
  managed_flag: boolean;
  other_flag: boolean;
  router_lifetime: number;
  prefix_valid_lifetime: number;
  prefix_preferred_lifetime: number;
  prefix_on_link: boolean;
  prefix_autonomous: boolean;
  rdnss: string[];
  dnssl: string[];
}

export interface RAConfigPreview {
  group_id: string;
  scopes: RAScopeConfig[];
  radvd_conf: string;
}

export interface DHCPClientClass {
  id: string;
  // Under the group-centric model, classes belong to a server group —
  // every member renders the same classes into its Kea config.
  group_id: string;
  name: string;
  description: string;
  match_expression: string;
  options: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

// #700 — fingerprint-driven device policy. ``class_name`` is the Kea client
// class this compiles to; a pool's ``class_restriction`` binds to that string,
// which is why it is stable across renames rather than derived from ``name``.
export interface DHCPDevicePolicy {
  id: string;
  group_id: string;
  name: string;
  description: string;
  enabled: boolean;
  class_name: string;
  device_classes: string[];
  options: Record<string, unknown>;
  lease_time: number | null;
  match_override: string | null;
  include_ambiguous: boolean;
  priority: number;
  created_at: string;
  modified_at: string;
}

export interface DHCPDeviceSignature {
  option_55: string | null;
  option_60: string | null;
}

export interface DHCPDevicePolicyPreview {
  policy_id: string;
  class_name: string;
  expression: string;
  source: string;
  compiled_expression: string;
  signature_count: number;
  confidence: number | null;
  signatures: DHCPDeviceSignature[];
  ambiguous_signatures: DHCPDeviceSignature[];
  ambiguous_excluded: boolean;
  truncated: number;
  max_signature_terms: number;
  matched_macs: string[];
  matched_macs_truncated: boolean;
  matched_device_count: number;
  unclassified_matches: number;
  warnings: string[];
  renders: boolean;
}

export interface DHCPDeviceObservation {
  device_class: string;
  device_count: number;
  signature_count: number;
  // Fingerbank's own 0-100 confidence. A low score usually means it fell
  // back to the MAC vendor rather than identifying the device, so the
  // class groups unrelated hardware — worth showing next to the name.
  best_score: number | null;
  avg_score: number | null;
}

export interface DHCPDeviceObservations {
  classes: DHCPDeviceObservation[];
  unclassified_devices: number;
  total_devices: number;
  note: string;
}

export interface DHCPOptionCodeDef {
  code: number;
  name: string;
  kind: string;
  description: string;
  rfc?: string | null;
}

export interface DHCPOptionTemplate {
  id: string;
  group_id: string;
  name: string;
  description: string;
  address_family: "ipv4" | "ipv6";
  options: Record<string, string | string[]>;
  created_at: string;
  modified_at: string;
}

export interface DHCPOptionTemplateWrite {
  name: string;
  description?: string;
  address_family?: "ipv4" | "ipv6";
  options?: Record<string, string | string[]>;
}

export interface DHCPApplyTemplateResponse {
  scope_id: string;
  options: Record<string, string | string[]>;
  overwritten_keys: string[];
}

export type DHCPMACBlockReason =
  | "rogue"
  | "lost_stolen"
  | "quarantine"
  | "policy"
  | "other";

export interface DHCPMACBlockIPAMMatch {
  ip_address: string;
  subnet_cidr: string;
  hostname: string;
  description: string;
}

export interface DHCPMACBlock {
  id: string;
  group_id: string;
  mac_address: string;
  reason: DHCPMACBlockReason;
  description: string;
  enabled: boolean;
  expires_at: string | null;
  created_at: string;
  modified_at: string;
  created_by_user_id: string | null;
  updated_by_user_id: string | null;
  last_match_at: string | null;
  match_count: number;
  vendor: string | null;
  ipam_matches: DHCPMACBlockIPAMMatch[];
}

export interface DHCPMACBlockWrite {
  mac_address?: string;
  reason?: DHCPMACBlockReason;
  description?: string;
  enabled?: boolean;
  expires_at?: string | null;
}

export interface DHCPLease {
  id: string;
  server_id: string;
  scope_id: string | null;
  ip_address: string;
  // null on most DHCPv6 leases, which are identified by DUID + IAID (#1141).
  mac_address: string | null;
  duid?: string | null;
  iaid?: number | null;
  hostname: string | null;
  state: string; // "active" | "expired" | "released" | "abandoned"
  starts_at: string | null;
  ends_at: string | null;
  expires_at: string | null;
  last_seen_at: string;
  vendor?: string | null;
  // Issue #112 phase 3 — flag from the curated VoIP-phone vendor list.
  // Drives a Phone icon next to the lease's MAC in the lease table.
  is_voip_phone?: boolean;
  // Fingerbank passive-fingerprinting device classification (#373), joined
  // from dhcp_fingerprint by MAC. All null/undefined when no fingerprint
  // exists (fingerprinting off / unconfigured / not-yet-looked-up).
  device_class?: string | null;
  device_name?: string | null;
  device_manufacturer?: string | null;
  fingerbank_score?: number | null;
}

export interface PublicAuthProvider {
  id: string;
  name: string;
  type: AuthProviderType;
}

/** One effective permission triple the calling credential resolves to.
 *  `resource_id === null` means "any instance" of `resource_type`. */
export interface PermissionGrant {
  action: string;
  resource_type: string;
  resource_id: string | null;
}

/** Self-introspection of the calling credential's effective permissions
 *  (`GET /auth/me/permissions`). When `is_superadmin` is true, callers
 *  short-circuit and never inspect `grants`. */
export interface MyPermissions {
  is_superadmin: boolean;
  grants: PermissionGrant[];
}

export const authApi = {
  // withCredentials on the auth calls so the browser stores (login/mfa/
  // refresh) and returns (refresh/logout) the HttpOnly refresh cookie on a
  // cross-ORIGIN same-site API host with CORS credentials enabled (#484). The
  // cookie is path-scoped to /api/v1/auth, so it never rides ordinary API
  // requests. NOTE: the cookie is SameSite=Strict — a genuinely cross-SITE
  // SPA/API split (different registrable domains) can't send it and is out of
  // scope; the default same-origin (nginx-proxied) deployment is unaffected.
  login: (username: string, password: string) =>
    api
      .post<LoginResponse>(
        "/auth/login",
        { username, password },
        { withCredentials: true },
      )
      .then((r) => r.data),
  /** Complete a TOTP-gated login. Submit either ``code`` (6-digit
   * authenticator) or ``recovery_code``; submitting both 422s. */
  loginMfa: (
    mfa_token: string,
    body: { code?: string; recovery_code?: string },
  ) =>
    api
      .post<LoginResponse>(
        "/auth/login/mfa",
        { mfa_token, ...body },
        { withCredentials: true },
      )
      .then((r) => r.data),
  publicProviders: () =>
    api.get<PublicAuthProvider[]>("/auth/providers").then((r) => r.data),
  /** Public read of the active password policy. Returned unauthenticated
   *  so the login + change-password forms can render the rule list
   *  before the user even submits. */
  passwordPolicy: () =>
    api.get<PasswordPolicy>("/auth/password-policy").then((r) => r.data),
  logout: () => api.post("/auth/logout", undefined, { withCredentials: true }),
  /** Exchange the HttpOnly refresh cookie for a fresh access token. No
   *  argument — the cookie rides the request automatically (#484). */
  refresh: () =>
    api
      .post<RefreshResponse>("/auth/refresh", {}, { withCredentials: true })
      .then((r) => r.data),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post("/auth/change-password", {
      current_password: currentPassword,
      new_password: newPassword,
    }),
  me: () =>
    api
      .get<{
        id: string;
        username: string;
        email: string;
        display_name: string;
        is_superadmin: boolean;
        force_password_change: boolean;
        auth_source: string;
      }>("/auth/me")
      .then((r) => r.data),

  /** Effective permissions of the calling credential (self-only; reflects
   *  RBAC ∪ live time-bound grants, narrowed by any API-token resource
   *  binding). Drives client-side gating via the `usePermissions` hook. */
  myPermissions: () =>
    api.get<MyPermissions>("/auth/me/permissions").then((r) => r.data),

  // ── MFA (issue #69) ─────────────────────────────────────────────────
  mfaStatus: () =>
    api.get<MfaStatusResponse>("/auth/mfa/status").then((r) => r.data),
  mfaEnrollBegin: () =>
    api
      .post<MfaEnrolBeginResponse>("/auth/mfa/enroll/begin")
      .then((r) => r.data),
  mfaEnrollVerify: (code: string) =>
    api.post("/auth/mfa/enroll/verify", { code }),
  mfaDisable: (password: string | undefined, code: string) =>
    api.post("/auth/mfa/disable", { password, code }),
  mfaRegenerateRecoveryCodes: (password: string | undefined, code: string) =>
    api
      .post<MfaEnrolBeginResponse>("/auth/mfa/recovery-codes/regenerate", {
        password,
        code,
      })
      .then((r) => r.data),
};

// ── Logs ──────────────────────────────────────────────────────────────────

export interface LogNameOption {
  name: string; // e.g. "Microsoft-Windows-Dhcp-Server/Operational"
  display: string; // what the UI shows in the picker
}

export interface LogSource {
  server_id: string;
  server_name: string;
  server_kind: "dns" | "dhcp";
  driver: string;
  host: string;
  logs: LogNameOption[];
}

export interface LogEventRow {
  time: string; // ISO 8601
  id: number;
  level: string; // "Error" | "Warning" | "Information" | "Verbose" | "Critical"
  provider: string;
  machine: string;
  message: string;
}

export interface LogQueryRequest {
  server_id: string;
  server_kind: "dns" | "dhcp";
  log_name: string;
  max_events?: number; // 1..500, default 100
  level?: number | null; // 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose
  since?: string | null; // ISO 8601
  event_id?: number | null;
}

export interface LogQueryResponse {
  server_id: string;
  server_kind: "dns" | "dhcp";
  log_name: string;
  events: LogEventRow[];
  truncated: boolean;
}

export interface DhcpAuditRow {
  time: string;
  event_code: number;
  event_label: string;
  description: string;
  ip_address: string;
  hostname: string;
  mac_address: string;
  user_name: string;
  transaction_id: string;
  q_result: string;
}

export type DhcpAuditDay =
  | "Mon"
  | "Tue"
  | "Wed"
  | "Thu"
  | "Fri"
  | "Sat"
  | "Sun";

export interface DhcpAuditRequest {
  server_id: string;
  day?: DhcpAuditDay | null;
  max_events?: number;
}

export interface DhcpAuditResponse {
  server_id: string;
  day: DhcpAuditDay;
  events: DhcpAuditRow[];
  truncated: boolean;
}

// ── Agent-shipped logs (BIND9 + Kea) ─────────────────────────────

export interface AgentLogSource {
  server_id: string;
  server_name: string;
  server_kind: "dns" | "dhcp";
  driver: string;
  host: string;
}

export interface DNSQueryLogRow {
  id: number;
  ts: string;
  client_ip: string | null;
  client_port: number | null;
  qname: string | null;
  qclass: string | null;
  qtype: string | null;
  flags: string | null;
  view: string | null;
  /**
   * What the client was actually told (#914). `null` means the outcome
   * was never recorded — response logging is off for the group — and NOT
   * that the query succeeded. Render the two differently.
   */
  rcode?: string | null;
  /** RRs in the answer section. NOERROR with 0 is a NODATA response. */
  answer_count?: number | null;
  raw: string;
}

export interface DNSQueryLogRequest {
  server_id: string;
  since?: string | null;
  until?: string | null;
  q?: string | null;
  qtype?: string | null;
  client_ip?: string | null;
  // Exact-match view filter (#371) — seeded by the per-view analytics card.
  view?: string | null;
  /** Exact outcome (#914). `UNKNOWN` selects rows with no recorded rcode. */
  rcode?: string | null;
  max_events?: number;
}

export interface DNSQueryLogResponse {
  server_id: string;
  events: DNSQueryLogRow[];
  truncated: boolean;
}

export interface DHCPActivityLogRow {
  id: number;
  ts: string;
  severity: string | null;
  code: string | null;
  mac_address: string | null;
  ip_address: string | null;
  transaction_id: string | null;
  raw: string;
}

export interface DHCPActivityLogRequest {
  server_id: string;
  since?: string | null;
  until?: string | null;
  q?: string | null;
  severity?: string | null;
  code?: string | null;
  mac_address?: string | null;
  ip_address?: string | null;
  max_events?: number;
}

export interface DHCPActivityLogResponse {
  server_id: string;
  events: DHCPActivityLogRow[];
  truncated: boolean;
}

// On-demand top-N rollups computed against `dns_query_log_entry`
// (24 h retention). One round trip returns three dimensions.
export interface DNSQueryAnalyticsRow {
  key: string;
  count: number;
}

export interface DNSQueryAnalyticsRequest {
  server_id: string;
  since?: string | null;
  until?: string | null;
  limit?: number;
}

export interface DNSQueryAnalyticsResponse {
  server_id: string;
  since: string | null;
  until: string | null;
  total_queries: number;
  top_qnames: DNSQueryAnalyticsRow[];
  top_clients: DNSQueryAnalyticsRow[];
  qtype_distribution: DNSQueryAnalyticsRow[];
  // Per-view query split (#371). Empty for single-view servers.
  top_views?: DNSQueryAnalyticsRow[];
  /**
   * Outcome split (#914). Queries with no recorded outcome appear under
   * the `UNKNOWN` key rather than being dropped, so a group with response
   * logging off shows one honest bar instead of an empty panel that reads
   * as "no failures".
   */
  rcode_distribution?: DNSQueryAnalyticsRow[];
}

/** One scored per-client DNS behaviour window (issue #699). */
export interface DNSClientWindow {
  id: string;
  client_ip: string;
  window_start: string;
  window_end: string;
  query_count: number;
  distinct_qnames: number;
  distinct_parents: number;
  top_parent: string | null;
  top_parent_subdomains: number;
  max_label_length: number;
  mean_label_entropy: number;
  payload_qtype_count: number;
  tunnel_score: number;
  tunnel_signals: DNSTunnelSignal[];
  /** Timing-based C2 callback score (#699) — independent of tunneling. */
  beacon_score: number;
  beacon_candidates: DNSBeaconCandidate[];
  beacon_detail: string;
  /**
   * Domain-generation-algorithm score (#699). Structurally the inverse
   * of tunneling — a tunnel concentrates subdomains under one parent,
   * a DGA sprays across many — so the two never fire together.
   */
  dga_score: number;
  dga_candidates: DNSDGACandidate[];
  dga_signals: DNSTunnelSignal[];
  dga_detail: string;
  allowlisted: boolean;
  server_count: number;
  /** An operator reviewed this client and cleared it (#699). */
  muted: boolean;
  mute_reason: string | null;
  mute_until: string | null;
}

export interface DNSThreatMute {
  id: string;
  client_ip: string;
  reason: string;
  muted_until: string | null;
  muted_by_display: string;
  created_at: string;
  /** False once an expiring mute has lapsed — the row is kept for audit. */
  active: boolean;
}

export interface DNSTunnelSignal {
  name: string;
  value: number;
  contribution: number;
  /** This signal's maximum possible contribution — weights differ per signal. */
  max_contribution: number;
  detail: string;
}

/**
 * One (client, name) pair that repeated on a regular cadence. The
 * qname matters more than the score: monitoring agents and C2
 * callbacks are indistinguishable by timing alone.
 */
export interface DNSBeaconCandidate {
  qname: string;
  samples: number;
  period_seconds: number;
  cv: number;
  score: number;
}

/**
 * One implausible registrable domain from a DGA crop. The domains
 * matter more than the score: hashed-CDN buckets and shortlink
 * services share the shape, so an operator needs to see which names
 * actually scored before acting.
 */
export interface DNSDGACandidate {
  parent: string;
  label: string;
  implausibility: number;
  vowel_ratio: number;
}

/** A client ranked by how many blocked lookups it made (#699). */
export interface RPZOffender {
  client_ip: string;
  hits: number;
  distinct_names: number;
  distinct_feeds: number;
  last_seen: string;
  top_qname: string | null;
  top_qname_hits: number;
  /** Past the "worth chasing" bar; set server-side so UI and copilot agree. */
  noisy: boolean;
}

export interface RPZBlockedName {
  qname: string;
  hits: number;
  clients: number;
  rpz_zone: string | null;
}

/** One individual RPZ policy hit (#914) — the raw event, not a rollup. */
export interface RPZHitRow {
  id: string;
  ts: string;
  server_id: string | null;
  client_ip: string | null;
  qname: string | null;
  trigger: string;
  policy: string;
  rpz_zone: string | null;
  raw: string;
}

export interface RPZFeedRow {
  rpz_zone: string | null;
  hits: number;
  clients: number;
  distinct_names: number;
}

export interface RPZSummary {
  blocked_hits: number;
  clients_blocked: number;
  distinct_names: number;
  feeds_firing: number;
  /** PASSTHRU is an explicit ALLOW, not a block — counted separately. */
  passthru_hits: number;
  worst_client_ip: string | null;
  worst_client_hits: number | null;
  since: string;
  /** Zero blocks is a plausible real answer; this says whether anything ran. */
  has_data: boolean;
}

export interface DNSThreatSummary {
  windows_scored: number;
  clients_seen: number;
  suspicious_clients: number;
  peak_score: number;
  worst_client_ip: string | null;
  worst_client_score: number | null;
  worst_client_parent: string | null;
  since: string;
  /** False when the rollup has produced nothing — "no data" is not "no threats". */
  has_data: boolean;
}

/**
 * DNS threat analytics (#699). The whole prefix 404s unless the
 * default-off ``security.dns_threat`` module is enabled, so callers
 * must treat a 404 as "feature off", not as an error.
 */
export const dnsThreatApi = {
  listWindows: (params?: {
    client_ip?: string;
    hours?: number;
    min_score?: number;
    /**
     * Rank and filter by "tunnel" (name content), "beacon" (timing) or
     * "dga" (name plausibility). Kept explicit rather than a combined
     * max: the three mean different things, and an operator hunting
     * exfil should not have their list reordered by a chatty
     * monitoring agent.
     */
    detection?: "tunnel" | "beacon" | "dga";
    include_allowlisted?: boolean;
    include_muted?: boolean;
    limit?: number;
  }) =>
    api
      .get<DNSClientWindow[]>("/dns-threat/windows", { params })
      .then((r) => r.data),
  summary: (params?: { hours?: number; min_score?: number }) =>
    api
      .get<DNSThreatSummary>("/dns-threat/summary", { params })
      .then((r) => r.data),
  listMutes: () =>
    api.get<DNSThreatMute[]>("/dns-threat/mutes").then((r) => r.data),
  /** Muting a client hides its findings AND stops the alert firing. */
  mute: (body: {
    client_ip: string;
    reason: string;
    muted_until?: string | null;
  }) => api.post<DNSThreatMute>("/dns-threat/mutes", body).then((r) => r.data),
  unmute: (clientIp: string) =>
    api
      .delete<void>(`/dns-threat/mutes/${encodeURIComponent(clientIp)}`)
      .then((r) => r.data),
  /**
   * RPZ hit attribution (#699). Ground truth rather than a heuristic —
   * named matched a policy and logged it — so these need no score or
   * threshold, only ranking.
   */
  rpzSummary: (params?: { hours?: number }) =>
    api
      .get<RPZSummary>("/dns-threat/rpz/summary", { params })
      .then((r) => r.data),
  rpzClients: (params?: {
    hours?: number;
    limit?: number;
    min_hits?: number;
  }) =>
    api
      .get<RPZOffender[]>("/dns-threat/rpz/clients", { params })
      .then((r) => r.data),
  rpzNames: (params?: { hours?: number; limit?: number }) =>
    api
      .get<RPZBlockedName[]>("/dns-threat/rpz/names", { params })
      .then((r) => r.data),
  rpzFeeds: (params?: { hours?: number }) =>
    api
      .get<RPZFeedRow[]>("/dns-threat/rpz/feeds", { params })
      .then((r) => r.data),
  /**
   * The individual hits (#914) — what the rollups above cannot answer:
   * "which three lookups did this PC make that were blocked".
   */
  rpzHits: (params?: {
    hours?: number;
    limit?: number;
    client_ip?: string;
    qname_contains?: string;
    include_passthru?: boolean;
  }) =>
    api
      .get<RPZHitRow[]>("/dns-threat/rpz/hits", { params })
      .then((r) => r.data),
};

export const logsApi = {
  listSources: () => api.get<LogSource[]>("/logs/sources").then((r) => r.data),
  listAgentSources: () =>
    api.get<AgentLogSource[]>("/logs/agent-sources").then((r) => r.data),
  query: (body: LogQueryRequest) =>
    api.post<LogQueryResponse>("/logs/query", body).then((r) => r.data),
  dhcpAudit: (body: DhcpAuditRequest) =>
    api.post<DhcpAuditResponse>("/logs/dhcp-audit", body).then((r) => r.data),
  dnsQueries: (body: DNSQueryLogRequest) =>
    api
      .post<DNSQueryLogResponse>("/logs/dns-queries", body)
      .then((r) => r.data),
  dnsQueryAnalytics: (body: DNSQueryAnalyticsRequest) =>
    api
      .post<DNSQueryAnalyticsResponse>("/logs/dns-queries/analytics", body)
      .then((r) => r.data),
  dhcpActivity: (body: DHCPActivityLogRequest) =>
    api
      .post<DHCPActivityLogResponse>("/logs/dhcp-activity", body)
      .then((r) => r.data),
};

// ── API Tokens ────────────────────────────────────────────────────────────────

/** Coarse-grained scope vocabulary — see issue #74 +
 * `app/services/api_token_scopes.py`. Empty list = no scope
 * restriction (token still inherits the owner's RBAC). Non-empty
 * = enforced at the auth layer BEFORE RBAC. Multiple scopes
 * union; ``read`` covers safe-method requests across the surface.
 */
export type ApiTokenScope =
  | "read"
  | "ipam:write"
  | "dns:write"
  | "dhcp:write"
  | "agent";

export const API_TOKEN_SCOPES: {
  value: ApiTokenScope;
  label: string;
  hint: string;
}[] = [
  {
    value: "read",
    label: "Read-only",
    hint: "GET / HEAD / OPTIONS only — no mutations anywhere.",
  },
  {
    value: "ipam:write",
    label: "IPAM write",
    hint: "Mutate /ipam/*, /vlans*, /vrfs*, /network-devices*.",
  },
  {
    value: "dns:write",
    label: "DNS write",
    hint: "Mutate /dns/* + /dns-pools*. Excludes the agent surface.",
  },
  {
    value: "dhcp:write",
    label: "DHCP write",
    hint: "Mutate /dhcp/*. Excludes the agent surface.",
  },
  {
    value: "agent",
    label: "Agent",
    hint: "Bootstrap + push for /dns/agents/* and /dhcp/agents/*.",
  },
];

/** Per-token resource binding (#374). resource_type ∈ {subnet, dns_zone}. */
export interface ApiTokenResourceGrant {
  action: string;
  resource_type: string;
  resource_id: string;
}

export interface ApiToken {
  id: string;
  name: string;
  description: string;
  prefix: string;
  scope: string;
  scopes: ApiTokenScope[];
  resource_grants?: ApiTokenResourceGrant[];
  user_id: string | null;
  expires_at: string | null;
  last_used_at: string | null;
  is_active: boolean;
  created_at: string;
}

export interface ApiTokenCreate {
  name: string;
  description?: string;
  expires_in_days?: number | null;
  scopes?: ApiTokenScope[];
  resource_grants?: ApiTokenResourceGrant[];
}

/** Response from POST — contains the raw token ONCE. */
export interface ApiTokenCreated extends ApiToken {
  token: string;
}

export interface ApiTokenUpdate {
  name?: string;
  description?: string;
  is_active?: boolean;
  scopes?: ApiTokenScope[];
}

/**
 * What the enrolment QR code needs that only the server can answer (#906).
 *
 * Just the certificate fingerprint — the connection itself comes from
 * `window.location`, because behind a proxy or split DNS the server does not
 * know its own externally-reachable address.
 */
export interface EnrolmentContext {
  /** Bare lower-case hex, or null when the server does not manage its TLS. */
  tls_fingerprint_sha256: string | null;
  fingerprint_source: string | null;
  fingerprint_unavailable_reason: string | null;
}

export const apiTokensApi = {
  list: () => api.get<ApiToken[]>("/api-tokens").then((r) => r.data),
  enrolmentContext: () =>
    api
      .get<EnrolmentContext>("/api-tokens/enrolment-context")
      .then((r) => r.data),
  create: (body: ApiTokenCreate) =>
    api.post<ApiTokenCreated>("/api-tokens", body).then((r) => r.data),
  update: (id: string, body: ApiTokenUpdate) =>
    api.patch<ApiToken>(`/api-tokens/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/api-tokens/${id}`),
};

// ── Alerts ─────────────────────────────────────────────────────────────────────

export type AlertRuleType =
  | "subnet_utilization"
  | "server_unreachable"
  | "asn_holder_drift"
  | "asn_whois_unreachable"
  | "rpki_roa_expiring"
  | "rpki_roa_expired"
  | "domain_expiring"
  | "domain_nameserver_drift"
  | "domain_registrar_changed"
  | "domain_dnssec_status_changed"
  | "circuit_term_expiring"
  | "circuit_status_changed"
  | "service_term_expiring"
  | "service_resource_orphaned"
  | "compliance_change"
  | "voice_lease_count_below"
  | "stale_ip_count"
  | "dhcp_pool_exhaustion"
  | "secret_expiring"
  | "decom_expiring"
  | "node_pressure";
export type AlertSeverity = "info" | "warning" | "critical";
export type AlertServerType = "dns" | "dhcp" | "any";
// ``compliance_change`` rule type — keep in lock-step with
// ``COMPLIANCE_CLASSIFICATIONS`` / ``COMPLIANCE_CHANGE_SCOPES`` in
// ``backend/app/services/alerts.py``.
export type AlertClassification =
  | "pci_scope"
  | "hipaa_scope"
  | "internet_facing";
export type AlertChangeScope = "any_change" | "create" | "delete";

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rule_type: AlertRuleType;
  threshold_percent: number | null;
  threshold_days: number | null;
  min_free_addresses: number | null;
  server_type: AlertServerType | null;
  classification: AlertClassification | null;
  change_scope: AlertChangeScope | null;
  last_scanned_audit_at: string | null;
  severity: AlertSeverity;
  notify_syslog: boolean;
  notify_webhook: boolean;
  notify_smtp: boolean;
  created_at: string;
  modified_at: string;
}

export interface AlertRuleCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  rule_type: AlertRuleType;
  threshold_percent?: number | null;
  threshold_days?: number | null;
  min_free_addresses?: number | null;
  server_type?: AlertServerType | null;
  classification?: AlertClassification | null;
  change_scope?: AlertChangeScope | null;
  severity?: AlertSeverity;
  notify_syslog?: boolean;
  notify_webhook?: boolean;
  notify_smtp?: boolean;
}

export interface AlertRuleUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  threshold_percent?: number | null;
  threshold_days?: number | null;
  min_free_addresses?: number | null;
  server_type?: AlertServerType | null;
  classification?: AlertClassification | null;
  change_scope?: AlertChangeScope | null;
  severity?: AlertSeverity;
  notify_syslog?: boolean;
  notify_webhook?: boolean;
  notify_smtp?: boolean;
}

export interface AlertEvent {
  id: string;
  rule_id: string;
  subject_type: string;
  subject_id: string;
  subject_display: string;
  severity: AlertSeverity;
  message: string;
  fired_at: string;
  resolved_at: string | null;
  delivered_syslog: boolean;
  delivered_webhook: boolean;
  delivered_smtp: boolean;
  last_observed_value: Record<string, unknown> | null;
}

export interface AlertEvaluateResult {
  opened: number;
  resolved: number;
  delivered_syslog: number;
  delivered_webhook: number;
  delivered_smtp: number;
}

export const alertsApi = {
  listRules: () => api.get<AlertRule[]>("/alerts/rules").then((r) => r.data),
  createRule: (body: AlertRuleCreate) =>
    api.post<AlertRule>("/alerts/rules", body).then((r) => r.data),
  updateRule: (id: string, body: AlertRuleUpdate) =>
    api.patch<AlertRule>(`/alerts/rules/${id}`, body).then((r) => r.data),
  deleteRule: (id: string) => api.delete(`/alerts/rules/${id}`),
  listEvents: (
    params: { open_only?: boolean; rule_id?: string; limit?: number } = {},
  ) => api.get<AlertEvent[]>("/alerts/events", { params }).then((r) => r.data),
  resolveEvent: (id: string) =>
    api.post<AlertEvent>(`/alerts/events/${id}/resolve`).then((r) => r.data),
  evaluateNow: () =>
    api.post<AlertEvaluateResult>("/alerts/evaluate").then((r) => r.data),
};

// ── Conformity evaluations (issue #106) ─────────────────────────────────────

export type ConformityTargetKind =
  | "platform"
  | "subnet"
  | "ip_address"
  | "dns_zone"
  | "dhcp_scope"
  | "multicast_group";
export type ConformityStatus = "pass" | "fail" | "warn" | "not_applicable";
export type ConformitySeverity = "info" | "warning" | "critical";

export interface ConformityPolicy {
  id: string;
  name: string;
  description: string;
  framework: string;
  reference: string | null;
  severity: ConformitySeverity;
  target_kind: ConformityTargetKind;
  target_filter: Record<string, unknown>;
  check_kind: string;
  check_args: Record<string, unknown>;
  is_builtin: boolean;
  enabled: boolean;
  eval_interval_hours: number;
  last_evaluated_at: string | null;
  fail_alert_rule_id: string | null;
  created_at: string;
  modified_at: string;
}

export interface ConformityPolicyCreate {
  name: string;
  description?: string;
  framework?: string;
  reference?: string | null;
  severity?: ConformitySeverity;
  target_kind: ConformityTargetKind;
  target_filter?: Record<string, unknown>;
  check_kind: string;
  check_args?: Record<string, unknown>;
  enabled?: boolean;
  eval_interval_hours?: number;
  fail_alert_rule_id?: string | null;
}

export type ConformityPolicyUpdate = Partial<ConformityPolicyCreate>;

export interface ConformityResult {
  id: string;
  policy_id: string;
  resource_kind: string;
  resource_id: string;
  resource_display: string;
  evaluated_at: string;
  status: ConformityStatus;
  detail: string;
  diagnostic: Record<string, unknown> | null;
}

export interface ConformityFrameworkRollup {
  framework: string;
  policies_total: number;
  policies_enabled: number;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  not_applicable_count: number;
}

export interface ConformitySummary {
  overall_pass: number;
  overall_warn: number;
  overall_fail: number;
  overall_not_applicable: number;
  last_evaluated_at: string | null;
  frameworks: ConformityFrameworkRollup[];
}

export interface ConformityCheckCatalogEntry {
  name: string;
  label: string;
  supports: ConformityTargetKind[];
  args: {
    name: string;
    type: string;
    required: boolean;
    label?: string;
    default?: unknown;
    options?: string[];
  }[];
}

export interface ConformityEvaluateResult {
  passed: number;
  failed: number;
  warned: number;
  not_applicable: number;
  total: number;
}

export const conformityApi = {
  listPolicies: (params: { framework?: string; enabled_only?: boolean } = {}) =>
    api
      .get<ConformityPolicy[]>("/conformity/policies", { params })
      .then((r) => r.data),
  getPolicy: (id: string) =>
    api.get<ConformityPolicy>(`/conformity/policies/${id}`).then((r) => r.data),
  createPolicy: (body: ConformityPolicyCreate) =>
    api
      .post<ConformityPolicy>("/conformity/policies", body)
      .then((r) => r.data),
  updatePolicy: (id: string, body: ConformityPolicyUpdate) =>
    api
      .patch<ConformityPolicy>(`/conformity/policies/${id}`, body)
      .then((r) => r.data),
  deletePolicy: (id: string) => api.delete(`/conformity/policies/${id}`),
  evaluatePolicyNow: (id: string) =>
    api
      .post<ConformityEvaluateResult>(`/conformity/policies/${id}/evaluate`)
      .then((r) => r.data),
  listResults: (
    params: {
      policy_id?: string;
      resource_kind?: string;
      resource_id?: string;
      status?: ConformityStatus;
      since?: string;
      limit?: number;
    } = {},
  ) =>
    api
      .get<ConformityResult[]>("/conformity/results", { params })
      .then((r) => r.data),
  summary: () =>
    api.get<ConformitySummary>("/conformity/summary").then((r) => r.data),
  listCheckKinds: () =>
    api
      .get<ConformityCheckCatalogEntry[]>("/conformity/checks")
      .then((r) => r.data),
  // Fetches the PDF via the authenticated axios client (Bearer token
  // lives in axios memory, not cookies — a plain ``window.open`` to
  // the same URL would 401 because the browser nav doesn't carry the
  // header). Mirrors ``ipamIoApi.exportFile``: blob response, parse
  // ``Content-Disposition`` for the backend's UTC-timestamped
  // filename, trigger a synthetic anchor click for the download.
  exportPdf: async (framework?: string): Promise<void> => {
    const res = await api.get<Blob>("/conformity/export.pdf", {
      params: framework ? { framework } : undefined,
      responseType: "blob",
    });
    const disp = (res.headers["content-disposition"] as string) || "";
    const match = disp.match(/filename="?([^";]+)"?/i);
    const ts = new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[-:]/g, "")
      .replace("T", "-");
    const fallback = framework
      ? `spatiumddi-conformity-${framework.toLowerCase().replace(/[\s/]+/g, "-")}-${ts}.pdf`
      : `spatiumddi-conformity-${ts}.pdf`;
    const filename = match ? match[1] : fallback;
    const blob = new Blob([res.data as BlobPart], {
      type: "application/pdf",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },
};

// ── Dashboard rollups (issues #107 / #108 / #109) ───────────────────────────

// Network dashboard tab (#107)
export interface NetworkDashboardASNDriftRow {
  id: string;
  number: number;
  name: string | null;
  holder_org: string | null;
  previous_holder: string | null;
}
export interface NetworkDashboardRpkiRoaRow {
  id: string;
  asn_id: string;
  asn_number: number | null;
  prefix: string;
  max_length: number | null;
  valid_to: string | null;
  state: string;
}
export interface NetworkDashboardCircuitRow {
  id: string;
  name: string;
  status: string;
  transport: string | null;
  term_end_date: string | null;
  customer_id: string | null;
  provider_id: string | null;
}
export interface NetworkDashboardOrphanServiceRow {
  service_id: string;
  service_name: string;
  resource_kind: string;
  resource_id: string;
}
export interface NetworkDashboardOverlayImpactRow {
  id: string;
  name: string;
  site_count: number;
  note: string;
}
export interface NetworkDashboardSummary {
  generated_at: string;
  asn_drift_count: number;
  rpki_expiring_count: number;
  rpki_expired_count: number;
  /** Total ROAs tracked, and when the pull last touched one. Lets the
   *  panel tell a real all-clear from stale or absent data (#942). */
  rpki_total_count: number;
  rpki_last_checked_at: string | null;
  circuit_term_expiring_count: number;
  circuit_status_changed_count: number;
  service_orphan_count: number;
  overlay_impacted_count: number;
  asn_drift: NetworkDashboardASNDriftRow[];
  rpki_expiring: NetworkDashboardRpkiRoaRow[];
  circuit_alerts: NetworkDashboardCircuitRow[];
  orphan_services: NetworkDashboardOrphanServiceRow[];
  overlay_impact: NetworkDashboardOverlayImpactRow[];
}

// Integrations dashboard tab (#108)
export type IntegrationDashboardKind =
  | "kubernetes"
  | "docker"
  | "proxmox"
  | "tailscale"
  | "unifi"
  | "cloud"
  | "opnsense"
  | "paloalto"
  | "fortinet"
  | "meraki"
  | "netbird";
export interface IntegrationsDashboardTargetRow {
  id: string;
  display: string;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  // #797 — non-fatal findings; null for integrations that don't compute them.
  last_sync_warning: string | null;
  is_stale: boolean;
}
export interface IntegrationsDashboardPanel {
  kind: IntegrationDashboardKind;
  label: string;
  enabled: boolean;
  target_count: number;
  healthy_count: number;
  stale_count: number;
  error_count: number;
  warning_count: number;
  targets: IntegrationsDashboardTargetRow[];
}
export interface IntegrationsDashboardErrorRow {
  id: string;
  integration: string;
  target_id: string;
  target_display: string;
  error_detail: string | null;
  timestamp: string;
}
export interface IntegrationsDashboardSummary {
  generated_at: string;
  panels: IntegrationsDashboardPanel[];
  recent_errors: IntegrationsDashboardErrorRow[];
}

// Security dashboard tab (#109)
export interface SecurityDashboardMFAUserRow {
  id: string;
  username: string;
  display_name: string;
  last_login_at: string | null;
  auth_source: string;
}
export interface SecurityDashboardAPITokenRow {
  id: string;
  name: string;
  user_id: string | null;
  user_display: string | null;
  expires_at: string | null;
  days_remaining: number | null;
  scopes: string[];
}
export interface SecurityDashboardFailedLoginRow {
  user_display_name: string;
  source_ip: string | null;
  failure_count: number;
  latest_at: string;
}
export interface SecurityDashboardPermissionChangeRow {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource_type: string;
  resource_id: string;
  resource_display: string;
  changed_fields: string[] | null;
}
export interface SecurityDashboardSummary {
  generated_at: string;
  mfa_total_local_users: number;
  mfa_enrolled_count: number;
  mfa_coverage_pct: number;
  mfa_unenrolled: SecurityDashboardMFAUserRow[];
  api_tokens_total: number;
  api_tokens_expiring_count: number;
  api_tokens_expiring: SecurityDashboardAPITokenRow[];
  failed_login_window_hours: number;
  failed_login_total: number;
  failed_login_top_sources: SecurityDashboardFailedLoginRow[];
  permission_change_window_days: number;
  permission_change_count: number;
  permission_changes: SecurityDashboardPermissionChangeRow[];
}

export const dashboardsApi = {
  networkSummary: () =>
    api
      .get<NetworkDashboardSummary>("/dashboards/network/summary")
      .then((r) => r.data),
  integrationsSummary: () =>
    api
      .get<IntegrationsDashboardSummary>("/dashboards/integrations/summary")
      .then((r) => r.data),
  securitySummary: () =>
    api
      .get<SecurityDashboardSummary>("/dashboards/security/summary")
      .then((r) => r.data),
};

// ── Top-N reports (issue #47) ───────────────────────────────────────────────

export interface TopSubnetRow {
  id: string;
  name: string;
  network: string;
  utilization_percent: number;
  allocated_ips: number;
  total_ips: number;
}

export interface TopOwnerRow {
  customer_id: string | null;
  customer_name: string;
  ip_count: number;
}

export interface TopModifiedResourceRow {
  resource_type: string;
  resource_id: string;
  resource_display: string;
  change_count: number;
}

export interface TopDNSClientRow {
  client_ip: string;
  query_count: number;
}

export interface TopSubnetsReport {
  generated_at: string;
  rows: TopSubnetRow[];
}

export interface TopOwnersReport {
  generated_at: string;
  rows: TopOwnerRow[];
}

export interface TopModifiedResourcesReport {
  generated_at: string;
  window_days: number;
  rows: TopModifiedResourceRow[];
}

export interface TopDNSClientsReport {
  generated_at: string;
  rows: TopDNSClientRow[];
}

export const reportsApi = {
  topSubnetsByUtilization: () =>
    api
      .get<TopSubnetsReport>("/reports/top-subnets-by-utilization")
      .then((r) => r.data),
  topOwnersByIpCount: () =>
    api
      .get<TopOwnersReport>("/reports/top-owners-by-ip-count")
      .then((r) => r.data),
  topModifiedResources: () =>
    api
      .get<TopModifiedResourcesReport>("/reports/top-modified-resources")
      .then((r) => r.data),
  topDnsClients: () =>
    api
      .get<TopDNSClientsReport>("/reports/top-dns-clients")
      .then((r) => r.data),
};

// ── Domain registration (RDAP / WHOIS tracking) ─────────────────────────────

export type DomainWhoisState =
  // "n/a" (#986) — the name is not under a delegated TLD, so there is no
  // registry to query and the refresh skips it rather than reporting the
  // registry as unreachable.
  "n/a" | "ok" | "drift" | "expiring" | "expired" | "unreachable" | "unknown";

export interface Domain {
  id: string;
  name: string;
  registrar: string | null;
  registrant_org: string | null;
  registered_at: string | null;
  expires_at: string | null;
  last_renewed_at: string | null;
  expected_nameservers: string[];
  actual_nameservers: string[];
  nameserver_drift: boolean;
  dnssec_signed: boolean;
  whois_last_checked_at: string | null;
  whois_state: DomainWhoisState;
  whois_data: Record<string, unknown> | null;
  next_check_at: string | null;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  customer_id: string | null;
  registrar_provider_id: string | null;
  /** #986 — TLD scope of the name; non-public means RDAP is skipped. */
  name_scope?: ZoneNameScope;
  created_at: string;
  modified_at: string;
}

export interface DomainCreate {
  name: string;
  expected_nameservers?: string[];
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
  customer_id?: string | null;
  registrar_provider_id?: string | null;
}

export interface DomainUpdate {
  name?: string;
  expected_nameservers?: string[];
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
  customer_id?: string | null;
  registrar_provider_id?: string | null;
}

export interface DomainListResponse {
  items: Domain[];
  total: number;
  page: number;
  page_size: number;
}

export interface DomainListParams {
  whois_state?: DomainWhoisState;
  expiring_within_days?: number;
  customer_id?: string;
  registrar_provider_id?: string;
  search?: string;
  page?: number;
  page_size?: number;
  tag?: string[];
}

export const domainsApi = {
  list: (params: DomainListParams = {}) =>
    api.get<DomainListResponse>("/domains", { params }).then((r) => r.data),
  get: (id: string) => api.get<Domain>(`/domains/${id}`).then((r) => r.data),
  create: (body: DomainCreate) =>
    api.post<Domain>("/domains", body).then((r) => r.data),
  update: (id: string, body: DomainUpdate) =>
    api.put<Domain>(`/domains/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/domains/${id}`),
  refreshWhois: (id: string) =>
    api.post<Domain>(`/domains/${id}/refresh-whois`).then((r) => r.data),
  bulkDelete: (ids: string[]) =>
    api
      .post<{ deleted: number }>("/domains/bulk-delete", { ids })
      .then((r) => r.data),
};

// ── Webhooks (typed-event subscriptions) ────────────────────────────────────

export interface WebhookSubscription {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  url: string;
  // Server-side bool — the secret itself is Fernet-encrypted at rest
  // and only ever returned in plaintext from the create / update
  // response when one was newly assigned (``secret_plaintext``).
  secret_set: boolean;
  event_types: string[] | null;
  headers: Record<string, string> | null;
  timeout_seconds: number;
  max_attempts: number;
  created_at: string;
  modified_at: string;
  // Populated only on the create response (and on update when the
  // operator supplied a new value). Surface to the operator once,
  // then drop.
  secret_plaintext?: string | null;
}

export interface WebhookSubscriptionWrite {
  name: string;
  description?: string;
  enabled: boolean;
  url: string;
  // ``null`` on edit = keep existing, ``""`` = clear, anything else =
  // sent in plaintext + encrypted server-side.
  secret?: string | null;
  event_types?: string[] | null;
  headers?: Record<string, string> | null;
  timeout_seconds?: number;
  max_attempts?: number;
}

export interface WebhookDelivery {
  id: string;
  subscription_id: string;
  event_type: string;
  state: "pending" | "in_flight" | "delivered" | "failed" | "dead";
  attempts: number;
  next_attempt_at: string;
  last_error: string | null;
  last_status_code: number | null;
  delivered_at: string | null;
  created_at: string;
}

export interface WebhookTestResult {
  status: "ok" | "error";
  status_code: number | null;
  error: string | null;
}

export const webhooksApi = {
  listEventTypes: () =>
    api
      .get<{ event_types: string[] }>("/webhooks/event-types")
      .then((r) => r.data.event_types),
  list: () => api.get<WebhookSubscription[]>("/webhooks").then((r) => r.data),
  get: (id: string) =>
    api.get<WebhookSubscription>(`/webhooks/${id}`).then((r) => r.data),
  create: (body: WebhookSubscriptionWrite) =>
    api.post<WebhookSubscription>("/webhooks", body).then((r) => r.data),
  update: (id: string, body: WebhookSubscriptionWrite) =>
    api.put<WebhookSubscription>(`/webhooks/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/webhooks/${id}`),
  test: (id: string) =>
    api.post<WebhookTestResult>(`/webhooks/${id}/test`).then((r) => r.data),
  listDeliveries: (id: string, limit = 100) =>
    api
      .get<WebhookDelivery[]>(`/webhooks/${id}/deliveries`, {
        params: { limit },
      })
      .then((r) => r.data),
  retryDelivery: (deliveryId: string) =>
    api
      .post<WebhookDelivery>(`/webhooks/deliveries/${deliveryId}/retry`)
      .then((r) => r.data),
};

// ── Change requests (two-person approval workflow, #62) ─────────────────────
//
// Gated behind the default-OFF ``governance.approvals`` feature module — the
// whole router 404s when the module is disabled, so every covered mutation
// executes inline exactly as before (the Sidebar nav entry carries the same
// module gate so the page is hidden until an operator turns the feature on).

export type ChangeRequestState =
  | "pending"
  | "approved"
  | "rejected"
  | "executed"
  | "failed"
  | "expired"
  | "cancelled";

export interface ChangeRequest {
  id: string;
  operation: string;
  resource_type: string;
  resource_id: string | null;
  resource_display: string;
  args: Record<string, unknown>;
  preview_text: string;
  risk_reason: string;
  state: ChangeRequestState;
  requested_by_user_id: string | null;
  requested_by_display: string;
  decided_by_user_id: string | null;
  decided_by_display: string | null;
  decision_note: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
  expires_at: string;
  decided_at: string | null;
  executed_at: string | null;
  created_at: string;
  modified_at: string;
}

export interface ChangeRequestListParams {
  state?: ChangeRequestState;
  resource_type?: string;
  mine?: boolean;
  limit?: number;
  offset?: number;
}

// Threshold actions an approval policy can gate (mirror the backend
// ``APPROVAL_POLICY_ACTIONS`` frozenset).
export const APPROVAL_POLICY_ACTIONS = [
  "delete",
  "bulk_delete",
  "bulk_edit",
  "bulk_allocate",
  "factory_reset",
  "import_commit",
] as const;
export type ApprovalPolicyAction = (typeof APPROVAL_POLICY_ACTIONS)[number];

export interface ApprovalPolicy {
  id: string;
  name: string;
  resource_type: string;
  action: string;
  min_count: number | null;
  enabled: boolean;
  applies_to_superadmin: boolean;
  ttl_hours: number;
  is_builtin: boolean;
  created_at: string;
  modified_at: string;
}

export interface ApprovalPolicyWrite {
  name: string;
  resource_type: string;
  action: string;
  min_count?: number | null;
  enabled: boolean;
  applies_to_superadmin: boolean;
  ttl_hours: number;
}

// The 202 envelope a covered mutation returns (instead of 204) when the
// operation was queued for approval rather than executed inline.
export interface ChangeRequestQueued {
  change_request_id: string;
  state: "pending";
  preview_text: string;
}

export const changeRequestsApi = {
  list: (params: ChangeRequestListParams = {}) =>
    api
      .get<ChangeRequest[]>("/change-requests", { params })
      .then((r) => r.data),
  get: (id: string) =>
    api.get<ChangeRequest>(`/change-requests/${id}`).then((r) => r.data),
  // No dedicated pending-count endpoint server-side — derive the badge from
  // a state=pending list (cheap; the queue is small by construction).
  countPending: () =>
    api
      .get<ChangeRequest[]>("/change-requests", {
        params: { state: "pending", limit: 500 },
      })
      .then((r) => r.data.length),
  approve: (id: string, decisionNote?: string) =>
    api
      .post<ChangeRequest>(`/change-requests/${id}/approve`, {
        decision_note: decisionNote ?? null,
      })
      .then((r) => r.data),
  reject: (id: string, decisionNote?: string) =>
    api
      .post<ChangeRequest>(`/change-requests/${id}/reject`, {
        decision_note: decisionNote ?? null,
      })
      .then((r) => r.data),
  cancel: (id: string, decisionNote?: string) =>
    api
      .post<ChangeRequest>(`/change-requests/${id}/cancel`, {
        decision_note: decisionNote ?? null,
      })
      .then((r) => r.data),
  listPolicies: () =>
    api.get<ApprovalPolicy[]>("/change-requests/policies").then((r) => r.data),
  createPolicy: (body: ApprovalPolicyWrite) =>
    api
      .post<ApprovalPolicy>("/change-requests/policies", body)
      .then((r) => r.data),
  // #62 self-governance lock: WEAKENING a policy (disable enabled→false, lower
  // applies_to_superadmin true→false, or delete) returns **202** with a
  // ``ChangeRequestQueued`` body when the lock is on instead of mutating
  // inline. Return the FULL axios response so callers can route it through
  // ``handleApprovalQueued``; strengthening edits + lock-off return the
  // 200/204 inline path. (See featureModulesApi.toggle for the same shape.)
  updatePolicy: (id: string, body: ApprovalPolicyWrite) =>
    api.put<ApprovalPolicy | ChangeRequestQueued>(
      `/change-requests/policies/${id}`,
      body,
    ),
  deletePolicy: (id: string) =>
    api.delete<ChangeRequestQueued | "">(`/change-requests/policies/${id}`),
};

// ── Self-service request portal (#696) ──────────────────────────────────
// The #62 approval lifecycle pointed the other way: a requester asks for
// something they can't create themselves, and approving PROVISIONS it. Rows
// share the change_request table under origin='portal', so the state
// vocabulary is identical — but the two queues are served by different
// endpoints and never show each other's rows.

export const REQUEST_KINDS = [
  "subnet",
  "ip_address",
  "dns_record",
  "dhcp_reservation",
] as const;
export type RequestKindId = (typeof REQUEST_KINDS)[number];

export interface RequestKind {
  kind: RequestKindId;
  label: string;
  description: string;
  category: string;
  operation: string;
  // JSON Schema of the backing operation's args model — the form is rendered
  // from this, so there is no second client-side schema to drift.
  args_schema: {
    properties?: Record<string, Record<string, unknown>>;
    required?: string[];
    [k: string]: unknown;
  };
}

export interface ProvisioningRequest {
  id: string;
  operation: string;
  resource_type: string;
  resource_display: string;
  args: Record<string, unknown>;
  preview_text: string;
  justification: string | null;
  state: ChangeRequestState;
  requested_by_user_id: string | null;
  requested_by_display: string;
  decided_by_user_id: string | null;
  decided_by_display: string | null;
  decision_note: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
  expires_at: string;
  decided_at: string | null;
  executed_at: string | null;
  created_at: string;
  modified_at: string;
}

export interface ProvisioningRequestListParams {
  state?: ChangeRequestState;
  mine?: boolean;
  limit?: number;
  offset?: number;
}

export interface SubmitRequestBody {
  kind: RequestKindId;
  args: Record<string, unknown>;
  justification?: string | null;
}

export interface ResourceOption {
  id: string;
  label: string;
  sublabel: string | null;
}

export interface ResourceOptionsResponse {
  options: ResourceOption[];
  // True when the permission scan stopped before covering every candidate —
  // the caller's readable rows may exist beyond the window, so show "keep
  // typing to narrow" rather than "no matches".
  truncated: boolean;
}

export const requestsApi = {
  catalog: () =>
    api.get<RequestKind[]>("/requests/catalog").then((r) => r.data),
  // #759 — permission-filtered typeahead options for x-resource fields.
  resourceOptions: (resource: string, q: string) =>
    api
      .get<ResourceOptionsResponse>("/requests/resource-options", {
        params: { resource, q },
      })
      .then((r) => r.data),
  list: (params: ProvisioningRequestListParams = {}) =>
    api.get<ProvisioningRequest[]>("/requests", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<ProvisioningRequest>(`/requests/${id}`).then((r) => r.data),
  submit: (body: SubmitRequestBody) =>
    api.post<ProvisioningRequest>("/requests", body).then((r) => r.data),
  // No dedicated count endpoint — same reasoning as changeRequestsApi: the
  // pending queue is small by construction, so a state=pending list is cheap.
  countPending: () =>
    api
      .get<ProvisioningRequest[]>("/requests", {
        params: { state: "pending", limit: 500 },
      })
      .then((r) => r.data.length),
  approve: (id: string, decisionNote?: string) =>
    api
      .post<ProvisioningRequest>(`/requests/${id}/approve`, {
        decision_note: decisionNote ?? null,
      })
      .then((r) => r.data),
  reject: (id: string, decisionNote?: string) =>
    api
      .post<ProvisioningRequest>(`/requests/${id}/reject`, {
        decision_note: decisionNote ?? null,
      })
      .then((r) => r.data),
  cancel: (id: string, decisionNote?: string) =>
    api
      .post<ProvisioningRequest>(`/requests/${id}/cancel`, {
        decision_note: decisionNote ?? null,
      })
      .then((r) => r.data),
};

export type MetricsWindow = "1h" | "6h" | "24h" | "7d";

export interface DNSMetricsPoint {
  t: string;
  /** Seconds this point actually covers (60 x distinct agent buckets), NOT
   *  `bucket_seconds`. Derive rates from this: the newest bucket is always
   *  partial, and dividing it by the nominal width draws a phantom dip at
   *  the right edge of the chart (#942). */
  covered_seconds: number;
  queries_total: number;
  noerror: number;
  nxdomain: number;
  servfail: number;
  recursion: number;
  rate_dropped: number;
  rate_slipped: number;
}

export interface DNSMetricsSeries {
  window: MetricsWindow;
  bucket_seconds: number;
  points: DNSMetricsPoint[];
}

export interface DHCPMetricsPoint {
  t: string;
  /** Seconds this point actually covers (60 x distinct agent buckets), NOT
   *  `bucket_seconds`. Derive rates from this: the newest bucket is always
   *  partial, and dividing it by the nominal width draws a phantom dip at
   *  the right edge of the chart (#942). */
  covered_seconds: number;
  discover: number;
  offer: number;
  request: number;
  ack: number;
  nak: number;
  decline: number;
  release: number;
  inform: number;
  /** #980 — packets lost, and where. `socket_drop` is the kernel dropping
   *  datagrams before the server could read them (its receive buffer filled;
   *  the node is short of CPU). `receive_drop` is the server reading a packet
   *  and discarding it. `null` means the agent did not measure it — too old,
   *  or unable to read /proc/net/udp — and must render as "not measured",
   *  never as 0. Zero is a measurement; null is the absence of one. */
  receive_drop: number | null;
  socket_drop: number | null;
}

export interface DHCPMetricsSeries {
  window: MetricsWindow;
  bucket_seconds: number;
  points: DHCPMetricsPoint[];
}

export const metricsApi = {
  dnsTimeseries: (
    params: { window?: MetricsWindow; server_id?: string } = {},
  ) =>
    api
      .get<DNSMetricsSeries>("/metrics/dns/timeseries", { params })
      .then((r) => r.data),
  dhcpTimeseries: (
    params: { window?: MetricsWindow; server_id?: string } = {},
  ) =>
    api
      .get<DHCPMetricsSeries>("/metrics/dhcp/timeseries", { params })
      .then((r) => r.data),
};

export interface VersionInfo {
  version: string;
  latest_version: string | null;
  update_available: boolean;
  latest_release_url: string | null;
  latest_checked_at: string | null;
  release_check_enabled: boolean;
  latest_check_error: string | null;
  // Appliance mode — true when the API runs on the SpatiumDDI OS
  // appliance ISO. Gates the "Appliance" sidebar entry and the
  // /appliance route. Phase 4 (issue #134).
  appliance_mode: boolean;
  appliance_version: string | null;
  appliance_hostname: string | null;
}

export const versionApi = {
  get: () => api.get<VersionInfo>("/version").then((r) => r.data),
};

// ── Appliance management (Phase 4) ─────────────────────────────────
// Mounted at /api/v1/appliance. Phase 4a ships only /info — sub-phases
// 4b-4g extend this client with the real management surfaces (TLS
// cert upload, release manager, containers, logs, network/host
// config, web first-boot wizard).
// #416 — identity + lifecycle of the LOCAL appliance for the browser
// Console view, sourced from the self ``Appliance`` row the supervisor
// populates on heartbeat (matched by hostname). ``null`` on docker / k8s
// control planes (no supervisor) or before the local supervisor has
// registered + been approved. Mirrors the backend ``SelfApplianceInfo``.
export interface SelfApplianceInfo {
  state: string;
  deployment_kind: string | null;
  supervisor_version: string | null;
  installed_appliance_version: string | null;
  current_slot: string | null;
  durable_default: string | null;
  is_trial_boot: boolean;
  last_upgrade_state: string | null;
  node_ip: string | null;
  // ``{<compose-service>: {role, status, since, …}}`` — the supervisor's
  // service-container watchdog rollup; drives the Console's per-role chips.
  role_health: Record<
    string,
    { role?: string; status?: string; since?: string; [k: string]: unknown }
  >;
  role_switch_state: string | null;
  last_seen_at: string | null;
}

export interface ApplianceInfo {
  appliance_mode: boolean;
  appliance_version: string | null;
  appliance_hostname: string | null;
  // #416 — local appliance lifecycle for the Console view; null off-box.
  self_appliance: SelfApplianceInfo | null;
}

/**
 * One remote way in, and whether it admits the caller (#1013).
 *
 * The appliance has two source restrictions — the Web UI allow-list and the
 * SSH allow-list — and each used to be editable from a screen that could not
 * see the other, so both could be closed one at a time.
 */
export interface RemoteDoor {
  name: "web_ui" | "ssh";
  restricted: boolean;
  allowed_cidrs: string[];
  admits: boolean;
}

export interface RemoteAccess {
  caller_ip: string | null;
  web_ui: RemoteDoor;
  ssh: RemoteDoor;
  /** Neither door admits you — the console is all that is left. */
  console_only: boolean;
}

export const applianceApi = {
  getInfo: () => api.get<ApplianceInfo>("/appliance/info").then((r) => r.data),
  /**
   * #999 Part B — run an md / multipath management action on one
   * appliance. Superadmin + audited; the control plane validates what
   * may be ASKED for and the host runner re-checks what is safe to do at
   * the moment of the action (its view of the array is current, ours is
   * up to one heartbeat old).
   */
  storageAction: (applianceId: string, body: StorageActionRequest) =>
    api
      .post<StorageActionResult>(
        `/appliance/appliances/${applianceId}/storage/action`,
        body,
      )
      .then((r) => r.data),
  /**
   * Read by BOTH lockout-sensitive screens (Firewall → Web UI access, and
   * SSH → source restriction) so each can show the state of the OTHER door.
   * Lives on the always-mounted hub, not under /appliance/firewall, because
   * the SSH screen must be able to ask with that module off.
   */
  getRemoteAccess: () =>
    api.get<RemoteAccess>("/appliance/remote-access").then((r) => r.data),
  /**
   * #989 item 3 — removable (USB) backup disks on one appliance.
   *
   * The listing comes from that node's last heartbeat, so it is at most
   * one heartbeat interval old: a disk plugged in a moment ago appears
   * on the next tick. The UI says so rather than implying the read is
   * live, because a Refresh button that cannot possibly help is worse
   * than none.
   */
  listRemovable: (applianceId: string) =>
    api
      .get<RemovableResponse>(`/appliance/appliances/${applianceId}/removable`)
      .then((r) => r.data),
  mountRemovable: (applianceId: string, body: RemovableMountRequest) =>
    api
      .post<RemovableResponse>(
        `/appliance/appliances/${applianceId}/removable/mount`,
        body,
      )
      .then((r) => r.data),
  ejectRemovable: (applianceId: string, name: string) =>
    api
      .delete<RemovableResponse>(
        `/appliance/appliances/${applianceId}/removable/${encodeURIComponent(name)}`,
      )
      .then((r) => r.data),
};

// ── Fleet firewall (issue #285 Phase 3) ──────────────────────────────
// Policy/rule/alias CRUD + server-side effective render + staged preview.
// Gated by the appliance.firewall feature module (router 404s when off) and
// the firewall_enabled master switch (render stays dark until enforcement).
export type FirewallScopeKind = "fleet" | "role" | "appliance";
export type FirewallAction = "accept" | "drop";
export type FirewallProtocol = "tcp" | "udp" | "icmp" | "icmpv6";
export type FirewallFamily = "v4" | "v6" | "both";
export type FirewallSourceKind =
  | "any"
  | "cidr"
  | "alias"
  | "cluster_peers"
  | "pod_cidr"
  | "service_cidr"
  | "kubeapi"
  // #993 — pod ∪ service, WITHOUT the operator's kubeapi_expose allowlist.
  // Kept out of that union on purpose: it widens the RBAC-guarded
  // apiserver, and the kubelet API serves /exec, /run and /attach.
  | "kubelet"
  | "mgmt"
  | "vip";

export interface FirewallRuleInput {
  seq: number;
  action: FirewallAction;
  protocol: FirewallProtocol;
  ports: number[];
  source_kind: FirewallSourceKind;
  source_cidrs: string[];
  source_alias: string | null;
  family: FirewallFamily;
  comment: string | null;
  render_guard?: Record<string, unknown> | null;
  enabled: boolean;
}

export interface FirewallRule extends FirewallRuleInput {
  id: string;
  policy_id: string;
}

export interface FirewallPolicy {
  id: string;
  name: string;
  description: string | null;
  scope_kind: FirewallScopeKind;
  scope_role: string | null;
  scope_appliance_id: string | null;
  enabled: boolean;
  is_builtin: boolean;
  priority: number;
  rules: FirewallRule[];
}

export interface FirewallAlias {
  id: string;
  name: string;
  kind: "port" | "cidr";
  port_members: number[];
  v4_members: string[];
  v6_members: string[];
  description: string | null;
  is_builtin: boolean;
}

export interface FirewallEffective {
  appliance_id: string;
  hostname: string;
  firewall_enabled: boolean;
  config_hash: string;
  firewall_conf: string;
  layers: Record<string, string[]>;
  rendered_hash: string | null;
  applied_hash: string | null;
  applied_status: string | null;
  base_conf_marker: string | null;
  drift: boolean;
}

export interface FirewallPreviewWarning {
  kind: string;
  detail: string;
  seqs: number[];
}

export interface FirewallPreview {
  appliance_id: string;
  added: string[];
  removed: string[];
  warnings: FirewallPreviewWarning[];
  upgrade_in_flight: boolean;
  staging_id: string;
}

export interface FirewallEnforcementNode {
  appliance_id: string;
  hostname: string;
  hardened: boolean;
  base_lanwide_k3s: boolean | null;
  last_seen_at: string | null;
}

export interface FirewallEnforcement {
  enabled: boolean;
  /** #404 — opt-in firewall drop-logging master switch. */
  logging_enabled: boolean;
  reported_count: number;
  hardened_count: number;
  lanwide_count: number;
  all_hardened: boolean;
  safe_to_enable: boolean;
  nodes: FirewallEnforcementNode[];
}

// #285 Phase 6 — Web UI source restriction.
export interface FirewallWebUIAccess {
  allowed_cidrs: string[];
  open: boolean;
  caller_ip: string | null;
  caller_covered: boolean;
}

const _FW = "/appliance/firewall";
export const firewallApi = {
  listPolicies: (params?: {
    scope_kind?: FirewallScopeKind;
    scope_role?: string;
  }) =>
    api
      .get<FirewallPolicy[]>(`${_FW}/policies`, { params })
      .then((r) => r.data),
  createPolicy: (body: {
    name: string;
    description?: string | null;
    scope_kind: FirewallScopeKind;
    scope_role?: string | null;
    scope_appliance_id?: string | null;
    enabled?: boolean;
    priority?: number;
  }) => api.post<FirewallPolicy>(`${_FW}/policies`, body).then((r) => r.data),
  updatePolicy: (
    id: string,
    body: Partial<{
      name: string;
      description: string | null;
      enabled: boolean;
      priority: number;
    }>,
  ) =>
    api
      .patch<FirewallPolicy>(`${_FW}/policies/${id}`, body)
      .then((r) => r.data),
  deletePolicy: (id: string) =>
    api.delete(`${_FW}/policies/${id}`).then((r) => r.data),
  replaceRules: (id: string, rules: FirewallRuleInput[]) =>
    api
      .put<FirewallPolicy>(`${_FW}/policies/${id}/rules`, { rules })
      .then((r) => r.data),
  listAliases: () =>
    api.get<FirewallAlias[]>(`${_FW}/aliases`).then((r) => r.data),
  createAlias: (body: {
    name: string;
    kind: "port" | "cidr";
    port_members?: number[];
    v4_members?: string[];
    v6_members?: string[];
    description?: string | null;
  }) => api.post<FirewallAlias>(`${_FW}/aliases`, body).then((r) => r.data),
  deleteAlias: (id: string) =>
    api.delete(`${_FW}/aliases/${id}`).then((r) => r.data),
  effective: (applianceId: string) =>
    api
      .get<FirewallEffective>(`${_FW}/appliances/${applianceId}/effective`)
      .then((r) => r.data),
  preview: (body: {
    appliance_id: string;
    fleet_rules?: FirewallRuleInput[];
    appliance_rules?: FirewallRuleInput[];
  }) => api.post<FirewallPreview>(`${_FW}/preview`, body).then((r) => r.data),
  getEnforcement: () =>
    api.get<FirewallEnforcement>(`${_FW}/enforcement`).then((r) => r.data),
  setEnforcement: (body: { enabled: boolean; override_unhardened?: boolean }) =>
    api
      .put<FirewallEnforcement>(`${_FW}/enforcement`, body)
      .then((r) => r.data),
  // #404 — opt-in firewall drop-logging toggle (independent of enforcement).
  setLogging: (enabled: boolean) =>
    api
      .put<FirewallEnforcement>(`${_FW}/logging`, { enabled })
      .then((r) => r.data),
  applyPosture: (preset: "locked" | "balanced" | "open") =>
    api.post<FirewallPolicy>(`${_FW}/posture`, { preset }).then((r) => r.data),
  getWebUIAccess: () =>
    api.get<FirewallWebUIAccess>(`${_FW}/web-ui-access`).then((r) => r.data),
  setWebUIAccess: (body: {
    allowed_cidrs: string[];
    /** Accept losing THIS door while another remains open. */
    override_lockout?: boolean;
    /** Accept losing EVERY remote door, leaving only the console (#1013). */
    acknowledge_console_only?: boolean;
  }) =>
    api
      .put<FirewallWebUIAccess>(`${_FW}/web-ui-access`, body)
      .then((r) => r.data),
};

// Appliance Web UI certificate management (Phase 4b.1). Mounted at
// /api/v1/appliance/tls. Phase 4b.1 ships upload + list + activate +
// delete; CSR generation lands in 4b.3, Let's Encrypt in 4b.4.
export type CertificateSource =
  | "uploaded"
  | "csr"
  | "letsencrypt"
  | "self-signed";

export interface ApplianceCertificate {
  id: string;
  name: string;
  source: CertificateSource;
  is_active: boolean;
  activated_at: string | null;
  subject_cn: string;
  issuer_cn: string | null;
  sans: string[];
  fingerprint_sha256: string | null;
  valid_from: string | null;
  valid_to: string | null;
  notes: string | null;
  created_at: string;
  created_by_user_id: string | null;
  // CSR-pending state — true when the row was created via /tls/csr
  // and is waiting for the operator to paste back the signed cert.
  pending: boolean;
  csr_pem: string | null;
}

export interface ApplianceCertificateDetail extends ApplianceCertificate {
  cert_pem: string | null;
}

export interface CertificateUploadPayload {
  name: string;
  cert_pem: string;
  key_pem: string;
  notes?: string | null;
  activate?: boolean;
}

export type CSRKeyType =
  | "rsa-2048"
  | "rsa-3072"
  | "rsa-4096"
  | "ec-p256"
  | "ec-p384";

export interface CSRGeneratePayload {
  name: string;
  common_name: string;
  organization?: string | null;
  organizational_unit?: string | null;
  country?: string | null;
  state?: string | null;
  locality?: string | null;
  email?: string | null;
  sans?: string[];
  key_type?: CSRKeyType;
  notes?: string | null;
}

export interface CSRImportPayload {
  cert_pem: string;
  activate?: boolean;
}

export const applianceTlsApi = {
  list: () =>
    api.get<ApplianceCertificate[]>("/appliance/tls").then((r) => r.data),
  get: (id: string) =>
    api
      .get<ApplianceCertificateDetail>(`/appliance/tls/${id}`)
      .then((r) => r.data),
  upload: (body: CertificateUploadPayload) =>
    api
      .post<ApplianceCertificate>("/appliance/tls/upload", body)
      .then((r) => r.data),
  generateCsr: (body: CSRGeneratePayload) =>
    api
      .post<ApplianceCertificate>("/appliance/tls/csr", body)
      .then((r) => r.data),
  importSignedCert: (id: string, body: CSRImportPayload) =>
    api
      .post<ApplianceCertificate>(`/appliance/tls/${id}/import-cert`, body)
      .then((r) => r.data),
  activate: (id: string) =>
    api
      .post<ApplianceCertificate>(`/appliance/tls/${id}/activate`)
      .then((r) => r.data),
  remove: (id: string) =>
    api.delete<void>(`/appliance/tls/${id}`).then((r) => r.data),
};

// ── Appliance: embedded ACME client — Let's Encrypt (issue #438) ───
//
// Mounted at /api/v1/appliance/acme behind the "security.certificates"
// feature module (the whole surface 404s when the module is off).
// SpatiumDDI acts as an RFC 8555 ACME client against a public CA
// (Let's Encrypt), solving the DNS-01 challenge through its OWN managed
// DNS zones, and lands the issued chain in the existing
// ApplianceCertificate storage with source="letsencrypt".
//
// dns-01 (Phase 1/3) solves over SpatiumDDI-managed zones, cloud-hosted
// zones (Cloudflare / Route53 / Azure / Google via the agentless drivers),
// or — with allow_manual — an operator-pasted TXT for an unmanaged domain.
// http-01 (Phase 4) is supported (frontend nginx proxies the challenge to
// the api). tls-alpn-01 (Phase 5) is NOT supported on the nginx/k3s
// topology — POST /issue 422s for it and the UI marks it disabled.
// Active LE certs auto-renew ~30d before expiry (Phase 2 Celery task).
//
// Secret material (account key, EAB HMAC) NEVER comes back over the
// wire — the account summary exposes only an ``eab_hmac_set`` boolean.
export type AcmeChallengeType = "dns-01" | "http-01" | "tls-alpn-01";

export type AcmeOrderStatus = "pending" | "processing" | "valid" | "invalid";

export interface AcmeAccountConfig {
  id: string;
  directory_url: string;
  account_url: string | null;
  email: string | null;
  eab_kid: string | null;
  // Boolean presence flag only — the HMAC itself never leaves the server.
  eab_hmac_set: boolean;
  created_at: string;
  modified_at: string;
}

export interface AcmeAccountUpsert {
  directory_url: string;
  email?: string | null;
  eab_kid?: string | null;
  // Write-only — supply to set/replace, omit to leave unchanged.
  eab_hmac_b64?: string | null;
}

// Per-domain solvability report (POST /preview, dns-01 only). When
// ``managed`` the challenge is solved automatically (SpatiumDDI-managed
// zone or a cloud driver named in ``driver``); otherwise the operator
// must add the TXT by hand (allow_manual on the order).
export interface ACMEDomainResolution {
  domain: string;
  challenge_fqdn: string;
  managed: boolean;
  zone_name: string | null;
  record_name: string | null;
  driver: string | null;
}

// A manual TXT the operator must publish for an allow_manual order to
// converge. The order sits in "processing" until each record_name's
// txt_value is visible in public DNS.
export interface AcmeManualChallenge {
  fqdn: string;
  record_name: string;
  txt_value: string;
}

export interface AcmeOrder {
  id: string;
  domains: string[];
  challenge_type: string;
  dns_provider: string | null;
  status: AcmeOrderStatus;
  order_url: string | null;
  finalize_url: string | null;
  // Set to the new ApplianceCertificate (source="letsencrypt") row on
  // a valid order.
  certificate_id: string | null;
  last_error: string | null;
  // True when the operator opted into solving unmanaged domains by hand.
  allow_manual: boolean;
  // Populated while a manual order is "processing" — the TXT records the
  // operator must add. Empty for fully-managed orders.
  manual_challenges: AcmeManualChallenge[];
  created_at: string;
  modified_at: string;
}

export interface AcmeIssueRequest {
  domains: string[];
  challenge_type?: AcmeChallengeType;
  dns_provider?: string | null;
  // dns-01 only — let an unmanaged domain be solved by an operator-pasted
  // TXT (the order goes "processing" with manual_challenges populated).
  allow_manual?: boolean;
}

// Well-known Let's Encrypt directory endpoints surfaced as form
// presets — operators rarely type these by hand.
export const ACME_DIRECTORY_PRESETS: { label: string; url: string }[] = [
  {
    label: "Let's Encrypt (production)",
    url: "https://acme-v02.api.letsencrypt.org/directory",
  },
  {
    label: "Let's Encrypt (staging)",
    url: "https://acme-staging-v02.api.letsencrypt.org/directory",
  },
];

export const applianceAcmeApi = {
  // null (not 404) when no account is configured — gate the Issue
  // button on a configured account.
  getAccount: () =>
    api
      .get<AcmeAccountConfig | null>("/appliance/acme/account")
      .then((r) => r.data),
  setAccount: (body: AcmeAccountUpsert) =>
    api
      .put<AcmeAccountConfig>("/appliance/acme/account", body)
      .then((r) => r.data),
  deleteAccount: () =>
    api.delete<void>("/appliance/acme/account").then((r) => r.data),
  // dns-01 solvability check — per-domain managed(auto)/manual + driver.
  preview: (domains: string[]) =>
    api
      .post<ACMEDomainResolution[]>("/appliance/acme/preview", { domains })
      .then((r) => r.data),
  issue: (body: AcmeIssueRequest) =>
    api.post<AcmeOrder>("/appliance/acme/issue", body).then((r) => r.data),
  listOrders: () =>
    api.get<AcmeOrder[]>("/appliance/acme/orders").then((r) => r.data),
  getOrder: (id: string) =>
    api.get<AcmeOrder>(`/appliance/acme/orders/${id}`).then((r) => r.data),
  cancelOrder: (id: string) =>
    api
      .post<AcmeOrder>(`/appliance/acme/orders/${id}/cancel`)
      .then((r) => r.data),
};

// ── Appliance: release management (Phase 4c) ───────────────────────
export interface ApplianceRelease {
  tag: string;
  name: string;
  published_at: string;
  body: string;
  html_url: string;
  is_prerelease: boolean;
  is_installed: boolean;
}

export interface ApplianceReleasesResponse {
  installed_version: string;
  releases: ApplianceRelease[];
}

// #294 — read-only. The old one-click `apply` (+ `log` poll) drove a
// docker-compose-era host updater that does nothing on the k3s
// appliance; OS upgrades go through the A/B slot flow (Fleet tab) and
// docker/k8s use the manual-command modal in the UI.
export const applianceReleasesApi = {
  list: () =>
    api
      .get<ApplianceReleasesResponse>("/appliance/releases")
      .then((r) => r.data),
};

// ── Appliance: A/B slot upgrade (Phase 8b-3, issue #138) ──────────
export type ApplianceSlot = "slot_a" | "slot_b";
export type ApplianceSlotUpgradeState =
  | "ready"
  | "in-flight"
  | "done"
  | "failed";

export interface ApplianceSlotStatus {
  appliance_mode: boolean;
  current_slot: ApplianceSlot | null;
  durable_default: ApplianceSlot | null;
  is_trial_boot: boolean;
  upgrade_state: ApplianceSlotUpgradeState;
  upgrade_state_at: string | null;
  log_tail: string;
  // Per-slot installed APPLIANCE_VERSION from the slot-versions.json
  // sidecar. Null when the sidecar's missing.
  slot_a_version: string | null;
  slot_b_version: string | null;
}

export const applianceSlotApi = {
  status: () =>
    api.get<ApplianceSlotStatus>("/appliance/slot-upgrade").then((r) => r.data),
  apply: (image_url: string, checksum_url?: string | null) =>
    api
      .post<{ scheduled: string }>("/appliance/slot-upgrade/apply", {
        image_url,
        checksum_url: checksum_url || null,
      })
      .then((r) => r.data),
  rollback: (target_slot: ApplianceSlot | null) =>
    api
      .post<{
        scheduled: string;
        target_slot: ApplianceSlot | null;
      }>("/appliance/slot-upgrade/rollback", { target_slot })
      .then((r) => r.data),
};

// ── Appliance: fleet upgrade orchestration (Phase 8f, issue #138) ──
export type FleetAgentKind = "dns" | "dhcp";
export type ApplianceDeploymentKind =
  | "appliance"
  | "docker"
  | "k8s"
  | "unknown"
  | null;

export interface FleetAgentRow {
  kind: FleetAgentKind;
  id: string;
  name: string;
  host: string;
  deployment_kind: ApplianceDeploymentKind;
  installed_appliance_version: string | null;
  current_slot: ApplianceSlot | null;
  durable_default: ApplianceSlot | null;
  is_trial_boot: boolean;
  last_upgrade_state: string | null;
  last_upgrade_state_at: string | null;
  last_seen_at: string | null;
  last_seen_ip: string | null;
  desired_appliance_version: string | null;
  desired_slot_image_url: string | null;
  // Phase 8f-8 — operator-triggered reboot. True while a request is
  // in flight (operator clicked Reboot but agent hasn't reconnected
  // post-reboot yet).
  reboot_requested: boolean;
  reboot_requested_at: string | null;
}

// issue #566 decision D1 — MetalLB BGP mode (export path: advertise the
// VIP to upstream routers). One entry per BGPPeer / BGPAdvertisement CR.
export interface MetalLBBgpPeer {
  my_asn: number;
  peer_asn: number;
  peer_address: string;
  peer_port?: number | null;
  hold_time?: string | null;
}

export interface MetalLBBgpAdvertisement {
  ip_address_pools: string[];
  communities?: string[];
  aggregation_length?: number | null;
}

// #272 Phase 7c — cluster-wide MetalLB / control-plane-VIP config.
export interface MetalLBConfig {
  enabled: boolean;
  pool_addresses: string[];
  control_plane_vip: string;
  // #272 Phase 10 — optional data-plane resolver VIPs (same pool).
  // Empty = the hostNetwork data plane (no VIP). dns_vip fronts
  // bind9/powerdns :53; dhcp_relay_vip fronts the Kea relay→server :67.
  dns_vip?: string;
  dhcp_relay_vip?: string;
  // issue #566 decision D1 — BGP mode. Layered on top of the same
  // MetalLB install; requires `enabled: true`. bgp_advertisements is
  // auto-derived server-side when omitted (see the backend cross-field
  // validator), so the form only needs to manage bgp_peers.
  bgp_enabled?: boolean;
  bgp_peers?: MetalLBBgpPeer[];
  bgp_advertisements?: MetalLBBgpAdvertisement[];
  // #272 — live readiness from the GET (best-effort; absent/zero when
  // kubeapi is unreachable). Not sent on PUT.
  controller_ready?: boolean;
  speakers_ready?: number;
  speakers_total?: number;
}

// #272 Phase 9 — dead-node replacement result.
export interface ControlPlaneReplaceResult {
  evicted: ApplianceRow;
  pairing_code: string;
  pairing_expires_at: string;
}

// #272 Phase 9b — etcd snapshot inventory + guided restore.
export interface EtcdSnapshotRow {
  name: string;
  location: string;
  node_name: string;
  size: number | null;
  created_at: string | null;
}
export interface EtcdSnapshots {
  available: boolean;
  seed_id: string | null;
  seed_hostname: string | null;
  reported_at: string | null;
  snapshots: EtcdSnapshotRow[];
  desired_restore_snapshot: string | null;
  restore_state: string | null;
  restore_reason: string | null;
}

export const applianceFleetApi = {
  list: () =>
    api
      .get<{ agents: FleetAgentRow[] }>("/appliance/fleet")
      .then((r) => r.data),
  scheduleUpgrade: (
    kind: FleetAgentKind,
    server_id: string,
    desired_appliance_version: string,
    desired_slot_image_url: string,
  ) =>
    api
      .post<{
        kind: FleetAgentKind;
        id: string;
        desired_appliance_version: string;
        desired_slot_image_url: string;
      }>(`/appliance/fleet/${kind}/${server_id}/upgrade`, {
        desired_appliance_version,
        desired_slot_image_url,
      })
      .then((r) => r.data),
  clearUpgrade: (kind: FleetAgentKind, server_id: string) =>
    api
      .post<FleetAgentRow>(`/appliance/fleet/${kind}/${server_id}/clear`)
      .then((r) => r.data),
  scheduleReboot: (kind: FleetAgentKind, server_id: string) =>
    api
      .post<FleetAgentRow>(`/appliance/fleet/${kind}/${server_id}/reboot`)
      .then((r) => r.data),
};

// ── Multi-node rolling upgrade orchestrator (#296 Phases A-F) ──────
// Consumed by the Fleet UI's Rolling Upgrade tab. Wraps every endpoint
// in /api/v1/upgrades — preflight (Phase A), lease state (A),
// plan + lifecycle endpoints (D), and run details / history (D).
//
// The orchestrator drives Phases C (per-node primitive), E (post-loop
// chart bump), and F (alert + failure classifier) under the hood;
// from the UI's perspective it's one state machine on a
// SystemUpgradeRun row that walks planned → running → succeeded |
// failed | halted | aborted with rich per-node progress along the way.

export type ClusterUpgradeState =
  | "planned"
  | "running"
  | "succeeded"
  | "failed"
  | "halted"
  | "aborted";

export type ClusterUpgradeFailureCategory =
  | "preflight_fail"
  | "drain_stuck"
  | "cordon_fail"
  | "cnpg_primary_stuck"
  | "node_auto_reverted"
  | "node_unreachable_after_apply"
  | "supervisor_reported_failed"
  | "node_did_not_rejoin"
  | "chart_bump_failed"
  | "uncordon_fail"
  | "other";

export type PreflightLevel = "ok" | "warn" | "fail";

export interface PreflightCheck {
  name: string;
  level: PreflightLevel;
  message: string;
  detail: Record<string, unknown>;
}

export interface PreflightReport {
  target_version: string;
  current_version: string;
  overall: PreflightLevel;
  can_start: boolean;
  results: PreflightCheck[];
}

export interface UpgradeLeaseState {
  held: boolean;
  holder: string | null;
  renew_time: string | null;
  transitions: number;
  expired: boolean;
}

export interface PerNodeStepProgress {
  name: string;
  ok: boolean;
  started_at: string | null;
  finished_at: string | null;
  detail: Record<string, unknown>;
  error: string | null;
}

export interface PerNodeProgress {
  ok: boolean;
  failed_at: string | null;
  error: string | null;
  steps: PerNodeStepProgress[];
  // Phase F — stable category string the Fleet UI keys off to
  // render the right operator-action hint. Absent on still-in-flight
  // nodes; set when the node's primitive returns ok=False.
  failure_category?: ClusterUpgradeFailureCategory;
}

export interface ChartBumpProgress {
  ok: boolean;
  new_tag: string;
  chart_name: string;
  namespace: string;
  started_at: string;
  finished_at: string | null;
  rolled_deployments: string[] | null;
  migrate_job_state: string | null;
  error: string | null;
  skipped: boolean;
  skip_reason: string | null;
}

export interface UpgradeRunEvent {
  event: string;
  at: string;
  [k: string]: unknown;
}

export interface UpgradeRunProgress {
  events: UpgradeRunEvent[];
  per_node: Record<string, PerNodeProgress>;
  chart_bump?: ChartBumpProgress;
}

export interface UpgradeRunPlan {
  node_order: string[];
  slot_image_url: string;
  cnpg_cluster_name: string;
  cnpg_namespace: string | null;
  preflight_at_plan?: Array<{
    name: string;
    level: PreflightLevel;
    message: string;
  }>;
  [k: string]: unknown;
}

export interface SystemUpgradeRun {
  id: string;
  kind: string;
  state: ClusterUpgradeState;
  target_version: string;
  source_versions: Record<string, string | null>;
  plan: UpgradeRunPlan;
  progress: UpgradeRunProgress;
  lease_holder: string | null;
  lease_acquired_at: string | null;
  last_error: string | null;
  started_by_user_id: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface PreflightPlanRow {
  name: string;
  level: PreflightLevel;
  message: string;
}

export interface ClusterUpgradePlanResponse {
  run_id: string;
  target_version: string;
  node_order: string[];
  preflight_overall: PreflightLevel;
  preflight: PreflightPlanRow[];
}

// Two source modes for the upgrade image — exactly one must be set.
// ``slot_image_url`` is the connected / online path (operator pastes
// an HTTPS URL like a GitHub release asset). ``slot_image_id`` is the
// staged-image path: operator first uploads or imports the .raw.xz via
// ``applianceUpgradeImagesApi`` (in the Fleet → Upgrade images panel),
// then references the returned id here. (The request field names keep
// the ``slot_image_*`` form — they feed the lower-level slot mechanism;
// #199 renamed the operator-facing surface, not the wire fields.) The
// control plane composes the authenticated internal URL server-side so
// every node's host runner pulls bytes through the same control-plane →
// mirror pipe as the per-box upgrade flow.
export interface ClusterUpgradePlanRequest {
  target_version: string;
  slot_image_url?: string;
  slot_image_id?: string;
  cnpg_cluster_name?: string;
  cnpg_namespace?: string | null;
}

export const clusterUpgradesApi = {
  preflight: (target: string) =>
    api
      .get<PreflightReport>("/upgrades/preflight", { params: { target } })
      .then((r) => r.data),
  lease: () =>
    api.get<UpgradeLeaseState>("/upgrades/lease").then((r) => r.data),
  plan: (body: ClusterUpgradePlanRequest) =>
    api
      .post<ClusterUpgradePlanResponse>("/upgrades/plan", body)
      .then((r) => r.data),
  start: (runId: string) =>
    api.post<SystemUpgradeRun>(`/upgrades/${runId}/start`).then((r) => r.data),
  halt: (runId: string) =>
    api.post<SystemUpgradeRun>(`/upgrades/${runId}/halt`).then((r) => r.data),
  resume: (runId: string) =>
    api.post<SystemUpgradeRun>(`/upgrades/${runId}/resume`).then((r) => r.data),
  abort: (runId: string) =>
    api.post<SystemUpgradeRun>(`/upgrades/${runId}/abort`).then((r) => r.data),
  get: (runId: string) =>
    api.get<SystemUpgradeRun>(`/upgrades/${runId}`).then((r) => r.data),
  runs: (limit = 25) =>
    api
      .get<SystemUpgradeRun[]>("/upgrades/runs", { params: { limit } })
      .then((r) => r.data),
};

// ── Appliance: pairing codes (issue #169) ──────────────────────────
// Pairing codes (#169 + #170 Wave A3 reshape).
//
// Two flavours:
//   * Ephemeral (persistent=false) — single-use, short expiry,
//     cleartext shown once on create.
//   * Persistent (persistent=true) — multi-claim; default no expiry;
//     admin can disable / re-reveal the cleartext via Fernet decrypt
//     after a password re-check.
//
// The consume side is no longer /pair — supervisors claim via
// POST /api/v1/appliance/supervisor/register (Wave A2). Legacy
// /pair is gone in Wave A3.
export type PairingCodeState =
  | "pending"
  | "claimed"
  | "expired"
  | "revoked"
  | "disabled";

export interface PairingCodeCreate {
  persistent: boolean;
  expires_in_minutes?: number | null;
  max_claims?: number | null;
  note?: string | null;
}

export interface PairingCodeCreated {
  id: string;
  // 8-digit cleartext code. Shown once on create. For persistent
  // codes the cleartext is also recoverable via /reveal; for
  // ephemeral codes this is the only chance to record it.
  code: string;
  persistent: boolean;
  enabled: boolean;
  expires_at: string | null;
  max_claims: number | null;
  note: string | null;
  created_at: string;
}

export interface PairingCodeRow {
  id: string;
  code_last_two: string;
  persistent: boolean;
  enabled: boolean;
  state: PairingCodeState;
  expires_at: string | null;
  max_claims: number | null;
  claim_count: number;
  revoked_at: string | null;
  note: string | null;
  created_at: string;
  created_by_user_id: string | null;
}

export interface PairingCodeRevealResponse {
  id: string;
  code: string;
}

export const appliancePairingApi = {
  list: (params: { include_terminal?: boolean } = {}) =>
    api
      .get<{ codes: PairingCodeRow[] }>("/appliance/pairing-codes", { params })
      .then((r) => r.data),
  create: (body: PairingCodeCreate) =>
    api
      .post<PairingCodeCreated>("/appliance/pairing-codes", body)
      .then((r) => r.data),
  revoke: (id: string) =>
    api.delete<void>(`/appliance/pairing-codes/${id}`).then((r) => r.data),
  enable: (id: string) =>
    api.post<void>(`/appliance/pairing-codes/${id}/enable`).then((r) => r.data),
  disable: (id: string) =>
    api
      .post<void>(`/appliance/pairing-codes/${id}/disable`)
      .then((r) => r.data),
  reveal: (id: string, password?: string, totpCode?: string) =>
    api
      .post<PairingCodeRevealResponse>(
        `/appliance/pairing-codes/${id}/reveal`,
        { password, totp_code: totpCode },
      )
      .then((r) => r.data),
};

// ── Appliance: approval workflow (#170 Wave B1 backend, B3 UI) ─────
// Supervisors land here after claiming a pairing code via
// /api/v1/appliance/supervisor/register. They sit in
// pending_approval until an admin clicks Approve — the control
// plane's internal CA signs an X.509 cert against the supervisor's
// submitted Ed25519 pubkey + the supervisor picks the cert up on its
// next /supervisor/poll. Reject = delete the row + the supervisor
// falls back to bootstrapping.
export type ApplianceState =
  | "pending_approval"
  | "approved"
  | "rejected"
  // Issue #170 Wave E follow-up — soft-deleted. Heartbeats return
  // 403, the supervisor flips to local revoked + tears down its
  // service containers. Admin can Re-authorize (back to ``approved``)
  // or Permanently delete (hard DELETE).
  | "revoked";

export interface SupervisorCapabilities {
  can_run_dns_bind9?: boolean;
  can_run_dns_powerdns?: boolean;
  can_run_dns_technitium?: boolean;
  can_run_dhcp?: boolean;
  can_run_looking_glass?: boolean;
  can_run_observer?: boolean;
  has_baked_images?: boolean;
  baked_images_version?: string;
  supervisor_version?: string;
  cpu_count?: number;
  memory_mb?: number;
  storage_type?: string;
  host_nics?: string[];
  [k: string]: unknown;
}

// #386 Part C — structured per-phase progress the host slot-upgrade
// runner emits, surfaced on the appliance row so the Fleet drilldown
// can render a real step-by-step status instead of just a coarse chip.
export type ApplianceUpgradeStep =
  | "queued"
  | "downloading"
  | "verifying"
  | "writing"
  | "bootloader"
  | "arming"
  | "reboot-pending"
  | "done"
  | "failed";

export interface ApplianceUpgradeProgress {
  step: ApplianceUpgradeStep | string;
  /** 0–100 during download; null for steps without a measurable %. */
  pct: number | null;
  detail: string;
  /** ISO-8601 timestamp the step was entered. */
  at: string;
}

export interface ApplianceRow {
  id: string;
  hostname: string;
  state: ApplianceState;
  public_key_fingerprint: string;
  supervisor_version: string | null;
  capabilities: SupervisorCapabilities;
  paired_at: string;
  paired_from_ip: string | null;
  last_seen_at: string | null;
  last_seen_ip: string | null;
  approved_at: string | null;
  approved_by_user_id: string | null;
  rejected_at: string | null;
  cert_serial: string | null;
  cert_issued_at: string | null;
  cert_expires_at: string | null;
  // #170 Wave C1 — slot telemetry surfaced from the supervisor's
  // heartbeat. Pre-C1 (Wave A4-era) Application appliances never
  // run the supervisor heartbeat path, so these stay null on those
  // rows.
  deployment_kind: string | null;
  // #272 — installer-role variant ("control-plane" / "appliance";
  // legacy full-stack / frontend-core / application normalised away
  // by the supervisor). Drives the Fleet UI's two-table split
  // (Control plane vs Service agents). NULL on pre-#272 supervisors
  // that haven't slot-upgraded yet.
  appliance_variant: string | null;
  // #1026 — the node's CPU architecture from the supervisor's uname.
  // null on a supervisor too old to report it, and treated as UNKNOWN
  // everywhere: it never matches and never blocks.
  architecture: string | null;
  installed_appliance_version: string | null;
  current_slot: string | null;
  durable_default: string | null;
  // Per-slot installed version, surfaced from the supervisor's
  // ``slot-versions.json`` sidecar. Two side-by-side slot cards in
  // the Fleet drilldown read these; ``slotVersionLabel`` normalises
  // ``"unstamped"`` / ``"unreadable"`` / ``"unknown"`` to ``"—"``.
  slot_a_version: string | null;
  slot_b_version: string | null;
  is_trial_boot: boolean;
  last_upgrade_state: string | null;
  last_upgrade_state_at: string | null;
  // #386 Part C — full upgrade status: tail of the host slot-upgrade.log
  // + structured per-phase progress, shipped by the supervisor while an
  // apply is in-flight / failed / awaiting-reboot.
  last_upgrade_log_tail: string | null;
  last_upgrade_progress: ApplianceUpgradeProgress | null;
  snmpd_running: boolean | null;
  lldpd_running: boolean | null;
  ntp_sync_state: string | null;
  /** Issue #156 — best-effort rsyslog forwarding status:
   *  "forwarding" / "unreachable" / "disabled", or null on
   *  non-appliance / pre-#156 rows. */
  syslog_forwarding: string | null;
  /** Issue #157 — per-host count of authorized_keys lines the host runner
   *  actually applied, or null on non-appliance / pre-#157 / never-reported
   *  rows. */
  ssh_key_count: number | null;
  /** Issue #158 — per-host systemd-resolved state the supervisor reported:
   *  "override" / "automatic" / "failed", or null on non-appliance /
   *  pre-#158 / never-reported rows. */
  resolver_status: string | null;
  /** Issue #155 — per-host APT host-config state the supervisor reported:
   *  "synced" / "proxy-failed" / "mirror-unreachable" / "signature-mismatch"
   *  / "no-sources" / "unmanaged", or null on non-appliance / pre-#155 /
   *  never-reported rows. */
  apt_state: string | null;
  desired_appliance_version: string | null;
  desired_slot_image_url: string | null;
  // #386 Part A — integrity + transport hints (not secret). sha256 the
  // host verifies the image bytes against; tls_insecure is true only for
  // the appliance's own self-served URL.
  desired_slot_image_sha256: string | null;
  desired_slot_image_tls_insecure: boolean;
  // Operator's per-slot boot intents. Non-null means the Fleet UI
  // has asked the appliance to switch boot slots; the supervisor's
  // next heartbeat picks the field up + writes a host-side trigger.
  // Auto-clears in the heartbeat handler once the supervisor reports
  // back that the action landed.
  desired_next_boot_slot: string | null;
  desired_default_slot: string | null;
  reboot_requested: boolean;
  reboot_requested_at: string | null;
  // #170 Wave C2 — role assignment + free-form tags.
  assigned_roles: string[];
  assigned_dns_group_id: string | null;
  assigned_dhcp_group_id: string | null;
  tags: Record<string, string>;
  // #170 Wave C3 — operator-pasted nft fragment rendered after the
  // role-driven mgmt + per-role blocks.
  firewall_extra: string | null;
  // #170 Phase E2 — supervisor-reported host-side port conflicts.
  // Keyed by ``<proto>_<port>`` (e.g. ``udp_53`` / ``tcp_53`` /
  // ``udp_67``); values are the ss ``users`` string (pid+name when
  // available, else local-address fallback).
  port_conflicts: Record<string, string>;
  // #593 — the supervisor refused a firewall drop-in that would have closed
  // etcd's raft peer port on this node while k3s still considers it an etcd
  // member (a stale / diverged appliance row). `{}` when healthy; otherwise
  // `{ state: "refused_self_partition", source, reason }`.
  //
  // Keys are OPTIONAL, not `Record<string, string>`: the healthy case is an
  // empty object, so a required-key type would tell TypeScript `state.state`
  // is always a string when it is in fact `undefined` most of the time.
  firewall_state: {
    state?: string;
    source?: string;
    reason?: string;
  };
  // #170 Wave D follow-up — outcome of the supervisor's last
  // docker-compose lifecycle apply. ``idle`` / ``ready`` / ``failed``
  // or null on the first heartbeat / before any role assignment.
  role_switch_state: string | null;
  role_switch_reason: string | null;
  // #170 Wave E — supervisor's service-container watchdog. Free-form
  // map keyed by compose service name (``dns-bind9`` / ``dns-powerdns``
  // / ``dns-technitium`` / ``dhcp-kea``); each value carries the
  // per-service health verdict.
  // Empty when the supervisor hasn't run a watchdog probe yet or the
  // appliance is idle (no roles assigned).
  role_health: Record<
    string,
    {
      role: string;
      status: "healthy" | "missing" | "unhealthy" | "starting";
      since: string;
      container_id: string | null;
    }
  >;
  // #387 — per-plane host-config apply health from the supervisor's
  // bounded-retry fire-guard. Keyed by plane name (``ntp`` / ``snmp`` /
  // ``lldp`` / ``syslog`` / ``ssh`` / ``resolver`` / ``firewall`` /
  // ``timezone``); only planes whose desired config isn't applied appear,
  // so an all-healthy appliance reports ``{}``. ``failing`` = the apply
  // keeps failing (the guard is backing it off); ``retrying`` = transient.
  host_config_health: Record<
    string,
    {
      state: "retrying" | "failing";
      attempts: number;
      at: string | null;
    }
  >;
  // #395 — host-migration reconcile health. Keyed by patch id (e.g.
  // ``001-grub-render`` / ``reconcile``); only patches whose ``ok``
  // field is ``false`` in the ledger appear, so an all-applied appliance
  // reports ``{}``. ``state`` is always ``"failing"`` (run-once-per-boot
  // — no continuous retry loop). The ``error`` field carries the exit-
  // code or error string from the patch runner when available.
  host_migration_health: Record<
    string,
    {
      state: "retrying" | "failing";
      attempts: number;
      at: string | null;
      error?: string;
    }
  >;
  // Issue #183 Phase 4 — local k3s cluster health summary, supplied
  // by the supervisor on every heartbeat. Empty object on legacy
  // compose appliances or pre-#183 supervisors.
  cluster_health: {
    kubeapi_ready?: boolean;
    nodes_total?: number;
    nodes_ready?: number;
    pods_total?: number;
    pods_by_phase?: Record<string, number>;
    // #999 Part A — raw md / multipath reading, with NO verdict attached
    // (the appliance row carries that in `storage_findings` below). Typed
    // as the reading rather than as `NodeStorage` on purpose: `findings`
    // is added by the cluster-health merge and is absent here, so the
    // wider type would let a caller read `undefined` and type-check.
    storage?: NodeStorageReading;
  };
  // #999 Part A — storage redundancy, classified server-side by the same
  // function that backs the `appliance_storage_degraded` alert and the
  // `find_appliance_storage` copilot tool, so no two surfaces can
  // disagree about whether an array is in trouble.
  storage_findings: StorageFinding[];
  storage_worst_severity: string | null;
  // False = the supervisor never looked (too old to collect it), which is
  // UNKNOWN — distinct from "looked and found no arrays".
  storage_reported: boolean;
  // #1017 — the interface MTU spatium-etc-render actually APPLIED at this
  // node's last boot, which is not what STATE asked for: the renderer
  // drops a value that is out of range, that would break a pinned IPv6
  // address (RFC 8200), or that has no keyfile to live in.
  // `mtu_requested` carries the operator's value so the difference is
  // diagnosable on screen instead of only in the render log.
  mtu: number | null;
  // A string, not a number: what it reports is the operator's configured
  // value, and the case it exists for is the one where that value was
  // not a number and the renderer dropped it.
  mtu_requested: string | null;
  // "applied" | "default" | "dropped" | "n/a" — null on a supervisor too
  // old to report, which is UNKNOWN and must not render like "default".
  mtu_applied: string | null;
  mtu_reported: boolean;
  // Per-node findings only (a value the renderer refused). The
  // fleet-consistency verdict needs every row and rides on the list
  // response as `mtu_fleet`.
  mtu_findings: MtuFinding[];
  // Issue #183 Phase 5 — installed k3s version (e.g. ``v1.36.4+k3s1``).
  // Null on legacy compose / pre-#183 supervisors.
  k3s_version: string | null;
  // Issue #183 Phase 5 — boolean "supervisor has shipped a kubeconfig".
  // The ciphertext itself only crosses the wire on the reveal endpoint.
  kubeconfig_set: boolean;
  // Issue #183 Phase 6 — k3s server-cert ``Not After`` timestamp
  // (ISO-8601 UTC). Drives the cluster-health "expires in N days"
  // chip + the ``k3s_api_cert_expiring`` alert rule.
  k3s_api_cert_expires_at: string | null;
  // Issue #183 Phase 6 — operator-controlled CIDR allowlist for
  // direct kubeapi access on tcp/6443. Empty = proxy-only.
  kubeapi_expose_cidrs: string[];
  // #272 Phase 7 — control-plane cluster membership. cluster_role is
  // the settled role (primary / member / null); the desired_/join_state
  // pair reflect an in-flight promote/demote (joining / ready / leaving
  // / left / failed) so the UI can render a status chip.
  cluster_role: string | null;
  desired_cluster_role: string | null;
  cluster_join_state: string | null;
  cluster_join_reason: string | null;
  // #590 — ISO timestamp of the last cluster_join_state change. The Fleet
  // UI gates the destructive "Clear stuck state" affordance on its age so
  // it isn't offered during a healthy multi-minute k3s join.
  cluster_join_state_at: string | null;
  // Issue #170 Wave E follow-up — soft-delete timestamp. Non-null on
  // ``state=revoked`` rows; cleared by re-authorize.
  revoked_at: string | null;
  created_at: string;
}

export interface ApplianceRolesUpdate {
  roles?: string[];
  dns_group_id?: string | null;
  dhcp_group_id?: string | null;
  tags?: Record<string, string>;
  firewall_extra?: string | null;
}

export interface MtuFinding {
  severity: string;
  kind: string;
  detail: string;
}

/**
 * #1017 — whether every approved node is on the same interface MTU.
 *
 * k3s runs flannel in host-gw mode, so the pod network inherits the node
 * MTU with no tunnel headroom: a mixed-MTU cluster black-holes pod-to-pod
 * traffic and presents as random timeouts, with nothing else in the UI
 * explaining it.
 *
 * `consistent` is true when nobody reported — the absence of a reading is
 * not a fault, and every appliance installed before #1017 reports
 * nothing. `answers` maps each distinct answer ("1400", or the literal
 * "default") to the hostnames giving it; "default" is deliberately not
 * the number 1500, because that would be a guess about hardware nobody
 * read.
 */
export interface ApplianceMtuFleet {
  reported: number;
  answers: Record<string, string[]>;
  consistent: boolean;
  detail: string | null;
}

export interface ApplianceListResponse {
  appliances: ApplianceRow[];
  mtu_fleet: ApplianceMtuFleet;
}

export const applianceApprovalApi = {
  list: () =>
    api
      .get<{ appliances: ApplianceRow[] }>("/appliance/appliances")
      .then((r) => r.data.appliances),
  /**
   * The same endpoint, keeping the fleet-level block the row list drops.
   *
   * A separate method rather than widening `list()`: ten callers expect
   * an `ApplianceRow[]` and only the Fleet tab needs the verdict. Callers
   * that want rows pass `select: (d) => d.appliances`, so React Query
   * still issues ONE request per key and existing usages are unchanged.
   */
  listFleet: () =>
    api.get<ApplianceListResponse>("/appliance/appliances").then((r) => r.data),
  get: (id: string) =>
    api.get<ApplianceRow>(`/appliance/appliances/${id}`).then((r) => r.data),
  approve: (id: string) =>
    api
      .post<ApplianceRow>(`/appliance/appliances/${id}/approve`)
      .then((r) => r.data),
  reject: (id: string) =>
    api.post<void>(`/appliance/appliances/${id}/reject`).then((r) => r.data),
  // Issue #170 Wave E follow-up — soft-delete. Row flips to
  // ``state=revoked`` + ``revoked_at`` stamped; heartbeats return 403,
  // supervisor tears down its service containers, but the row stays
  // for an admin to either Re-authorize or Permanently delete.
  remove: (id: string, password: string) =>
    api
      .delete<ApplianceRow>(`/appliance/appliances/${id}`, {
        data: { password },
      })
      .then((r) => r.data),
  // Issue #197 — preview the dns_server + dhcp_server rows that
  // ``remove`` will sweep alongside the appliance. UI calls this
  // before showing the delete-confirm modal so the operator sees the
  // full blast radius before clicking. Matches by appliance_id FK
  // (populated at supervisor-driven register time, forward-compat)
  // OR by hostname (legacy / pre-FK rows).
  dependents: (id: string) =>
    api
      .get<{
        dns: Array<{
          kind: "dns";
          id: string;
          name: string;
          host: string;
          status: string;
        }>;
        dhcp: Array<{
          kind: "dhcp";
          id: string;
          name: string;
          host: string;
          status: string;
        }>;
      }>(`/appliance/appliances/${id}/dependents`)
      .then((r) => r.data),
  reauthorize: (id: string) =>
    api
      .post<ApplianceRow>(`/appliance/appliances/${id}/reauthorize`)
      .then((r) => r.data),
  permanentDelete: (id: string, password: string) =>
    api
      .post<void>(`/appliance/appliances/${id}/permanent-delete`, {
        password,
      })
      .then((r) => r.data),
  rekey: (id: string) =>
    api
      .post<ApplianceRow>(`/appliance/appliances/${id}/rekey`)
      .then((r) => r.data),
  updateRoles: (id: string, body: ApplianceRolesUpdate) =>
    api
      .put<ApplianceRow>(`/appliance/appliances/${id}/roles`, body)
      .then((r) => r.data),
  // #272 Phase 7 — batch promote/demote control-plane cluster members.
  // Promote turns approved Appliance nodes into k3s control-plane
  // (etcd) members; demote reverses it. Batch (a list of ids) because
  // etcd HA wants an ODD total — the API 422s if the resulting count
  // would be even, and the message is surfaced inline.
  promoteControlPlane: (applianceIds: string[]) =>
    api
      .post<{
        appliances: ApplianceRow[];
      }>("/appliance/fleet/control-plane/promote", {
        appliance_ids: applianceIds,
      })
      .then((r) => r.data.appliances),
  demoteControlPlane: (applianceIds: string[]) =>
    api
      .post<{
        appliances: ApplianceRow[];
      }>("/appliance/fleet/control-plane/demote", {
        appliance_ids: applianceIds,
      })
      .then((r) => r.data.appliances),
  // #272 Phase 9 — replace a DEAD control-plane member: the seed evicts
  // its k8s Node (k3s drops the etcd member), and a single-use pairing
  // code is minted for the replacement box. Returns the code (shown once).
  replaceControlPlaneMember: (applianceId: string) =>
    api
      .post<ControlPlaneReplaceResult>(
        `/appliance/fleet/control-plane/${applianceId}/replace`,
      )
      .then((r) => r.data),
  // #590 — escape hatch for a wedged promote / demote / eviction. No
  // cluster transition has a timeout: each converges only on a supervisor
  // report, so a node that died mid-join (or a seed that can't reach the
  // kubeapi) pins the row in joining/leaving/evicting forever. This clears
  // the BOOKKEEPING only — cluster_role, k3s and etcd are untouched.
  //
  // The server 409s a transition younger than its staleness threshold
  // unless `force` is set: clearing a RUNNING join would strand the joiner
  // as a live control-plane member the control plane accounts for as
  // nothing. The UI only offers the button once the row is already stale,
  // so `force` is reserved for "the node is never coming back".
  clearControlPlaneState: (applianceId: string, force = false) =>
    api
      .post<ApplianceRow>(
        `/appliance/fleet/control-plane/${applianceId}/clear-cluster-state`,
        { force },
      )
      .then((r) => r.data),
  // #272 Phase 7c — cluster-wide MetalLB pool + control-plane VIP. The
  // seed supervisor picks the saved config up on heartbeat and patches
  // the HelmCharts; the VIP must fall inside the pool (the API 422s
  // otherwise, message surfaced inline).
  getMetalLBConfig: () =>
    api
      .get<MetalLBConfig>("/appliance/fleet/control-plane/metallb")
      .then((r) => r.data),
  setMetalLBConfig: (body: MetalLBConfig) =>
    api
      .put<MetalLBConfig>("/appliance/fleet/control-plane/metallb", body)
      .then((r) => r.data),
  // #272 Phase 9b — etcd snapshot inventory + guided restore. The seed
  // reports its local snapshots on heartbeat; restore stamps the seed
  // row (superadmin + typed-hostname confirm) and the host runner does a
  // destructive single-node cluster-reset.
  listEtcdSnapshots: () =>
    api
      .get<EtcdSnapshots>("/appliance/fleet/control-plane/etcd-snapshots")
      .then((r) => r.data),
  restoreEtcdSnapshot: (snapshot_name: string, confirm_hostname: string) =>
    api
      .post<EtcdSnapshots>("/appliance/fleet/control-plane/restore", {
        snapshot_name,
        confirm_hostname,
      })
      .then((r) => r.data),
  // #170 Wave D1 — OS slot upgrade + reboot affordances on the
  // Fleet drilldown. Appliance-only deployments; the API surfaces a
  // 409 with a useful message on docker / k8s rows.
  scheduleUpgrade: (
    id: string,
    desired_appliance_version: string,
    source:
      | { kind: "url"; url: string }
      | { kind: "uploaded"; slot_image_id: string },
  ) =>
    api
      .post<ApplianceRow>(`/appliance/appliances/${id}/upgrade`, {
        desired_appliance_version,
        ...(source.kind === "url"
          ? { desired_slot_image_url: source.url }
          : { slot_image_id: source.slot_image_id }),
      })
      .then((r) => r.data),
  clearUpgrade: (id: string) =>
    api
      .post<ApplianceRow>(`/appliance/appliances/${id}/clear-upgrade`)
      .then((r) => r.data),
  // Per-slot boot intents (operator-facing affordances on the two
  // slot cards in the Fleet drilldown). Both ride the same heartbeat-
  // pickup pipeline as ``scheduleUpgrade`` — the backend stamps a
  // desired-state column on the appliance row, the supervisor's next
  // heartbeat reads it + writes the host-side trigger file.
  setNextBootSlot: (id: string, slot: "slot_a" | "slot_b") =>
    api
      .post<ApplianceRow>(`/appliance/appliances/${id}/set-next-boot`, { slot })
      .then((r) => r.data),
  setDefaultSlot: (id: string, slot: "slot_a" | "slot_b") =>
    api
      .post<ApplianceRow>(`/appliance/appliances/${id}/set-default-slot`, {
        slot,
      })
      .then((r) => r.data),
  scheduleReboot: (id: string) =>
    api
      .post<ApplianceRow>(`/appliance/appliances/${id}/reboot`)
      .then((r) => r.data),
  // Issue #183 Phase 4 — direct kubeapi action via the supervisor's
  // long-poll proxy. Sub-second on a healthy appliance; surfaces a
  // 504 / 502 when the proxy times out or kubeapi returns an error.
  k8sRolloutRestart: (
    id: string,
    body: {
      kind: ApplianceWorkloadKind;
      namespace?: string;
      name: string;
    },
  ) =>
    api
      .post<{
        ok: boolean;
        status: number;
        kind: string;
        name: string;
      }>(`/appliance/appliances/${id}/k8s/restart`, body)
      .then((r) => r.data),
  /** #890 — what this appliance actually runs, so the Fleet restart
   *  picker isn't hardcoded to one workload. Filtered server-side to
   *  spatiumddi-labelled objects. */
  k8sWorkloads: (id: string, namespace?: string) =>
    api
      .get<ApplianceWorkloadsResponse>(
        `/appliance/appliances/${id}/k8s/workloads`,
        { params: namespace ? { namespace } : undefined },
      )
      .then((r) => r.data),
  // Issue #183 Phase 5 — reveal the stored kubeconfig after a
  // password re-confirmation. Same shape as the SNMP-community and
  // agent-bootstrap-key reveal endpoints.
  revealKubeconfig: (id: string, password?: string, totpCode?: string) =>
    api
      .post<{
        configured: boolean;
        kubeconfig: string | null;
        hostname: string;
      }>(`/appliance/appliances/${id}/k8s/kubeconfig/reveal`, {
        password,
        totp_code: totpCode,
      })
      .then((r) => r.data),
  // Issue #183 Phase 6 — operator-controlled CIDR allowlist for
  // direct kubeapi access. Empty = proxy-only (default).
  updateKubeapiCidrs: (id: string, cidrs: string[]) =>
    api
      .put<ApplianceRow>(`/appliance/appliances/${id}/kubeapi-cidrs`, {
        cidrs,
      })
      .then((r) => r.data),
  // Issue #183 Phase 8 — pod listing + log viewer via the kubeapi
  // proxy. Snapshot-mode (no --follow) since the proxy is request/
  // response; operators get the recent tail + a refresh button.
  k8sListPods: (id: string, namespace: string = "spatium") =>
    api
      .get<{
        pods: Array<{
          name: string;
          namespace: string;
          phase: string;
          ready: boolean;
          containers: string[];
          labels: Record<string, string>;
        }>;
      }>(`/appliance/appliances/${id}/k8s/pods`, {
        params: { namespace },
      })
      .then((r) => r.data),
  k8sGetPodLogs: (
    id: string,
    pod: string,
    opts: {
      namespace?: string;
      container?: string;
      tail_lines?: number;
    } = {},
  ) =>
    api
      .get<string>(`/appliance/appliances/${id}/k8s/logs`, {
        params: {
          pod,
          namespace: opts.namespace ?? "spatium",
          ...(opts.container ? { container: opts.container } : {}),
          tail_lines: opts.tail_lines ?? 1000,
        },
        responseType: "text",
      })
      .then((r) => r.data),
};

// ── Upgrade images (#170 follow-up; renamed slot-images → upgrade-
// images in #199) ──────────────────────────────────────────────────
// Two ways to stage an OS upgrade image on the control plane:
//   * Upload (air-gap) — operators upload the .raw.xz directly.
//   * Import from GitHub (connected) — the control plane downloads +
//     sha256-verifies a release asset on the operator's behalf.
// Either way the backend stores it on a local volume + serves it back
// under an authenticated internal URL. The supervisor's existing
// heartbeat → trigger-file → host runner pipeline picks it up
// unchanged via the appliance row's ``desired_slot_image_url`` (the
// lower-level slot mechanism keeps the "slot" name).
export interface UpgradeImage {
  id: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  appliance_version: string;
  // #1026 — which CPU architecture this image's rootfs is built for.
  // null is UNKNOWN (every image stored before the column existed, and
  // any upload where the operator left it unset) and must render as
  // such, never as a default: the whole point of the field is to stop
  // an image being applied to a node it cannot boot on.
  architecture: string | null;
  uploaded_by_user_id: string | null;
  uploaded_at: string;
  notes: string | null;
}

// A GitHub release carrying an importable appliance upgrade image.
export interface AvailableUpgradeImage {
  tag: string;
  name: string;
  published_at: string;
  body: string;
  html_url: string;
  is_prerelease: boolean;
  is_installed: boolean;
  image_asset_url: string;
  checksum_asset_url: string;
  size_bytes: number | null;
  // #1026 — a release publishing both architectures appears as two
  // rows, one per architecture.
  architecture: string;
}

export interface AvailableUpgradeImages {
  github_reachable: boolean;
  available: AvailableUpgradeImage[];
}

export const applianceUpgradeImagesApi = {
  list: () =>
    api
      .get<{ images: UpgradeImage[] }>("/appliance/upgrade-images")
      .then((r) => r.data.images),
  // Connected-install picker source — releases with an importable
  // upgrade-image asset + its .sha256 sidecar.
  listAvailable: () =>
    api
      .get<AvailableUpgradeImages>("/appliance/upgrade-images/available")
      .then((r) => r.data),
  // Control plane downloads + verifies + stores the release asset.
  importFromGithub: (release_tag: string, architecture?: string) =>
    api
      .post<UpgradeImage>("/appliance/upgrade-images/import-from-github", {
        release_tag,
        // Omitted rather than sent as null when the release publishes
        // only one architecture — the server treats absent as "the only
        // one there is" and 422s only on a genuine ambiguity.
        ...(architecture ? { architecture } : {}),
      })
      .then((r) => r.data),
  upload: (
    file: File,
    sha256: string,
    appliance_version: string,
    notes: string | undefined,
    onProgress?: (loaded: number, total: number) => void,
    architecture?: string,
  ) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("sha256", sha256);
    fd.append("appliance_version", appliance_version);
    if (architecture) fd.append("architecture", architecture);
    if (notes) fd.append("notes", notes);
    return api
      .post<UpgradeImage>("/appliance/upgrade-images", fd, {
        // Axios picks the right multipart boundary automatically
        // when the body is a FormData; explicit Content-Type would
        // strip the boundary.
        headers: { "Content-Type": undefined },
        onUploadProgress: (e) => {
          if (onProgress && e.total) onProgress(e.loaded, e.total);
        },
      })
      .then((r) => r.data);
  },
  remove: (id: string) =>
    api.delete<void>(`/appliance/upgrade-images/${id}`).then((r) => r.data),
};

// ── Appliance: container management (Phase 4d) ─────────────────────
export interface ApplianceContainer {
  name: string;
  image: string;
  state: string;
  status: string;
  health: string | null;
  short_id: string;
  started_at: string | null;
  is_spatium: boolean;
}

export type ContainerAction = "start" | "stop" | "restart";

export const applianceContainersApi = {
  list: () =>
    api.get<ApplianceContainer[]>("/appliance/containers").then((r) => r.data),
  action: (name: string, action: ContainerAction) =>
    api
      .post<{
        name: string;
        action: string;
        status: string;
      }>(`/appliance/containers/${encodeURIComponent(name)}/${action}`)
      .then((r) => r.data),
  logs: (name: string, tail = 200) =>
    api
      .get<{
        name: string;
        tail: string;
      }>(`/appliance/containers/${encodeURIComponent(name)}/logs`, {
        params: { tail },
      })
      .then((r) => r.data),
};

// ── Appliance: Cluster health dashboard (#402) ─────────────────────
export interface HostPartition {
  mount: string;
  label: string;
  total_bytes: number;
  used_bytes: number;
}

/** One member of a software-RAID array (#999 Part A). */
export interface MdMember {
  device: string;
  /** The kernel's own comma-joined member state, verbatim. */
  state: string;
  slot: number | null;
}

/** A rebuild / resync / scrub in progress. Absent when idle. */
export interface MdSync {
  action: string;
  percent: number | null;
  eta_seconds: number | null;
}

export interface MdArray {
  name: string;
  level: string;
  /**
   * DERIVED, not the kernel's `array_state`: a raid1 down to one member
   * reports `clean` because the survivor is internally consistent.
   * `unknown` when the member count could not be read — which is never
   * to be rendered as healthy.
   */
  state: string;
  array_state: string;
  /** `null` when `raid_disks` was unreadable — never 0, which would make
   * every degradation test false and read as clean. */
  members_expected: number | null;
  members_in_sync: number;
  members_faulty: number;
  spares: number;
  /** How many more members can be lost before the array stops serving. */
  redundancy_remaining: number | null;
  min_working_members: number | null;
  size_bytes: number | null;
  members: MdMember[];
  sync: MdSync | null;
}

export interface MultipathPath {
  device: string;
  /** dm's own path verdict — always `unknown` until #999 Part B. */
  state: string;
  /** SCSI device state (`running` / `offline` / `blocked`), or null. */
  device_state: string | null;
}

export interface MultipathMap {
  name: string;
  dm_device: string;
  uuid: string;
  paths_total: number;
  /** Paths whose SCSI device reports a DEFINITE fault. */
  paths_faulted: number;
  size_bytes: number | null;
  paths: MultipathPath[];
}

/** One classified thing worth saying about a node's redundancy. */
/** #989 item 3 — one USB filesystem an appliance reported. */
export interface RemovableDisk {
  device: string;
  by_id: string;
  fs_uuid: string;
  fstype: string;
  label: string;
  model: string;
  vendor: string;
  serial: string;
  size_bytes: number | null;
  mounted_at: string | null;
  /**
   * An unusable disk is listed DISABLED with its reason rather than
   * filtered out — a disk that does not appear at all reads as a broken
   * feature, and the operator cannot tell that from "not noticed yet".
   */
  usable: boolean;
  reason: string | null;
}

/** #989 item 3 — one configured removable mount, desired ∪ reported. */
export interface RemovableMount {
  name: string;
  fs_uuid: string;
  fstype: string;
  label: string | null;
  added_at: string | null;
  /**
   * `mounted` — the disk is there and live.
   * `waiting` — configured and armed; the disk is not plugged in. NOT an
   *   error: a rotated off-site disk is legitimately absent for days.
   * `present` — the disk IS plugged in and is not mounted. This one IS a
   *   fault; rendering it as `waiting` tells the operator to plug in a
   *   disk that is already in the port.
   * `blind` — the node cannot read its removable root at all.
   * `unreported` — the node has not said (offline, or too old to look).
   */
  state: "mounted" | "waiting" | "present" | "blind" | "unreported";
  /** Where a backup target should point (inside the mount, not its root). */
  path: string;
  mountpoint: string;
  total_bytes: number | null;
  free_bytes: number | null;
  present: boolean;
}

export interface RemovableResponse {
  /** False = the node has not reported. NOT the same as "no disks". */
  reported: boolean;
  /** The k8s node the disks are on — a removable target is node-local. */
  node_name: string | null;
  disks: RemovableDisk[];
  mounts: RemovableMount[];
  /** `retrying` | `failing` when the host-side apply has not landed. */
  apply_state: string | null;
  /** The host runner's own reason for the last failed apply, if any. */
  apply_error: string | null;
  /** False = the node can see disks but cannot read the removable root. */
  root_readable: boolean;
  /** Where a destination should point, with `{name}` to substitute. */
  path_template: string;
}

export interface RemovableMountRequest {
  fs_uuid: string;
  name: string;
}

/** #999 Part B — an md / multipath management action. */
export interface StorageActionRequest {
  action:
    | "scrub_start"
    | "scrub_cancel"
    | "fail_member"
    | "remove_member"
    | "add_member"
    | "mpath_reinstate"
    | "mpath_topology";
  array?: string | null;
  device?: string | null;
  /**
   * Destructive actions require the DEVICE path typed back verbatim — a
   * typed confirmation that is not the thing being destroyed is a
   * click-through with extra steps.
   */
  confirm?: string | null;
}

export interface StorageActionResult {
  ok: boolean;
  action: string;
  detail: string;
  output: string | null;
}

export interface StorageFinding {
  /** `critical` | `warning` | `info`. */
  severity: string;
  /** `md` | `multipath`. */
  kind: string;
  name: string;
  detail: string;
}

/**
 * The raw reading, exactly as the supervisor shipped it. This is what
 * rides in an `ApplianceRow`'s `cluster_health` JSONB — no verdict, and
 * the row carries the classification in its own `storage_findings`.
 */
export interface NodeStorageReading {
  md_supported: boolean;
  md_arrays: MdArray[];
  multipath_maps: MultipathMap[];
}

/**
 * The reading plus its server-derived verdict, as the cluster-health
 * snapshot returns it per node.
 *
 * The verdict is never re-derived in the browser: severity keys off
 * redundancy remaining, not off `state`, and a second copy of that rule
 * in TypeScript is exactly how a chip ends up saying "clean" while the
 * alert says "degraded".
 */
export interface NodeStorage extends NodeStorageReading {
  findings: StorageFinding[];
  worst_severity: string | null;
}

export interface ClusterNodeVitals {
  name: string;
  ready: boolean;
  roles: string[];
  schedulable: boolean;
  kubelet_version: string | null;
  os_image: string | null;
  kernel: string | null;
  container_runtime: string | null;
  architecture: string | null;
  internal_ip: string | null;
  age_seconds: number | null;
  memory_pressure: boolean;
  disk_pressure: boolean;
  pid_pressure: boolean;
  cpu_capacity_cores: number | null;
  memory_capacity_bytes: number | null;
  pods_capacity: number | null;
  pods_running: number;
  cpu_usage_cores: number | null;
  memory_working_set_bytes: number | null;
  memory_available_bytes: number | null;
  fs_used_bytes: number | null;
  fs_capacity_bytes: number | null;
  // #983 Phase 2 — PSI stall shares. `null` means the kubelet did not report
  // it (below Kubernetes 1.36), which is NOT "no pressure" — render the two
  // differently or the panel lies about the quiet case.
  psi_cpu: ClusterPSIStats | null;
  psi_memory: ClusterPSIStats | null;
  psi_io: ClusterPSIStats | null;
  host_disk_partitions: HostPartition[];
  /**
   * `null` means the supervisor has not reported storage at all (too old
   * to collect it) — UNKNOWN, never a green tick. An empty snapshot is a
   * real "no arrays here" reading.
   */
  host_storage: NodeStorage | null;
}

/** One /proc/pressure line's rolling averages, as % of wall time. */
export interface ClusterPSIWindow {
  avg10: number | null;
  avg60: number | null;
  avg300: number | null;
}

/**
 * `some` — at least one task stalled waiting for the resource.
 * `full` — every runnable task was. The kernel reports CPU `full` as 0 at
 * node level, so a CPU verdict reads `some`.
 */
export interface ClusterPSIStats {
  some: ClusterPSIWindow | null;
  full: ClusterPSIWindow | null;
}

/**
 * Which transport served the kubelet Summary API, per node (#983 Phase 2).
 *
 * `all_direct` is the decision the broad `nodes/proxy` grant hangs on, and it
 * is false when nothing was probed — measuring nothing is not "safe".
 */
export interface ClusterKubeletTransport {
  by_node: Record<string, string>;
  direct_nodes: number;
  proxy_nodes: number;
  all_direct: boolean;
  blocked_reasons: Record<string, string>;
}

export interface ClusterPodSummary {
  name: string;
  namespace: string;
  component: string | null;
  node: string | null;
  phase: string;
  state: string;
  ready: string;
  restarts: number;
  age_seconds: number | null;
  cpu_usage_cores: number | null;
  memory_working_set_bytes: number | null;
}

export interface ClusterWorkloadHealth {
  component: string;
  kind: string | null;
  ready: number;
  total: number;
  restarts: number;
  status: string;
}

/** The resolve probe's verdict (#985). */
export interface ClusterDnsProbe {
  ok: boolean;
  latency_ms: number | null;
  error: string | null;
  /**
   * Which node's api replica ran the probe. On a multi-node control plane
   * the request is served by whichever replica took it, so a pass is a
   * statement about one vantage, not the whole cluster.
   */
  from_node: string | null;
}

/**
 * Cluster DNS (CoreDNS) health (#985). Every count is nullable and `null`
 * means UNKNOWN — rendering it as 0 would claim "no replicas", which is a
 * far more alarming statement than "we could not look".
 */
export interface ClusterDns {
  available: boolean;
  detail: string | null;
  resolver_ip: string | null;
  replicas_ready: number | null;
  replicas_total: number | null;
  expected_replicas: number | null;
  nodes: string[];
  spread_ok: boolean | null;
  resolve_probe: ClusterDnsProbe | null;
  checked_at: string | null;
}

export interface ClusterHealthSnapshot {
  available: boolean;
  detail: string | null;
  nodes_total: number;
  nodes_ready: number;
  pods_total: number;
  pods_running: number;
  pods_by_phase: Record<string, number>;
  kubelet_version: string | null;
  is_ha: boolean;
  control_plane_nodes: number;
  metrics_available: boolean;
  kubelet_transport: ClusterKubeletTransport | null;
  cluster_dns: ClusterDns | null;
  cpu_usage_cores: number | null;
  cpu_capacity_cores: number | null;
  memory_working_set_bytes: number | null;
  memory_capacity_bytes: number | null;
  nodes: ClusterNodeVitals[];
  workloads: ClusterWorkloadHealth[];
  top_pods_cpu: ClusterPodSummary[];
  top_pods_mem: ClusterPodSummary[];
}

export const applianceClusterApi = {
  // One-shot snapshot — used for the very first paint while the SSE
  // stream warms up, and as the fallback when SSE can't connect.
  health: () =>
    api
      .get<ClusterHealthSnapshot>("/appliance/cluster/health")
      .then((r) => r.data),
};

// ── Agent bootstrap keys (Phase 6 prerequisite) ────────────────────
// Reveal the DNS_AGENT_KEY + DHCP_AGENT_KEY the control plane uses
// to validate first-boot agent registration. Applies to every
// deployment topology (docker, k8s, appliance) — the keys live in
// the api container's env regardless of how it's deployed.
export interface AgentBootstrapKeysReveal {
  dns_agent_key: string;
  dhcp_agent_key: string;
  dns_agent_configured: boolean;
  dhcp_agent_configured: boolean;
}

export const agentBootstrapKeysApi = {
  reveal: (password?: string, totpCode?: string) =>
    api
      .post<AgentBootstrapKeysReveal>("/admin/agent-keys/reveal", {
        password,
        totp_code: totpCode,
      })
      .then((r) => r.data),
};

// ── Appliance: system info + lifecycle (Phase 4f) ──────────────────
export interface ApplianceSystemInfo {
  hostname: string;
  host_ips: string[];
  uptime_seconds: number | null;
  maintenance_mode: boolean;
  reboot_pending_from_host: boolean;
  reboot_scheduled: boolean;
  appliance_version: string;
  appliance_mode: boolean;
}

export const applianceSystemApi = {
  info: () =>
    api.get<ApplianceSystemInfo>("/appliance/system/info").then((r) => r.data),
  setMaintenance: (enabled: boolean) =>
    api
      .post<{ maintenance_mode: boolean }>("/appliance/system/maintenance", {
        enabled,
      })
      .then((r) => r.data),
  reboot: () =>
    api
      .post<{
        scheduled: boolean;
        grace_seconds: number;
      }>("/appliance/system/reboot")
      .then((r) => r.data),
};

// Phase 4g setup wizard state (lives under /system but separate
// concern from network/lifecycle — kept as its own API surface).
export interface ApplianceSetupState {
  complete: boolean;
  completed_at: string | null;
  completed_by: string | null;
}

export const applianceSetupApi = {
  state: () =>
    api.get<ApplianceSetupState>("/appliance/system/setup").then((r) => r.data),
  complete: () =>
    api
      .post<{
        complete: boolean;
        completed_at: string;
      }>("/appliance/system/setup/complete")
      .then((r) => r.data),
};

// ── Appliance: diagnostics (Phase 4e) ──────────────────────────────
export interface ApplianceLogListResponse {
  sources: string[];
}

export interface ApplianceLogTailResponse {
  name: string;
  lines: number;
  tail: string;
}

export interface ApplianceSelfTestCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface ApplianceSelfTestReport {
  run_at: string;
  overall_ok: boolean;
  checks: ApplianceSelfTestCheck[];
}

export const applianceDiagnosticsApi = {
  listLogs: () =>
    api
      .get<ApplianceLogListResponse>("/appliance/diagnostics/logs")
      .then((r) => r.data),
  tailLog: (name: string, lines = 500) =>
    api
      .get<ApplianceLogTailResponse>(
        `/appliance/diagnostics/logs/${encodeURIComponent(name)}`,
        { params: { lines } },
      )
      .then((r) => r.data),
  selfTest: () =>
    api
      .post<ApplianceSelfTestReport>("/appliance/diagnostics/self-test")
      .then((r) => r.data),
  // Bundle download uses a direct URL — the browser handles the
  // attachment + filename via Content-Disposition.
  bundleUrl: () => "/api/v1/appliance/diagnostics/bundle",
};

/**
 * Stream container logs as SSE. Mirrors streamChatTurn — uses fetch
 * (not EventSource) so we can send the Bearer token in Authorization.
 * Yields each parsed log line; cancel via the AbortSignal.
 */
async function* _streamApplianceLogSse(
  url: string,
  signal?: AbortSignal,
): AsyncIterable<string> {
  const token = getAccessToken();
  const res = await fetch(url, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      Accept: "text/event-stream",
    },
    signal,
  });
  if (!res.ok || !res.body) {
    throw new Error(`log stream failed: HTTP ${res.status}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() ?? "";
    for (const frame of frames) {
      if (!frame.trim()) continue;
      let data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("data: ")) data += line.slice(6);
      }
      if (!data) continue;
      try {
        const parsed = JSON.parse(data) as { line: string };
        if (typeof parsed.line === "string") yield parsed.line;
      } catch {
        // skip malformed frames
      }
    }
  }
}

// Tail one pod's logs by exact pod name (used by the Pods tab).
export function streamApplianceContainerLogs(
  name: string,
  signal?: AbortSignal,
  tail = 100,
): AsyncIterable<string> {
  return _streamApplianceLogSse(
    `/api/v1/appliance/containers/${encodeURIComponent(name)}/logs/stream?tail=${tail}`,
    signal,
  );
}

// Tail a workload (deployment / daemonset) by its component label
// (api / worker / frontend / …); the backend resolves it to the current
// pod, so the stream survives pod rolls without exposing pod names (#416).
export function streamApplianceWorkloadLogs(
  component: string,
  signal?: AbortSignal,
  tail = 100,
): AsyncIterable<string> {
  return _streamApplianceLogSse(
    `/api/v1/appliance/containers/workloads/${encodeURIComponent(component)}/logs/stream?tail=${tail}`,
    signal,
  );
}

/**
 * Stream live cluster-health snapshots over SSE (#402).
 *
 * Server pushes a fresh `ClusterHealthSnapshot` every ~2s; we yield each
 * parsed frame so the Cluster → Overview dashboard can animate. Same
 * `fetch`-not-`EventSource` shape as `streamApplianceContainerLogs` so the
 * bearer token rides an `Authorization` header (EventSource can't set
 * headers). Caller passes an `AbortSignal` and re-invokes on error to
 * reconnect.
 */
export async function* streamClusterHealth(
  signal?: AbortSignal,
): AsyncIterable<ClusterHealthSnapshot> {
  const token = getAccessToken();
  const res = await fetch("/api/v1/appliance/cluster/health/stream", {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      Accept: "text/event-stream",
    },
    signal,
  });
  if (!res.ok || !res.body) {
    throw new Error(`cluster health stream failed: HTTP ${res.status}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() ?? "";
    for (const frame of frames) {
      if (!frame.trim()) continue;
      let data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("data: ")) data += line.slice(6);
      }
      if (!data) continue;
      try {
        yield JSON.parse(data) as ClusterHealthSnapshot;
      } catch {
        // skip malformed frames
      }
    }
  }
}

// ── Kubernetes integration ─────────────────────────────────────────

export interface KubernetesCluster {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  api_server_url: string;
  ca_bundle_present: boolean;
  token_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  pod_cidr: string;
  service_cidr: string;
  sync_interval_seconds: number;
  mirror_pods: boolean;
  last_synced_at: string | null;
  last_sync_error: string | null;
  cluster_version: string | null;
  node_count: number | null;
  created_at: string;
  modified_at: string;
}

export interface KubernetesClusterCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  api_server_url: string;
  ca_bundle_pem?: string;
  token: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  pod_cidr?: string;
  service_cidr?: string;
  sync_interval_seconds?: number;
  mirror_pods?: boolean;
}

export interface KubernetesClusterUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  api_server_url?: string;
  ca_bundle_pem?: string;
  token?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  pod_cidr?: string;
  service_cidr?: string;
  sync_interval_seconds?: number;
  mirror_pods?: boolean;
}

export interface KubernetesTestResult {
  ok: boolean;
  message: string;
  version: string | null;
  node_count: number | null;
}

export interface KubernetesDetectCIDRsResult {
  pod_cidr: string | null;
  service_cidr: string | null;
  messages: string[];
}

export const kubernetesApi = {
  listClusters: () =>
    api.get<KubernetesCluster[]>("/kubernetes/clusters").then((r) => r.data),
  createCluster: (data: KubernetesClusterCreate) =>
    api
      .post<KubernetesCluster>("/kubernetes/clusters", data)
      .then((r) => r.data),
  updateCluster: (id: string, data: KubernetesClusterUpdate) =>
    api
      .put<KubernetesCluster>(`/kubernetes/clusters/${id}`, data)
      .then((r) => r.data),
  deleteCluster: (id: string) => api.delete(`/kubernetes/clusters/${id}`),
  testConnection: (body: {
    cluster_id?: string;
    api_server_url?: string;
    ca_bundle_pem?: string;
    token?: string;
  }) =>
    api
      .post<KubernetesTestResult>("/kubernetes/clusters/test", body)
      .then((r) => r.data),
  syncNow: (id: string) =>
    api
      .post<{
        status: string;
        task_id: string;
      }>(`/kubernetes/clusters/${id}/sync`)
      .then((r) => r.data),
  detectCidrs: (body: {
    cluster_id?: string;
    api_server_url?: string;
    ca_bundle_pem?: string;
    token?: string;
  }) =>
    api
      .post<KubernetesDetectCIDRsResult>(
        "/kubernetes/clusters/detect-cidrs",
        body,
      )
      .then((r) => r.data),
};

// ── Docker integration ──────────────────────────────────────────────

export interface DockerHost {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  connection_type: "unix" | "tcp";
  endpoint: string;
  ca_bundle_present: boolean;
  client_cert_present: boolean;
  client_key_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  mirror_containers: boolean;
  include_default_networks: boolean;
  include_stopped_containers: boolean;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  engine_version: string | null;
  container_count: number | null;
  created_at: string;
  modified_at: string;
}

export interface DockerHostCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  connection_type: "unix" | "tcp";
  endpoint: string;
  ca_bundle_pem?: string;
  client_cert_pem?: string;
  client_key_pem?: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  mirror_containers?: boolean;
  include_default_networks?: boolean;
  include_stopped_containers?: boolean;
  sync_interval_seconds?: number;
}

export interface DockerHostUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  connection_type?: "unix" | "tcp";
  endpoint?: string;
  ca_bundle_pem?: string;
  client_cert_pem?: string;
  client_key_pem?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  mirror_containers?: boolean;
  include_default_networks?: boolean;
  include_stopped_containers?: boolean;
  sync_interval_seconds?: number;
}

export interface DockerTestResult {
  ok: boolean;
  message: string;
  engine_version: string | null;
  container_count: number | null;
}

// ── Platform health ─────────────────────────────────────────────────

export type PlatformHealthStatus = "ok" | "warn" | "error";

export interface PlatformHealthComponent {
  name: string;
  status: PlatformHealthStatus;
  detail: string;
  workers?: string[];
  last_tick?: string;
}

export interface PlatformHealthResponse {
  status: "ok" | "degraded";
  components: PlatformHealthComponent[];
  demo_mode?: boolean;
  /** Maintenance mode (issue #57) — bundled into the existing poll so the
   *  global banner doesn't need a separate request. */
  maintenance_mode?: boolean;
  maintenance_message?: string;
  maintenance_started_at?: string | null;
}

export const platformHealthApi = {
  get: () =>
    // Endpoint lives at root (outside /api/v1) so strip the prefix.
    api
      .get<PlatformHealthResponse>("/health/platform", { baseURL: "/" })
      .then((r) => r.data),
};

export const dockerApi = {
  listHosts: () => api.get<DockerHost[]>("/docker/hosts").then((r) => r.data),
  createHost: (data: DockerHostCreate) =>
    api.post<DockerHost>("/docker/hosts", data).then((r) => r.data),
  updateHost: (id: string, data: DockerHostUpdate) =>
    api.put<DockerHost>(`/docker/hosts/${id}`, data).then((r) => r.data),
  deleteHost: (id: string) => api.delete(`/docker/hosts/${id}`),
  testConnection: (body: {
    host_id?: string;
    connection_type?: "unix" | "tcp";
    endpoint?: string;
    ca_bundle_pem?: string;
    client_cert_pem?: string;
    client_key_pem?: string;
  }) =>
    api.post<DockerTestResult>("/docker/hosts/test", body).then((r) => r.data),
  syncNow: (id: string) =>
    api
      .post<{ status: string; task_id: string }>(`/docker/hosts/${id}/sync`)
      .then((r) => r.data),
};

// ── Proxmox VE integration ─────────────────────────────────────────

export interface ProxmoxDiscoveryGuest {
  kind: "qemu" | "lxc";
  vmid: number;
  name: string;
  node: string;
  status: string;
  nic_count: number;
  bridges: string[];
  ips_mirrored: number;
  ips_from_agent: number;
  ips_from_static: number;
  // "reporting" = agent on + returned IPs; "not_responding" = agent on
  // but no response; "off" = agent flag 0; "n/a" = LXC (no agent concept).
  agent_state: "reporting" | "not_responding" | "off" | "n/a";
  // Single top-level reason code for filtering in the UI. ``null`` ==
  // "everything's fine, guest is mirroring IPs into IPAM".
  issue:
    | null
    | "agent_not_responding"
    | "agent_off"
    | "no_ip"
    | "no_nic"
    | "static_only";
  // Operator-facing hint for fixing the issue. ``null`` when there's
  // nothing to fix.
  hint: string | null;
}

export interface ProxmoxDiscoverySummary {
  vm_total: number;
  vm_agent_reporting: number;
  vm_agent_not_responding: number;
  vm_agent_off: number;
  vm_no_nic: number;
  lxc_total: number;
  lxc_reporting: number;
  lxc_no_ip: number;
  sdn_vnets_total: number;
  sdn_vnets_with_subnet: number;
  sdn_vnets_unresolved: number;
  addresses_skipped_no_subnet: number;
  desired_subnets: number;
}

export interface ProxmoxDiscovery {
  summary: ProxmoxDiscoverySummary;
  guests: ProxmoxDiscoveryGuest[];
  generated_at: string;
}

export interface ProxmoxNode {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  host: string;
  port: number;
  verify_tls: boolean;
  ca_bundle_present: boolean;
  token_id: string;
  token_secret_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  mirror_vms: boolean;
  mirror_lxc: boolean;
  include_stopped: boolean;
  infer_vnet_subnets: boolean;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  pve_version: string | null;
  cluster_name: string | null;
  node_count: number | null;
  last_discovery: ProxmoxDiscovery | null;
  created_at: string;
  modified_at: string;
}

export interface ProxmoxNodeCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  host: string;
  port?: number;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  token_id: string;
  token_secret: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  mirror_vms?: boolean;
  mirror_lxc?: boolean;
  include_stopped?: boolean;
  infer_vnet_subnets?: boolean;
  sync_interval_seconds?: number;
}

export interface ProxmoxNodeUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  host?: string;
  port?: number;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  token_id?: string;
  token_secret?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  mirror_vms?: boolean;
  mirror_lxc?: boolean;
  include_stopped?: boolean;
  infer_vnet_subnets?: boolean;
  sync_interval_seconds?: number;
}

export interface ProxmoxTestResult {
  ok: boolean;
  message: string;
  pve_version: string | null;
  cluster_name: string | null;
  node_count: number | null;
}

export const proxmoxApi = {
  listNodes: () => api.get<ProxmoxNode[]>("/proxmox/nodes").then((r) => r.data),
  createNode: (data: ProxmoxNodeCreate) =>
    api.post<ProxmoxNode>("/proxmox/nodes", data).then((r) => r.data),
  updateNode: (id: string, data: ProxmoxNodeUpdate) =>
    api.put<ProxmoxNode>(`/proxmox/nodes/${id}`, data).then((r) => r.data),
  deleteNode: (id: string) => api.delete(`/proxmox/nodes/${id}`),
  testConnection: (body: {
    node_id?: string;
    host?: string;
    port?: number;
    verify_tls?: boolean;
    ca_bundle_pem?: string;
    token_id?: string;
    token_secret?: string;
  }) =>
    api
      .post<ProxmoxTestResult>("/proxmox/nodes/test", body)
      .then((r) => r.data),
  syncNow: (id: string) =>
    api
      .post<{ status: string; task_id: string }>(`/proxmox/nodes/${id}/sync`)
      .then((r) => r.data),
};

// ── OPNsense integration (issue #31) ───────────────────────────────

export interface OPNsenseRouter {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  host: string;
  port: number;
  verify_tls: boolean;
  ca_bundle_present: boolean;
  api_key: string;
  api_secret_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  mirror_dhcp_leases: boolean;
  mirror_static_mappings: boolean;
  mirror_arp: boolean;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  // #797 — non-fatal findings from the last pass, newline-joined. A sync
  // can report ok and still mirror nothing (no DHCP backend on the
  // firmware, a subnet another integration already owns); this is what
  // distinguishes that from a genuinely idle firewall.
  last_sync_warning: string | null;
  firmware_version: string | null;
  interface_count: number | null;
  lease_count: number | null;
  created_at: string;
  modified_at: string;
}

export interface OPNsenseRouterCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  host: string;
  port?: number;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  api_key: string;
  api_secret: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  mirror_dhcp_leases?: boolean;
  mirror_static_mappings?: boolean;
  mirror_arp?: boolean;
  sync_interval_seconds?: number;
}

export interface OPNsenseRouterUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  host?: string;
  port?: number;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  api_key?: string;
  api_secret?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  mirror_dhcp_leases?: boolean;
  mirror_static_mappings?: boolean;
  mirror_arp?: boolean;
  sync_interval_seconds?: number;
}

export interface OPNsenseTestResult {
  ok: boolean;
  message: string;
  firmware_version: string | null;
}

export const opnsenseApi = {
  listRouters: () =>
    api.get<OPNsenseRouter[]>("/opnsense/routers").then((r) => r.data),
  createRouter: (data: OPNsenseRouterCreate) =>
    api.post<OPNsenseRouter>("/opnsense/routers", data).then((r) => r.data),
  updateRouter: (id: string, data: OPNsenseRouterUpdate) =>
    api
      .put<OPNsenseRouter>(`/opnsense/routers/${id}`, data)
      .then((r) => r.data),
  deleteRouter: (id: string) => api.delete(`/opnsense/routers/${id}`),
  testConnection: (body: {
    router_id?: string;
    host?: string;
    port?: number;
    verify_tls?: boolean;
    ca_bundle_pem?: string;
    api_key?: string;
    api_secret?: string;
  }) =>
    api
      .post<OPNsenseTestResult>("/opnsense/routers/test", body)
      .then((r) => r.data),
  syncNow: (id: string) =>
    api
      .post<{ status: string; task_id: string }>(`/opnsense/routers/${id}/sync`)
      .then((r) => r.data),
};

// ── Palo Alto PAN-OS / Panorama integration (issue #605) ───────────

export interface PANOSFirewall {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  host: string;
  port: number;
  verify_tls: boolean;
  ca_bundle_present: boolean;
  api_version: string;
  api_key_present: boolean;
  is_panorama: boolean;
  vsys: string;
  device_group: string;
  ipam_space_id: string;
  dns_group_id: string | null;
  mirror_address_objects: boolean;
  mirror_nat_rules: boolean;
  mirror_interfaces: boolean;
  mirror_dhcp_leases: boolean;
  sync_interval_seconds: number;
  block_sync_enabled: boolean;
  block_tag_name: string;
  last_block_sync_at: string | null;
  last_block_sync_error: string | null;
  last_synced_at: string | null;
  last_sync_error: string | null;
  sw_version: string | null;
  model: string | null;
  object_count: number | null;
  nat_rule_count: number | null;
  created_at: string;
  modified_at: string;
}

export interface PANOSFirewallCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  host: string;
  port?: number;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  api_version?: string;
  is_panorama?: boolean;
  vsys?: string;
  device_group?: string;
  api_key: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  mirror_address_objects?: boolean;
  mirror_nat_rules?: boolean;
  mirror_interfaces?: boolean;
  mirror_dhcp_leases?: boolean;
  sync_interval_seconds?: number;
}

export interface PANOSFirewallUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  host?: string;
  port?: number;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  api_version?: string;
  is_panorama?: boolean;
  vsys?: string;
  device_group?: string;
  api_key?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  mirror_address_objects?: boolean;
  mirror_nat_rules?: boolean;
  mirror_interfaces?: boolean;
  mirror_dhcp_leases?: boolean;
  sync_interval_seconds?: number;
}

export interface PANOSTestResult {
  ok: boolean;
  message: string;
  sw_version?: string | null;
  model?: string | null;
  // Returned when a keygen (username + password) minted a fresh API key —
  // the create form captures it so the operator doesn't have to paste it.
  api_key?: string | null;
}

export interface FirewallObject {
  id: string;
  name: string;
  kind: string;
  value: string;
  description: string;
  tags: string[];
  resolved_cidr: string | null;
  ip_address_id: string | null;
  subnet_id: string | null;
  unlinked: boolean;
}

export interface PANOSDrift {
  objects_total: number;
  objects_unlinked: number;
  subnets_uncovered: number;
  subnets_uncovered_cidrs: string[];
}

export const panosApi = {
  list: () =>
    api.get<PANOSFirewall[]>("/paloalto/firewalls").then((r) => r.data),
  create: (data: PANOSFirewallCreate) =>
    api.post<PANOSFirewall>("/paloalto/firewalls", data).then((r) => r.data),
  update: (id: string, data: PANOSFirewallUpdate) =>
    api
      .put<PANOSFirewall>(`/paloalto/firewalls/${id}`, data)
      .then((r) => r.data),
  remove: (id: string) => api.delete(`/paloalto/firewalls/${id}`),
  sync: (id: string) =>
    api
      .post<{
        status: string;
        task_id: string;
      }>(`/paloalto/firewalls/${id}/sync`)
      .then((r) => r.data),
  listObjects: (id: string) =>
    api
      .get<FirewallObject[]>(`/paloalto/firewalls/${id}/objects`)
      .then((r) => r.data),
  drift: (id: string) =>
    api.get<PANOSDrift>(`/paloalto/firewalls/${id}/drift`).then((r) => r.data),
  test: (body: {
    firewall_id?: string;
    host?: string;
    port?: number;
    verify_tls?: boolean;
    ca_bundle_pem?: string;
    api_version?: string;
    is_panorama?: boolean;
    vsys?: string;
    device_group?: string;
    api_key?: string;
    username?: string;
    password?: string;
  }) =>
    api
      .post<PANOSTestResult>("/paloalto/firewalls/test", body)
      .then((r) => r.data),
};

// ── Fortinet integration (issue #606) ──────────────────────────────
// FirewallObject + PANOSDrift are shared shapes reused across the
// firewall-family integrations (Palo Alto / Fortinet / Meraki).

export interface FortinetFirewall {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  host: string;
  port: number;
  verify_tls: boolean;
  ca_bundle_present: boolean;
  vdom: string;
  api_token_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  mirror_address_objects: boolean;
  mirror_nat_rules: boolean;
  mirror_interfaces: boolean;
  mirror_dhcp_leases: boolean;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  sw_version: string | null;
  model: string | null;
  object_count: number | null;
  nat_rule_count: number | null;
  created_at: string;
  modified_at: string;
}

export interface FortinetFirewallCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  host: string;
  port?: number;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  vdom?: string;
  api_token: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  mirror_address_objects?: boolean;
  mirror_nat_rules?: boolean;
  mirror_interfaces?: boolean;
  mirror_dhcp_leases?: boolean;
  sync_interval_seconds?: number;
}

export interface FortinetFirewallUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  host?: string;
  port?: number;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  vdom?: string;
  api_token?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  mirror_address_objects?: boolean;
  mirror_nat_rules?: boolean;
  mirror_interfaces?: boolean;
  mirror_dhcp_leases?: boolean;
  sync_interval_seconds?: number;
}

export interface FortinetTestResult {
  ok: boolean;
  message: string;
  sw_version?: string | null;
  model?: string | null;
}

export const fortinetApi = {
  list: () =>
    api.get<FortinetFirewall[]>("/fortinet/firewalls").then((r) => r.data),
  create: (data: FortinetFirewallCreate) =>
    api.post<FortinetFirewall>("/fortinet/firewalls", data).then((r) => r.data),
  update: (id: string, data: FortinetFirewallUpdate) =>
    api
      .put<FortinetFirewall>(`/fortinet/firewalls/${id}`, data)
      .then((r) => r.data),
  remove: (id: string) => api.delete(`/fortinet/firewalls/${id}`),
  sync: (id: string) =>
    api
      .post<{
        status: string;
        task_id: string;
      }>(`/fortinet/firewalls/${id}/sync`)
      .then((r) => r.data),
  listObjects: (id: string) =>
    api
      .get<FirewallObject[]>(`/fortinet/firewalls/${id}/objects`)
      .then((r) => r.data),
  drift: (id: string) =>
    api.get<PANOSDrift>(`/fortinet/firewalls/${id}/drift`).then((r) => r.data),
  test: (body: {
    firewall_id?: string;
    host?: string;
    port?: number;
    verify_tls?: boolean;
    ca_bundle_pem?: string;
    vdom?: string;
    api_token?: string;
  }) =>
    api
      .post<FortinetTestResult>("/fortinet/firewalls/test", body)
      .then((r) => r.data),
};

// ── Meraki integration (issue #606) ────────────────────────────────
// Cloud dashboard — no host/port; an org_id string + optional
// network-id allow-list. Per-client Blocked enforcement is armed on
// the Active block sync page (a mac target).

export interface MerakiOrg {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  base_url: string;
  org_id: string;
  network_ids: string[];
  api_key_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  mirror_policy_objects: boolean;
  mirror_vlans: boolean;
  mirror_dhcp_reservations: boolean;
  mirror_nat_rules: boolean;
  mirror_clients: boolean;
  sync_interval_seconds: number;
  block_sync_enabled: boolean;
  block_policy_name: string;
  last_block_sync_at: string | null;
  last_block_sync_error: string | null;
  last_synced_at: string | null;
  last_sync_error: string | null;
  network_count: number | null;
  object_count: number | null;
  created_at: string;
  modified_at: string;
}

export interface MerakiOrgCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  base_url?: string;
  org_id: string;
  network_ids?: string[];
  api_key: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  mirror_policy_objects?: boolean;
  mirror_vlans?: boolean;
  mirror_dhcp_reservations?: boolean;
  mirror_nat_rules?: boolean;
  mirror_clients?: boolean;
  sync_interval_seconds?: number;
}

export interface MerakiOrgUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  base_url?: string;
  org_id?: string;
  network_ids?: string[];
  api_key?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  mirror_policy_objects?: boolean;
  mirror_vlans?: boolean;
  mirror_dhcp_reservations?: boolean;
  mirror_nat_rules?: boolean;
  mirror_clients?: boolean;
  sync_interval_seconds?: number;
}

export interface MerakiTestResult {
  ok: boolean;
  message: string;
  org_name?: string | null;
  network_count?: number | null;
}

export const merakiApi = {
  list: () => api.get<MerakiOrg[]>("/meraki/orgs").then((r) => r.data),
  create: (data: MerakiOrgCreate) =>
    api.post<MerakiOrg>("/meraki/orgs", data).then((r) => r.data),
  update: (id: string, data: MerakiOrgUpdate) =>
    api.put<MerakiOrg>(`/meraki/orgs/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/meraki/orgs/${id}`),
  sync: (id: string) =>
    api
      .post<{
        status: string;
        task_id: string;
      }>(`/meraki/orgs/${id}/sync`)
      .then((r) => r.data),
  listObjects: (id: string) =>
    api.get<FirewallObject[]>(`/meraki/orgs/${id}/objects`).then((r) => r.data),
  drift: (id: string) =>
    api.get<PANOSDrift>(`/meraki/orgs/${id}/drift`).then((r) => r.data),
  test: (body: {
    org_id_pk?: string;
    base_url?: string;
    org_id?: string;
    api_key?: string;
  }) =>
    api.post<MerakiTestResult>("/meraki/orgs/test", body).then((r) => r.data),
};

// ── Firewall block-list feeds (issue #606) ─────────────────────────
// The feed-inversion path — SpatiumDDI serves a token-guarded plain-
// text blocklist that a FortiGate External Threat Feed (or a Cisco SI
// feed) polls. Credential-free enforcement: no write access to the
// device is required.

export interface FirewallFeed {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  kind: string;
  poll_path: string;
  last_polled_at: string | null;
  last_polled_ip: string | null;
  poll_count: number;
  created_at: string;
  modified_at: string;
}

export interface FirewallFeedCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  kind?: string;
}

export interface FirewallFeedCreateResult {
  feed: FirewallFeed;
  token: string;
  poll_path: string;
}

export interface FirewallFeedUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
}

export interface FirewallFeedTokenResult {
  token: string;
  poll_path: string;
}

export const firewallFeedsApi = {
  list: () =>
    api.get<FirewallFeed[]>("/firewall-feeds/feeds").then((r) => r.data),
  create: (data: FirewallFeedCreate) =>
    api
      .post<FirewallFeedCreateResult>("/firewall-feeds/feeds", data)
      .then((r) => r.data),
  update: (id: string, data: FirewallFeedUpdate) =>
    api
      .put<FirewallFeed>(`/firewall-feeds/feeds/${id}`, data)
      .then((r) => r.data),
  remove: (id: string) => api.delete(`/firewall-feeds/feeds/${id}`),
  reveal: (id: string, password?: string, totpCode?: string) =>
    api
      .post<FirewallFeedTokenResult>(`/firewall-feeds/feeds/${id}/reveal`, {
        password,
        totp_code: totpCode,
      })
      .then((r) => r.data),
  rotateToken: (id: string) =>
    api
      .post<FirewallFeedTokenResult>(`/firewall-feeds/feeds/${id}/rotate-token`)
      .then((r) => r.data),
};

// ── Cloud integration (issue #37, Part A — AWS / Azure / GCP) ──────

export type CloudProvider = "aws" | "azure" | "gcp";

export interface CloudEndpoint {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  provider: CloudProvider;
  credentials_present: boolean;
  // Non-secret routing scope: azure {subscription_ids}, gcp {project_ids}.
  provider_config: Record<string, unknown>;
  regions: string[];
  ipam_space_id: string;
  public_space_id: string | null;
  dns_group_id: string | null;
  mirror_load_balancers: boolean;
  mirror_stopped_instances: boolean;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  provider_account_id: string | null;
  network_count: number | null;
  instance_count: number | null;
  last_discovery: Record<string, unknown> | null;
  created_at: string;
  modified_at: string;
}

export interface CloudEndpointCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  provider: CloudProvider;
  credentials: Record<string, string>;
  provider_config?: Record<string, unknown>;
  regions?: string[];
  ipam_space_id: string;
  public_space_id?: string | null;
  dns_group_id?: string | null;
  mirror_load_balancers?: boolean;
  mirror_stopped_instances?: boolean;
  sync_interval_seconds?: number;
}

export interface CloudEndpointUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  // Omit/empty to keep stored creds; non-empty rotates.
  credentials?: Record<string, string>;
  provider_config?: Record<string, unknown>;
  regions?: string[];
  ipam_space_id?: string;
  public_space_id?: string | null;
  dns_group_id?: string | null;
  mirror_load_balancers?: boolean;
  mirror_stopped_instances?: boolean;
  sync_interval_seconds?: number;
}

export interface CloudTestResult {
  ok: boolean;
  message: string;
  provider_account_id: string | null;
  network_count: number | null;
  instance_count: number | null;
}

export const cloudApi = {
  listEndpoints: () =>
    api.get<CloudEndpoint[]>("/cloud/endpoints").then((r) => r.data),
  createEndpoint: (data: CloudEndpointCreate) =>
    api.post<CloudEndpoint>("/cloud/endpoints", data).then((r) => r.data),
  updateEndpoint: (id: string, data: CloudEndpointUpdate) =>
    api.put<CloudEndpoint>(`/cloud/endpoints/${id}`, data).then((r) => r.data),
  deleteEndpoint: (id: string) => api.delete(`/cloud/endpoints/${id}`),
  testConnection: (body: {
    endpoint_id?: string;
    provider?: CloudProvider;
    credentials?: Record<string, string>;
    provider_config?: Record<string, unknown>;
    regions?: string[];
  }) =>
    api
      .post<CloudTestResult>("/cloud/endpoints/test", body)
      .then((r) => r.data),
  syncNow: (id: string) =>
    api
      .post<{ status: string; task_id: string }>(`/cloud/endpoints/${id}/sync`)
      .then((r) => r.data),
};

// ── UniFi integration (issue #30) ─────────────────────────────────

export interface UnifiDiscoverySummary {
  site_total: number;
  network_total: number;
  network_mirrored: number;
  client_total: number;
  client_mirrored: number;
  addresses_skipped_no_subnet: number;
}

export interface UnifiDiscoverySite {
  name: string;
  desc: string;
  networks: number;
  mirrored: number;
  clients: number;
  clients_mirrored: number;
}

export interface UnifiDiscovery {
  summary: UnifiDiscoverySummary;
  sites: UnifiDiscoverySite[];
  generated_at: string;
}

export interface UnifiController {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  mode: "local" | "cloud";
  host: string | null;
  port: number;
  cloud_host_id: string | null;
  verify_tls: boolean;
  ca_bundle_present: boolean;
  auth_kind: "api_key" | "user_password";
  api_key_present: boolean;
  username_present: boolean;
  password_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  mirror_networks: boolean;
  mirror_clients: boolean;
  mirror_fixed_ips: boolean;
  site_allowlist: string[];
  network_allowlist: Record<string, number[]>;
  include_wired: boolean;
  include_wireless: boolean;
  include_vpn: boolean;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  controller_version: string | null;
  site_count: number | null;
  network_count: number | null;
  client_count: number | null;
  last_discovery: UnifiDiscovery | null;
  created_at: string;
  modified_at: string;
}

export interface UnifiControllerCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  mode: "local" | "cloud";
  host?: string | null;
  port?: number;
  cloud_host_id?: string | null;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  auth_kind: "api_key" | "user_password";
  api_key?: string;
  username?: string;
  password?: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  mirror_networks?: boolean;
  mirror_clients?: boolean;
  mirror_fixed_ips?: boolean;
  site_allowlist?: string[];
  network_allowlist?: Record<string, number[]>;
  include_wired?: boolean;
  include_wireless?: boolean;
  include_vpn?: boolean;
  sync_interval_seconds?: number;
}

export interface UnifiControllerUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  mode?: "local" | "cloud";
  host?: string | null;
  port?: number;
  cloud_host_id?: string | null;
  verify_tls?: boolean;
  ca_bundle_pem?: string;
  auth_kind?: "api_key" | "user_password";
  api_key?: string;
  username?: string;
  password?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  mirror_networks?: boolean;
  mirror_clients?: boolean;
  mirror_fixed_ips?: boolean;
  site_allowlist?: string[];
  network_allowlist?: Record<string, number[]>;
  include_wired?: boolean;
  include_wireless?: boolean;
  include_vpn?: boolean;
  sync_interval_seconds?: number;
}

export interface UnifiTestResult {
  ok: boolean;
  message: string;
  controller_version: string | null;
  site_count: number | null;
}

export interface UnifiDashboardSubnet {
  id: string;
  network: string;
  name: string;
  description: string;
  gateway: string | null;
  vlan_id: number | null;
  vlan_ref_id: string | null;
  total_ips: number;
  allocated_ips: number;
  utilization_percent: number;
}

export interface UnifiDashboardVlan {
  id: string;
  vlan_id: number;
  name: string;
  description: string;
}

export interface UnifiDashboardClient {
  id: string;
  address: string;
  subnet_id: string | null;
  hostname: string | null;
  mac_address: string | null;
  status: string;
  description: string;
  last_seen_at: string | null;
}

export interface UnifiDashboardResponse {
  controller: UnifiController;
  router_id: string | null;
  subnets: UnifiDashboardSubnet[];
  vlans: UnifiDashboardVlan[];
  clients: UnifiDashboardClient[];
  client_count_total: number;
}

export const unifiApi = {
  listControllers: () =>
    api.get<UnifiController[]>("/unifi/controllers").then((r) => r.data),
  getController: (id: string) =>
    api.get<UnifiController>(`/unifi/controllers/${id}`).then((r) => r.data),
  getDashboard: (id: string) =>
    api
      .get<UnifiDashboardResponse>(`/unifi/controllers/${id}/dashboard`)
      .then((r) => r.data),
  createController: (data: UnifiControllerCreate) =>
    api.post<UnifiController>("/unifi/controllers", data).then((r) => r.data),
  updateController: (id: string, data: UnifiControllerUpdate) =>
    api
      .put<UnifiController>(`/unifi/controllers/${id}`, data)
      .then((r) => r.data),
  deleteController: (id: string) => api.delete(`/unifi/controllers/${id}`),
  testConnection: (body: {
    controller_id?: string;
    mode?: "local" | "cloud";
    host?: string | null;
    port?: number;
    cloud_host_id?: string | null;
    verify_tls?: boolean;
    ca_bundle_pem?: string;
    auth_kind?: "api_key" | "user_password";
    api_key?: string;
    username?: string;
    password?: string;
  }) =>
    api
      .post<UnifiTestResult>("/unifi/controllers/test", body)
      .then((r) => r.data),
  syncNow: (id: string) =>
    api
      .post<{
        status: string;
        task_id: string;
      }>(`/unifi/controllers/${id}/sync`)
      .then((r) => r.data),
};

// ── Tailscale integration ──────────────────────────────────────────

export interface TailscaleTenant {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  tailnet: string;
  api_key_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  cgnat_cidr: string;
  ipv6_cidr: string;
  skip_expired: boolean;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  tailnet_domain: string | null;
  device_count: number | null;
  created_at: string;
  modified_at: string;
}

export interface TailscaleTenantCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  tailnet?: string;
  api_key: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  cgnat_cidr?: string;
  ipv6_cidr?: string;
  skip_expired?: boolean;
  sync_interval_seconds?: number;
}

export interface TailscaleTenantUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  tailnet?: string;
  api_key?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  cgnat_cidr?: string;
  ipv6_cidr?: string;
  skip_expired?: boolean;
  sync_interval_seconds?: number;
}

export interface TailscaleTestResult {
  ok: boolean;
  message: string;
  tailnet_domain: string | null;
  device_count: number | null;
}

export const tailscaleApi = {
  listTenants: () =>
    api.get<TailscaleTenant[]>("/tailscale/tenants").then((r) => r.data),
  createTenant: (data: TailscaleTenantCreate) =>
    api.post<TailscaleTenant>("/tailscale/tenants", data).then((r) => r.data),
  updateTenant: (id: string, data: TailscaleTenantUpdate) =>
    api
      .put<TailscaleTenant>(`/tailscale/tenants/${id}`, data)
      .then((r) => r.data),
  deleteTenant: (id: string) => api.delete(`/tailscale/tenants/${id}`),
  testConnection: (body: {
    tenant_id?: string;
    tailnet?: string;
    api_key?: string;
  }) =>
    api
      .post<TailscaleTestResult>("/tailscale/tenants/test", body)
      .then((r) => r.data),
  syncNow: (id: string) =>
    api
      .post<{
        status: string;
        task_id: string;
      }>(`/tailscale/tenants/${id}/sync`)
      .then((r) => r.data),
};

export interface NetbirdInstance {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  api_url: string;
  verify_tls: boolean;
  api_key_present: boolean;
  ipam_space_id: string;
  dns_group_id: string | null;
  network_cidr: string;
  skip_expired: boolean;
  sync_interval_seconds: number;
  last_synced_at: string | null;
  last_sync_error: string | null;
  dns_domain: string | null;
  peer_count: number | null;
  created_at: string;
  modified_at: string;
}

export interface NetbirdInstanceCreate {
  name: string;
  description?: string;
  enabled?: boolean;
  api_url?: string;
  verify_tls?: boolean;
  api_key: string;
  ipam_space_id: string;
  dns_group_id?: string | null;
  network_cidr?: string;
  skip_expired?: boolean;
  sync_interval_seconds?: number;
}

export interface NetbirdInstanceUpdate {
  name?: string;
  description?: string;
  enabled?: boolean;
  api_url?: string;
  verify_tls?: boolean;
  api_key?: string;
  ipam_space_id?: string;
  dns_group_id?: string | null;
  network_cidr?: string;
  skip_expired?: boolean;
  sync_interval_seconds?: number;
}

export interface NetbirdTestResult {
  ok: boolean;
  message: string;
  dns_domain: string | null;
  peer_count: number | null;
}

export const netbirdApi = {
  listInstances: () =>
    api.get<NetbirdInstance[]>("/netbird/instances").then((r) => r.data),
  createInstance: (data: NetbirdInstanceCreate) =>
    api.post<NetbirdInstance>("/netbird/instances", data).then((r) => r.data),
  updateInstance: (id: string, data: NetbirdInstanceUpdate) =>
    api
      .put<NetbirdInstance>(`/netbird/instances/${id}`, data)
      .then((r) => r.data),
  deleteInstance: (id: string) => api.delete(`/netbird/instances/${id}`),
  testConnection: (body: {
    instance_id?: string;
    api_url?: string;
    verify_tls?: boolean;
    api_key?: string;
  }) =>
    api
      .post<NetbirdTestResult>("/netbird/instances/test", body)
      .then((r) => r.data),
  syncNow: (id: string) =>
    api
      .post<{
        status: string;
        task_id: string;
      }>(`/netbird/instances/${id}/sync`)
      .then((r) => r.data),
};

// ── Trash (soft-delete recovery) ────────────────────────────────────────────

export type TrashEntryType =
  | "ip_space"
  | "ip_block"
  | "subnet"
  | "dns_zone"
  | "dns_record"
  | "dhcp_scope";

export interface TrashEntry {
  id: string;
  type: TrashEntryType;
  name_or_cidr: string;
  deleted_at: string;
  deleted_by_user_id: string | null;
  deleted_by_username: string | null;
  deletion_batch_id: string | null;
  batch_size: number;
}

export interface TrashListResponse {
  items: TrashEntry[];
  total: number;
}

export interface TrashRestoreResponse {
  batch_id: string;
  restored: number;
  skipped: { type: string; id: string; display: string; reason: string }[];
}

export const trashApi = {
  list: (
    params: {
      type?: TrashEntryType;
      since?: string;
      until?: string;
      q?: string;
      limit?: number;
      offset?: number;
    } = {},
  ) =>
    api.get<TrashListResponse>("/admin/trash", { params }).then((r) => r.data),
  // ``skipConflicts`` restores every sibling that does not clash with a live
  // row and reports the rest in ``skipped`` (#963 — one hand-recreated record
  // must not pin a whole bulk-delete batch in the trash). Without it a
  // conflict is a 409 for the whole batch, as for cascade batches.
  restore: (
    type: TrashEntryType,
    id: string,
    opts?: { skipConflicts?: boolean },
  ) =>
    api
      .post<TrashRestoreResponse>(
        `/admin/trash/${type}/${id}/restore`,
        undefined,
        { params: opts?.skipConflicts ? { skip_conflicts: true } : undefined },
      )
      .then((r) => r.data),
  permanentDelete: (type: TrashEntryType, id: string) =>
    api.delete(`/admin/trash/${type}/${id}`),
};

// ── DHCP lease history ─────────────────────────────────────────────────────────

export interface DHCPLeaseHistoryRow {
  id: string;
  server_id: string;
  scope_id: string | null;
  ip_address: string;
  // null for a DHCPv6 lease identified by DUID only (#1141).
  mac_address: string | null;
  duid?: string | null;
  iaid?: number | null;
  hostname: string | null;
  client_id: string | null;
  started_at: string | null;
  expired_at: string;
  // "expired" | "released" | "removed" | "superseded"
  lease_state: string;
  created_at: string;
}

export interface DHCPLeaseHistoryPage {
  total: number;
  page: number;
  per_page: number;
  items: DHCPLeaseHistoryRow[];
}

export interface DHCPLeaseHistoryQuery {
  since?: string;
  until?: string;
  mac?: string;
  ip?: string;
  hostname?: string;
  lease_state?: string;
  page?: number;
  per_page?: number;
}

export const dhcpLeaseHistoryApi = {
  list: (serverId: string, params?: DHCPLeaseHistoryQuery) =>
    api
      .get<DHCPLeaseHistoryPage>(`/dhcp/servers/${serverId}/lease-history`, {
        params,
      })
      .then((r) => r.data),
};

// ── NAT mappings ───────────────────────────────────────────────────────────────

export type NATKind = "1to1" | "pat" | "hide";
export type NATProtocol = "tcp" | "udp" | "any";

export interface NATMapping {
  id: string;
  name: string;
  kind: NATKind;
  internal_ip: string | null;
  internal_ip_address_id: string | null;
  internal_subnet_id: string | null;
  // Display labels for the internal subnet (populated server-side on the
  // hide-NAT path); without these the UI can only show the bare UUID.
  internal_subnet_cidr: string | null;
  internal_subnet_name: string | null;
  internal_port_start: number | null;
  internal_port_end: number | null;
  external_ip: string | null;
  external_ip_address_id: string | null;
  external_port_start: number | null;
  external_port_end: number | null;
  protocol: NATProtocol;
  device_label: string | null;
  description: string | null;
  tags: unknown[];
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface NATMappingPage {
  total: number;
  page: number;
  per_page: number;
  items: NATMapping[];
}

export interface NATMappingWrite {
  name?: string;
  kind?: NATKind;
  internal_ip?: string | null;
  internal_subnet_id?: string | null;
  internal_port_start?: number | null;
  internal_port_end?: number | null;
  external_ip?: string | null;
  external_port_start?: number | null;
  external_port_end?: number | null;
  protocol?: NATProtocol;
  device_label?: string | null;
  description?: string | null;
  tags?: unknown[];
  custom_fields?: Record<string, unknown>;
}

export interface NATMappingQuery {
  kind?: NATKind;
  internal_ip?: string;
  external_ip?: string;
  q?: string;
  page?: number;
  per_page?: number;
}

// ── Postgres insights + container stats ──────────────────────────────────────

export interface PostgresOverview {
  version: string;
  db_size_bytes: number;
  cache_hit_ratio: number | null;
  wal_bytes: number | null;
  active_connections: number;
  max_connections: number;
  longest_transaction: {
    pid: number;
    state: string | null;
    age_seconds: number;
    query: string | null;
    application_name: string | null;
    client_addr: string | null;
  } | null;
}

export interface PostgresTableSize {
  schema_name: string;
  table_name: string;
  total_bytes: number;
  table_bytes: number;
  index_bytes: number;
  toast_bytes: number;
  live_rows: number;
  dead_rows: number;
  last_autovacuum: string | null;
  last_autoanalyze: string | null;
}

export interface PostgresConnection {
  state: string;
  count: number;
}

export interface PostgresSlowQuery {
  query: string;
  calls: number;
  total_time_ms: number;
  mean_time_ms: number;
  rows: number;
}

export interface PostgresSlowQueriesResponse {
  available: boolean;
  hint: string | null;
  rows: PostgresSlowQuery[];
}

export const postgresApi = {
  overview: () =>
    api.get<PostgresOverview>("/admin/postgres/overview").then((r) => r.data),
  tables: (limit = 50) =>
    api
      .get<{ rows: PostgresTableSize[] }>("/admin/postgres/tables", {
        params: { limit },
      })
      .then((r) => r.data.rows),
  connections: () =>
    api
      .get<{ rows: PostgresConnection[] }>("/admin/postgres/connections")
      .then((r) => r.data.rows),
  slowQueries: (limit = 20) =>
    api
      .get<PostgresSlowQueriesResponse>("/admin/postgres/slow-queries", {
        params: { limit },
      })
      .then((r) => r.data),
  // #272 follow-up — alembic schema-head divergence (cold-boot / rolling
  // upgrade visibility; the readiness probe gates on the same check).
  schemaHealth: () =>
    api
      .get<PostgresSchemaHealth>("/admin/postgres/schema-health")
      .then((r) => r.data),
};

export interface PostgresSchemaHealth {
  status: "ok" | "behind" | "error";
  expected_head: string | null;
  db_revision: string | null;
  detail: string;
}

// ── Redis insights (#358) ─────────────────────────────────────────────
export interface RedisReplica {
  ip: string | null;
  port: number | null;
  state: string | null;
}

export interface RedisOverview {
  available: boolean;
  hint?: string | null;
  sentinel: boolean;
  redis_version: string | null;
  role: string | null;
  uptime_seconds: number | null;
  connected_clients: number | null;
  used_memory_bytes: number | null;
  used_memory_peak_bytes: number | null;
  mem_fragmentation_ratio: number | null;
  maxmemory_bytes: number | null;
  instantaneous_ops_per_sec: number | null;
  keyspace_hits: number | null;
  keyspace_misses: number | null;
  total_commands_processed: number | null;
  connected_replicas: number | null;
  replicas: RedisReplica[];
}

export interface RedisKeyspaceDb {
  db: string;
  keys: number;
  expires: number;
}

export interface RedisWakeChannel {
  channel: string;
  subscribers: number;
}

export interface RedisWakeBus {
  available: boolean;
  hint?: string | null;
  published_by_class: Record<string, number>;
  active_channels: RedisWakeChannel[];
  total_subscribers: number;
}

export const redisApi = {
  overview: () =>
    api.get<RedisOverview>("/admin/redis/overview").then((r) => r.data),
  keyspace: () =>
    api
      .get<{
        available: boolean;
        hint?: string | null;
        dbs: RedisKeyspaceDb[];
      }>("/admin/redis/keyspace")
      .then((r) => r.data),
  wakeBus: () =>
    api.get<RedisWakeBus>("/admin/redis/wake-bus").then((r) => r.data),
};

export interface ContainerStat {
  id: string;
  name: string;
  image: string;
  state: string;
  started_at: string | null;
  cpu_percent: number | null;
  memory_bytes: number | null;
  memory_limit_bytes: number | null;
  memory_percent: number | null;
  network_rx_bytes: number | null;
  network_tx_bytes: number | null;
  block_read_bytes: number | null;
  block_write_bytes: number | null;
}

export interface ContainerStatsResponse {
  available: boolean;
  hint: string | null;
  rows: ContainerStat[];
}

export const containersApi = {
  stats: (params: { prefix?: string; include_stopped?: boolean } = {}) =>
    api
      .get<ContainerStatsResponse>("/admin/containers/stats", { params })
      .then((r) => r.data),
};

// ── Service lifecycle control (issue #890) ────────────────────────────────────

/** Which lifecycle backend the deployment actually has. Reported before
 *  anything is attempted, so the UI never infers "unsupported" from a 503. */
/** #890 — the workload kinds the Fleet restart picker can act on.
 *  StatefulSet joined the union so the picker can't list a row that
 *  errors on click. */
export type ApplianceWorkloadKind = "Deployment" | "DaemonSet" | "StatefulSet";

export interface ApplianceWorkload {
  kind: ApplianceWorkloadKind;
  name: string;
  namespace: string;
  component: string;
  image: string;
  desired: number;
  ready: number;
  state: string;
  last_restarted_at: string | null;
}

export interface ApplianceWorkloadsResponse {
  workloads: ApplianceWorkload[];
  /** Per-kind failures. Reported rather than swallowed so a cluster with
   *  an RBAC gap on one kind still lists the others. */
  errors: string[];
}

export type ServiceControlBackend = "kubernetes" | "compose" | "none";
export type ServiceAction = "start" | "stop" | "restart";

export interface ServiceControlCapability {
  backend: ServiceControlBackend;
  /** "k3s-appliance" | "kubernetes" | "compose" | "none" */
  flavor: string;
  enabled: boolean;
  supported_actions: ServiceAction[];
  /** Populated whenever control is unavailable — always actionable prose. */
  reason: string | null;
}

export interface ServiceRow {
  id: string;
  name: string;
  kind: string;
  state: string;
  image: string;
  detail: string;
  actions: ServiceAction[];
  component: string | null;
  desired: number | null;
  ready: number | null;
  last_restarted_at: string | null;
}

export interface ServiceListResponse {
  capability: ServiceControlCapability;
  services: ServiceRow[];
  /** Backend is live but could not be queried — distinct from an empty
   *  inventory, which would read as "nothing to restart". */
  error: string | null;
}

export interface ServiceActionResult {
  id: string;
  action: ServiceAction;
  status: string;
  /** The target is the API serving this request; expect the session to
   *  blink rather than treating a dropped poll as a failure. */
  self_targeted: boolean;
}

export const serviceControlApi = {
  list: () =>
    api.get<ServiceListResponse>("/system/services").then((r) => r.data),
  act: (id: string, action: ServiceAction) =>
    api
      .post<ServiceActionResult>(
        `/system/services/${encodeURIComponent(id)}/${action}`,
      )
      .then((r) => r.data),
};

export const natApi = {
  list: (params?: NATMappingQuery) =>
    api
      .get<NATMappingPage>("/ipam/nat-mappings", { params })
      .then((r) => r.data),
  get: (id: string) =>
    api.get<NATMapping>(`/ipam/nat-mappings/${id}`).then((r) => r.data),
  create: (data: NATMappingWrite) =>
    api.post<NATMapping>("/ipam/nat-mappings", data).then((r) => r.data),
  update: (id: string, data: NATMappingWrite) =>
    api.patch<NATMapping>(`/ipam/nat-mappings/${id}`, data).then((r) => r.data),
  delete: (id: string) => api.delete(`/ipam/nat-mappings/${id}`),
  byIp: (ipId: string) =>
    api
      .get<NATMapping[]>(`/ipam/nat-mappings/by-ip/${ipId}`)
      .then((r) => r.data),
  bySubnet: (subnetId: string) =>
    api
      .get<NATMapping[]>(`/ipam/nat-mappings/by-subnet/${subnetId}`)
      .then((r) => r.data),
};

// ── Network discovery (SNMP-based router/switch/AP polling) ────────────

export type NetworkDeviceType =
  | "router"
  | "switch"
  | "ap"
  | "firewall"
  | "l3_switch"
  | "other";

export type NetworkSnmpVersion = "v1" | "v2c" | "v3";

export type NetworkV3SecurityLevel = "noAuthNoPriv" | "authNoPriv" | "authPriv";

export type NetworkV3AuthProtocol =
  | "MD5"
  | "SHA"
  | "SHA224"
  | "SHA256"
  | "SHA384"
  | "SHA512";

export type NetworkV3PrivProtocol =
  | "DES"
  | "3DES"
  | "AES128"
  | "AES192"
  | "AES256";

export type NetworkPollStatus =
  | "pending"
  | "success"
  | "partial"
  | "failed"
  | "timeout";

export interface NetworkDeviceRead {
  id: string;
  name: string;
  hostname: string;
  ip_address: string;
  device_type: NetworkDeviceType;
  description: string | null;
  vendor: string | null;
  sys_descr: string | null;
  sys_object_id: string | null;
  sys_name: string | null;
  sys_uptime_seconds: number | null;
  snmp_version: NetworkSnmpVersion;
  snmp_port: number;
  snmp_timeout_seconds: number;
  snmp_retries: number;
  has_community: boolean;
  v3_security_name: string | null;
  v3_security_level: NetworkV3SecurityLevel | null;
  v3_auth_protocol: NetworkV3AuthProtocol | null;
  has_auth_key: boolean;
  v3_priv_protocol: NetworkV3PrivProtocol | null;
  has_priv_key: boolean;
  v3_context_name: string | null;
  poll_interval_seconds: number;
  poll_arp: boolean;
  poll_fdb: boolean;
  poll_interfaces: boolean;
  poll_lldp: boolean;
  auto_create_discovered: boolean;
  last_poll_at: string | null;
  next_poll_at: string | null;
  last_poll_status: NetworkPollStatus;
  last_poll_error: string | null;
  last_poll_arp_count: number | null;
  last_poll_fdb_count: number | null;
  last_poll_interface_count: number | null;
  last_poll_neighbour_count: number | null;
  ip_space_id: string;
  ip_space_name: string;
  is_active: boolean;
  tags: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface NetworkDeviceListResponse {
  items: NetworkDeviceRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface NetworkDeviceListQuery {
  active?: boolean;
  device_type?: NetworkDeviceType;
  last_poll_status?: NetworkPollStatus;
  page?: number;
  page_size?: number;
  tag?: string[];
}

export interface NetworkDeviceCreate {
  name: string;
  hostname: string;
  ip_address: string;
  device_type?: NetworkDeviceType;
  description?: string | null;
  snmp_version?: NetworkSnmpVersion;
  snmp_port?: number;
  snmp_timeout_seconds?: number;
  snmp_retries?: number;
  community?: string;
  v3_security_name?: string;
  v3_security_level?: NetworkV3SecurityLevel;
  v3_auth_protocol?: NetworkV3AuthProtocol;
  v3_auth_key?: string;
  v3_priv_protocol?: NetworkV3PrivProtocol;
  v3_priv_key?: string;
  v3_context_name?: string;
  poll_interval_seconds?: number;
  poll_arp?: boolean;
  poll_fdb?: boolean;
  poll_interfaces?: boolean;
  poll_lldp?: boolean;
  auto_create_discovered?: boolean;
  ip_space_id: string;
  is_active?: boolean;
  tags?: Record<string, unknown>;
}

export type NetworkDeviceUpdate = Partial<NetworkDeviceCreate>;

export interface NetworkTestConnectionResult {
  success: boolean;
  sys_descr: string | null;
  sys_object_id: string | null;
  sys_name: string | null;
  vendor: string | null;
  error_kind:
    | "timeout"
    | "auth_failure"
    | "no_response"
    | "transport_error"
    | "internal"
    | null;
  error_message: string | null;
  elapsed_ms: number;
}

export interface NetworkPollNowResponse {
  task_id: string;
  queued_at: string;
}

export interface NetworkInterfaceRead {
  id: string;
  device_id: string;
  if_index: number;
  name: string;
  alias: string | null;
  description: string | null;
  speed_bps: number | null;
  mac_address: string | null;
  admin_status: "up" | "down" | "testing" | null;
  oper_status:
    | "up"
    | "down"
    | "testing"
    | "unknown"
    | "dormant"
    | "notPresent"
    | "lowerLayerDown"
    | null;
  last_change_seconds: number | null;
  created_at: string;
  updated_at: string;
}

export interface NetworkInterfaceListResponse {
  items: NetworkInterfaceRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface NetworkArpEntryRead {
  id: string;
  device_id: string;
  interface_id: string | null;
  interface_name: string | null;
  ip_address: string;
  mac_address: string;
  vrf_name: string | null;
  address_type: "ipv4" | "ipv6";
  state: "reachable" | "stale" | "delay" | "probe" | "invalid" | "unknown";
  first_seen: string;
  last_seen: string;
}

export interface NetworkArpListResponse {
  items: NetworkArpEntryRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface NetworkArpQuery {
  ip?: string;
  mac?: string;
  vrf?: string;
  state?: NetworkArpEntryRead["state"];
  page?: number;
  page_size?: number;
}

export interface NetworkFdbEntryRead {
  id: string;
  device_id: string;
  interface_id: string;
  interface_name: string;
  mac_address: string;
  vlan_id: number | null;
  fdb_type: "learned" | "static" | "mgmt" | "other";
  first_seen: string;
  last_seen: string;
}

export interface NetworkFdbListResponse {
  items: NetworkFdbEntryRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface NetworkFdbQuery {
  mac?: string;
  vlan_id?: number;
  interface_id?: string;
  page?: number;
  page_size?: number;
}

export interface NetworkContextEntry {
  device_id: string;
  device_name: string;
  interface_id: string;
  interface_name: string;
  interface_alias: string | null;
  vlan_id: number | null;
  mac_address: string;
  fdb_type: string;
  last_seen: string;
}

// LLDP-MIB chassis-id / port-id subtype enums kept in sync with the
// backend poller. Used by the Neighbours tab to render the right
// label next to opaque IDs (e.g. "MAC" vs "interfaceName").
export const LLDP_CHASSIS_ID_SUBTYPES: Record<number, string> = {
  1: "chassisComponent",
  2: "interfaceAlias",
  3: "portComponent",
  4: "macAddress",
  5: "networkAddress",
  6: "interfaceName",
  7: "local",
};
export const LLDP_PORT_ID_SUBTYPES: Record<number, string> = {
  1: "interfaceAlias",
  2: "portComponent",
  3: "macAddress",
  4: "networkAddress",
  5: "interfaceName",
  6: "agentCircuitId",
  7: "local",
};

export interface NetworkNeighbourRead {
  id: string;
  device_id: string;
  interface_id: string | null;
  interface_name: string | null;
  local_port_num: number;
  remote_chassis_id_subtype: number;
  remote_chassis_id: string;
  remote_port_id_subtype: number;
  remote_port_id: string;
  remote_port_desc: string | null;
  remote_sys_name: string | null;
  remote_sys_desc: string | null;
  remote_sys_cap_enabled: number | null;
  first_seen: string;
  last_seen: string;
}

export interface NetworkNeighbourListResponse {
  items: NetworkNeighbourRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface NetworkNeighbourQuery {
  sys_name?: string;
  chassis_id?: string;
  interface_id?: string;
  page?: number;
  page_size?: number;
}

export const networkApi = {
  listDevices: (params?: NetworkDeviceListQuery) =>
    api
      .get<NetworkDeviceListResponse>("/network-devices", { params })
      .then((r) => r.data),
  getDevice: (id: string) =>
    api.get<NetworkDeviceRead>(`/network-devices/${id}`).then((r) => r.data),
  createDevice: (data: NetworkDeviceCreate) =>
    api.post<NetworkDeviceRead>("/network-devices", data).then((r) => r.data),
  updateDevice: (id: string, data: NetworkDeviceUpdate) =>
    api
      .patch<NetworkDeviceRead>(`/network-devices/${id}`, data)
      .then((r) => r.data),
  deleteDevice: (id: string) => api.delete(`/network-devices/${id}`),
  testConnection: (id: string) =>
    api
      .post<NetworkTestConnectionResult>(`/network-devices/${id}/test`)
      .then((r) => r.data),
  pollNow: (id: string) =>
    api
      .post<NetworkPollNowResponse>(`/network-devices/${id}/poll-now`)
      .then((r) => r.data),
  listInterfaces: (
    deviceId: string,
    params?: { page?: number; page_size?: number },
  ) =>
    api
      .get<NetworkInterfaceListResponse>(
        `/network-devices/${deviceId}/interfaces`,
        { params },
      )
      .then((r) => r.data),
  listArp: (deviceId: string, params?: NetworkArpQuery) =>
    api
      .get<NetworkArpListResponse>(`/network-devices/${deviceId}/arp`, {
        params,
      })
      .then((r) => r.data),
  listFdb: (deviceId: string, params?: NetworkFdbQuery) =>
    api
      .get<NetworkFdbListResponse>(`/network-devices/${deviceId}/fdb`, {
        params,
      })
      .then((r) => r.data),
  listNeighbours: (deviceId: string, params?: NetworkNeighbourQuery) =>
    api
      .get<NetworkNeighbourListResponse>(
        `/network-devices/${deviceId}/neighbours`,
        { params },
      )
      .then((r) => r.data),
  // Mounted under /ipam/addresses/{address_id}/network-context but exposed
  // here so all network-discovery client wrappers live in one place.
  getAddressNetworkContext: (addressId: string) =>
    api
      .get<
        NetworkContextEntry[]
      >(`/ipam/addresses/${addressId}/network-context`)
      .then((r) => r.data),
  // Batched: one round-trip per subnet, returns {ip_id: [entries...]}.
  // Drives the "Network" column on the IPAM IP listing without an
  // N+1 fan-out of per-IP requests.
  getSubnetNetworkContext: (subnetId: string) =>
    api
      .get<
        Record<string, NetworkContextEntry[]>
      >(`/ipam/subnets/${subnetId}/network-context`)
      .then((r) => r.data),
};

// ── Nmap on-demand scans ──────────────────────────────────────────────

export type NmapPreset =
  | "quick"
  | "service_version"
  | "os_fingerprint"
  | "service_and_os"
  | "subnet_sweep"
  | "default_scripts"
  | "udp_top1000"
  | "aggressive"
  | "custom";

export type NmapScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface NmapPortResult {
  port: number;
  proto: string;
  state: string;
  reason: string | null;
  service: string | null;
  product: string | null;
  version: string | null;
  extrainfo: string | null;
}

export interface NmapOsResult {
  name: string | null;
  accuracy: number | null;
}

export interface NmapHostResult {
  address: string | null;
  hostname: string | null;
  host_state: string;
  ports: NmapPortResult[];
  os: NmapOsResult | null;
}

export interface NmapSummary {
  host_state: string;
  ports: NmapPortResult[];
  os: NmapOsResult | null;
  /** Populated when the scan target was a CIDR (or any target nmap
   *  expanded to multiple hosts). The single-host fields above mirror
   *  the first entry. */
  hosts: NmapHostResult[] | null;
}

export interface NmapScanRead {
  id: string;
  target_ip: string;
  ip_address_id: string | null;
  preset: NmapPreset;
  port_spec: string | null;
  extra_args: string | null;
  status: NmapScanStatus;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  exit_code: number | null;
  command_line: string | null;
  error_message: string | null;
  summary: NmapSummary | null;
  raw_xml: string | null;
  raw_stdout: string | null;
  created_by_user_id: string | null;
  created_at: string;
  modified_at: string;
}

export interface NmapScanCreate {
  target_ip: string;
  preset: NmapPreset;
  port_spec?: string | null;
  extra_args?: string | null;
  ip_address_id?: string | null;
}

export interface NmapScanListResponse {
  items: NmapScanRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface NmapScanListQuery {
  ip_address_id?: string;
  target_ip?: string;
  status?: NmapScanStatus;
  page?: number;
  page_size?: number;
}

export const nmapApi = {
  listScans: (params?: NmapScanListQuery) =>
    api
      .get<NmapScanListResponse>("/nmap/scans", { params })
      .then((r) => r.data),
  getScan: (id: string) =>
    api.get<NmapScanRead>(`/nmap/scans/${id}`).then((r) => r.data),
  createScan: (body: NmapScanCreate) =>
    api.post<NmapScanRead>("/nmap/scans", body).then((r) => r.data),
  cancelScan: (id: string) => api.delete(`/nmap/scans/${id}`),
  /** Bulk-delete scans. Server returns ``{deleted, cancelled}`` —
   *  queued/running scans get cancelled, terminal scans are removed.
   *  Capped at 500 scan ids per call. */
  bulkDeleteScans: (scanIds: string[]) =>
    api
      .post<{ deleted: number; cancelled: number }>("/nmap/scans/bulk-delete", {
        scan_ids: scanIds,
      })
      .then((r) => r.data),
  /** Stamp every alive host from a multi-host (CIDR) scan into IPAM.
   *  Existing rows in ``available`` / ``discovered`` get bumped to
   *  ``discovered``; integration / operator-owned rows get a
   *  ``last_seen`` stamp only. New rows land as ``discovered``.
   *  Returns counters for the UI to render. */
  stampDiscovered: (scanId: string) =>
    api
      .post<{
        created: number;
        bumped: number;
        refreshed: number;
        skipped_no_subnet: number;
        skipped_addresses: string[];
      }>(`/nmap/scans/${scanId}/stamp-discovered`)
      .then((r) => r.data),
  // SECURITY (#400, M8): the SSE stream is consumed via `streamScan`
  // (fetch + ReadableStream) so the access token rides the
  // Authorization header instead of a `?token=` query arg that would
  // leak through proxy access logs / browser history / Referer.
  // `streamUrl` is kept only for callers that build the path; it no
  // longer embeds the token.
  streamUrl: (id: string) => {
    const base = API_BASE.replace(/\/$/, "");
    return `${base}/nmap/scans/${id}/stream`;
  },
};

/**
 * Stream live nmap scan output as SSE. Mirrors `streamChatTurn` /
 * `streamApplianceContainerLogs` — uses `fetch` (not `EventSource`)
 * so the Bearer token rides the Authorization header rather than a
 * `?token=` query arg (SECURITY #400, M8). Yields `{ data, done }`
 * for each frame: `done` carries the terminal event payload (the
 * scan's final status) when the server emits `event: done`. Cancel
 * via the AbortSignal.
 */
export async function* streamNmapScan(
  scanId: string,
  signal?: AbortSignal,
): AsyncIterable<{ data: string; done: boolean }> {
  const token = getAccessToken();
  const url = nmapApi.streamUrl(scanId);
  const res = await fetch(url, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      Accept: "text/event-stream",
    },
    signal,
  });
  if (!res.ok || !res.body) {
    throw new Error(`scan stream failed: HTTP ${res.status}`);
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() ?? "";
    for (const frame of frames) {
      if (!frame.trim() || frame.startsWith(":")) continue; // skip heartbeats
      let isDone = false;
      let data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("event:") && line.slice(6).trim() === "done") {
          isDone = true;
        } else if (line.startsWith("data:")) {
          data += line.slice(5).replace(/^ /, "");
        }
      }
      yield { data, done: isDone };
      if (isDone) return;
    }
  }
}

// ── Packet capture (tcpdump) — issue #59 ────────────────────────────
//
// Persisted long-running capture jobs (mirrors the nmap scanner) whose
// deliverable is a binary `.pcap` download. NO SSE — the UI polls
// `getCapture` for live `bytes_captured` + status while running.

export type PcapVantageKind = "server" | "appliance";
export type PcapStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface PcapCaptureRead {
  id: string;
  vantage_kind: PcapVantageKind;
  appliance_id: string | null;
  vantage_label: string;
  interface: string | null;
  bpf_filter: string | null;
  snaplen: number;
  promiscuous: boolean;
  max_packets: number | null;
  max_duration_s: number | null;
  max_bytes: number | null;
  status: PcapStatus;
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number | null;
  exit_code: number | null;
  command_line: string | null;
  error_message: string | null;
  packets_captured: number;
  bytes_captured: number;
  pcap_size_bytes: number | null;
  pcap_sha256: string | null;
  has_artifact: boolean;
  metadata_json: Record<string, unknown> | null;
  created_by_user_id: string | null;
  created_at: string;
  modified_at: string;
}

export interface PcapCaptureCreate {
  vantage_kind?: PcapVantageKind;
  appliance_id?: string | null;
  interface?: string | null;
  bpf_filter?: string | null;
  snaplen?: number;
  promiscuous?: boolean;
  max_packets?: number | null;
  max_duration_s?: number | null;
  max_bytes?: number | null;
}

export interface PcapCaptureListResponse {
  items: PcapCaptureRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface PcapCaptureListQuery {
  status?: PcapStatus;
  vantage?: PcapVantageKind;
  appliance_id?: string;
  page?: number;
  page_size?: number;
}

export interface PcapInterfacesResponse {
  interfaces: string[];
  note: string;
}

export const pcapApi = {
  listCaptures: (params?: PcapCaptureListQuery) =>
    api
      .get<PcapCaptureListResponse>("/pcap/captures", { params })
      .then((r) => r.data),
  getCapture: (id: string) =>
    api.get<PcapCaptureRead>(`/pcap/captures/${id}`).then((r) => r.data),
  createCapture: (body: PcapCaptureCreate) =>
    api.post<PcapCaptureRead>("/pcap/captures", body).then((r) => r.data),
  cancelCapture: (id: string) => api.delete(`/pcap/captures/${id}`),
  /** Cancel + delete up to 500 captures; returns `{deleted, cancelled}`. */
  bulkDeleteCaptures: (captureIds: string[]) =>
    api
      .post<{ deleted: number; cancelled: number }>(
        "/pcap/captures/bulk-delete",
        {
          capture_ids: captureIds,
        },
      )
      .then((r) => r.data),
  listInterfaces: (vantage: PcapVantageKind = "server", applianceId?: string) =>
    api
      .get<PcapInterfacesResponse>("/pcap/interfaces", {
        params: { vantage, appliance_id: applianceId },
      })
      .then((r) => r.data),
  /** Download the finished `.pcap` as an authed blob → trigger a save.
   *  Uses the axios instance so the Bearer token rides the
   *  Authorization header (no `?token=` in the URL). */
  downloadCapture: async (id: string): Promise<void> => {
    const res = await api.get<Blob>(`/pcap/captures/${id}/download`, {
      responseType: "blob",
    });
    const disposition = (res.headers as Record<string, string>)[
      "content-disposition"
    ];
    const match = disposition?.match(/filename="?([^"]+)"?/);
    const filename = match ? match[1] : `capture-${id}.pcap`;
    const blob = new Blob([res.data as BlobPart], {
      type: "application/vnd.tcpdump.pcap",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};

// ── Built-in network tools (issue #58) ──────────────────────────────
//
// Stateless, synchronous server-perspective utilities. Each call POSTs
// and returns the result inline (no SSE / persisted rows — that's the
// nmap scanner's model, not this one).

/** Uniform subprocess-tool result (ping / traceroute / mtr / dig / whois). */
// ── reachability-tool run-from target ─────────────────────────────────
//
// Optional vantage selector accepted by the five reachability tools
// (ping / traceroute / dig / port-test / tls-cert). Omitted or
// ``kind: "server"`` runs inline on the control plane (today's
// behaviour); ``kind: "appliance"`` dispatches the run from the named
// Fleet appliance's supervisor. The matching result carries
// ``ran_from`` ("server" or "appliance:<hostname>").
export interface NetToolTarget {
  kind: "server" | "appliance" | "bgp_lg_collector";
  id: string;
}

export interface NetToolCommandResult {
  tool: string;
  argv: string[];
  available: boolean;
  exit_code: number | null;
  timed_out: boolean;
  duration_ms: number | null;
  stdout: string;
  stderr: string;
  error: string | null;
  /** Vantage the run executed from — "server" or "appliance:<name>". */
  ran_from?: string;
}

export interface NetToolPortTestResult {
  host: string;
  port: number;
  protocol: string;
  /** tcp: open|closed|filtered|error · udp: open|filtered|closed|error */
  state: string;
  rtt_ms: number | null;
  error: string | null;
  /** Vantage the run executed from — "server" or "appliance:<name>". */
  ran_from?: string;
}

export interface NetToolTlsCertResult {
  host: string;
  port: number;
  server_name: string | null;
  ok: boolean;
  subject: string | null;
  issuer: string | null;
  san: string[];
  not_before: string | null;
  not_after: string | null;
  days_remaining: number | null;
  expired: boolean;
  self_signed: boolean;
  hostname_matches: boolean | null;
  serial: string | null;
  signature_algorithm: string | null;
  error: string | null;
  /** Vantage the run executed from — "server" or "appliance:<name>". */
  ran_from?: string;
}

export interface NetToolMacVendorEntry {
  mac: string;
  vendor: string | null;
  is_voip_phone: boolean;
}

export interface NetToolMacVendorResult {
  oui_enabled: boolean;
  entries: NetToolMacVendorEntry[];
}

// Wake-on-LAN result (#533) — mirrors backend WolResult.
export interface NetToolWolResult {
  mac: string;
  broadcast: string;
  port: number;
  sent: boolean;
  ran_from: string;
  error: string | null;
}

// Fold the routing-only ``target`` into a reachability-tool body only
// when it points somewhere other than the control-plane server — a
// "server" target (or none) is the back-compatible inline run, so we
// omit the field entirely. ``appliance`` and ``bgp_lg_collector`` (#566
// Phase 4 — ping/traceroute from a Looking Glass collector's vantage)
// both ride the wire the same way.
function withTarget<T extends object>(body: T, target?: NetToolTarget): T {
  if (target && target.kind !== "server") {
    return { ...body, target };
  }
  return body;
}

export const networkToolsApi = {
  ping: (host: string, target?: NetToolTarget) =>
    api
      .post<NetToolCommandResult>("/tools/ping", withTarget({ host }, target))
      .then((r) => r.data),
  traceroute: (host: string, target?: NetToolTarget) =>
    api
      .post<NetToolCommandResult>(
        "/tools/traceroute",
        withTarget({ host }, target),
      )
      .then((r) => r.data),
  mtr: (host: string) =>
    api.post<NetToolCommandResult>("/tools/mtr", { host }).then((r) => r.data),
  dig: (
    body: { name: string; record_type?: string; server?: string | null },
    target?: NetToolTarget,
  ) =>
    api
      .post<NetToolCommandResult>("/tools/dig", withTarget(body, target))
      .then((r) => r.data),
  whois: (query: string) =>
    api
      .post<NetToolCommandResult>("/tools/whois", { query })
      .then((r) => r.data),
  portTest: (
    body: { host: string; port: number; protocol?: string },
    target?: NetToolTarget,
  ) =>
    api
      .post<NetToolPortTestResult>("/tools/port-test", withTarget(body, target))
      .then((r) => r.data),
  tlsCert: (
    body: {
      host: string;
      port?: number;
      server_name?: string | null;
    },
    target?: NetToolTarget,
  ) =>
    api
      .post<NetToolTlsCertResult>("/tools/tls-cert", withTarget(body, target))
      .then((r) => r.data),
  dnsPropagation: (body: {
    name: string;
    record_type?: string;
    resolvers?: string[];
  }) =>
    api
      .post<PropagationCheckResult>("/tools/dns-propagation", body)
      .then((r) => r.data),
  macVendor: (macs: string[]) =>
    api
      .post<NetToolMacVendorResult>("/tools/mac-vendor", { macs })
      .then((r) => r.data),
  // Wake-on-LAN (#533) — MAC-based; broadcast optional (defaults to the local
  // segment 255.255.255.255 server-side). Runs from the server or an appliance.
  wol: (
    body: { mac: string; broadcast?: string | null; port?: number },
    target?: NetToolTarget,
  ) =>
    api
      .post<NetToolWolResult>("/tools/wol", withTarget(body, target))
      .then((r) => r.data),
  // #404 — tail an appliance's nftables drop logs. Always appliance-targeted
  // (the api can't read host kernel logs); poll with the returned cursor.
  firewallLogs: (
    body: { since_seq?: number; limit?: number },
    target: NetToolTarget,
  ) =>
    api
      .post<FirewallLogsResult>("/tools/firewall-logs", { ...body, target })
      .then((r) => r.data),
};

// #404 — firewall drop-log line + result (Firewall → Logs viewer).
export interface FirewallLogLine {
  seq: number;
  ts_us: number;
  text: string;
}

export interface FirewallLogsResult {
  available: boolean;
  lines: FirewallLogLine[];
  cursor: number;
  error: string | null;
  /** Vantage the run executed from — "appliance:<name>". */
  ran_from?: string;
}

// ── ASN management ──────────────────────────────────────────────────

export type ASNKind = "public" | "private";
export type ASNRegistry =
  | "arin"
  | "ripe"
  | "apnic"
  | "lacnic"
  | "afrinic"
  | "unknown";
export type ASNWhoisState = "ok" | "drift" | "unreachable" | "n/a";

export interface ASNRead {
  id: string;
  number: number;
  name: string;
  description: string;
  kind: ASNKind;
  holder_org: string | null;
  registry: ASNRegistry;
  whois_last_checked_at: string | null;
  whois_data: Record<string, unknown> | null;
  whois_state: ASNWhoisState;
  customer_id: string | null;
  provider_id: string | null;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

// Mirrors the canonical set written by ``app.tasks.rpki_roa_refresh``:
// ``valid`` (under 30 days from expiry — also the default when
// validity is unknown), ``expiring_soon`` (<30 days), ``expired``,
// ``not_found`` (the trust anchor stopped emitting the ROA).
export type ASNRpkiRoaState =
  | "valid"
  | "expiring_soon"
  | "expired"
  | "not_found";

export interface ASNRpkiRoa {
  id: string;
  asn_id: string;
  prefix: string;
  max_length: number;
  valid_from: string | null;
  valid_to: string | null;
  trust_anchor: string;
  state: ASNRpkiRoaState;
  last_checked_at: string | null;
}

export interface ASNListResponse {
  items: ASNRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface ASNListQuery {
  limit?: number;
  offset?: number;
  kind?: ASNKind;
  registry?: ASNRegistry;
  whois_state?: ASNWhoisState;
  customer_id?: string;
  provider_id?: string;
  search?: string;
  /** Repeated as ``?tag=key`` (key present, any value) or
   *  ``?tag=key:value`` (exact match). Multiple entries AND together. */
  tag?: string[];
}

export interface ASNCreate {
  number: number;
  name?: string;
  description?: string;
  holder_org?: string | null;
  customer_id?: string | null;
  provider_id?: string | null;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface ASNUpdate {
  name?: string;
  description?: string;
  holder_org?: string | null;
  customer_id?: string | null;
  provider_id?: string | null;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export type BGPRelationshipType = "peer" | "customer" | "provider" | "sibling";

export interface BGPPeering {
  id: string;
  local_asn_id: string;
  peer_asn_id: string;
  relationship_type: BGPRelationshipType;
  description: string;
  local_asn_number: number;
  local_asn_name: string;
  peer_asn_number: number;
  peer_asn_name: string;
  created_at: string;
  modified_at: string;
}

export interface BGPPeeringCreate {
  local_asn_id: string;
  peer_asn_id: string;
  relationship_type: BGPRelationshipType;
  description?: string;
}

export interface BGPPeeringUpdate {
  relationship_type?: BGPRelationshipType;
  description?: string;
}

// ── BGP prefix-hijack monitoring (issue #527) ──────────────────────
export type BGPTrackedPrefixSource = "roa" | "announced" | "both" | "manual";

export interface BGPTrackedPrefix {
  id: string;
  asn_id: string;
  prefix: string;
  expected_origin_asn: number;
  source: BGPTrackedPrefixSource;
  enabled: boolean;
  allowed_origins: number[];
  last_seen_origins: number[] | null;
  last_checked_at: string | null;
  next_check_at: string | null;
}

export type BGPHijackKind = "prefix_hijack" | "more_specific";
export type BGPHijackRpkiStatus = "invalid" | "unknown" | "valid";

export interface BGPHijackDetection {
  id: string;
  asn_id: string;
  tracked_prefix_id: string | null;
  tracked_prefix: string;
  observed_prefix: string;
  expected_origin_asn: number;
  observed_origin_asn: number;
  detection_kind: BGPHijackKind;
  rpki_status: BGPHijackRpkiStatus;
  severity: AlertSeverity;
  source: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  acknowledged: boolean;
  detail: Record<string, unknown> | null;
  notes: string;
}

export interface BGPRefreshResult {
  asn_id: string;
  asn_number: number;
  prefixes_added: number;
  prefixes_evaluated: number;
  detections_opened: number;
  detections_resolved: number;
}

export const asnsApi = {
  list: (params?: ASNListQuery) =>
    api.get<ASNListResponse>("/asns", { params }).then((r) => r.data),
  get: (id: string) => api.get<ASNRead>(`/asns/${id}`).then((r) => r.data),
  create: (data: ASNCreate) =>
    api.post<ASNRead>("/asns", data).then((r) => r.data),
  update: (id: string, data: ASNUpdate) =>
    api.put<ASNRead>(`/asns/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/asns/${id}`),
  refreshWhois: (id: string) =>
    api.post<ASNRead>(`/asns/${id}/refresh-whois`).then((r) => r.data),
  refreshRpki: (id: string) =>
    api
      .post<{
        asn_id: string;
        asn_number: number;
        added: number;
        updated: number;
        removed: number;
        transitions: number;
      }>(`/asns/${id}/refresh-rpki`)
      .then((r) => r.data),
  getRpkiRoas: (id: string) =>
    api.get<ASNRpkiRoa[]>(`/asns/${id}/rpki-roas`).then((r) => r.data),
  bulkDelete: (ids: string[]) =>
    api
      .post<{ deleted: number; not_found: string[] }>("/asns/bulk-delete", {
        ids,
      })
      .then((r) => r.data),
  // BGP peering — operator-curated graph of peering relationships.
  listPeerings: (params?: {
    asn_id?: string;
    relationship_type?: BGPRelationshipType;
  }) => api.get<BGPPeering[]>("/asns/peerings", { params }).then((r) => r.data),
  createPeering: (data: BGPPeeringCreate) =>
    api.post<BGPPeering>("/asns/peerings", data).then((r) => r.data),
  updatePeering: (id: string, data: BGPPeeringUpdate) =>
    api.patch<BGPPeering>(`/asns/peerings/${id}`, data).then((r) => r.data),
  deletePeering: (id: string) => api.delete(`/asns/peerings/${id}`),

  // BGP communities catalog (issue #88).
  listStandardCommunities: () =>
    api.get<BGPCommunity[]>("/asns/communities/standard").then((r) => r.data),
  listCommunities: (asnId: string) =>
    api.get<BGPCommunity[]>(`/asns/${asnId}/communities`).then((r) => r.data),
  createCommunity: (asnId: string, data: BGPCommunityCreate) =>
    api
      .post<BGPCommunity>(`/asns/${asnId}/communities`, data)
      .then((r) => r.data),
  updateCommunity: (id: string, data: BGPCommunityUpdate) =>
    api
      .patch<BGPCommunity>(`/asns/communities/${id}`, data)
      .then((r) => r.data),
  deleteCommunity: (id: string) => api.delete(`/asns/communities/${id}`),

  // BGP prefix-hijack monitoring (issue #527).
  listTrackedPrefixes: (params?: { asn_id?: string; enabled?: boolean }) =>
    api
      .get<BGPTrackedPrefix[]>("/asns/bgp/tracked-prefixes", { params })
      .then((r) => r.data),
  createTrackedPrefix: (
    asnId: string,
    data: { prefix: string; enabled?: boolean; allowed_origins?: number[] },
  ) =>
    api
      .post<BGPTrackedPrefix>(`/asns/${asnId}/bgp/tracked-prefixes`, data)
      .then((r) => r.data),
  deleteTrackedPrefix: (prefixId: string) =>
    api.delete(`/asns/bgp/tracked-prefixes/${prefixId}`),
  listHijacks: (params?: {
    asn_id?: string;
    detection_kind?: BGPHijackKind;
    active_only?: boolean;
    limit?: number;
  }) =>
    api
      .get<BGPHijackDetection[]>("/asns/bgp/hijacks", { params })
      .then((r) => r.data),
  acknowledgeHijack: (detectionId: string) =>
    api
      .post<BGPHijackDetection>(`/asns/bgp/hijacks/${detectionId}/acknowledge`)
      .then((r) => r.data),
  allowlistHijackOrigin: (detectionId: string) =>
    api
      .post<BGPHijackDetection>(
        `/asns/bgp/hijacks/${detectionId}/allowlist-origin`,
      )
      .then((r) => r.data),
  refreshBgp: (id: string) =>
    api.post<BGPRefreshResult>(`/asns/${id}/refresh-bgp`).then((r) => r.data),
};

// ── BGP communities ────────────────────────────────────────────────

export type BGPCommunityKind = "standard" | "regular" | "large";

export interface BGPCommunity {
  id: string;
  asn_id: string | null;
  value: string;
  kind: BGPCommunityKind;
  name: string;
  description: string;
  inbound_action: string;
  outbound_action: string;
  tags: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface BGPCommunityCreate {
  value: string;
  kind: BGPCommunityKind;
  name?: string;
  description?: string;
  inbound_action?: string;
  outbound_action?: string;
  tags?: Record<string, unknown>;
}

export interface BGPCommunityUpdate {
  name?: string;
  description?: string;
  inbound_action?: string;
  outbound_action?: string;
  tags?: Record<string, unknown>;
}

// ── BGP Looking Glass (issue #566) ─────────────────────────────────
//
// A receive-only BGP collector: a per-appliance-node GoBGP daemon peers
// passively with the operator's edge/core routers and turns the live
// Adj-RIB-In into an operator surface. Distinct from ``bgpApi`` (the
// RIPEstat public-data proxy) and ``asnsApi``'s BGP sub-namespaces
// (peering / community catalog / #527 public-table hijack monitor) —
// this is the real internal routing table, mounted at
// ``/looking-glass`` (not ``/bgp``).

// vpnv4/vpnv6 (issue #566 Phase 6) — MP-BGP VPNv4/VPNv6 (RFC 4364). EVPN
// stays out of scope. Not yet exercised against a live gobgpd VPNv4/VPNv6
// session — see the collector's own "verified live" convention.
export type BGPLGAddressFamily =
  | "ipv4-unicast"
  | "ipv6-unicast"
  | "vpnv4"
  | "vpnv6";

// idle | connect | active | opensent | openconfirm | established (GoBGP FSM).
export type BGPLGSessionState =
  | "idle"
  | "connect"
  | "active"
  | "opensent"
  | "openconfirm"
  | "established";

export type BGPLGRpkiStatus = "valid" | "invalid" | "unknown";

export interface BGPLGImportFilter {
  mode: "accept_all" | "scope";
  prefixes?: string[];
}

export interface BGPLGCollector {
  id: string;
  name: string;
  description: string;
  host: string | null;
  status: string;
  enabled: boolean;
  agent_id: string | null;
  agent_registered: boolean;
  agent_version: string | null;
  last_seen_ip: string | null;
  config_apply_status: ConfigApplyStatus | null;
  config_apply_error: string | null;
  config_failed_etag: string | null;
  config_apply_at: string | null;
  last_seen_at: string | null;
  last_health_check_at: string | null;
  appliance_id: string | null;
  created_at: string;
  modified_at: string;
}

export interface BGPLGPeerCreate {
  name: string;
  collector_id: string;
  local_asn: number;
  peer_asn: number;
  peer_address: string;
  matched_asn_id?: string | null;
  peer_router_id?: string | null;
  address_families?: BGPLGAddressFamily[];
  /** Plaintext MD5 password — Fernet-encrypted server-side, never echoed
   *  back. See ``BGPLGPeer.md5_password_set``. */
  md5_password?: string | null;
  max_prefixes?: number;
  import_filter?: BGPLGImportFilter;
  enabled?: boolean;
  description?: string;
}

/** Partial update. ``md5_password``: non-empty rotates, ``""`` clears,
 *  omitted (default) leaves the stored ciphertext untouched. */
export interface BGPLGPeerUpdate {
  name?: string;
  collector_id?: string;
  local_asn?: number;
  peer_asn?: number;
  peer_address?: string;
  matched_asn_id?: string | null;
  peer_router_id?: string | null;
  address_families?: BGPLGAddressFamily[];
  md5_password?: string | null;
  max_prefixes?: number;
  import_filter?: BGPLGImportFilter;
  enabled?: boolean;
  description?: string;
}

export interface BGPLGPeer {
  id: string;
  name: string;
  collector_id: string;
  local_asn: number;
  peer_asn: number;
  peer_address: string;
  matched_asn_id: string | null;
  peer_router_id: string | null;
  address_families: BGPLGAddressFamily[];
  md5_password_set: boolean;
  max_prefixes: number;
  import_filter: BGPLGImportFilter;
  enabled: boolean;
  description: string;
  // Runtime state (collector-reported via heartbeat).
  session_state: BGPLGSessionState;
  uptime_started_at: string | null;
  prefixes_received: number;
  prefixes_accepted: number;
  last_state_change: string | null;
  last_flap_at: string | null;
  rpki_invalid_count: number;
  down_since: string | null;
  created_at: string;
  modified_at: string;
}

/** One row per configured peer, joined with its owning collector — the
 *  Sessions-tab feed (``GET /looking-glass/sessions``). */
export interface BGPLGSession {
  peer_id: string;
  peer_name: string;
  collector_id: string;
  collector_name: string;
  collector_status: string;
  local_asn: number;
  peer_asn: number;
  peer_address: string;
  enabled: boolean;
  session_state: BGPLGSessionState;
  uptime_started_at: string | null;
  prefixes_received: number;
  prefixes_accepted: number;
  last_state_change: string | null;
  last_flap_at: string | null;
  rpki_invalid_count: number;
  down_since: string | null;
}

export interface BGPLGRoute {
  id: string;
  peer_id: string;
  prefix: string;
  origin_asn: number | null;
  as_path: number[];
  next_hop: string;
  local_pref: number | null;
  med: number | null;
  communities: string[];
  large_communities: string[];
  ext_communities: string[];
  /** Route Distinguisher (RFC 4364) — non-empty only for vpnv4/vpnv6
   *  paths; part of the row's identity server-side (issue #566 Phase 6). */
  route_distinguisher: string;
  rpki_status: BGPLGRpkiStatus;
  is_best: boolean;
  matched_block_id: string | null;
  matched_subnet_id: string | null;
  matched_space_id: string | null;
  matched_asn_id: string | null;
  matched_vrf_id: string | null;
  first_seen_at: string;
  last_seen_at: string;
  withdrawn_at: string | null;
  flap_count: number;
  detail: Record<string, unknown> | null;
  created_at: string;
  modified_at: string;
}

/** Server-paginated envelope for ``GET /looking-glass/routes`` — mirrors
 *  ``AddressSearchResponse`` (``GET /ipam/addresses/search``). */
export interface BGPLGRouteListResponse {
  items: BGPLGRoute[];
  total: number;
  limit: number;
  offset: number;
}

export interface BGPLGRouteQuery {
  /** Contains-or-within CIDR match (not an exact-prefix lookup). */
  prefix?: string;
  origin_asn?: number;
  /** Matches against either ``communities`` or ``large_communities``. */
  community?: string;
  rpki_status?: BGPLGRpkiStatus;
  peer_id?: string;
  matched_block_id?: string;
  matched_subnet_id?: string;
  matched_space_id?: string;
  matched_asn_id?: string;
  matched_vrf_id?: string;
  best_path_only?: boolean;
  /** Withdrawn routes are hidden by default. */
  withdrawn?: boolean;
  /** AS-path regex ('_' boundary convention), matched against the
   *  space-joined AS path — e.g. '_65001_' (anywhere) or '65001_$'-style
   *  (near the end, i.e. toward the origin AS). See the Query tab's
   *  ``show route regexp`` command (#566 Phase 4). */
  as_path_regexp?: string;
  limit?: number;
  offset?: number;
}

/** GET /looking-glass/routes/for-ip — reverse LPM-by-address lookup. */
export interface BGPLGRouteForIpResponse {
  ip: string;
  found: boolean;
  route: BGPLGRoute | null;
  alternate_paths_count: number;
}

/** GET /looking-glass/dashboard-summary — single-shot rollup backing the
 *  Dashboard's "Looking Glass health" card. */
export interface BGPLGDashboardSummary {
  peers_total: number;
  peers_established: number;
  peers_down: number;
  routes_rpki_invalid: number;
  routes_flapping: number;
}

// GET /looking-glass/multicast-reachability (issue #566 Phase 6) —
// read-only cross-reference of PIM rendezvous-point addresses + multicast
// group producer source subnets against the learned RIB. Computed live,
// nothing persisted.
export interface MulticastDomainReachability {
  domain_id: string;
  domain_name: string;
  rp_address: string;
  covering_route: BGPLGRoute | null;
}

export interface MulticastGroupReachability {
  group_id: string;
  group_name: string;
  group_address: string;
  source_subnet_id: string;
  source_subnet: string;
  covering_route: BGPLGRoute | null;
}

export interface MulticastReachabilityResponse {
  domains: MulticastDomainReachability[];
  groups: MulticastGroupReachability[];
}

// GET /looking-glass/peers/{peer_id}/detail — the rich rollup backing the
// Sessions-tab peer detail modal (issue #566).
export interface BGPLGPeerDetailCollector {
  id: string;
  name: string;
  host: string | null;
  status: string;
  last_seen_ip: string | null;
  agent_version: string | null;
  enabled: boolean;
}

export interface BGPLGPeerDetailMatchedAsn {
  id: string;
  number: number;
  name: string;
}

export interface BGPLGPeerDetailRouter {
  id: string;
  name: string;
}

export interface BGPLGPeerDetailRpkiBreakdown {
  valid: number;
  invalid: number;
  unknown: number;
}

export interface BGPLGPeerDetailOriginAsnCount {
  asn: number;
  count: number;
}

export interface BGPLGPeerDetailCommunityCount {
  value: string;
  count: number;
}

export interface BGPLGPeerDetailRouteStats {
  active_total: number;
  withdrawn_total: number;
  best_count: number;
  rpki: BGPLGPeerDetailRpkiBreakdown;
  top_origin_asns: BGPLGPeerDetailOriginAsnCount[];
  top_communities: BGPLGPeerDetailCommunityCount[];
  /** True when at least one active route carries a non-empty RD —
   *  i.e. this peer has VPNv4/VPNv6 (RFC 4364) paths, not just plain
   *  ipv4/ipv6-unicast. */
  has_vpn_routes: boolean;
  /** First ~8 active routes, for the modal's preview mini-table. */
  sample_routes: BGPLGRoute[];
}

export interface BGPLGPeerDetailAlert {
  severity: string;
  message: string;
  rule_type: string;
  fired_at: string;
}

export interface BGPLGPeerDetail {
  peer: BGPLGPeer;
  collector: BGPLGPeerDetailCollector;
  matched_asn: BGPLGPeerDetailMatchedAsn | null;
  peer_router: BGPLGPeerDetailRouter | null;
  route_stats: BGPLGPeerDetailRouteStats;
  active_alerts: BGPLGPeerDetailAlert[];
}

// GET /looking-glass/routes/detail — the rich per-prefix rollup backing
// the Routes-tab detail modal (issue #566). Distinct from
// ``getRoute()``/``/routes/by-prefix`` (a flat ``BGPLGRoute[]``): every
// path here is enriched with its peer + collector name, and the response
// carries a server-computed summary + covering IPAM/ASN/VRF context.
export interface BGPLGRouteDetailPath {
  route_id: string;
  peer_id: string;
  peer_name: string;
  collector_name: string;
  origin_asn: number | null;
  next_hop: string;
  local_pref: number | null;
  med: number | null;
  as_path: number[];
  communities: string[];
  large_communities: string[];
  ext_communities: string[];
  route_distinguisher: string;
  rpki_status: BGPLGRpkiStatus;
  is_best: boolean;
  first_seen_at: string;
  last_seen_at: string;
  flap_count: number;
  withdrawn_at: string | null;
  matched_subnet_id: string | null;
  matched_block_id: string | null;
  matched_space_id: string | null;
  matched_asn_id: string | null;
  matched_vrf_id: string | null;
}

export interface BGPLGRouteDetailRpkiBreakdown {
  valid: number;
  invalid: number;
  unknown: number;
}

/** The headline server-computed rollup the detail modal's banner leads
 *  with. ``multi_origin`` (more than one origin ASN) is the hijack/leak
 *  signal; ``anycast_candidate`` (more than one peer/router) alone is the
 *  normal anycast/multi-homed shape. Both can be true at once. */
export interface BGPLGRouteDetailSummary {
  path_count: number;
  peer_count: number;
  distinct_origin_asns: number[];
  multi_origin: boolean;
  anycast_candidate: boolean;
  rpki: BGPLGRouteDetailRpkiBreakdown;
  /** Origin ASN (as a string key) -> tracked ASN row's name, only for
   *  origins that match a row in the ASN catalog. */
  origin_names: Record<string, string>;
}

export interface BGPLGRouteDetailIpamContext {
  subnet_id: string | null;
  subnet_name: string | null;
  block_id: string | null;
  block_name: string | null;
  space_id: string | null;
  space_name: string | null;
  asn_id: string | null;
  asn_number: number | null;
  asn_name: string | null;
  vrf_id: string | null;
  vrf_name: string | null;
}

export interface BGPLGRouteDetail {
  prefix: string;
  paths: BGPLGRouteDetailPath[];
  summary: BGPLGRouteDetailSummary;
  ipam: BGPLGRouteDetailIpamContext;
}

export const lookingGlassApi = {
  // Collectors — agent-registration identity rows (one per GoBGP daemon).
  // Registration itself is agent-side; operators only read the list here.
  listCollectors: () =>
    api.get<BGPLGCollector[]>("/looking-glass/collectors").then((r) => r.data),

  // Peers — configured receive-only BGP sessions.
  listPeers: (params?: { collector_id?: string }) =>
    api
      .get<BGPLGPeer[]>("/looking-glass/peers", { params })
      .then((r) => r.data),
  createPeer: (data: BGPLGPeerCreate) =>
    api.post<BGPLGPeer>("/looking-glass/peers", data).then((r) => r.data),
  updatePeer: (id: string, data: BGPLGPeerUpdate) =>
    api
      .patch<BGPLGPeer>(`/looking-glass/peers/${id}`, data)
      .then((r) => r.data),
  deletePeer: (id: string) => api.delete(`/looking-glass/peers/${id}`),

  // Sessions — read-only per-peer runtime-state rollup (collector + peer
  // joined). Not paginated — peer counts are bounded (a handful per
  // collector), unlike the RIB.
  listSessions: (params?: { collector_id?: string }) =>
    api
      .get<BGPLGSession[]>("/looking-glass/sessions", { params })
      .then((r) => r.data),

  // Routes — the learned RIB, server-paginated + filterable (the RIB can
  // hold thousands of rows, unlike peers/sessions/collectors).
  searchRoutes: (params?: BGPLGRouteQuery) =>
    api
      .get<BGPLGRouteListResponse>("/looking-glass/routes", { params })
      .then((r) => r.data),
  /** All paths for one *exact* prefix, across every peer — distinct from
   *  ``searchRoutes({prefix})``'s contains-or-within match. */
  getRoute: (prefix: string) =>
    api
      .get<BGPLGRoute[]>("/looking-glass/routes/by-prefix", {
        params: { prefix },
      })
      .then((r) => r.data),
  /** Reverse LPM-by-address lookup — "what route covers this IP?" */
  routeForIp: (ip: string) =>
    api
      .get<BGPLGRouteForIpResponse>("/looking-glass/routes/for-ip", {
        params: { ip },
      })
      .then((r) => r.data),
  /** Single-shot rollup for the Dashboard's Looking Glass health card. */
  getDashboardSummary: () =>
    api
      .get<BGPLGDashboardSummary>("/looking-glass/dashboard-summary")
      .then((r) => r.data),
  /** Multicast PIM-RP + producer-subnet reachability against the learned
   *  RIB (issue #566 Phase 6) — read-only, computed on demand. */
  getMulticastReachability: () =>
    api
      .get<MulticastReachabilityResponse>(
        "/looking-glass/multicast-reachability",
      )
      .then((r) => r.data),
  /** Rich rollup backing the Sessions-tab peer detail modal — collector,
   *  matched ASN/router, RIB stats, open bgp_lg_* alerts. */
  getPeerDetail: (peerId: string) =>
    api
      .get<BGPLGPeerDetail>(`/looking-glass/peers/${peerId}/detail`)
      .then((r) => r.data),
  /** Rich rollup backing the Routes-tab detail modal — every path for the
   *  exact prefix across every peer, enriched with peer/collector names +
   *  a server-computed multi-origin/anycast summary + IPAM context. */
  getRouteDetail: (prefix: string, params?: { withdrawn?: boolean }) =>
    api
      .get<BGPLGRouteDetail>("/looking-glass/routes/detail", {
        params: { prefix, ...params },
      })
      .then((r) => r.data),
};

// ── Logical ownership entities (issue #91) ─────────────────────────
//
// Customer / Site / Provider are first-class operator-facing rows that
// cross-cut IPAM / DNS / DHCP. The cross-reference FK columns
// (subnet.customer_id, ip_block.site_id, dns_zone.customer_id, …) are
// nullable on day one so existing trees stay valid; operators tag
// resources at whatever level the assignment is meaningful.

export type CustomerStatus = "active" | "inactive" | "decommissioning";

export interface CustomerRead {
  id: string;
  name: string;
  account_number: string | null;
  contact_email: string | null;
  contact_phone: string | null;
  contact_address: string | null;
  status: CustomerStatus;
  notes: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface CustomerCreate {
  name: string;
  account_number?: string | null;
  contact_email?: string | null;
  contact_phone?: string | null;
  contact_address?: string | null;
  status?: CustomerStatus;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface CustomerUpdate {
  name?: string;
  account_number?: string | null;
  contact_email?: string | null;
  contact_phone?: string | null;
  contact_address?: string | null;
  status?: CustomerStatus;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface CustomerListResponse {
  items: CustomerRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface CustomerListQuery {
  limit?: number;
  offset?: number;
  status?: CustomerStatus;
  search?: string;
}

export const customersApi = {
  list: (params?: CustomerListQuery) =>
    api.get<CustomerListResponse>("/customers", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<CustomerRead>(`/customers/${id}`).then((r) => r.data),
  create: (data: CustomerCreate) =>
    api.post<CustomerRead>("/customers", data).then((r) => r.data),
  update: (id: string, data: CustomerUpdate) =>
    api.put<CustomerRead>(`/customers/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/customers/${id}`),
  bulkDelete: (ids: string[]) =>
    api
      .post<{ deleted: number; not_found: string[] }>(
        "/customers/bulk-delete",
        {
          ids,
        },
      )
      .then((r) => r.data),
};

export type SiteKind =
  | "datacenter"
  | "branch"
  | "pop"
  | "colo"
  | "cloud_region"
  | "customer_premise";

export interface SiteRead {
  id: string;
  name: string;
  code: string | null;
  kind: SiteKind;
  region: string | null;
  parent_site_id: string | null;
  notes: string;
  tags: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface SiteCreate {
  name: string;
  code?: string | null;
  kind?: SiteKind;
  region?: string | null;
  parent_site_id?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
}

export interface SiteUpdate {
  name?: string;
  code?: string | null;
  kind?: SiteKind;
  region?: string | null;
  parent_site_id?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
}

export interface SiteListResponse {
  items: SiteRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface SiteListQuery {
  limit?: number;
  offset?: number;
  kind?: SiteKind;
  region?: string;
  parent_site_id?: string;
  search?: string;
}

export const sitesApi = {
  list: (params?: SiteListQuery) =>
    api.get<SiteListResponse>("/sites", { params }).then((r) => r.data),
  get: (id: string) => api.get<SiteRead>(`/sites/${id}`).then((r) => r.data),
  create: (data: SiteCreate) =>
    api.post<SiteRead>("/sites", data).then((r) => r.data),
  update: (id: string, data: SiteUpdate) =>
    api.put<SiteRead>(`/sites/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/sites/${id}`),
  bulkDelete: (ids: string[]) =>
    api
      .post<{ deleted: number; not_found: string[] }>("/sites/bulk-delete", {
        ids,
      })
      .then((r) => r.data),
};

export type ProviderKind =
  | "transit"
  | "peering"
  | "carrier"
  | "cloud"
  | "registrar"
  | "sdwan_vendor";

export interface ProviderRead {
  id: string;
  name: string;
  kind: ProviderKind;
  account_number: string | null;
  contact_email: string | null;
  contact_phone: string | null;
  notes: string;
  default_asn_id: string | null;
  tags: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface ProviderCreate {
  name: string;
  kind?: ProviderKind;
  account_number?: string | null;
  contact_email?: string | null;
  contact_phone?: string | null;
  notes?: string;
  default_asn_id?: string | null;
  tags?: Record<string, unknown>;
}

export interface ProviderUpdate {
  name?: string;
  kind?: ProviderKind;
  account_number?: string | null;
  contact_email?: string | null;
  contact_phone?: string | null;
  notes?: string;
  default_asn_id?: string | null;
  tags?: Record<string, unknown>;
}

export interface ProviderListResponse {
  items: ProviderRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface ProviderListQuery {
  limit?: number;
  offset?: number;
  kind?: ProviderKind;
  search?: string;
}

export const providersApi = {
  list: (params?: ProviderListQuery) =>
    api.get<ProviderListResponse>("/providers", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<ProviderRead>(`/providers/${id}`).then((r) => r.data),
  create: (data: ProviderCreate) =>
    api.post<ProviderRead>("/providers", data).then((r) => r.data),
  update: (id: string, data: ProviderUpdate) =>
    api.put<ProviderRead>(`/providers/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/providers/${id}`),
  bulkDelete: (ids: string[]) =>
    api
      .post<{ deleted: number; not_found: string[] }>(
        "/providers/bulk-delete",
        {
          ids,
        },
      )
      .then((r) => r.data),
};

// ── WAN circuits (issue #93) ───────────────────────────────────────
//
// Carrier-supplied WAN pipes — the contract + transport class +
// bandwidth + endpoints. Foundation for the future MPLS L3VPN
// service catalog (#94) and SD-WAN overlay routing (#95) which both
// reference circuits by ``transport_class``.

export type TransportClass =
  | "mpls"
  | "internet_broadband"
  | "fiber_direct"
  | "wavelength"
  | "lte"
  | "satellite"
  | "direct_connect_aws"
  | "express_route_azure"
  | "interconnect_gcp";

export type CircuitStatus = "active" | "pending" | "suspended" | "decom";

export interface CircuitRead {
  id: string;
  name: string;
  ckt_id: string | null;
  provider_id: string;
  customer_id: string | null;
  transport_class: TransportClass;
  bandwidth_mbps_down: number;
  bandwidth_mbps_up: number;
  a_end_site_id: string | null;
  a_end_subnet_id: string | null;
  z_end_site_id: string | null;
  z_end_subnet_id: string | null;
  term_start_date: string | null;
  term_end_date: string | null;
  // Decimal serialised as a string by Pydantic; the frontend keeps it
  // as a string so we don't round on display. Render via Number()
  // only for math (sums, sorting).
  monthly_cost: string | null;
  currency: string;
  status: CircuitStatus;
  notes: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  previous_status: string | null;
  last_status_change_at: string | null;
  created_at: string;
  modified_at: string;
}

export interface CircuitCreate {
  name: string;
  ckt_id?: string | null;
  provider_id: string;
  customer_id?: string | null;
  transport_class?: TransportClass;
  bandwidth_mbps_down?: number;
  bandwidth_mbps_up?: number;
  a_end_site_id?: string | null;
  a_end_subnet_id?: string | null;
  z_end_site_id?: string | null;
  z_end_subnet_id?: string | null;
  term_start_date?: string | null;
  term_end_date?: string | null;
  monthly_cost?: string | null;
  currency?: string;
  status?: CircuitStatus;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface CircuitUpdate {
  name?: string;
  ckt_id?: string | null;
  provider_id?: string;
  customer_id?: string | null;
  transport_class?: TransportClass;
  bandwidth_mbps_down?: number;
  bandwidth_mbps_up?: number;
  a_end_site_id?: string | null;
  a_end_subnet_id?: string | null;
  z_end_site_id?: string | null;
  z_end_subnet_id?: string | null;
  term_start_date?: string | null;
  term_end_date?: string | null;
  monthly_cost?: string | null;
  currency?: string;
  status?: CircuitStatus;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface CircuitListResponse {
  items: CircuitRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface CircuitListQuery {
  limit?: number;
  offset?: number;
  provider_id?: string;
  customer_id?: string;
  site_id?: string;
  subnet_id?: string;
  transport_class?: TransportClass;
  status?: CircuitStatus;
  expiring_within_days?: number;
  search?: string;
  tag?: string[];
}

export const circuitsApi = {
  list: (params?: CircuitListQuery) =>
    api.get<CircuitListResponse>("/circuits", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<CircuitRead>(`/circuits/${id}`).then((r) => r.data),
  create: (data: CircuitCreate) =>
    api.post<CircuitRead>("/circuits", data).then((r) => r.data),
  update: (id: string, data: CircuitUpdate) =>
    api.put<CircuitRead>(`/circuits/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/circuits/${id}`),
  bulkDelete: (ids: string[]) =>
    api
      .post<{
        deleted: number;
        not_found: string[];
      }>("/circuits/bulk-delete", { ids })
      .then((r) => r.data),
  bySite: (siteId: string) =>
    api.get<CircuitRead[]>(`/circuits/by-site/${siteId}`).then((r) => r.data),
};

// ── TLS certificate monitoring (issue #118 Phase 1) ───────────────
//
// Read-only-style watch list of TLS endpoints. Each ``TLSCertTarget``
// is probed on its interval (or on demand); the server records the
// leaf cert subject / issuer / validity window + chain status and
// derives a single ``state`` pill. ``days_remaining`` is computed
// server-side from ``not_after``.

export type TLSCertState =
  | "unknown"
  | "ok"
  | "expiring"
  | "expired"
  | "mismatch"
  | "unreachable";

export type TLSCertSource = "manual" | "discovered";

export interface TLSCertTarget {
  id: string;
  host: string;
  port: number;
  server_name: string | null;
  display_name: string | null;
  enabled: boolean;
  source: TLSCertSource;
  dns_record_id: string | null;
  dns_zone_id: string | null;
  domain_id: string | null;
  ip_address_id: string | null;
  interval_hours: number | null;
  next_check_at: string | null;
  last_checked_at: string | null;
  state: TLSCertState;
  last_error: string | null;
  consecutive_failures: number;
  serial: string | null;
  subject_cn: string | null;
  issuer_cn: string | null;
  not_before: string | null;
  not_after: string | null;
  sans_json: string[];
  key_algo: string | null;
  key_size: number | null;
  sig_algo: string | null;
  chain_depth: number | null;
  chain_valid: boolean | null;
  chain_error: string | null;
  self_signed: boolean | null;
  fingerprint_sha256: string | null;
  created_at: string;
  modified_at: string;
  days_remaining: number | null;
}

export interface TLSCertProbe {
  id: string;
  target_id: string;
  probed_at: string;
  ok: boolean;
  state: TLSCertState;
  error: string | null;
  serial: string | null;
  subject_cn: string | null;
  issuer_cn: string | null;
  not_before: string | null;
  not_after: string | null;
  sans_json: string[];
  key_algo: string | null;
  key_size: number | null;
  sig_algo: string | null;
  chain_depth: number | null;
  chain_valid: boolean | null;
  chain_error: string | null;
  self_signed: boolean | null;
  fingerprint_sha256: string | null;
}

export interface TLSChainCert {
  position: number;
  role: "leaf" | "intermediate" | "root";
  subject_cn: string;
  issuer_cn: string;
  serial: string;
  not_before: string;
  not_after: string;
  key_algo: string | null;
  key_size: number | null;
  sig_algo: string | null;
  is_ca: boolean | null;
  self_signed: boolean;
  fingerprint_sha256: string;
}

export interface TLSCertChain {
  target_id: string;
  probed_at: string;
  subject_cn: string | null;
  issuer_cn: string | null;
  serial: string | null;
  not_before: string | null;
  not_after: string | null;
  sans: string[];
  key_algo: string | null;
  key_size: number | null;
  sig_algo: string | null;
  chain_depth: number | null;
  chain_valid: boolean | null;
  chain_error: string | null;
  self_signed: boolean | null;
  fingerprint_sha256: string | null;
  leaf_pem: string | null;
  chain_pem: string | null;
  chain: TLSChainCert[];
}

export interface TLSCertTargetCreate {
  host: string;
  port?: number;
  server_name?: string | null;
  display_name?: string | null;
  interval_hours?: number | null;
  enabled?: boolean;
}

export interface TLSCertTargetUpdate {
  host?: string;
  port?: number;
  server_name?: string | null;
  display_name?: string | null;
  interval_hours?: number | null;
  enabled?: boolean;
}

export interface TLSCertTargetListResponse {
  items: TLSCertTarget[];
  total: number;
  limit: number;
  offset: number;
}

export interface TLSCertTargetListQuery {
  limit?: number;
  offset?: number;
  state?: TLSCertState;
  source?: TLSCertSource;
  enabled?: boolean;
  dns_zone_id?: string;
  domain_id?: string;
  ip_address_id?: string;
  search?: string;
}

export interface TLSCertCTEntry {
  id: number | null;
  common_name: string | null;
  name_value: string | null;
  issuer_name: string | null;
  serial_number: string | null;
  not_before: string | null;
  not_after: string | null;
  entry_timestamp: string | null;
}

export interface TLSCertCTResult {
  host: string;
  entries: TLSCertCTEntry[];
  count: number;
  error: string | null;
}

export interface TLSCertProbeListResponse {
  items: TLSCertProbe[];
  total: number;
  limit: number;
  offset: number;
}

export const tlsCertsApi = {
  list: (params?: TLSCertTargetListQuery) =>
    api
      .get<TLSCertTargetListResponse>("/tls-certs", { params })
      .then((r) => r.data),
  get: (id: string) =>
    api.get<TLSCertTarget>(`/tls-certs/${id}`).then((r) => r.data),
  create: (data: TLSCertTargetCreate) =>
    api.post<TLSCertTarget>("/tls-certs", data).then((r) => r.data),
  update: (id: string, data: TLSCertTargetUpdate) =>
    api.put<TLSCertTarget>(`/tls-certs/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/tls-certs/${id}`),
  probes: (id: string, params?: { limit?: number; offset?: number }) =>
    api
      .get<TLSCertProbeListResponse>(`/tls-certs/${id}/probes`, { params })
      .then((r) => r.data),
  chain: (id: string) =>
    api.get<TLSCertChain>(`/tls-certs/${id}/chain`).then((r) => r.data),
  ctLog: (id: string, params?: { limit?: number }) =>
    api
      .get<TLSCertCTResult>(`/tls-certs/${id}/ct-log`, { params })
      .then((r) => r.data),
  probeNow: (id: string) =>
    api.post<TLSCertTarget>(`/tls-certs/${id}/probe`).then((r) => r.data),
};

// ── DNSBL / RBL reputation monitoring (issue #528) ────────────────
//
// Curated blocklist catalog (per-list enable + custom lists), pinned IPs,
// blocklisted-IP overview, on-demand per-IP check, and the master sweep
// settings. Distinct from `dnsBlocklistApi` above (DNS *domain* blocklists).

export interface DNSBLList {
  id: string;
  name: string;
  zone_suffix: string;
  category: string;
  description: string;
  homepage_url: string | null;
  enabled: boolean;
  return_codes: Record<string, string>;
  requires_registration: boolean;
  qps_note: string;
  is_builtin: boolean;
  created_at: string;
  modified_at: string;
}

export interface DNSBLPinnedIP {
  id: string;
  ip: string;
  note: string;
  ip_address_id: string | null;
  created_at: string;
}

export interface DNSBLListingItem {
  id: string;
  ip: string;
  list_id: string;
  list_name: string | null;
  listed: boolean;
  source: string;
  return_codes: string[];
  txt_reason: string | null;
  check_error: string | null;
  first_listed_at: string | null;
  last_checked_at: string | null;
  resolved_at: string | null;
}

export interface DNSBLListingList {
  items: DNSBLListingItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface DNSBLByIPEntry {
  list_id: string;
  list_name: string;
  zone_suffix: string;
  listed: boolean;
  checked: boolean;
  return_codes: string[];
  txt_reason: string | null;
  check_error: string | null;
  first_listed_at: string | null;
  last_checked_at: string | null;
}

export interface DNSBLByIP {
  ip: string;
  listed_count: number;
  entries: DNSBLByIPEntry[];
}

export interface DNSBLSettings {
  dnsbl_monitoring_enabled: boolean;
  dnsbl_check_interval_hours: number;
  dnsbl_query_resolvers: string[] | null;
  dnsbl_sweep_last_run_at: string | null;
}

export const dnsblApi = {
  listLists: () => api.get<DNSBLList[]>("/dnsbl/lists").then((r) => r.data),
  createList: (data: Partial<DNSBLList>) =>
    api.post<DNSBLList>("/dnsbl/lists", data).then((r) => r.data),
  updateList: (id: string, data: Partial<DNSBLList>) =>
    api.put<DNSBLList>(`/dnsbl/lists/${id}`, data).then((r) => r.data),
  deleteList: (id: string) => api.delete(`/dnsbl/lists/${id}`),
  listPinned: () =>
    api.get<DNSBLPinnedIP[]>("/dnsbl/pinned").then((r) => r.data),
  addPinned: (data: { ip: string; note?: string }) =>
    api.post<DNSBLPinnedIP>("/dnsbl/pinned", data).then((r) => r.data),
  deletePinned: (id: string) => api.delete(`/dnsbl/pinned/${id}`),
  listListings: (params?: {
    listed_only?: boolean;
    list_id?: string;
    source?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }) =>
    api
      .get<DNSBLListingList>("/dnsbl/listings", { params })
      .then((r) => r.data),
  byIp: (ip: string) =>
    api.get<DNSBLByIP>(`/dnsbl/listings/by-ip/${ip}`).then((r) => r.data),
  checkNow: (ip: string) =>
    api
      .post<{
        ip: string;
        checked: number;
        listed: number;
        source?: string;
      }>("/dnsbl/check", { ip })
      .then((r) => r.data),
  getSettings: () =>
    api.get<DNSBLSettings>("/dnsbl/settings").then((r) => r.data),
  updateSettings: (data: Partial<DNSBLSettings>) =>
    api.put<DNSBLSettings>("/dnsbl/settings", data).then((r) => r.data),
};

// ── Multicast groups (issue #126 Phase 1) ─────────────────────────
//
// First-class registry of multicast streams + producer/consumer
// memberships. Phase 1 ships the registry only — Phase 2 adds PIM
// domain context, Phase 3 adds observed populators (IGMP-snooping +
// SAP), Phase 4 adds Operator Copilot tools.

export type MulticastMembershipRole =
  | "producer"
  | "consumer"
  | "rendezvous_point";
export type MulticastMembershipSource =
  | "manual"
  | "igmp_snooping"
  | "sap_announce";
export type MulticastPortTransport = "udp" | "rtp" | "tcp" | "srt";

export interface MulticastGroupRead {
  id: string;
  space_id: string;
  address: string;
  name: string;
  description: string;
  application: string;
  rtp_payload_type: number | null;
  // ``Numeric`` columns are serialised as strings by Pydantic to
  // preserve precision across the wire — see CircuitRead.monthly_cost.
  bandwidth_mbps_estimate: string | null;
  vlan_id: string | null;
  customer_id: string | null;
  service_id: string | null;
  domain_id: string | null;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface MulticastGroupListResponse {
  items: MulticastGroupRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface MulticastGroupListQuery {
  limit?: number;
  offset?: number;
  space_id?: string;
  vlan_id?: string;
  customer_id?: string;
  service_id?: string;
  domain_id?: string;
  search?: string;
  tag?: string[];
}

export interface MulticastGroupCreate {
  space_id: string;
  address: string;
  name: string;
  description?: string;
  application?: string;
  rtp_payload_type?: number | null;
  bandwidth_mbps_estimate?: string | null;
  vlan_id?: string | null;
  customer_id?: string | null;
  service_id?: string | null;
  domain_id?: string | null;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface MulticastGroupUpdate {
  address?: string;
  name?: string;
  description?: string;
  application?: string;
  rtp_payload_type?: number | null;
  bandwidth_mbps_estimate?: string | null;
  vlan_id?: string | null;
  customer_id?: string | null;
  service_id?: string | null;
  domain_id?: string | null;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface MulticastGroupPortRead {
  id: string;
  group_id: string;
  port_start: number;
  port_end: number | null;
  transport: string;
  notes: string;
}

export interface MulticastGroupPortCreate {
  port_start: number;
  port_end?: number | null;
  transport?: MulticastPortTransport;
  notes?: string;
}

export interface MulticastMembershipRead {
  id: string;
  group_id: string;
  ip_address_id: string;
  role: string;
  seen_via: string;
  last_seen_at: string | null;
  notes: string;
}

export interface MulticastMembershipCreate {
  ip_address_id: string;
  role?: MulticastMembershipRole;
  seen_via?: MulticastMembershipSource;
  notes?: string;
}

export interface MulticastMembershipReadWithGroup {
  id: string;
  group_id: string;
  group_address: string;
  group_name: string;
  group_application: string;
  ip_address_id: string;
  role: string;
  seen_via: string;
  last_seen_at: string | null;
  notes: string;
}

export interface MulticastBulkAllocateRequest {
  space_id: string;
  count: number;
  name_template: string;
  start_address: string;
  template_start?: number;
  application?: string;
  description?: string;
  vlan_id?: string | null;
  customer_id?: string | null;
  service_id?: string | null;
  domain_id?: string | null;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface MulticastBulkAllocateItem {
  address: string;
  name: string;
  conflict: string | null;
}

export interface MulticastBulkAllocatePreviewResponse {
  items: MulticastBulkAllocateItem[];
  conflict_count: number;
  cap: number;
}

export interface MulticastBulkAllocateCommitResponse {
  created: number;
  group_ids: string[];
}

export type MulticastPIMMode = "sparse" | "dense" | "ssm" | "bidir" | "none";

export interface MulticastDomainRead {
  id: string;
  name: string;
  description: string;
  pim_mode: string;
  vrf_id: string | null;
  rendezvous_point_device_id: string | null;
  rendezvous_point_address: string | null;
  ssm_range: string | null;
  notes: string;
  tags: Record<string, unknown>;
  group_count: number;
  created_at: string;
  modified_at: string;
}

export interface MulticastDomainCreate {
  name: string;
  description?: string;
  pim_mode?: MulticastPIMMode;
  vrf_id?: string | null;
  rendezvous_point_device_id?: string | null;
  rendezvous_point_address?: string | null;
  ssm_range?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
}

export interface MulticastDomainUpdate {
  name?: string;
  description?: string;
  pim_mode?: MulticastPIMMode;
  vrf_id?: string | null;
  rendezvous_point_device_id?: string | null;
  rendezvous_point_address?: string | null;
  ssm_range?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
}

export const multicastApi = {
  list: (params?: MulticastGroupListQuery) =>
    api
      .get<MulticastGroupListResponse>("/multicast/groups", { params })
      .then((r) => r.data),
  get: (id: string) =>
    api.get<MulticastGroupRead>(`/multicast/groups/${id}`).then((r) => r.data),
  create: (data: MulticastGroupCreate) =>
    api.post<MulticastGroupRead>("/multicast/groups", data).then((r) => r.data),
  update: (id: string, data: MulticastGroupUpdate) =>
    api
      .put<MulticastGroupRead>(`/multicast/groups/${id}`, data)
      .then((r) => r.data),
  remove: (id: string) => api.delete(`/multicast/groups/${id}`),
  bulkDelete: (ids: string[]) =>
    api
      .post<{
        deleted: number;
        not_found: string[];
      }>("/multicast/groups/bulk-delete", { ids })
      .then((r) => r.data),

  listPorts: (groupId: string) =>
    api
      .get<MulticastGroupPortRead[]>(`/multicast/groups/${groupId}/ports`)
      .then((r) => r.data),
  createPort: (groupId: string, data: MulticastGroupPortCreate) =>
    api
      .post<MulticastGroupPortRead>(`/multicast/groups/${groupId}/ports`, data)
      .then((r) => r.data),
  deletePort: (portId: string) => api.delete(`/multicast/ports/${portId}`),

  listMemberships: (groupId: string) =>
    api
      .get<
        MulticastMembershipRead[]
      >(`/multicast/groups/${groupId}/memberships`)
      .then((r) => r.data),
  listMembershipsByIP: (ipAddressId: string) =>
    api
      .get<MulticastMembershipReadWithGroup[]>("/multicast/memberships", {
        params: { ip_address_id: ipAddressId },
      })
      .then((r) => r.data),
  createMembership: (groupId: string, data: MulticastMembershipCreate) =>
    api
      .post<MulticastMembershipRead>(
        `/multicast/groups/${groupId}/memberships`,
        data,
      )
      .then((r) => r.data),
  deleteMembership: (membershipId: string) =>
    api.delete(`/multicast/memberships/${membershipId}`),

  listDomains: () =>
    api.get<MulticastDomainRead[]>("/multicast/domains").then((r) => r.data),
  getDomain: (id: string) =>
    api
      .get<MulticastDomainRead>(`/multicast/domains/${id}`)
      .then((r) => r.data),
  createDomain: (data: MulticastDomainCreate) =>
    api
      .post<MulticastDomainRead>("/multicast/domains", data)
      .then((r) => r.data),
  updateDomain: (id: string, data: MulticastDomainUpdate) =>
    api
      .put<MulticastDomainRead>(`/multicast/domains/${id}`, data)
      .then((r) => r.data),
  deleteDomain: (id: string) => api.delete(`/multicast/domains/${id}`),

  bulkAllocatePreview: (data: MulticastBulkAllocateRequest) =>
    api
      .post<MulticastBulkAllocatePreviewResponse>(
        "/multicast/groups/bulk-allocate/preview",
        data,
      )
      .then((r) => r.data),
  bulkAllocateCommit: (data: MulticastBulkAllocateRequest) =>
    api
      .post<MulticastBulkAllocateCommitResponse>(
        "/multicast/groups/bulk-allocate/commit",
        data,
      )
      .then((r) => r.data),
};

// ── Service catalog (issue #94) ────────────────────────────────────
//
// First-class customer-deliverable bundles. ``mpls_l3vpn`` is the
// concrete kind in v1; ``custom`` is the catch-all. Other kinds (DIA,
// hosted DNS / DHCP, SD-WAN, MPLS L2VPN, VPLS, EVPN) reserve names in
// the backend enum and will surface as kind options here in later
// phases. The polymorphic ``ServiceResource`` join row binds a service
// to VRF / Subnet / IPBlock / DNSZone / DHCPScope / Circuit / Site
// (overlay_network is reserved for SD-WAN #95 and rejected at attach
// time).

export type ServiceKind = "mpls_l3vpn" | "sdwan" | "custom";
export type ServiceStatus = "active" | "provisioning" | "suspended" | "decom";
export type ServiceResourceKind =
  | "vrf"
  | "subnet"
  | "ip_block"
  | "dns_zone"
  | "dhcp_scope"
  | "circuit"
  | "overlay_network"
  | "site";

export interface ServiceResourceRead {
  id: string;
  service_id: string;
  resource_kind: ServiceResourceKind;
  resource_id: string;
  role: string | null;
  created_at: string;
}

export interface ServiceRead {
  id: string;
  name: string;
  kind: ServiceKind;
  customer_id: string;
  status: ServiceStatus;
  term_start_date: string | null;
  term_end_date: string | null;
  // Decimal serialised as a string by Pydantic — see CircuitRead above.
  monthly_cost_usd: string | null;
  currency: string;
  sla_tier: string | null;
  notes: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
  resources: ServiceResourceRead[];
  resource_count: number;
}

export interface ServiceCreate {
  name: string;
  kind?: ServiceKind;
  customer_id: string;
  status?: ServiceStatus;
  term_start_date?: string | null;
  term_end_date?: string | null;
  monthly_cost_usd?: string | null;
  currency?: string;
  sla_tier?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface ServiceUpdate {
  name?: string;
  kind?: ServiceKind;
  customer_id?: string;
  status?: ServiceStatus;
  term_start_date?: string | null;
  term_end_date?: string | null;
  monthly_cost_usd?: string | null;
  currency?: string;
  sla_tier?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface ServiceListResponse {
  items: ServiceRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface ServiceListQuery {
  limit?: number;
  offset?: number;
  customer_id?: string;
  kind?: ServiceKind;
  status?: ServiceStatus;
  expiring_within_days?: number;
  search?: string;
  tag?: string[];
}

export interface ServiceResourceAttach {
  resource_kind: ServiceResourceKind;
  resource_id: string;
  role?: string | null;
}

// Summary payload — kind-aware shape. The backend returns an L3VPN
// shape for ``kind=mpls_l3vpn`` and a grouped-by-kind shape for
// everything else. Discriminated by the ``kind`` field on the
// payload itself so the frontend can switch on it.
export interface L3VPNVrfSummary {
  id: string;
  name: string;
  route_distinguisher: string | null;
  import_targets: string[];
  export_targets: string[];
}

export interface L3VPNSiteSummary {
  id: string;
  name: string;
  code: string | null;
  role: string | null;
}

export interface L3VPNCircuitSummary {
  id: string;
  name: string;
  ckt_id: string | null;
  transport_class: TransportClass;
  bandwidth_mbps_down: number;
  bandwidth_mbps_up: number;
  role: string | null;
}

export interface L3VPNSubnetSummary {
  id: string;
  cidr: string;
  vrf_id: string | null;
  role: string | null;
}

export interface L3VPNSummary {
  kind: "mpls_l3vpn";
  vrf: L3VPNVrfSummary | null;
  edge_sites: L3VPNSiteSummary[];
  edge_circuits: L3VPNCircuitSummary[];
  edge_subnets: L3VPNSubnetSummary[];
  warnings: string[];
}

export interface CustomGroupedSummary {
  kind: "custom";
  by_kind: Record<string, number>;
  resources: ServiceResourceRead[];
}

export type ServiceSummary = L3VPNSummary | CustomGroupedSummary;

export const servicesApi = {
  list: (params?: ServiceListQuery) =>
    api.get<ServiceListResponse>("/services", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<ServiceRead>(`/services/${id}`).then((r) => r.data),
  create: (data: ServiceCreate) =>
    api.post<ServiceRead>("/services", data).then((r) => r.data),
  update: (id: string, data: ServiceUpdate) =>
    api.put<ServiceRead>(`/services/${id}`, data).then((r) => r.data),
  remove: (id: string) => api.delete(`/services/${id}`),
  bulkDelete: (ids: string[]) =>
    api
      .post<{
        deleted: number;
        not_found: string[];
      }>("/services/bulk-delete", { ids })
      .then((r) => r.data),
  attachResource: (id: string, body: ServiceResourceAttach) =>
    api
      .post<ServiceResourceRead>(`/services/${id}/resources`, body)
      .then((r) => r.data),
  detachResource: (id: string, resourcePk: string) =>
    api.delete(`/services/${id}/resources/${resourcePk}`),
  summary: (id: string) =>
    api.get<ServiceSummary>(`/services/${id}/summary`).then((r) => r.data),
  byResource: (kind: ServiceResourceKind, resourceId: string) =>
    api
      .get<ServiceRead[]>(`/services/by-resource/${kind}/${resourceId}`)
      .then((r) => r.data),
};

// ── SD-WAN overlay topology (issue #95) ────────────────────────────
//
// Vendor-neutral source of truth for overlay topology + routing
// policy intent. ``overlay_network`` rows describe the logical
// overlay; ``overlay_site`` rows bind sites with role + edge device
// + ordered preferred-circuit list; ``routing_policy`` rows declare
// per-overlay match → action policies. The ``application_category``
// catalog is shared across overlays and seeded at startup.

export type OverlayKind =
  | "sdwan"
  | "ipsec_mesh"
  | "wireguard_mesh"
  | "dmvpn"
  | "vxlan_evpn"
  | "gre_mesh";

export type OverlayStatus = "active" | "building" | "suspended" | "decom";
export type OverlayPathStrategy =
  | "active_active"
  | "active_backup"
  | "load_balance"
  | "app_aware";
export type OverlaySiteRole = "hub" | "spoke" | "transit" | "gateway";
export type RoutingMatchKind =
  | "application"
  | "dscp"
  | "source_subnet"
  | "destination_subnet"
  | "port_range"
  | "acl";
export type RoutingAction =
  | "steer_to_circuit"
  | "steer_to_transport_class"
  | "steer_to_site_via_path"
  | "drop"
  | "shape"
  | "mark_dscp";

export interface OverlayRead {
  id: string;
  name: string;
  kind: OverlayKind;
  customer_id: string | null;
  vendor: string | null;
  encryption_profile: string | null;
  default_path_strategy: OverlayPathStrategy;
  status: OverlayStatus;
  notes: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
  site_count: number;
  policy_count: number;
}

export interface OverlayCreate {
  name: string;
  kind?: OverlayKind;
  customer_id?: string | null;
  vendor?: string | null;
  encryption_profile?: string | null;
  default_path_strategy?: OverlayPathStrategy;
  status?: OverlayStatus;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface OverlayUpdate {
  name?: string;
  kind?: OverlayKind;
  customer_id?: string | null;
  vendor?: string | null;
  encryption_profile?: string | null;
  default_path_strategy?: OverlayPathStrategy;
  status?: OverlayStatus;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface OverlayListResponse {
  items: OverlayRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface OverlayListQuery {
  limit?: number;
  offset?: number;
  customer_id?: string;
  kind?: OverlayKind;
  status?: OverlayStatus;
  search?: string;
  tag?: string[];
}

export interface OverlaySiteRead {
  id: string;
  overlay_network_id: string;
  site_id: string;
  role: OverlaySiteRole;
  device_id: string | null;
  loopback_subnet_id: string | null;
  preferred_circuits: string[];
  notes: string;
  created_at: string;
  modified_at: string;
}

export interface OverlaySiteCreate {
  site_id: string;
  role?: OverlaySiteRole;
  device_id?: string | null;
  loopback_subnet_id?: string | null;
  preferred_circuits?: string[];
  notes?: string;
}

export interface OverlaySiteUpdate {
  role?: OverlaySiteRole;
  device_id?: string | null;
  loopback_subnet_id?: string | null;
  preferred_circuits?: string[];
  notes?: string;
}

export interface RoutingPolicyRead {
  id: string;
  overlay_network_id: string;
  name: string;
  priority: number;
  match_kind: RoutingMatchKind;
  match_value: string;
  action: RoutingAction;
  action_target: string | null;
  enabled: boolean;
  notes: string;
  created_at: string;
  modified_at: string;
}

export interface RoutingPolicyCreate {
  name: string;
  priority?: number;
  match_kind: RoutingMatchKind;
  match_value: string;
  action: RoutingAction;
  action_target?: string | null;
  enabled?: boolean;
  notes?: string;
}

export interface RoutingPolicyUpdate {
  name?: string;
  priority?: number;
  match_kind?: RoutingMatchKind;
  match_value?: string;
  action?: RoutingAction;
  action_target?: string | null;
  enabled?: boolean;
  notes?: string;
}

export interface TopologyNode {
  overlay_site_id: string;
  site_id: string;
  site_name: string;
  site_code: string | null;
  role: OverlaySiteRole;
  device_id: string | null;
  device_name: string | null;
  preferred_circuits: string[];
}

export interface TopologyEdge {
  a_overlay_site_id: string;
  z_overlay_site_id: string;
  shared_circuits: string[];
}

export interface TopologyResponse {
  overlay: OverlayRead;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  policies: RoutingPolicyRead[];
}

export interface SimulateRequest {
  down_circuits: string[];
}

export interface SimulatedSiteResolution {
  overlay_site_id: string;
  site_name: string;
  original_preferred_circuits: string[];
  surviving_preferred_circuits: string[];
  primary_circuit: string | null;
  primary_circuit_name: string | null;
  primary_transport_class: string | null;
  blackholed: boolean;
}

export interface SimulatedPolicyResolution {
  policy_id: string;
  policy_name: string;
  action: RoutingAction;
  original_target: string | null;
  effective_target: string | null;
  impacted: boolean;
  note: string | null;
}

export interface SimulateResponse {
  overlay_id: string;
  down_circuits: string[];
  site_resolutions: SimulatedSiteResolution[];
  policy_resolutions: SimulatedPolicyResolution[];
}

export const overlaysApi = {
  list: (params?: OverlayListQuery) =>
    api.get<OverlayListResponse>("/overlays", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<OverlayRead>(`/overlays/${id}`).then((r) => r.data),
  create: (body: OverlayCreate) =>
    api.post<OverlayRead>("/overlays", body).then((r) => r.data),
  update: (id: string, body: OverlayUpdate) =>
    api.put<OverlayRead>(`/overlays/${id}`, body).then((r) => r.data),
  remove: (id: string) => api.delete(`/overlays/${id}`),
  bulkDelete: (ids: string[]) =>
    api
      .post<{
        deleted: number;
        not_found: string[];
      }>("/overlays/bulk-delete", { ids })
      .then((r) => r.data),

  // Site membership
  listSites: (overlayId: string) =>
    api
      .get<OverlaySiteRead[]>(`/overlays/${overlayId}/sites`)
      .then((r) => r.data),
  attachSite: (overlayId: string, body: OverlaySiteCreate) =>
    api
      .post<OverlaySiteRead>(`/overlays/${overlayId}/sites`, body)
      .then((r) => r.data),
  updateSite: (overlayId: string, siteRowId: string, body: OverlaySiteUpdate) =>
    api
      .put<OverlaySiteRead>(`/overlays/${overlayId}/sites/${siteRowId}`, body)
      .then((r) => r.data),
  detachSite: (overlayId: string, siteRowId: string) =>
    api.delete(`/overlays/${overlayId}/sites/${siteRowId}`),

  // Routing policies
  listPolicies: (overlayId: string) =>
    api
      .get<RoutingPolicyRead[]>(`/overlays/${overlayId}/policies`)
      .then((r) => r.data),
  createPolicy: (overlayId: string, body: RoutingPolicyCreate) =>
    api
      .post<RoutingPolicyRead>(`/overlays/${overlayId}/policies`, body)
      .then((r) => r.data),
  updatePolicy: (
    overlayId: string,
    policyId: string,
    body: RoutingPolicyUpdate,
  ) =>
    api
      .put<RoutingPolicyRead>(
        `/overlays/${overlayId}/policies/${policyId}`,
        body,
      )
      .then((r) => r.data),
  deletePolicy: (overlayId: string, policyId: string) =>
    api.delete(`/overlays/${overlayId}/policies/${policyId}`),

  // Topology + simulate
  topology: (overlayId: string) =>
    api
      .get<TopologyResponse>(`/overlays/${overlayId}/topology`)
      .then((r) => r.data),
  simulate: (overlayId: string, body: SimulateRequest) =>
    api
      .post<SimulateResponse>(`/overlays/${overlayId}/simulate`, body)
      .then((r) => r.data),
};

// ── Application catalog (issue #95) ─────────────────────────────────

export type ApplicationKind =
  | "saas"
  | "voice"
  | "video"
  | "file_transfer"
  | "security"
  | "collaboration"
  | "ml"
  | "custom";

export interface ApplicationRead {
  id: string;
  name: string;
  description: string;
  default_dscp: number | null;
  category: ApplicationKind;
  is_builtin: boolean;
  created_at: string;
  modified_at: string;
}

export interface ApplicationCreate {
  name: string;
  description?: string;
  default_dscp?: number | null;
  category?: ApplicationKind;
}

export interface ApplicationUpdate {
  description?: string;
  default_dscp?: number | null;
  category?: ApplicationKind;
}

export interface ApplicationListResponse {
  items: ApplicationRead[];
  total: number;
}

export const applicationsApi = {
  list: (params?: {
    category?: ApplicationKind;
    builtin?: boolean;
    search?: string;
  }) =>
    api
      .get<ApplicationListResponse>("/applications", { params })
      .then((r) => r.data),
  create: (body: ApplicationCreate) =>
    api.post<ApplicationRead>("/applications", body).then((r) => r.data),
  update: (id: string, body: ApplicationUpdate) =>
    api.put<ApplicationRead>(`/applications/${id}`, body).then((r) => r.data),
  remove: (id: string) => api.delete(`/applications/${id}`),
};

// ── Factory Reset (issue #116) ────────────────────────────────────────

export interface FactoryResetSection {
  key: string;
  label: string;
  description: string;
  phrase: string;
  kind: "truncate" | "auth_rbac" | "settings_reset" | "everything";
  table_count: number;
}

export interface FactoryResetSectionPreview {
  section_key: string;
  label: string;
  kind: string;
  affected_rows: number;
  table_counts: Record<string, number>;
  notes: string[];
}

export interface FactoryResetPreviewResponse {
  sections: FactoryResetSectionPreview[];
  deleted_rows_total: number;
  backup_warning: boolean;
  backup_warning_detail: string | null;
  cooldown_blocking: boolean;
  cooldown_detail: string | null;
}

export interface FactoryResetExecuteRequest {
  section_keys: string[];
  password: string;
  confirm_phrases: Record<string, string>;
  acknowledge_no_backup?: boolean;
}

export interface FactoryResetExecuteResponse {
  success: boolean;
  sections: string[];
  deleted_rows_total: number;
  audit_anchor_id: string | null;
  duration_ms: number;
}

export const factoryResetApi = {
  listSections: () =>
    api
      .get<{
        sections: FactoryResetSection[];
      }>("/system/factory-reset/sections")
      .then((r) => r.data.sections),
  preview: (section_keys: string[]) =>
    api
      .post<FactoryResetPreviewResponse>("/system/factory-reset/preview", {
        section_keys,
      })
      .then((r) => r.data),
  execute: (body: FactoryResetExecuteRequest) =>
    api
      .post<FactoryResetExecuteResponse>("/system/factory-reset/execute", body)
      .then((r) => r.data),
};

// ── Support bundle (#875) ────────────────────────────────────────────

export interface SupportBundleFile {
  path: string;
  bytes: number;
  truncated: boolean;
}

export interface SupportBundlePreview {
  scrubbed: boolean;
  filename: string;
  total_bytes: number;
  files: SupportBundleFile[];
  manifest: Record<string, unknown>;
  section_errors: string[];
  sample: string;
  warning: string;
}

export interface SupportBundleDecodeMap {
  warning: string;
  mappings: Record<string, Record<string, string>>;
  counts: Record<string, number>;
}

/**
 * Typed verbatim when generating an unscrubbed bundle. Kept in sync with
 * UNSCRUBBED_CONFIRM in backend/app/api/v1/system/support_bundle.py — the
 * backend compares it exactly, so a drift here surfaces as a 400.
 */
export const SUPPORT_BUNDLE_UNSCRUBBED_CONFIRM =
  "I understand this bundle is not anonymised";

export const supportBundleApi = {
  preview: (scrubbed: boolean) =>
    api
      .post<SupportBundlePreview>("/system/support-bundle/preview", {
        scrubbed,
        confirm_unscrubbed: scrubbed
          ? undefined
          : SUPPORT_BUNDLE_UNSCRUBBED_CONFIRM,
      })
      .then((r) => r.data),
  download: (scrubbed: boolean) =>
    api
      .post(
        "/system/support-bundle",
        {
          scrubbed,
          confirm_unscrubbed: scrubbed
            ? undefined
            : SUPPORT_BUNDLE_UNSCRUBBED_CONFIRM,
        },
        { responseType: "blob" },
      )
      .then((r) => r.data as Blob),
  decodeMap: () =>
    api
      .post<SupportBundleDecodeMap>("/system/support-bundle/decode-map")
      .then((r) => r.data),
};

// ── Scheduled Wake-on-LAN (#586 Phase 1) ─────────────────────────────
// Mirrors backend/app/api/v1/wol_schedules/schemas.py. The Python package
// is ``wol_schedules`` but the wire prefix is ``/wake-scheduler`` — that
// prefix is the cross-surface contract shared with the MCP tools + runner.
// Phase 1's holiday gate is the built-in ``blackout_dates`` + ``active_from``
// / ``active_until`` + ``timezone`` (no external iCal / CalDAV — that's
// Phase 2, deliberately absent).

/** Selector mode — mirrors ``resolver.VALID_MODES``. */
export type WolSelectorMode =
  | "address_tags"
  | "subnet"
  | "subnet_tags"
  | "hosts";

/**
 * Calendar-gate polarity (Phase 2, #586). ``none`` = the external calendar
 * plays no part (built-in blackout/term still apply); ``skip_on_event`` = a
 * matching event on the fire date SKIPS the wake (holiday calendar);
 * ``only_on_event`` = the wake only fires when the date intersects a matching
 * event (term / school-day calendar). Mirrors ``wol_schedule.calendar_mode``.
 */
export type WolCalendarMode = "none" | "skip_on_event" | "only_on_event";

/** Calendar subscription kind — mirrors ``wol_calendar.kind``. */
export type WolCalendarKind = "ical_url" | "caldav";

/**
 * The stored ``target_selector``. Only the list relevant to ``mode`` is
 * consulted by the resolver, but all four fields are carried so the operator
 * can flip modes without losing the other selections. ``tags`` use the
 * ``key`` / ``key:value`` grammar (ANDed).
 */
export interface WolTargetSelector {
  mode: WolSelectorMode;
  tags: string[];
  subnet_ids: string[];
  address_ids: string[];
}

/**
 * Send-from vantage — a magic packet only originates from the control-plane
 * server or a Fleet appliance NIC, so Phase 1 restricts ``kind`` to those two
 * (validated server-side). ``id`` is required when ``kind === "appliance"``.
 */
export interface WolVantage {
  kind: "server" | "appliance";
  id: string | null;
}

/**
 * Post-wake liveness source (issue #596).
 *
 * - `ping` — ICMP echo from the control plane. Hosts behind a default Windows
 *   firewall read as down.
 * - `tcp` — connect-or-RST on a small port set; a refused connection still
 *   proves the host is up, so this survives an ICMP-blocking host firewall.
 * - `seen` — no traffic at all: was the host observed on the network *after*
 *   the wake fired, per `IPAddress.last_seen_at`. Works for segments the
 *   control plane cannot reach.
 * - `auto` — ping → tcp → seen, stopping at the first confirmation.
 */
export type WolVerifyMethod = "ping" | "tcp" | "seen" | "auto";

/** One entry in a target's post-wake evidence trail (#596). `observed_at` is a
 *  structured ISO timestamp of when the evidence was observed: for an active
 *  probe, when we checked; for a confirmed passive `seen` entry, the sighting
 *  time itself. `detail` is intentionally timestamp-free, so the UI can format
 *  `observed_at`. */
export interface WolVerifyEvidence {
  source: string;
  up: boolean;
  detail: string;
  observed_at: string;
}

export interface WolSchedule {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  target_selector: WolTargetSelector;
  /** NULL / empty cron == manual-only (never swept by the beat task). */
  schedule_cron: string | null;
  timezone: string; // IANA, e.g. "UTC"
  blackout_dates: string[] | null; // ISO YYYY-MM-DD
  active_from: string | null; // ISO date — term-range gate
  active_until: string | null;
  /** External-calendar gate (Phase 2). ``null`` calendar_id == no feed. */
  calendar_id: string | null;
  calendar_mode: WolCalendarMode;
  calendar_match: string | null; // optional summary/category regex
  vantage: WolVantage;
  repeat_count: number;
  repeat_interval_ms: number;
  stagger_ms: number;
  port: number;
  /**
   * Post-wake liveness verify + retry (Phase 3). When ``verify_enabled``, a
   * chained task probes each SENT host after ``verify_wait_seconds`` and
   * re-wakes non-responders up to ``verify_retries`` extra passes.
   * ``verify_method`` picks the liveness source (issue #596) — see
   * ``WolVerifyMethod``.
   */
  verify_enabled: boolean;
  verify_wait_seconds: number;
  verify_retries: number;
  /** Per-schedule mute for the `wol_wake_failed` alert (#596). The alert rule's
   *  own enabled flag is the master switch; this silences one noisy schedule. */
  verify_alert_enabled: boolean;
  verify_method: WolVerifyMethod;
  last_run_at: string | null;
  last_run_status: string | null;
  last_run_skip_reason: string | null;
  last_target_count: number | null;
  next_run_at: string | null;
  created_by_user_id: string | null;
  created_at: string;
  modified_at: string;
}

export interface WolScheduleCreate {
  name: string;
  description?: string | null;
  enabled?: boolean;
  target_selector: WolTargetSelector;
  schedule_cron?: string | null;
  timezone?: string;
  blackout_dates?: string[] | null;
  active_from?: string | null;
  active_until?: string | null;
  /**
   * External-calendar gate (Phase 2). ``calendar_mode !== "none"`` requires
   * ``calendar_id`` server-side; ``calendar_match`` is an optional
   * summary/category regex filtering which events count.
   */
  calendar_id?: string | null;
  calendar_mode?: WolCalendarMode;
  calendar_match?: string | null;
  vantage?: WolVantage | null;
  repeat_count?: number;
  repeat_interval_ms?: number;
  stagger_ms?: number;
  port?: number;
  /** Post-wake verify + retry (Phase 3). */
  verify_enabled?: boolean;
  verify_wait_seconds?: number;
  verify_retries?: number;
  verify_alert_enabled?: boolean;
  verify_method?: WolVerifyMethod;
}

/**
 * PATCH body — every field optional. Send only the changed keys;
 * ``model_dump(exclude_unset=True)`` server-side distinguishes "leave
 * unchanged" from an explicit ``null`` on the nullable columns.
 */
export interface WolScheduleUpdate {
  name?: string;
  description?: string | null;
  enabled?: boolean;
  target_selector?: WolTargetSelector;
  schedule_cron?: string | null;
  timezone?: string;
  blackout_dates?: string[] | null;
  active_from?: string | null;
  active_until?: string | null;
  calendar_id?: string | null;
  calendar_mode?: WolCalendarMode;
  calendar_match?: string | null;
  vantage?: WolVantage | null;
  repeat_count?: number;
  repeat_interval_ms?: number;
  stagger_ms?: number;
  port?: number;
  /** Post-wake verify + retry (Phase 3). */
  verify_enabled?: boolean;
  verify_wait_seconds?: number;
  verify_retries?: number;
  verify_alert_enabled?: boolean;
  verify_method?: WolVerifyMethod;
}

/** A host that WOULD be sent a magic packet (preview). */
export interface WolWakeTarget {
  ip_address_id: string | null;
  address: string | null;
  mac: string;
  subnet_id: string | null;
  broadcast: string;
  mac_source: string;
  hostname?: string | null;
}

/** A matched input that would NOT be sent, with a reason (preview). */
export interface WolSkippedTarget {
  reason: string;
  ip_address_id?: string | null;
  address?: string | null;
  subnet_id?: string | null;
}

/** Body for the unsaved ``POST /preview-targets`` (create-modal live count). */
export interface WolTargetPreviewRequest {
  target_selector: WolTargetSelector;
}

export interface WolTargetPreview {
  matched_count: number;
  wake_count: number;
  skipped_count: number;
  /** Per-host skips whose reason is ``no_mac`` — "N hosts have no known MAC". */
  mac_less_count: number;
  sample: WolWakeTarget[];
  skipped_sample: WolSkippedTarget[];
  /**
   * Stagger auto-tune (Phase 3): suggested inter-host gap (ms) for the resolved
   * ``wake_count`` when the operator leaves ``stagger_ms`` at 0/auto. Surfaced
   * as a hint next to the send options ("waking N hosts → suggest ~X ms").
   */
  suggested_stagger_ms: number;
  /** Only populated for a saved-schedule preview (unsaved has no cron/gate). */
  next_run_at: string | null;
  gate_verdict: string | null;
}

export interface WolRun {
  id: string;
  schedule_id: string | null;
  trigger: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  skip_reason: string | null;
  target_count: number;
  sent_count: number;
  skipped_count: number;
  failed_count: number;
  /**
   * Post-wake verify rollup (Phase 3). ``verify_state``:
   * ``none`` (verify off / never scheduled) → ``pending`` (verify enqueued) →
   * ``verifying`` (a probe pass holds the mutex) → ``done`` (finalised).
   * ``verified_count`` / ``unverified_count`` split the SENT targets by whether
   * they answered a liveness probe, populated at finalise.
   */
  verify_state: string;
  verified_count: number;
  unverified_count: number;
  triggered_by_user_id: string | null;
  error: string | null;
  created_at: string;
}

export interface WolRunTarget {
  id: string;
  run_id: string;
  ip_address_id: string | null;
  address: string | null;
  mac: string | null;
  subnet_id: string | null;
  broadcast: string | null;
  vantage: WolVantage | null;
  mac_source: string | null;
  sent: boolean;
  skip_reason: string | null;
  error: string | null;
  /**
   * Post-wake verify outcome (Phase 3). ``verified`` tri-state: ``null`` ==
   * not-yet / not-checked · ``false`` == probed DOWN (a re-wake candidate) ·
   * ``true`` == probed UP. ``wake_attempts`` is 1 for the original dispatch, +1
   * per re-wake pass.
   */
  verified: boolean | null;
  verified_at: string | null;
  verify_method: string | null;
  /** Ordered trail of every liveness source consulted on the final verify pass
   *  (#596). `null` when no source could run against the row, or for rows
   *  written before the trail shipped. */
  verify_evidence: WolVerifyEvidence[] | null;
  wake_attempts: number;
  created_at: string;
}

/** A run plus its per-host ``wol_run_target`` outcomes. */
export interface WolRunDetail extends WolRun {
  targets: WolRunTarget[];
}

// ── Calendars (#586 Phase 2) ─────────────────────────────────────────
// Subscribed iCal (.ics URL) / authenticated CalDAV feeds whose all-day
// event spans flatten into ``wol_calendar_event`` rows for the schedule's
// holiday / term gate. The CalDAV password is write-only — never returned;
// only ``password_set`` reveals whether one is stored.

export interface WolCalendar {
  id: string;
  name: string;
  kind: WolCalendarKind;
  url: string;
  username: string | null;
  password_set: boolean;
  enabled: boolean;
  refresh_interval_minutes: number;
  last_synced_at: string | null;
  last_sync_status: string | null;
  last_sync_error: string | null;
  event_count: number;
  created_at: string;
  modified_at: string;
}

export interface WolCalendarCreate {
  name: string;
  kind: WolCalendarKind;
  url: string;
  username?: string | null;
  /** Write-only; encrypted at rest, never returned. */
  password?: string | null;
  enabled?: boolean;
  refresh_interval_minutes?: number;
}

/**
 * PATCH body — every field optional. An explicit ``password: ""`` CLEARS the
 * stored secret; omitting ``password`` leaves it unchanged; a non-empty string
 * re-encrypts.
 */
export interface WolCalendarUpdate {
  name?: string;
  kind?: WolCalendarKind;
  url?: string;
  username?: string | null;
  password?: string | null;
  enabled?: boolean;
  refresh_interval_minutes?: number;
}

/** One flattened all-day event span (recurrence already expanded). */
export interface WolCalendarEvent {
  id: string;
  starts_on: string; // ISO date
  ends_on: string; // ISO date (inclusive)
  summary: string | null;
  categories: string[];
  uid: string | null;
}

/** Outcome of a ``POST /calendars/{id}/sync-now`` refresh. */
export interface WolCalendarSyncResult {
  status: string;
  added: number;
  removed: number;
  total: number;
  error: string | null;
  last_synced_at: string | null;
  last_sync_status: string | null;
  last_sync_error: string | null;
}

export const wakeSchedulesApi = {
  list: (enabled?: boolean) =>
    api
      .get<WolSchedule[]>("/wake-scheduler/schedules", {
        params: enabled === undefined ? undefined : { enabled },
      })
      .then((r) => r.data),
  get: (id: string) =>
    api.get<WolSchedule>(`/wake-scheduler/schedules/${id}`).then((r) => r.data),
  create: (body: WolScheduleCreate) =>
    api
      .post<WolSchedule>("/wake-scheduler/schedules", body)
      .then((r) => r.data),
  update: (id: string, body: WolScheduleUpdate) =>
    api
      .patch<WolSchedule>(`/wake-scheduler/schedules/${id}`, body)
      .then((r) => r.data),
  remove: (id: string) =>
    api.delete<void>(`/wake-scheduler/schedules/${id}`).then((r) => r.data),
  /** Fire a saved schedule immediately (bypasses the built-in holiday gate). */
  runNow: (id: string) =>
    api
      .post<WolRun>(`/wake-scheduler/schedules/${id}/run-now`)
      .then((r) => r.data),
  /**
   * Resolve an *unsaved* selector against the caller's read scope — the
   * create modal's live match count.
   */
  previewTargets: (body: WolTargetPreviewRequest) =>
    api
      .post<WolTargetPreview>("/wake-scheduler/preview-targets", body)
      .then((r) => r.data),
  /**
   * Resolve a *saved* schedule's selector + its next fire + the built-in
   * gate verdict at that fire.
   */
  previewScheduleTargets: (id: string) =>
    api
      .post<WolTargetPreview>(`/wake-scheduler/schedules/${id}/preview-targets`)
      .then((r) => r.data),
  listRuns: (params?: {
    schedule_id?: string;
    status?: string;
    limit?: number;
  }) =>
    api.get<WolRun[]>("/wake-scheduler/runs", { params }).then((r) => r.data),
  getRun: (id: string) =>
    api.get<WolRunDetail>(`/wake-scheduler/runs/${id}`).then((r) => r.data),

  // ── Calendars (Phase 2) ──────────────────────────────────────────
  listCalendars: (enabled?: boolean) =>
    api
      .get<WolCalendar[]>("/wake-scheduler/calendars", {
        params: enabled === undefined ? undefined : { enabled },
      })
      .then((r) => r.data),
  getCalendar: (id: string) =>
    api.get<WolCalendar>(`/wake-scheduler/calendars/${id}`).then((r) => r.data),
  createCalendar: (body: WolCalendarCreate) =>
    api
      .post<WolCalendar>("/wake-scheduler/calendars", body)
      .then((r) => r.data),
  updateCalendar: (id: string, body: WolCalendarUpdate) =>
    api
      .patch<WolCalendar>(`/wake-scheduler/calendars/${id}`, body)
      .then((r) => r.data),
  removeCalendar: (id: string) =>
    api.delete<void>(`/wake-scheduler/calendars/${id}`).then((r) => r.data),
  /** Refresh a calendar's cached event spans right now (inline). */
  syncCalendarNow: (id: string) =>
    api
      .post<WolCalendarSyncResult>(`/wake-scheduler/calendars/${id}/sync-now`)
      .then((r) => r.data),
  /** Preview the cached events reaching into the next ``days`` window. */
  getCalendarEvents: (id: string, params?: { days?: number; limit?: number }) =>
    api
      .get<
        WolCalendarEvent[]
      >(`/wake-scheduler/calendars/${id}/upcoming-events`, { params })
      .then((r) => r.data),
};

// ── Active block sync — firewall / network-block enforcement (#601) ────
// The enforcement half of the detect→block loop: SpatiumDDI-owned blocked
// IPs / MACs pushed into armed OPNsense (firewall alias membership) and
// UniFi (L2 client quarantine) targets. The whole surface is gated by the
// (default-off) ``security.block_sync`` feature module — every endpoint
// 404s when the module is off, so callers gate their queries on
// ``useFeatureModules().enabled("security.block_sync")``. Requires the
// ``manage_block_sync`` admin permission on every call.

export type BlockKind = "ip" | "mac";
export type BlockSource = "manual" | "new_device" | "rogue_dhcp";
export type BlockTargetKind = "opnsense" | "unifi" | "paloalto" | "meraki";
export type BlockPushStatus = "pending" | "pushed" | "removing" | "error";
export type BlockUnifiAuthKind = "api_key" | "user_password";

export interface BlockPushOut {
  target_kind: string;
  target_id: string;
  push_status: BlockPushStatus;
  last_pushed_at: string | null;
  last_error: string | null;
}

export interface NetworkBlock {
  id: string;
  kind: string;
  value: string;
  reason: string;
  description: string;
  source: string;
  source_ref: string | null;
  enabled: boolean;
  expires_at: string | null;
  created_at: string;
  modified_at: string;
  pushes: BlockPushOut[];
}

export interface NetworkBlockCreate {
  kind: BlockKind;
  value: string;
  reason?: string;
  description?: string;
  source?: BlockSource;
  source_ref?: string | null;
  expires_at?: string | null;
}

export interface BlockTargetDiff {
  target_kind: string;
  target_id: string;
  target_name: string;
  to_add: string[];
  to_remove: string[];
  error: string | null;
}

export interface BlockTarget {
  target_kind: BlockTargetKind;
  target_id: string;
  name: string;
  block_sync_enabled: boolean;
  // OPNsense-only
  block_alias_name?: string | null;
  // Palo Alto PAN-OS-only — the Dynamic Address Group tag SpatiumDDI writes.
  block_tag_name?: string | null;
  // Palo Alto PAN-OS-only — a Panorama target cannot be armed (DAG enforcement
  // needs a standalone firewall with a vsys); the backend 422s the arm call.
  is_panorama?: boolean;
  // Meraki-only — the per-client policy name SpatiumDDI applies (Blocked).
  block_policy_name?: string | null;
  // UniFi-only
  block_sync_site?: string | null;
  block_sync_auth_kind?: string | null;
  write_credentials_present: boolean;
  last_block_sync_at: string | null;
  last_block_sync_error: string | null;
}

export interface BlockOpnsenseArm {
  block_sync_enabled?: boolean;
  block_alias_name?: string;
  block_sync_api_key?: string;
  // Omit / empty keeps the stored secret; non-empty rotates it.
  block_sync_api_secret?: string;
}

export interface BlockPaloaltoArm {
  block_sync_enabled?: boolean;
  block_tag_name?: string;
  // Omit / empty keeps the stored key; non-empty rotates it.
  block_sync_api_key?: string;
}

export interface BlockMerakiArm {
  block_sync_enabled?: boolean;
  block_policy_name?: string;
  // Omit / empty keeps the stored key; non-empty rotates it.
  block_sync_api_key?: string;
}

export interface BlockUnifiArm {
  block_sync_enabled?: boolean;
  block_sync_site?: string;
  block_sync_auth_kind?: BlockUnifiAuthKind;
  block_sync_api_key?: string;
  block_sync_username?: string;
  block_sync_password?: string;
}

export interface BlockRevealResult {
  api_secret?: string;
  api_key?: string;
  password?: string;
}

export const blockSyncApi = {
  listBlocks: () =>
    api.get<NetworkBlock[]>("/block-sync/blocks").then((r) => r.data),
  previewBlock: (data: NetworkBlockCreate) =>
    api
      .post<BlockTargetDiff[]>("/block-sync/blocks/preview", data)
      .then((r) => r.data),
  // 201 → NetworkBlock, or 202 → ChangeRequestQueued when two-person
  // approval is armed. Returns the FULL axios response on purpose — do
  // NOT chain ``.then((r) => r.data)`` here or the 202 status is
  // invisible. Callers pass the response to ``handleApprovalQueued``.
  createBlock: (
    data: NetworkBlockCreate,
  ): Promise<AxiosResponse<NetworkBlock | ChangeRequestQueued>> =>
    api.post<NetworkBlock | ChangeRequestQueued>("/block-sync/blocks", data),
  liftBlock: (id: string) =>
    api.delete<NetworkBlock>(`/block-sync/blocks/${id}`).then((r) => r.data),
  listTargets: () =>
    api.get<BlockTarget[]>("/block-sync/targets").then((r) => r.data),
  armOpnsense: (id: string, data: BlockOpnsenseArm) =>
    api
      .put<BlockTarget>(`/block-sync/targets/opnsense/${id}`, data)
      .then((r) => r.data),
  armUnifi: (id: string, data: BlockUnifiArm) =>
    api
      .put<BlockTarget>(`/block-sync/targets/unifi/${id}`, data)
      .then((r) => r.data),
  armPaloalto: (id: string, data: BlockPaloaltoArm) =>
    api
      .put<BlockTarget>(`/block-sync/targets/paloalto/${id}`, data)
      .then((r) => r.data),
  armMeraki: (id: string, data: BlockMerakiArm) =>
    api
      .put<BlockTarget>(`/block-sync/targets/meraki/${id}`, data)
      .then((r) => r.data),
  // ``preview=true`` reads the device + returns the diff without pushing;
  // ``preview=false`` enqueues a converge.
  reconcile: (
    targetKind: BlockTargetKind,
    targetId: string,
    preview: boolean,
  ) =>
    api
      .post<BlockTargetDiff>(
        `/block-sync/targets/${targetKind}/${targetId}/reconcile`,
        undefined,
        { params: { preview } },
      )
      .then((r) => r.data),
  // Password / TOTP re-confirm reveal of the stored write-scoped secret,
  // mirroring the agent-bootstrap-key reveal. Audited server-side.
  reveal: (
    targetKind: BlockTargetKind,
    targetId: string,
    password?: string,
    totpCode?: string,
  ) =>
    api
      .post<BlockRevealResult>(
        `/block-sync/targets/${targetKind}/${targetId}/reveal`,
        { password, totp_code: totpCode },
      )
      .then((r) => r.data),
};

// ── Vertical network awareness (issue #543) ──────────────────────────
//
// Three sibling registries that annotate rows the platform already
// owns rather than introducing a parallel inventory:
//
//   * AV over IP (#540)  — a 1:1 sidecar on a ``multicast_group``,
//     plus operator-declared reserved ranges per protocol.
//   * BACnet/IP (#541)   — building-automation devices anchored to an
//     IPAM address, keyed by an internetwork-unique device instance.
//   * OT / industrial (#542) — a 1:1 sidecar on an IPAM address, plus
//     one Purdue zone per subnet.
//
// Each family sits behind its own default-on feature module
// (``network.av`` / ``network.bacnet`` / ``network.ot``), so callers
// must gate their queries on ``ready && enabled(id)`` from
// ``useFeatureModules`` — the routers 404 when the module is off.
//
// None of these surfaces talk to a device: every value is operator-
// entered or imported. There is no probe, scan or control-protocol
// write anywhere behind them.

// ── AV over IP (#540) ────────────────────────────────────────────────

export type AVProtocol =
  | "dante"
  | "aes67"
  | "smpte2110_video"
  | "smpte2110_audio"
  | "smpte2110_anc"
  | "ndi"
  | "ravenna"
  | "other";

export type AVFlowSource = "manual" | "mdns" | "nmos";

export interface AVReservedRange {
  id: string;
  space_id: string;
  cidr: string;
  av_protocol: string;
  name: string;
  description: string;
  /** Exclusive ranges conflict with other protocols; shared ones only advise. */
  exclusive: boolean;
  vlan_id: string | null;
  tags: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface AVReservedRangeCreate {
  space_id: string;
  cidr: string;
  av_protocol: AVProtocol;
  name?: string;
  description?: string;
  exclusive?: boolean;
  vlan_id?: string | null;
  tags?: Record<string, unknown>;
}

/** Partial update. ``space_id`` is intentionally absent — re-homing a
 *  range to another IPSpace is a delete + create on the backend. */
export interface AVReservedRangeUpdate {
  cidr?: string;
  av_protocol?: AVProtocol;
  name?: string;
  description?: string;
  exclusive?: boolean;
  vlan_id?: string | null;
  tags?: Record<string, unknown>;
}

export interface AVFlow {
  id: string;
  group_id: string;
  av_protocol: string;
  av_flow_label: string;
  /** PTP (IEEE 1588) clock domain, 0–255. ``null`` is the finding the
   *  ``av_flow_no_ptp_domain`` conformity check surfaces. */
  ptp_domain: number | null;
  seen_via: string;
  notes: string;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
  // Denormalised from the parent multicast group.
  group_address: string;
  group_name: string;
  group_application: string;
  space_id: string;
  vlan_id: string | null;
}

export interface AVFlowListResponse {
  items: AVFlow[];
  total: number;
  limit: number;
  offset: number;
}

/** Full-document upsert (``PUT /av/flows/{group_id}``): an omitted
 *  ``ptp_domain`` clears the stored one rather than leaving it alone. */
export interface AVFlowUpsert {
  av_protocol: AVProtocol;
  av_flow_label?: string;
  ptp_domain?: number | null;
  seen_via?: AVFlowSource;
  notes?: string;
  custom_fields?: Record<string, unknown>;
}

export interface AVFlowListQuery {
  limit?: number;
  offset?: number;
  av_protocol?: string;
  ptp_domain?: number;
  space_id?: string;
  vlan_id?: string;
  q?: string;
}

export interface AVReservedRangeMatch {
  range_id: string;
  cidr: string;
  av_protocol: string;
  exclusive: boolean;
  name: string;
  /** ``inside`` when wholly within the range, ``overlaps`` when it straddles. */
  relation: string;
}

export interface AVAllocationPreviewRequest {
  space_id: string;
  address_or_cidr: string;
  av_protocol: AVProtocol;
}

export interface AVAllocationPreviewResponse {
  space_id: string;
  target: string;
  av_protocol: string;
  /** ``ok`` | ``informational`` | ``conflict``. */
  status: string;
  conflicts: AVReservedRangeMatch[];
  advisories: AVReservedRangeMatch[];
  own_ranges: AVReservedRangeMatch[];
  outside_declared_range: boolean;
  suggested_range: string | null;
  detail: string;
}

export interface AVProtocolPreset {
  av_protocol: string;
  label: string;
  /** ``null`` where the protocol has no vendor default (SMPTE 2110, NDI). */
  default_cidr: string | null;
}

export interface AVPresetsResponse {
  protocols: AVProtocolPreset[];
  flow_sources: string[];
  ptp_domain_min: number;
  ptp_domain_max: number;
}

export const avApi = {
  listReservedRanges: (params?: {
    space_id?: string;
    av_protocol?: string;
    vlan_id?: string;
    exclusive?: boolean;
    tag?: string[];
  }) =>
    api
      .get<AVReservedRange[]>("/av/reserved-ranges", { params })
      .then((r) => r.data),
  createReservedRange: (data: AVReservedRangeCreate) =>
    api.post<AVReservedRange>("/av/reserved-ranges", data).then((r) => r.data),
  updateReservedRange: (id: string, data: AVReservedRangeUpdate) =>
    api
      .put<AVReservedRange>(`/av/reserved-ranges/${id}`, data)
      .then((r) => r.data),
  removeReservedRange: (id: string) => api.delete(`/av/reserved-ranges/${id}`),

  listFlows: (params?: AVFlowListQuery) =>
    api.get<AVFlowListResponse>("/av/flows", { params }).then((r) => r.data),
  // Keyed on the multicast group id, not the profile id — the caller is
  // looking at a group and declaring "this is a Dante flow".
  upsertFlow: (groupId: string, data: AVFlowUpsert) =>
    api.put<AVFlow>(`/av/flows/${groupId}`, data).then((r) => r.data),
  // Drops the AV identity; the multicast group itself survives.
  removeFlow: (groupId: string) => api.delete(`/av/flows/${groupId}`),

  allocationPreview: (data: AVAllocationPreviewRequest) =>
    api
      .post<AVAllocationPreviewResponse>("/av/allocation-preview", data)
      .then((r) => r.data),
  presets: () => api.get<AVPresetsResponse>("/av/presets").then((r) => r.data),
};

// ── BACnet/IP devices (#541) ─────────────────────────────────────────

export type BACnetSegmentation =
  | "both"
  | "transmit"
  | "receive"
  | "no-segmentation";

export type BACnetDeviceSource = "manual" | "whois" | "mirror" | "import";

export interface BACnetDevice {
  id: string;
  ip_address_id: string;
  subnet_id: string | null;
  /** Joined from the IPAM anchor so a list row needs no second request. */
  address: string | null;
  hostname: string | null;
  /** Unique across the whole BACnet internetwork — the identifier
   *  operators actually search by. */
  device_instance: number;
  vendor_id: number | null;
  vendor_name: string;
  /** ASHRAE vendor-id lookup, falling back to ``vendor_name``. */
  vendor_label: string | null;
  device_name: string;
  model_name: string;
  firmware_rev: string;
  location: string;
  max_apdu: number | null;
  segmentation_supported: string | null;
  network_number: number | null;
  udp_port: number;
  is_bbmd: boolean;
  is_foreign_device: boolean;
  bdt: unknown[];
  fdt: unknown[];
  seen_via: string;
  last_seen_at: string | null;
  notes: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

export interface BACnetDeviceCreate {
  ip_address_id: string;
  device_instance: number;
  vendor_id?: number | null;
  vendor_name?: string;
  device_name?: string;
  model_name?: string;
  firmware_rev?: string;
  location?: string;
  max_apdu?: number | null;
  segmentation_supported?: BACnetSegmentation | null;
  network_number?: number | null;
  udp_port?: number;
  is_bbmd?: boolean;
  is_foreign_device?: boolean;
  bdt?: unknown[];
  fdt?: unknown[];
  seen_via?: BACnetDeviceSource;
  last_seen_at?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

/** PATCH body. ``ip_address_id`` is re-parentable — a readdressed
 *  controller keeps its device instance and moves to the new IPAM row. */
export interface BACnetDeviceUpdate {
  ip_address_id?: string;
  device_instance?: number;
  vendor_id?: number | null;
  vendor_name?: string;
  device_name?: string;
  model_name?: string;
  firmware_rev?: string;
  location?: string;
  max_apdu?: number | null;
  segmentation_supported?: BACnetSegmentation | null;
  network_number?: number | null;
  udp_port?: number;
  is_bbmd?: boolean;
  is_foreign_device?: boolean;
  bdt?: unknown[];
  fdt?: unknown[];
  seen_via?: BACnetDeviceSource;
  last_seen_at?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface BACnetDeviceListResponse {
  items: BACnetDevice[];
  total: number;
  limit: number;
  offset: number;
}

export interface BACnetDeviceListQuery {
  limit?: number;
  offset?: number;
  subnet_id?: string;
  ip_address_id?: string;
  vendor_id?: number;
  is_bbmd?: boolean;
  seen_via?: BACnetDeviceSource;
  q?: string;
}

/** One Broadcast Distribution Device with the subnet it serves.
 *  ``subnet_id`` repeats when a subnet has two BBMDs — the
 *  misconfiguration this list exists to make visible. */
export interface BACnetBBMD {
  id: string;
  ip_address_id: string;
  address: string | null;
  device_instance: number;
  device_name: string;
  vendor_label: string | null;
  udp_port: number;
  subnet_id: string | null;
  subnet_network: string | null;
  subnet_name: string | null;
  bdt_entries: number;
  fdt_entries: number;
  last_seen_at: string | null;
}

export interface BACnetNextInstance {
  start: number;
  /** ``null`` when every number from ``start`` upwards is taken. */
  device_instance: number | null;
}

export const bacnetApi = {
  listDevices: (params?: BACnetDeviceListQuery) =>
    api
      .get<BACnetDeviceListResponse>("/bacnet/devices", { params })
      .then((r) => r.data),
  getDevice: (id: string) =>
    api.get<BACnetDevice>(`/bacnet/devices/${id}`).then((r) => r.data),
  createDevice: (data: BACnetDeviceCreate) =>
    api.post<BACnetDevice>("/bacnet/devices", data).then((r) => r.data),
  updateDevice: (id: string, data: BACnetDeviceUpdate) =>
    api.patch<BACnetDevice>(`/bacnet/devices/${id}`, data).then((r) => r.data),
  removeDevice: (id: string) => api.delete(`/bacnet/devices/${id}`),

  listBbmds: () => api.get<BACnetBBMD[]>("/bacnet/bbmds").then((r) => r.data),
  // 404 = "this IP isn't a BACnet device" — a normal answer, not a failure.
  byAddress: (ipAddressId: string) =>
    api
      .get<BACnetDevice>(`/bacnet/by-address/${ipAddressId}`)
      .then((r) => r.data),
  nextInstance: (start?: number) =>
    api
      .get<BACnetNextInstance>("/bacnet/next-instance", {
        params: start === undefined ? undefined : { start },
      })
      .then((r) => r.data),
};

// ── DICOM AE registry (#723) ─────────────────────────────────────────

export type DICOMRole = "scp" | "scu" | "both";

export type DICOMDeviceClass =
  | "modality"
  | "pacs"
  | "workstation"
  | "archive"
  | "router"
  | "worklist"
  | "printer"
  | "other";

export type DICOMAESource = "manual" | "import" | "echo";

export interface DICOMApplicationEntity {
  id: string;
  /** Unique institution-wide by specification (PS3.15 Annex H). Case is
   *  significant — peers match titles exactly. */
  ae_title: string;
  /** Null for a *reservation*: a title still burned into peer config
   *  whose host was decommissioned. Not an error state. */
  ip_address_id: string | null;
  subnet_id: string | null;
  address: string | null;
  hostname: string | null;
  port: number;
  tls_enabled: boolean;
  role: string;
  device_class: string;
  vendor: string;
  model_name: string;
  department: string;
  location: string;
  seen_via: string;
  last_seen_at: string | null;
  /** Network-configuration notes. Never patient data — the registry
   *  stores none. */
  notes: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  /** Still a known vendor default (DCM4CHEE, ANY-SCP, …) — advisory,
   *  and the most common cause of estate-wide title collisions. */
  is_vendor_default: boolean;
  is_reservation: boolean;
  created_at: string;
  modified_at: string;
}

export interface DICOMAECreate {
  ae_title: string;
  ip_address_id?: string | null;
  port?: number;
  tls_enabled?: boolean;
  role?: DICOMRole;
  device_class?: DICOMDeviceClass;
  vendor?: string;
  model_name?: string;
  department?: string;
  location?: string;
  seen_via?: DICOMAESource;
  last_seen_at?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

/** PATCH body. ``ip_address_id: null`` explicitly demotes the AE to a
 *  reservation — the normal lifecycle event when a host is retired. */
export interface DICOMAEUpdate {
  ae_title?: string;
  ip_address_id?: string | null;
  port?: number;
  tls_enabled?: boolean;
  role?: DICOMRole;
  device_class?: DICOMDeviceClass;
  vendor?: string;
  model_name?: string;
  department?: string;
  location?: string;
  seen_via?: DICOMAESource;
  last_seen_at?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface DICOMAEListResponse {
  items: DICOMApplicationEntity[];
  total: number;
  limit: number;
  offset: number;
}

export interface DICOMAEListQuery {
  limit?: number;
  offset?: number;
  subnet_id?: string;
  ip_address_id?: string;
  device_class?: DICOMDeviceClass;
  role?: DICOMRole;
  tls_enabled?: boolean;
  unbound?: boolean;
  q?: string;
}

/** A configured, directed AE→AE association. Documented by the operator
 *  or imported — never inferred from traffic, which would carry PHI. */
export interface DICOMPeer {
  id: string;
  source_ae_id: string;
  source_ae_title: string;
  target_ae_id: string;
  target_ae_title: string;
  services: string[];
  notes: string;
  created_at: string;
  modified_at: string;
}

export interface DICOMPeerCreate {
  source_ae_id: string;
  target_ae_id: string;
  services?: string[];
  notes?: string;
}

/** Blast radius of renumbering or retiring one AE. Split by direction:
 *  outbound edges stop sending, inbound edges stop being able to reach
 *  it — different remediation lists. */
export interface DICOMImpact {
  ae_id: string;
  ae_title: string;
  address: string | null;
  outbound: DICOMPeer[];
  inbound: DICOMPeer[];
  total_peers: number;
}

export interface DICOMAEImportColumnMap {
  ae_title: string;
  address?: string | null;
  port?: string | null;
  tls_enabled?: string | null;
  role?: string | null;
  device_class?: string | null;
  vendor?: string | null;
  model_name?: string | null;
  department?: string | null;
  location?: string | null;
  notes?: string | null;
}

export interface DICOMAEImportRequest {
  csv_text: string;
  column_map: DICOMAEImportColumnMap;
  delimiter?: "," | ";" | "\t" | "|";
  default_port?: number;
  default_department?: string;
  overwrite_existing?: boolean;
  space_id?: string | null;
}

export interface DICOMAEImportRow {
  line: number;
  ae_title: string;
  action: "create" | "update" | "skip" | "error";
  reason: string;
  address: string;
  ip_address_id: string | null;
  fields: Record<string, unknown>;
}

export interface DICOMAEImportPreview {
  rows: DICOMAEImportRow[];
  create_count: number;
  update_count: number;
  skip_count: number;
  error_count: number;
  max_rows: number;
}

export interface DICOMAEImportCommit {
  rows: DICOMAEImportRow[];
  created: number;
  updated: number;
  skipped: number;
  errors: number;
  ae_ids: string[];
}

export const dicomApi = {
  listAes: (params?: DICOMAEListQuery) =>
    api.get<DICOMAEListResponse>("/dicom/aes", { params }).then((r) => r.data),
  getAe: (id: string) =>
    api.get<DICOMApplicationEntity>(`/dicom/aes/${id}`).then((r) => r.data),
  createAe: (data: DICOMAECreate) =>
    api.post<DICOMApplicationEntity>("/dicom/aes", data).then((r) => r.data),
  updateAe: (id: string, data: DICOMAEUpdate) =>
    api
      .patch<DICOMApplicationEntity>(`/dicom/aes/${id}`, data)
      .then((r) => r.data),
  removeAe: (id: string) => api.delete(`/dicom/aes/${id}`),
  impact: (id: string) =>
    api.get<DICOMImpact>(`/dicom/aes/${id}/impact`).then((r) => r.data),

  listPeers: (aeId?: string) =>
    api
      .get<DICOMPeer[]>("/dicom/peers", {
        params: aeId ? { ae_id: aeId } : undefined,
      })
      .then((r) => r.data),
  createPeer: (data: DICOMPeerCreate) =>
    api.post<DICOMPeer>("/dicom/peers", data).then((r) => r.data),
  removePeer: (id: string) => api.delete(`/dicom/peers/${id}`),

  // 404 = "this IP isn't a DICOM node" — a normal answer, not a failure.
  byAddress: (ipAddressId: string) =>
    api
      .get<DICOMApplicationEntity>(`/dicom/by-address/${ipAddressId}`)
      .then((r) => r.data),

  importPreview: (data: DICOMAEImportRequest) =>
    api
      .post<DICOMAEImportPreview>("/dicom/aes/import/preview", data)
      .then((r) => r.data),
  importCommit: (data: DICOMAEImportRequest) =>
    api
      .post<DICOMAEImportCommit>("/dicom/aes/import/commit", data)
      .then((r) => r.data),
};

// ── E911 dispatchable location (#972) ────────────────────────────────
//
// Mirrors app/api/v1/e911/router.py. CIVIC_FIELDS below is the one list
// the forms iterate, so adding an RFC 5139 element is a single edit here
// rather than a field added to four places — the backend keeps the same
// property in app/models/e911.py::CIVIC_ELEMENTS, pinned by a test.

export type E911RuleKind =
  | "switch_port"
  | "wireless_ap"
  | "mac"
  | "ip"
  | "subnet"
  | "vlan"
  | "site_default";

export type E911ValidationState = "unvalidated" | "validated" | "rejected";
export type E911Confidence = "none" | "degraded" | "observed";

/** Rule kinds most-specific first. Mirrors ERL_RULE_PRECEDENCE; the
 *  server sends `precedence` on every binding so the UI never has to
 *  derive the ordering itself — this is for labelling only. */
export const E911_RULE_PRECEDENCE: E911RuleKind[] = [
  "switch_port",
  "wireless_ap",
  "mac",
  "ip",
  "subnet",
  "vlan",
  "site_default",
];

export const E911_RULE_LABELS: Record<E911RuleKind, string> = {
  switch_port: "Switch port",
  wireless_ap: "Wireless AP",
  mac: "MAC pin",
  ip: "IP pin",
  subnet: "Subnet",
  vlan: "VLAN",
  site_default: "Site default",
};

/** Which target field each rule kind requires. Mirrors
 *  ERL_RULE_TARGET_COLUMN — the server refuses any other combination
 *  with a 422 naming the field. */
export const E911_RULE_TARGET: Record<E911RuleKind, keyof ERLBindingCreate> = {
  switch_port: "network_interface_id",
  wireless_ap: "bssid",
  mac: "mac_address",
  ip: "ip_address_id",
  subnet: "subnet_id",
  vlan: "vlan_ref_id",
  site_default: "site_id",
};

export interface CivicAddress {
  country?: string | null;
  a1?: string | null;
  a2?: string | null;
  a3?: string | null;
  a4?: string | null;
  a5?: string | null;
  a6?: string | null;
  prd?: string | null;
  pod?: string | null;
  sts?: string | null;
  hno?: string | null;
  hns?: string | null;
  lmk?: string | null;
  loc?: string | null;
  nam?: string | null;
  pc?: string | null;
  bld?: string | null;
  unit?: string | null;
  flr?: string | null;
  room?: string | null;
  plc?: string | null;
  pcn?: string | null;
  pobox?: string | null;
  addcode?: string | null;
  seat?: string | null;
  rd?: string | null;
  rdsec?: string | null;
  rdbr?: string | null;
  rdsubbr?: string | null;
  prm?: string | null;
  pom?: string | null;
}

/** The civic elements, grouped the way an operator fills them in rather
 *  than the order RFC 5139 numbers them. "Interior" comes first because
 *  it is the half RAY BAUM'S §506 is actually about — a street address
 *  alone is not a dispatchable location. */
export const CIVIC_FIELD_GROUPS: {
  label: string;
  hint?: string;
  fields: { key: keyof CivicAddress; label: string; placeholder?: string }[];
}[] = [
  {
    label: "Inside the building",
    hint: "RAY BAUM'S §506 asks for room, floor, or similar. Without at least one of these an ERL is a street address, not a dispatchable location.",
    fields: [
      { key: "bld", label: "Building", placeholder: "A" },
      { key: "flr", label: "Floor", placeholder: "3" },
      { key: "unit", label: "Unit / suite", placeholder: "201" },
      { key: "room", label: "Room", placeholder: "312" },
      { key: "seat", label: "Seat / desk", placeholder: "14" },
      {
        key: "loc",
        label: "Additional detail",
        placeholder: "east wing, behind reception",
      },
    ],
  },
  {
    label: "Street",
    fields: [
      { key: "hno", label: "House number", placeholder: "1234" },
      { key: "hns", label: "Number suffix", placeholder: "A" },
      { key: "prd", label: "Leading direction", placeholder: "N" },
      { key: "rd", label: "Road name", placeholder: "Broadway" },
      { key: "sts", label: "Street type", placeholder: "Avenue" },
      { key: "pod", label: "Trailing suffix", placeholder: "SW" },
    ],
  },
  {
    label: "Locality",
    fields: [
      { key: "a3", label: "City", placeholder: "New York" },
      { key: "a4", label: "City division" },
      { key: "a5", label: "Neighbourhood" },
      { key: "a2", label: "County" },
      { key: "a1", label: "State / province", placeholder: "NY" },
      { key: "pc", label: "Postal code", placeholder: "10001" },
      {
        key: "country",
        label: "Country (ISO 3166-1 alpha-2)",
        placeholder: "US",
      },
    ],
  },
  {
    label: "Less common",
    hint: "Carried because a provider's validated address must round-trip without loss.",
    fields: [
      { key: "nam", label: "Occupant / business name" },
      { key: "lmk", label: "Landmark" },
      { key: "plc", label: "Place type" },
      { key: "pcn", label: "Postal community name" },
      { key: "pobox", label: "PO box" },
      { key: "addcode", label: "Additional code" },
      { key: "a6", label: "Street (legacy A6)" },
      { key: "rdsec", label: "Road section" },
      { key: "rdbr", label: "Road branch" },
      { key: "rdsubbr", label: "Road sub-branch" },
      { key: "prm", label: "Road pre-modifier" },
      { key: "pom", label: "Road post-modifier" },
    ],
  },
];

export interface GeoPoint {
  latitude?: number | null;
  longitude?: number | null;
  altitude?: number | null;
  altitude_unit?: "m" | "f" | null;
}

export interface ERL extends CivicAddress, GeoPoint {
  id: string;
  name: string;
  site_id: string | null;
  elins: string[];
  validation_state: E911ValidationState;
  validated_at: string | null;
  validation_source: string | null;
  validation_detail: string | null;
  is_dispatchable: boolean;
  is_active: boolean;
  notes: string;
  binding_count: number;
  created_at: string;
  modified_at: string;
}

export interface ERLCreate extends CivicAddress, GeoPoint {
  name: string;
  site_id?: string | null;
  elins?: string[];
  is_active?: boolean;
  notes?: string;
}

export type ERLUpdate = Partial<ERLCreate>;

export interface ERLListResponse {
  items: ERL[];
  total: number;
  limit: number;
  offset: number;
}

export interface ERLListQuery {
  limit?: number;
  offset?: number;
  site_id?: string;
  validation_state?: E911ValidationState;
  is_active?: boolean;
  dispatchable?: boolean;
  q?: string;
}

export interface E911ValidationVerdict {
  state: E911ValidationState;
  source?: string | null;
  detail?: string | null;
}

export interface ERLBinding {
  id: string;
  erl_id: string;
  erl_name: string;
  rule_kind: E911RuleKind;
  precedence: number;
  network_interface_id: string | null;
  bssid: string | null;
  subnet_id: string | null;
  vlan_ref_id: string | null;
  mac_address: string | null;
  ip_address_id: string | null;
  site_id: string | null;
  is_active: boolean;
  notes: string;
  created_at: string;
  modified_at: string;
}

export interface ERLBindingCreate {
  erl_id: string;
  rule_kind: E911RuleKind;
  network_interface_id?: string | null;
  bssid?: string | null;
  subnet_id?: string | null;
  vlan_ref_id?: string | null;
  mac_address?: string | null;
  ip_address_id?: string | null;
  site_id?: string | null;
  is_active?: boolean;
  notes?: string;
}

/** Only the mutable fields — a binding's kind and target are its
 *  identity, so repointing one is a delete plus a create. */
export interface ERLBindingUpdate {
  erl_id?: string;
  is_active?: boolean;
  notes?: string;
}

export interface ERLBindingListResponse {
  items: ERLBinding[];
  total: number;
  limit: number;
  offset: number;
}

export interface E911Evidence {
  kind: string;
  observed_at: string | null;
  age_seconds: number | null;
  window_seconds: number | null;
  stale: boolean;
  detail: string;
}

export interface E911Location {
  identity_kind: string;
  identity_value: string;
  found: boolean;
  confidence: E911Confidence;
  rule_matched: E911RuleKind | null;
  degraded_reason: string | null;
  observed_at: string | null;
  evidence_age_seconds: number | null;
  erl: ERL | null;
  evidence: E911Evidence[];
}

export const e911Api = {
  listErls: (params?: ERLListQuery) =>
    api.get<ERLListResponse>("/e911/erls", { params }).then((r) => r.data),
  getErl: (id: string) => api.get<ERL>(`/e911/erls/${id}`).then((r) => r.data),
  createErl: (data: ERLCreate) =>
    api.post<ERL>("/e911/erls", data).then((r) => r.data),
  updateErl: (id: string, data: ERLUpdate) =>
    api.patch<ERL>(`/e911/erls/${id}`, data).then((r) => r.data),
  removeErl: (id: string) => api.delete(`/e911/erls/${id}`),
  // Records a verdict the operator obtained from their E911 provider.
  // SpatiumDDI makes no outbound call and never decides this itself.
  recordValidation: (id: string, data: E911ValidationVerdict) =>
    api.post<ERL>(`/e911/erls/${id}/validation`, data).then((r) => r.data),

  listBindings: (params?: {
    limit?: number;
    offset?: number;
    erl_id?: string;
    rule_kind?: E911RuleKind;
    is_active?: boolean;
  }) =>
    api
      .get<ERLBindingListResponse>("/e911/bindings", { params })
      .then((r) => r.data),
  createBinding: (data: ERLBindingCreate) =>
    api.post<ERLBinding>("/e911/bindings", data).then((r) => r.data),
  updateBinding: (id: string, data: ERLBindingUpdate) =>
    api.patch<ERLBinding>(`/e911/bindings/${id}`, data).then((r) => r.data),
  removeBinding: (id: string) => api.delete(`/e911/bindings/${id}`),

  lookup: (params: {
    ip?: string;
    mac?: string;
    chassis_id?: string;
    port_id?: string;
  }) => api.get<E911Location>("/e911/location", { params }).then((r) => r.data),

  /** Exports (#972 Phase 3). Both return text the operator reads — the IOS
   *  snippet is explicitly NOT applied to any device by SpatiumDDI.
   *
   *  Downloads through the axios client rather than a bare link so the
   *  Authorization header is sent; these endpoints are permission-gated and a
   *  plain `<a href>` would 401. Filename comes from Content-Disposition,
   *  with the same UTC stamp fallback the IPAM exporter uses. */
  download: async (kind: "csv" | "ios", siteId?: string) => {
    const path =
      kind === "csv" ? "/e911/export.csv" : "/e911/export/ios-lldp-med.txt";
    const res = await api.get(path, {
      params: siteId ? { site_id: siteId } : undefined,
      responseType: "blob",
    });
    const disp = String(res.headers["content-disposition"] ?? "");
    const match = disp.match(/filename="?([^"]+)"?/);
    const ts = new Date()
      .toISOString()
      .slice(0, 19)
      .replace(/[-:]/g, "")
      .replace("T", "-");
    const fallback =
      kind === "csv" ? `e911-erls-${ts}.csv` : `e911-ios-lldp-med-${ts}.txt`;
    const blob = new Blob([res.data as BlobPart]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = match ? match[1] : fallback;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },
};

// ── OT / industrial devices (#542) ───────────────────────────────────

export type OTProtocol =
  | "profinet"
  | "ethernet_ip"
  | "modbus_tcp"
  | "opc_ua"
  | "s7comm"
  | "bacnet_ip"
  | "dnp3"
  | "iec61850"
  | "other";

export type OTRole =
  | "plc"
  | "io_device"
  | "hmi"
  | "drive"
  | "gateway"
  | "sensor"
  | "historian"
  | "ews"
  | "switch"
  | "other";

export type OTDeviceSource =
  | "manual"
  | "import"
  | "enip"
  | "dcp"
  | "modbus"
  | "opcua"
  | "profiling";

/** Purdue model level. Travels the wire as a canonical **string** because
 *  3.5 (the manufacturing / enterprise DMZ) is a real level and the column
 *  is ``Numeric(2, 1)`` — never parse it as a JS number for display. */
export type PurdueLevel = "0" | "1" | "2" | "3" | "3.5" | "4" | "5";

export interface OTDevice {
  id: string;
  ip_address_id: string;
  /** Joined from the IPAM anchor — an OT inventory is read by IP first. */
  address: string;
  subnet_id: string;
  ot_protocol: string;
  ot_role: string | null;
  profinet_device_name: string;
  ot_vendor: string;
  ot_product: string;
  ot_serial: string;
  firmware_rev: string;
  /** Canonical string ("3.5"), not a number — see ``PurdueLevel``. */
  purdue_level: string | null;
  cell_area: string;
  seen_via: string;
  last_seen_at: string | null;
  notes: string;
  tags: Record<string, unknown>;
  custom_fields: Record<string, unknown>;
  created_at: string;
  modified_at: string;
}

/** By-address view: the descriptor plus its zone verdict.
 *  ``purdue_mismatch`` is tri-state — ``null`` when either the device or
 *  its zone has no declared level, because an unknown is not a violation. */
export interface OTDeviceDescriptor extends OTDevice {
  zone_id: string | null;
  zone_name: string;
  zone_cell_area: string;
  zone_purdue_level: string | null;
  purdue_mismatch: boolean | null;
}

export interface OTDeviceCreate {
  ip_address_id: string;
  ot_protocol: OTProtocol;
  ot_role?: OTRole | null;
  profinet_device_name?: string;
  ot_vendor?: string;
  ot_product?: string;
  ot_serial?: string;
  firmware_rev?: string;
  purdue_level?: PurdueLevel | null;
  cell_area?: string;
  seen_via?: OTDeviceSource;
  last_seen_at?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

/** Partial update. ``ip_address_id`` is absent on purpose — the descriptor
 *  *is* the OT identity of one address; moving it is a delete + create. */
export interface OTDeviceUpdate {
  ot_protocol?: OTProtocol;
  ot_role?: OTRole | null;
  profinet_device_name?: string;
  ot_vendor?: string;
  ot_product?: string;
  ot_serial?: string;
  firmware_rev?: string;
  purdue_level?: PurdueLevel | null;
  cell_area?: string;
  seen_via?: OTDeviceSource;
  last_seen_at?: string | null;
  notes?: string;
  tags?: Record<string, unknown>;
  custom_fields?: Record<string, unknown>;
}

export interface OTDeviceListResponse {
  items: OTDevice[];
  total: number;
  limit: number;
  offset: number;
}

export interface OTDeviceListQuery {
  limit?: number;
  offset?: number;
  ot_protocol?: string;
  ot_role?: string;
  purdue_level?: string;
  cell_area?: string;
  subnet_id?: string;
  q?: string;
  tag?: string[];
}

export interface OTZone {
  id: string;
  subnet_id: string;
  subnet_network: string;
  /** Canonical string, always present — a zone with no level is not a zone. */
  purdue_level: string;
  cell_area: string;
  name: string;
  description: string;
  tags: Record<string, unknown>;
  device_count: number;
  created_at: string;
  modified_at: string;
}

export interface OTZoneCreate {
  subnet_id: string;
  purdue_level: PurdueLevel;
  cell_area?: string;
  name?: string;
  description?: string;
  tags?: Record<string, unknown>;
}

/** Partial update. ``subnet_id`` is absent — the zone is a property of its
 *  subnet, so re-pointing it would mislabel two subnets in one PUT. */
export interface OTZoneUpdate {
  purdue_level?: PurdueLevel;
  cell_area?: string;
  name?: string;
  description?: string;
  tags?: Record<string, unknown>;
}

/** Which CSV header feeds which descriptor field. ``address`` is the only
 *  required mapping; a mapped column missing from the file is a hard 422. */
export interface OTDeviceImportColumnMap {
  address: string;
  ot_protocol?: string;
  ot_role?: string;
  profinet_device_name?: string;
  ot_vendor?: string;
  ot_product?: string;
  ot_serial?: string;
  firmware_rev?: string;
  purdue_level?: string;
  cell_area?: string;
  notes?: string;
}

/** Same body for preview and commit — the server keeps no state between
 *  the two calls, so there is no preview token to expire. */
export interface OTDeviceImportRequest {
  csv_text: string;
  column_map: OTDeviceImportColumnMap;
  delimiter?: "," | ";" | "\t" | "|";
  default_ot_protocol?: OTProtocol | null;
  default_cell_area?: string;
  overwrite_existing?: boolean;
  space_id?: string | null;
}

export interface OTDeviceImportRow {
  line: number;
  address: string;
  action: "create" | "update" | "skip" | "error";
  reason: string;
  ip_address_id: string | null;
  fields: Record<string, unknown>;
}

export interface OTDeviceImportPreviewResponse {
  rows: OTDeviceImportRow[];
  create_count: number;
  update_count: number;
  skip_count: number;
  error_count: number;
  max_rows: number;
}

export interface OTDeviceImportCommitResponse {
  rows: OTDeviceImportRow[];
  created: number;
  updated: number;
  skipped: number;
  errors: number;
  device_ids: string[];
}

export const otApi = {
  listDevices: (params?: OTDeviceListQuery) =>
    api
      .get<OTDeviceListResponse>("/ot/devices", { params })
      .then((r) => r.data),
  getDevice: (id: string) =>
    api.get<OTDevice>(`/ot/devices/${id}`).then((r) => r.data),
  createDevice: (data: OTDeviceCreate) =>
    api.post<OTDevice>("/ot/devices", data).then((r) => r.data),
  updateDevice: (id: string, data: OTDeviceUpdate) =>
    api.put<OTDevice>(`/ot/devices/${id}`, data).then((r) => r.data),
  removeDevice: (id: string) => api.delete(`/ot/devices/${id}`),
  // 404 = "this IP has no OT descriptor" — a normal answer, not a failure.
  byAddress: (ipAddressId: string) =>
    api
      .get<OTDeviceDescriptor>(`/ot/by-address/${ipAddressId}`)
      .then((r) => r.data),

  listZones: (params?: { purdue_level?: string; cell_area?: string }) =>
    api.get<OTZone[]>("/ot/zones", { params }).then((r) => r.data),
  getZone: (id: string) =>
    api.get<OTZone>(`/ot/zones/${id}`).then((r) => r.data),
  zoneBySubnet: (subnetId: string) =>
    api.get<OTZone>(`/ot/zones/by-subnet/${subnetId}`).then((r) => r.data),
  createZone: (data: OTZoneCreate) =>
    api.post<OTZone>("/ot/zones", data).then((r) => r.data),
  updateZone: (id: string, data: OTZoneUpdate) =>
    api.put<OTZone>(`/ot/zones/${id}`, data).then((r) => r.data),
  removeZone: (id: string) => api.delete(`/ot/zones/${id}`),

  importPreview: (data: OTDeviceImportRequest) =>
    api
      .post<OTDeviceImportPreviewResponse>("/ot/devices/import/preview", data)
      .then((r) => r.data),
  importCommit: (data: OTDeviceImportRequest) =>
    api
      .post<OTDeviceImportCommitResponse>("/ot/devices/import/commit", data)
      .then((r) => r.data),
};
