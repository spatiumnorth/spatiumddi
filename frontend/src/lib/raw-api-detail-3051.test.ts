/**
 * Nothing renders an API error's ``detail`` raw (#3051).
 *
 * FastAPI answers a validation failure with ``detail`` as an ARRAY of
 * objects. A page that stores ``err.response.data.detail`` and renders it as
 * a React child throws, and the error boundary replaces the whole page; one
 * that wraps it in ``String()`` / ``JSON.stringify()`` shows
 * "[object Object]" or raw JSON. ``formatApiError`` (lib/api.ts) handles
 * every shape, so error text goes through it.
 *
 * This fails with file:line for any read of ``.data.detail`` outside
 * lib/api.ts that is not listed below. Add to the list only for a reader
 * you have checked handles an array and an object, and say why.
 */

import { describe, expect, it } from "vitest";

const sources = import.meta.glob("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const LOCAL_HELPER =
  "local errMsg helper that maps a string detail and a 422 array itself";
const STRUCTURED =
  "reads a structured (object) detail on purpose and falls back safely";
const NOT_ERROR = "reads a success payload's own `detail` field, not an error";
const OTHER_PR =
  "being converted by another open PR; remove this entry once it merges";

const ALLOWED: Record<string, string> = {
  "/src/lib/refusal.ts":
    "only tests the detail for null; text is formatApiError",
  "/src/lib/upgrade-cancel.ts": STRUCTURED,
  "/src/lib/schema-rollback.ts": STRUCTURED,
  "/src/pages/ChangePasswordPage.tsx":
    "parsePasswordError handles all shapes (#1004)",
  "/src/pages/LoginPage.tsx":
    "string-checked before use; non-strings are ignored",
  "/src/pages/SettingsPage.tsx":
    "string-checked before use; falls back to fixed copy",
  "/src/pages/ipam/IPAMPage.tsx": STRUCTURED + " (409 collision warnings)",
  "/src/pages/ipam/SubnetPlannerEditorPage.tsx": STRUCTURED,
  "/src/pages/admin/TrashPage.tsx": STRUCTURED,
  "/src/pages/admin/CutoverPage.tsx": STRUCTURED,
  "/src/pages/network/MulticastGroupsPage.tsx":
    STRUCTURED + " (bulk commit conflicts)",
  "/src/pages/tools/NetworkToolsPage.tsx": "apiError maps string and 422 array",
  "/src/pages/network/_shared.tsx": LOCAL_HELPER,
  "/src/pages/dhcp/_shared.tsx": LOCAL_HELPER,
  "/src/pages/panos/PanosPage.tsx": LOCAL_HELPER,
  "/src/pages/unifi/UnifiPage.tsx": LOCAL_HELPER,
  "/src/pages/opnsense/OpnsensePage.tsx": LOCAL_HELPER,
  "/src/pages/tailscale/TailscalePage.tsx": LOCAL_HELPER,
  "/src/pages/docker/DockerPage.tsx": LOCAL_HELPER,
  "/src/pages/kubernetes/KubernetesPage.tsx": LOCAL_HELPER,
  "/src/pages/proxmox/ProxmoxPage.tsx": LOCAL_HELPER,
  "/src/pages/fortinet/FortinetPage.tsx": LOCAL_HELPER,
  "/src/pages/netbird/NetbirdPage.tsx": LOCAL_HELPER,
  "/src/pages/cloud/CloudPage.tsx": LOCAL_HELPER,
  "/src/pages/firewall_feeds/FirewallFeedsPage.tsx": LOCAL_HELPER,
  "/src/pages/meraki/MerakiPage.tsx": LOCAL_HELPER,
  "/src/pages/admin/PlatformInsightsPage.tsx": NOT_ERROR,
  "/src/pages/admin/BackupTargetsSection.tsx": NOT_ERROR,
  "/src/pages/dhcp/WindowsFailoverPanel.tsx": NOT_ERROR,
  "/src/pages/admin/DNSImportPage.tsx": OTHER_PR + " (#3050)",
  "/src/pages/admin/DHCPImportPage.tsx": OTHER_PR + " (#3050)",
  "/src/pages/admin/ApiTokensPage.tsx": OTHER_PR + " (#3056)",
  "/src/pages/admin/RolesPage.tsx": OTHER_PR + " (#3056)",
  "/src/pages/admin/GroupsPage.tsx": OTHER_PR + " (#3056)",
};

// `data.detail`, `data?.detail`, and either split across lines.
const READ = /\bdata\s*\??\s*\.\s*detail\b/g;

describe("raw API detail (#3051)", () => {
  it("is read only through formatApiError, or from a listed safe reader", () => {
    const offenders: string[] = [];
    for (const [path, src] of Object.entries(sources)) {
      if (/\.test\.tsx?$/.test(path) || path === "/src/lib/api.ts") continue;
      if (path in ALLOWED) continue;
      for (const m of src.matchAll(READ)) {
        const line = src.slice(0, m.index).split("\n").length;
        offenders.push(`${path.slice(1)}:${line}`);
      }
    }
    expect(
      offenders,
      "use formatApiError(err, fallback) from @/lib/api; a 422's detail is an array",
    ).toEqual([]);
  });

  it("lists only files that still read a detail", () => {
    const stale = Object.keys(ALLOWED).filter(
      (p) => !(p in sources) || !new RegExp(READ.source).test(sources[p]),
    );
    expect(stale, "remove from ALLOWED").toEqual([]);
  });
});
