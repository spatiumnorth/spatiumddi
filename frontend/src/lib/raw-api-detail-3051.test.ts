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
 * lib/api.ts that is not listed below, and for a listed file that gains a
 * read beyond its count. Add to the list only for a reader you have checked
 * handles an array and an object, and say why.
 *
 * What it matches: ``data.detail`` / ``data?.detail`` (also split across
 * lines), ``data["detail"]``, and ``const { detail } = …data``. What it
 * cannot see: a read through a renamed alias of the response body
 * (``const body = err.response?.data; body.detail``) or a nested
 * destructure (``const { data: { detail } } = err.response``). Neither
 * shape exists in src/ today; don't introduce one.
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

type Entry = {
  why: string;
  /** How many reads the file holds. A pending entry's is a maximum. */
  reads: number;
  /** Set while another open PR is converting the file. The count may drop
   *  to anything (that PR merging first must not fail this test); drop the
   *  entry, or set its real count, once both have merged. */
  pendingPr?: number;
};

const local = (reads = 1): Entry => ({ why: LOCAL_HELPER, reads });
const structured = (reads = 1, note = ""): Entry => ({
  why: STRUCTURED + note,
  reads,
});
const notError = (reads = 1): Entry => ({ why: NOT_ERROR, reads });
const pending = (pendingPr: number, reads: number): Entry => ({
  why: OTHER_PR,
  reads,
  pendingPr,
});

const ALLOWED: Record<string, Entry> = {
  "/src/lib/refusal.ts": {
    why: "only tests the detail for null; text is formatApiError",
    reads: 1,
  },
  "/src/lib/upgrade-cancel.ts": structured(),
  "/src/lib/schema-rollback.ts": structured(),
  "/src/lib/requestWords.ts": {
    why: "submitErrorWords reads only a 422 field-error array; anything else returns null and the caller uses formatApiError (#3253)",
    reads: 1,
  },
  "/src/pages/ChangePasswordPage.tsx": {
    why: "parsePasswordError handles all shapes (#1004)",
    reads: 1,
  },
  "/src/pages/LoginPage.tsx": {
    why: "string-checked before use; non-strings are ignored",
    reads: 3,
  },
  "/src/pages/SettingsPage.tsx": {
    why: "string-checked before use; falls back to fixed copy",
    reads: 1,
  },
  "/src/pages/ipam/IPAMPage.tsx": structured(1, " (409 collision warnings)"),
  "/src/pages/ipam/SubnetPlannerEditorPage.tsx": structured(),
  "/src/pages/admin/TrashPage.tsx": structured(),
  "/src/pages/admin/CutoverPage.tsx": structured(),
  "/src/pages/network/MulticastGroupsPage.tsx": structured(
    1,
    " (bulk commit conflicts)",
  ),
  "/src/pages/tools/NetworkToolsPage.tsx": {
    why: "apiError maps string and 422 array",
    reads: 1,
  },
  "/src/pages/network/_shared.tsx": local(),
  "/src/pages/dhcp/_shared.tsx": local(),
  "/src/pages/panos/PanosPage.tsx": local(),
  "/src/pages/unifi/UnifiPage.tsx": local(),
  "/src/pages/opnsense/OpnsensePage.tsx": local(),
  "/src/pages/tailscale/TailscalePage.tsx": local(),
  "/src/pages/docker/DockerPage.tsx": local(),
  "/src/pages/kubernetes/KubernetesPage.tsx": local(),
  "/src/pages/proxmox/ProxmoxPage.tsx": local(),
  "/src/pages/fortinet/FortinetPage.tsx": local(),
  "/src/pages/netbird/NetbirdPage.tsx": local(),
  "/src/pages/cloud/CloudPage.tsx": local(),
  "/src/pages/firewall_feeds/FirewallFeedsPage.tsx": local(),
  "/src/pages/meraki/MerakiPage.tsx": local(),
  "/src/pages/admin/PlatformInsightsPage.tsx": notError(),
  "/src/pages/admin/BackupTargetsSection.tsx": notError(),
  "/src/pages/dhcp/WindowsFailoverPanel.tsx": notError(),
  "/src/pages/admin/DNSImportPage.tsx": pending(3050, 12),
  "/src/pages/admin/DHCPImportPage.tsx": pending(3050, 1),
  "/src/pages/admin/ApiTokensPage.tsx": pending(3056, 2),
  "/src/pages/admin/RolesPage.tsx": pending(3056, 2),
  "/src/pages/admin/GroupsPage.tsx": pending(3056, 1),
  // #3056 adds a string-or-structured password-policy read here.
  "/src/pages/admin/UsersPage.tsx": pending(3056, 1),
};

const READS = [
  // `data.detail`, `data?.detail`, and either split across lines.
  /\bdata\s*\??\s*\.\s*detail\b/g,
  // `data["detail"]`, `data?.["detail"]`.
  /\bdata\s*\??\.?\s*\[\s*["'`]detail["'`]\s*\]/g,
  // `const { detail } = err.response.data`.
  /\{[^{}\n]*\bdetail\b[^{}\n]*\}\s*=\s*[^;\n]*\bdata\b/g,
];

function readLines(src: string): number[] {
  const lines: number[] = [];
  for (const re of READS) {
    for (const m of src.matchAll(re)) {
      lines.push(src.slice(0, m.index).split("\n").length);
    }
  }
  return lines.sort((a, b) => a - b);
}

describe("raw API detail (#3051)", () => {
  it("is read only through formatApiError, or from a listed safe reader", () => {
    const offenders: string[] = [];
    for (const [path, src] of Object.entries(sources)) {
      if (/\.test\.tsx?$/.test(path) || path === "/src/lib/api.ts") continue;
      const lines = readLines(src);
      const allowed = ALLOWED[path]?.reads ?? 0;
      if (lines.length > allowed) {
        offenders.push(
          `${path.slice(1)}: ${lines.length} reads (allowed ${allowed}) at ` +
            `lines ${lines.join(", ")}`,
        );
      }
    }
    expect(
      offenders,
      "use formatApiError(err, fallback) from @/lib/api; a 422's detail is an array",
    ).toEqual([]);
  });

  it("lists each file at the count it still reads", () => {
    const stale: string[] = [];
    for (const [path, entry] of Object.entries(ALLOWED)) {
      if (entry.pendingPr !== undefined) continue;
      const n = path in sources ? readLines(sources[path]).length : 0;
      if (n !== entry.reads)
        stale.push(`${path}: ${n} reads, listed ${entry.reads}`);
    }
    expect(stale, "lower the count, or remove the entry at 0").toEqual([]);
  });
});
