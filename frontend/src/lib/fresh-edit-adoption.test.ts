// Guard for #4379 (the class of #3926 / #4236 / #4370): an Edit dialog that
// seeds its form from a row the page holds out of a cached list puts back
// whatever another client saved since, on an unrelated Save. It must read the
// row when it opens (FreshEdit / useFreshRow) and send only changedFields.
//
// A source scan, a heuristic: a page that keeps an "edit this row" state
// (`const [edit…, setEdit…] = useState<Row | null>`) must go through
// FreshEdit or useFreshRow, or be listed below with the reason it need not.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..");

// The setter of a row-holding edit state: `[edit, setEdit] = useState<Row | null>`.
const EDIT_STATE =
  /const \[\s*(?:edit|editing|edit[A-Z]\w*|editing[A-Z]\w*)\s*,\s*set(?:Edit|Editing)\w*\s*\]\s*=\s*useState<[^>]*\|\s*null\s*>/;
const FRESH = /\b(?:FreshEdit|useFreshRow)\b/;

// Files that hold such a state and need no FreshEdit of their own.
const ALLOWED: Record<string, string> = {
  "pages/network/NetworkPage.tsx":
    "mounts DeviceFormModal, which reads the device fresh itself (#4370)",
  "pages/network/AsnsPage.tsx":
    "mounts AsnFormModal, which reads the ASN fresh itself (#3114)",
  "pages/admin/AIPromptsPage.tsx": "not in #4379's list; follow-up",
  "pages/dhcp/DHCPPage.tsx":
    "scope / static / client-class dialogs: not in #4379's list; follow-up",
  "pages/firewall_feeds/FirewallFeedsPage.tsx":
    "not in #4379's list; follow-up",
  "pages/appliance/FirewallTab.tsx": "not in #4379's list; follow-up",
};

// Every Edit dialog #4379 moved onto FreshEdit: each must keep using it even
// if its state is renamed away from what EDIT_STATE recognises.
const REQUIRED = [
  "pages/network/CertificatesPage.tsx",
  "pages/network/CustomersPage.tsx",
  "pages/network/MulticastDomainsPage.tsx",
  "pages/network/MulticastGroupsPage.tsx",
  "pages/network/OverlayDetailPage.tsx",
  "pages/network/OverlaysPage.tsx",
  "pages/network/DICOMPage.tsx",
  "pages/network/CommunitiesTab.tsx",
  "pages/network/PeeringsTab.tsx",
  "pages/network/OTDevicesPage.tsx",
  "pages/network/ServicesPage.tsx",
  "pages/network/ProvidersPage.tsx",
  "pages/network/SitesPage.tsx",
  "pages/network/CircuitsPage.tsx",
  "pages/network/AVFlowsPage.tsx",
  "pages/network/BACnetDevicesPage.tsx",
  "pages/network/E911Page.tsx",
  "pages/network/looking-glass/SessionsTab.tsx",
  "pages/admin/DomainsPage.tsx",
  "pages/admin/ChangeRequestsPage.tsx",
  "pages/admin/AlertsPage.tsx",
  "pages/admin/ConformityPage.tsx",
  "pages/tools/WakeSchedulesPage.tsx",
  "pages/dhcp/WindowsFailoverPanel.tsx", // mounts the WindowsFailoverActions edit
  "pages/network/looking-glass/LookingGlassPage.tsx", // mounts SessionsTab's peer edit
];

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory()
      ? files(join(dir, e.name))
      : e.name.endsWith(".tsx") && !e.name.includes(".test.")
        ? [join(dir, e.name)]
        : [],
  );
}

/** Edit-state files that do not go through FreshEdit / useFreshRow. */
export function unfreshEditors(sources: Record<string, string>): string[] {
  return Object.entries(sources)
    .filter(([, s]) => EDIT_STATE.test(s) && !FRESH.test(s))
    .map(([f]) => f)
    .sort();
}

const sources: Record<string, string> = {};
for (const f of files(SRC)) sources[relative(SRC, f)] = readFileSync(f, "utf8");

describe("Edit dialogs read the row fresh (#4379)", () => {
  it("detects an edit state that never reads fresh", () => {
    const stale = `const [edit, setEdit] = useState<Row | null>(null);\n{edit && <XModal row={edit} />}`;
    expect(unfreshEditors({ "a.tsx": stale })).toEqual(["a.tsx"]);
    expect(
      unfreshEditors({ "a.tsx": stale + "\n<FreshEdit row={edit}>" }),
    ).toEqual([]);
    expect(
      unfreshEditors({
        "a.tsx": `const [editing, setEditing] = useState(false);`,
      }),
    ).toEqual([]);
  });

  it("every Edit dialog seeded from a list row uses FreshEdit / useFreshRow", () => {
    const missing = unfreshEditors(sources).filter((f) => !(f in ALLOWED));
    expect(
      missing,
      `${missing.join(", ")}: an Edit dialog seeded from a list row must be wrapped in FreshEdit (components/FreshEdit.tsx) and send changedFields; or add the file to ALLOWED with the reason`,
    ).toEqual([]);
  });

  it("the allowlist holds no file that is fine now", () => {
    const stale = unfreshEditors(sources);
    const fine = Object.keys(ALLOWED).filter((f) => !stale.includes(f));
    expect(fine, "remove from ALLOWED").toEqual([]);
  });

  it("the dialogs #4379 moved still use it", () => {
    const gone = REQUIRED.filter(
      (f) => !(f in sources) || !FRESH.test(sources[f]),
    );
    expect(gone).toEqual([]);
  });
});
