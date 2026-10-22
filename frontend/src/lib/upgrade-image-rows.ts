// Row model for Fleet → Upgrade images (#2410).
//
// One row per (version, architecture), built from the union of the GitHub
// listing and the staged rows, so an air-gap upload with no matching
// release is a row too and a staged release is ONE row, not two. Kept out
// of the component so the merge / filter / sort rules can be tested
// without rendering a table.

import type {
  AvailableUpgradeImage,
  FleetArchitectures,
  UpgradeImage,
  UpgradeImageChannel,
  UpgradeImageFleetVerdict,
} from "@/lib/api";

export interface ImageRow {
  key: string;
  version: string;
  // null is UNKNOWN — rendered as such, never defaulted.
  architecture: string | null;
  channel: UpgradeImageChannel;
  publishedAt: string | null;
  htmlUrl: string | null;
  sizeBytes: number | null;
  staged: UpgradeImage | null;
  available: AvailableUpgradeImage | null;
  fleet: UpgradeImageFleetVerdict;
  fleetNodes: number | null;
  installedOn: string[];
  scheduledFor: string[];
  rollingRunId: string | null;
  // The CONTROL PLANE runs this tag (``is_installed`` on the GitHub row).
  isControlPlane: boolean;
}

export type SortKey =
  | "released"
  | "version"
  | "arch"
  | "channel"
  | "size"
  | "staged";

export interface SortState {
  key: SortKey;
  dir: "asc" | "desc";
}

export type StagedFilter = "any" | "staged" | "unstaged";

export interface ImageFilters {
  // "fleet": hide images no approved appliance can boot (when the whole
  // fleet has reported); "all": show everything.
  archScope: "fleet" | "all";
  showNightly: boolean;
  staged: StagedFilter;
  text: string;
}

export const DEFAULT_FILTERS: ImageFilters = {
  archScope: "fleet",
  showNightly: false,
  staged: "any",
  text: "",
};

export const DEFAULT_SORT: SortState = { key: "released", dir: "desc" };

const rowKey = (version: string, arch: string | null) =>
  `${version}\u0000${arch ?? ""}`;

// A staged row with no recorded architecture is the image for whichever
// architecture the release lists (re-importing it would dedupe by SHA).
export function buildRows(
  staged: UpgradeImage[],
  available: AvailableUpgradeImage[],
): ImageRow[] {
  const byId = new Map(staged.map((s) => [s.id, s]));
  const used = new Set<string>();
  const rows: ImageRow[] = [];

  const fromStaged = (
    s: UpgradeImage,
    a: AvailableUpgradeImage | null,
  ): ImageRow => ({
    key: rowKey(s.appliance_version, s.architecture ?? a?.architecture ?? null),
    version: s.appliance_version,
    architecture: s.architecture ?? a?.architecture ?? null,
    channel: s.channel ?? a?.channel ?? "stable",
    publishedAt: s.release?.published_at ?? a?.published_at ?? null,
    htmlUrl: s.release?.html_url ?? a?.html_url ?? null,
    sizeBytes: s.size_bytes,
    staged: s,
    available: a,
    fleet: s.fleet_architecture ?? "unknown",
    fleetNodes: s.fleet_nodes ?? null,
    installedOn: s.installed_on ?? [],
    scheduledFor: s.scheduled_for ?? [],
    rollingRunId: s.rolling_run_id ?? null,
    isControlPlane: a?.is_installed ?? false,
  });

  for (const a of available) {
    const s = a.staged_image_id ? (byId.get(a.staged_image_id) ?? null) : null;
    if (s) {
      used.add(s.id);
      rows.push(fromStaged(s, a));
      continue;
    }
    rows.push({
      key: rowKey(a.tag, a.architecture),
      version: a.tag,
      architecture: a.architecture,
      channel: a.channel ?? (a.is_prerelease ? "prerelease" : "stable"),
      publishedAt: a.published_at,
      htmlUrl: a.html_url,
      sizeBytes: a.size_bytes,
      staged: null,
      available: a,
      fleet: a.fleet_architecture ?? "unknown",
      fleetNodes: a.fleet_nodes ?? null,
      installedOn: [],
      scheduledFor: [],
      rollingRunId: null,
      isControlPlane: a.is_installed,
    });
  }
  for (const s of staged) {
    if (!used.has(s.id)) rows.push(fromStaged(s, null));
  }
  return rows;
}

export function isInUse(r: ImageRow): boolean {
  return r.scheduledFor.length > 0 || r.rollingRunId !== null;
}

export function inUseReason(r: ImageRow): string {
  const parts: string[] = [];
  if (r.scheduledFor.length)
    parts.push(`scheduled for ${r.scheduledFor.join(", ")}`);
  if (r.rollingRunId) parts.push(`named by rolling run ${r.rollingRunId}`);
  return parts.join("; ");
}

function passesNonChannel(r: ImageRow, f: ImageFilters): boolean {
  if (f.archScope === "fleet" && r.fleet === "no_node") return false;
  if (f.staged === "staged" && !r.staged) return false;
  if (f.staged === "unstaged" && r.staged) return false;
  const q = f.text.trim().toLowerCase();
  if (q && !r.version.toLowerCase().includes(q)) return false;
  return true;
}

export function applyFilters(rows: ImageRow[], f: ImageFilters): ImageRow[] {
  return rows.filter(
    (r) => passesNonChannel(r, f) && (f.showNightly || r.channel !== "nightly"),
  );
}

// Nightlies the other filters would show but the channel filter hides —
// the "12 hidden" on the chip, so the operator knows they exist.
export function hiddenNightlyCount(rows: ImageRow[], f: ImageFilters): number {
  if (f.showNightly) return 0;
  return rows.filter((r) => r.channel === "nightly" && passesNonChannel(r, f))
    .length;
}

const CHANNEL_ORDER: Record<UpgradeImageChannel, number> = {
  stable: 0,
  prerelease: 1,
  nightly: 2,
};

function sortValue(r: ImageRow, key: SortKey): string | number {
  switch (key) {
    case "released":
      // Staged-only rows have no release date; fall back to upload time
      // so they sort among their neighbours instead of sinking.
      return new Date(r.publishedAt ?? r.staged?.uploaded_at ?? 0).getTime();
    case "version":
      return r.version;
    case "arch":
      return r.architecture ?? "~";
    case "channel":
      return CHANNEL_ORDER[r.channel];
    case "size":
      return r.sizeBytes ?? -1;
    case "staged":
      return r.staged ? 1 : 0;
  }
}

function cmp(a: string | number, b: string | number): number {
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

// Sort, then keep each release's architecture rows adjacent: groups are
// ordered by their first row in the sorted list, and inside a group the
// rows are amd64, arm64, unknown. Grouping survives any sort key.
export function sortRows(rows: ImageRow[], s: SortState): ImageRow[] {
  const sign = s.dir === "asc" ? 1 : -1;
  const sorted = [...rows].sort((a, b) => {
    const c = sign * cmp(sortValue(a, s.key), sortValue(b, s.key));
    return c !== 0 ? c : a.version.localeCompare(b.version);
  });
  const groups = new Map<string, ImageRow[]>();
  for (const r of sorted) {
    const g = groups.get(r.version);
    if (g) g.push(r);
    else groups.set(r.version, [r]);
  }
  const out: ImageRow[] = [];
  for (const g of groups.values()) {
    g.sort((a, b) => cmp(a.architecture ?? "~", b.architecture ?? "~"));
    out.push(...g);
  }
  return out;
}

export function fleetNote(fleet: FleetArchitectures | undefined): string {
  if (!fleet) return "";
  if (fleet.restricted)
    return `This fleet runs ${fleet.architectures.join(", ")}.`;
  if (fleet.unknown_count > 0)
    return `${fleet.unknown_count} appliance${
      fleet.unknown_count === 1 ? " has" : "s have"
    } not reported an architecture yet, so every architecture is shown.`;
  return "No approved appliances yet, so every architecture is shown.";
}
