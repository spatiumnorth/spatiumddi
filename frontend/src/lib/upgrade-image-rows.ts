// Row model for Fleet → Upgrade images (#2410).
//
// One row per staged image plus one per GitHub release image that is not
// staged, so an air-gap upload with no matching release is a row too and a
// staged release is ONE row, not two. Two staged images of the same
// version + architecture (different SHA-256) are two rows: the server only
// links one of them to the release. Kept out
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
  // ``staged:<image id>`` for a staged image (ids are unique; version +
  // architecture is not), ``github:<version>\0<arch>`` for a release image
  // that is not staged. Selection, React keys and bulk actions use it.
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

const stagedKey = (id: string) => `staged:${id}`;
const githubKey = (version: string, arch: string) =>
  `github:${version}\u0000${arch}`;

// The server decides which staged image (if any) a GitHub row is: a
// labelled one of the same version + architecture, or an unlabelled one
// only when the release publishes a single architecture (#2410). An
// unlabelled image it did not link stays its own "unknown" row.
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
    key: stagedKey(s.id),
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
    // An image already linked to another row is never linked twice.
    const s =
      a.staged_image_id && !used.has(a.staged_image_id)
        ? (byId.get(a.staged_image_id) ?? null)
        : null;
    if (s) {
      used.add(s.id);
      rows.push(fromStaged(s, a));
      continue;
    }
    rows.push({
      key: githubKey(a.tag, a.architecture),
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

// The per-row Import button and the bulk Import set share this rule: a
// release image the server would refuse (no approved node runs its
// architecture) is not importable from either.
export function canImport(r: ImageRow): boolean {
  return !r.staged && r.available !== null && r.fleet !== "no_node";
}

export function bulkActions(selectedRows: ImageRow[]): {
  toDelete: ImageRow[];
  toImport: ImageRow[];
} {
  return {
    toDelete: selectedRows.filter((r) => r.staged !== null),
    toImport: selectedRows.filter(canImport),
  };
}

// Drop selected keys a filter now hides (or that are gone after a
// refetch), so a hidden row can never join a later bulk action. Returns
// the same Set when nothing changed, so a state setter can skip a render.
export function pruneSelection(
  selected: Set<string>,
  shown: ImageRow[],
): Set<string> {
  const visible = new Set(shown.map((r) => r.key));
  let changed = false;
  const next = new Set<string>();
  for (const k of selected) {
    if (visible.has(k)) next.add(k);
    else changed = true;
  }
  return changed ? next : selected;
}

const ALL_ARCHITECTURES = ["amd64", "arm64"];

// Architectures the air-gap upload offers. When the whole fleet has
// reported, only its architectures: the server refuses any other, but
// only after the browser has sent the whole image, so offering it would
// cost the operator the transfer. Otherwise every architecture. "Unknown"
// (empty) is always offered by the dialog itself.
export function uploadArchitectureOptions(
  fleet: FleetArchitectures | undefined,
): string[] {
  if (fleet?.restricted) return [...fleet.architectures];
  return [...ALL_ARCHITECTURES];
}
