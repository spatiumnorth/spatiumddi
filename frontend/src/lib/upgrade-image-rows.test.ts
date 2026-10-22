import { describe, expect, it } from "vitest";

import type { AvailableUpgradeImage, UpgradeImage } from "@/lib/api";
import {
  DEFAULT_FILTERS,
  applyFilters,
  buildRows,
  hiddenNightlyCount,
  inUseReason,
  isInUse,
  sortRows,
} from "@/lib/upgrade-image-rows";

const avail = (
  tag: string,
  arch: string,
  over: Partial<AvailableUpgradeImage> = {},
): AvailableUpgradeImage => ({
  tag,
  name: tag,
  published_at: "2026-10-01T00:00:00Z",
  body: "",
  html_url: `https://gh/${tag}`,
  is_prerelease: false,
  is_installed: false,
  image_asset_url: "u",
  checksum_asset_url: "c",
  size_bytes: 100,
  architecture: arch,
  ...over,
});

const staged = (
  id: string,
  version: string,
  arch: string | null,
  over: Partial<UpgradeImage> = {},
): UpgradeImage => ({
  id,
  filename: `${version}.raw.xz`,
  size_bytes: 50,
  sha256: "a".repeat(64),
  appliance_version: version,
  architecture: arch,
  uploaded_by_user_id: null,
  uploaded_at: "2026-09-01T00:00:00Z",
  notes: null,
  ...over,
});

describe("buildRows", () => {
  it("merges a staged release into one row, not two", () => {
    const rows = buildRows(
      [staged("s1", "2026.10.01-1", "amd64")],
      [
        avail("2026.10.01-1", "amd64", { staged_image_id: "s1" }),
        avail("2026.10.01-1", "arm64"),
      ],
    );
    expect(rows).toHaveLength(2);
    expect(rows.find((r) => r.architecture === "amd64")?.staged?.id).toBe("s1");
    expect(rows.find((r) => r.architecture === "arm64")?.staged).toBeNull();
  });

  it("keeps an air-gap upload with no release as its own row, arch unknown", () => {
    const rows = buildRows([staged("s2", "custom-1", null)], []);
    expect(rows).toHaveLength(1);
    expect(rows[0].architecture).toBeNull();
    expect(rows[0].publishedAt).toBeNull();
  });
});

describe("filters", () => {
  const rows = buildRows(
    [],
    [
      avail("2026.10.01-1", "amd64"),
      avail("nightly-2026.10.20", "amd64", { channel: "nightly" }),
      avail("nightly-2026.10.20", "arm64", {
        channel: "nightly",
        fleet_architecture: "no_node",
      }),
      avail("2026.09.01-1", "arm64", { fleet_architecture: "no_node" }),
    ],
  );

  it("hides nightlies and other architectures by default, and counts the nightlies", () => {
    const shown = applyFilters(rows, DEFAULT_FILTERS);
    expect(shown.map((r) => r.version)).toEqual(["2026.10.01-1"]);
    // the arm64 nightly is hidden by the arch filter, so not counted
    expect(hiddenNightlyCount(rows, DEFAULT_FILTERS)).toBe(1);
  });

  it("shows everything with all architectures and nightlies on", () => {
    const f = {
      ...DEFAULT_FILTERS,
      archScope: "all" as const,
      showNightly: true,
    };
    expect(applyFilters(rows, f)).toHaveLength(4);
    expect(hiddenNightlyCount(rows, f)).toBe(0);
  });

  it("filters on staged state and version text", () => {
    const f = { ...DEFAULT_FILTERS, staged: "staged" as const };
    expect(applyFilters(rows, f)).toHaveLength(0);
    const t = { ...DEFAULT_FILTERS, text: "10.01" };
    expect(applyFilters(rows, t)).toHaveLength(1);
  });
});

describe("sortRows", () => {
  const rows = buildRows(
    [],
    [
      avail("2026.09.01-1", "amd64", { published_at: "2026-09-01T00:00:00Z" }),
      avail("2026.10.01-1", "arm64", { published_at: "2026-10-01T00:00:00Z" }),
      avail("2026.10.01-1", "amd64", { published_at: "2026-10-01T00:00:00Z" }),
    ],
  );

  it("sorts newest release first with its architectures adjacent (amd64 then arm64)", () => {
    const out = sortRows(rows, { key: "released", dir: "desc" });
    expect(out.map((r) => `${r.version}/${r.architecture}`)).toEqual([
      "2026.10.01-1/amd64",
      "2026.10.01-1/arm64",
      "2026.09.01-1/amd64",
    ]);
  });

  it("keeps the grouping when sorted by another column", () => {
    const out = sortRows(rows, { key: "arch", dir: "asc" });
    const versions = out.map((r) => r.version);
    expect(versions).toEqual(["2026.09.01-1", "2026.10.01-1", "2026.10.01-1"]);
  });
});

describe("in use", () => {
  it("is scheduled or named by a run, not merely installed", () => {
    const [installed] = buildRows(
      [staged("s", "v", "amd64", { installed_on: ["a"] })],
      [],
    );
    expect(isInUse(installed)).toBe(false);
    const [sched] = buildRows(
      [staged("s", "v", "amd64", { scheduled_for: ["box1"] })],
      [],
    );
    expect(isInUse(sched)).toBe(true);
    expect(inUseReason(sched)).toContain("box1");
  });
});
