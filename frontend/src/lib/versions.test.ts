import { describe, expect, it } from "vitest";

import {
  compareReleases,
  includesRelease,
  nightlyBuildDay,
  parseRelease,
  releaseVerdict,
} from "@/lib/versions";

// The same cases as backend/tests/test_versions.py: the two implementations
// must agree, or the Fleet panel and the backend's nonce gate disagree about
// the same appliance.

describe("release order", () => {
  it.each([
    ["2026.06.12-1", "2026.06.12-2"],
    ["2026.06.12", "2026.06.12-1"],
    ["2026.06.12-9", "2026.06.13-1"],
    ["2026.09.04-1", "2026.10.01-1"],
    ["2026.12.31-1", "2027.01.01-1"],
    // Every SemVer release is newer than every CalVer one; as strings,
    // "1.0.0" < "2026.09.04-1".
    ["2026.09.04-1", "1.0.0"],
    ["2099.12.31-9", "1.0.0-rc.1"],
    // Numeric, not lexical: as strings, "1.0.10" < "1.0.9".
    ["1.0.9", "1.0.10"],
    ["1.9.0", "1.10.0"],
    ["1.0.0", "2.0.0"],
    // SemVer §11 pre-release precedence.
    ["1.0.0-alpha", "1.0.0-alpha.1"],
    ["1.0.0-alpha.1", "1.0.0-alpha.beta"],
    ["1.0.0-beta.2", "1.0.0-beta.11"],
    ["1.0.0-rc.1", "1.0.0"],
  ])("%s < %s", (older, newer) => {
    const a = parseRelease(older);
    const b = parseRelease(newer);
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(compareReleases(a!, b!)).toBeLessThan(0);
    expect(compareReleases(b!, a!)).toBeGreaterThan(0);
  });

  it("ignores build metadata", () => {
    expect(
      compareReleases(parseRelease("1.2.3+abc")!, parseRelease("1.2.3")!),
    ).toBe(0);
  });
});

describe("parseRelease", () => {
  it.each([
    [null],
    [undefined],
    [""],
    ["   "],
    ["dev"],
    ["dev-abc1234-9f2e"],
    ["latest"],
    // The frozen supervisor string (#1183) is not CalVer.
    ["2026.05.14.1"],
    // SemVer-shaped placeholders: a release starts at 1.0.0.
    ["0.1.0"],
    ["0.1.0-dev"],
    ["0.0.0-dev"],
    ["0.0.0-nightly-20260925+abc1234"],
    ["2026.13.01-1"],
    ["2026.02.30-1"],
    ["v1.0.0"],
    ["1.0"],
  ])("%s is not a release", (value) => {
    expect(parseRelease(value)).toBeNull();
  });
});

describe("nightlyBuildDay", () => {
  it("reads the build date of a nightly and nothing else", () => {
    expect(nightlyBuildDay("0.0.0-nightly-20260925+abc1234")).toBe(20260925);
    expect(nightlyBuildDay("0.0.0-nightly-20260925")).toBe(20260925);
    expect(nightlyBuildDay("2026.09.25-1")).toBeNull();
    expect(nightlyBuildDay("0.0.0-nightly-20260231")).toBeNull();
  });
});

describe("includesRelease", () => {
  it.each([
    ["2026.06.12-2", true],
    ["2026.06.13-1", true],
    ["1.0.0", true],
    ["2026.06.12-1", false],
    ["2026.06.11-1", false],
    // A nightly has every release tagged before its date; on the tag's own
    // date it may or may not.
    ["0.0.0-nightly-20260613+abc1234", true],
    ["0.0.0-nightly-20260611+abc1234", false],
    ["0.0.0-nightly-20260612+abc1234", null],
    ["dev-abc1234-9f2e", null],
    ["2026.05.14.1", null],
    [null, null],
  ])("%s → %s", (version, expected) => {
    expect(includesRelease(version, "2026.06.12-2")).toBe(expected);
  });

  it("cannot place a nightly against a SemVer release", () => {
    expect(includesRelease("0.0.0-nightly-20991231+abc", "1.0.0")).toBeNull();
    expect(includesRelease("2026.09.04-1", "1.0.0")).toBe(false);
    expect(includesRelease("1.0.1", "1.0.0")).toBe(true);
  });

  it("refuses a release that is not a release", () => {
    expect(() => includesRelease("2026.06.12-2", "dev")).toThrow();
  });
});

describe("releaseVerdict", () => {
  const FROZEN = "2026.05.14.1"; // what every supervisor reported until #1183

  it("takes the first version it can place", () => {
    // The Fleet panel lists the installed appliance version first.
    expect(releaseVerdict(["2026.09.04-1", FROZEN], "2026.06.12-2")).toEqual({
      version: "2026.09.04-1",
      includes: true,
    });
    expect(
      releaseVerdict(["2026.06.11-1", "2026.09.04-1"], "2026.06.12-2"),
    ).toEqual({
      version: "2026.06.11-1",
      includes: false,
    });
    expect(releaseVerdict(["dev-abc", "2026.06.11-1"], "2026.06.12-2")).toEqual(
      {
        version: "2026.06.11-1",
        includes: false,
      },
    );
  });

  it("is null when nothing can be placed", () => {
    // #1183: the frozen string alone used to mark every appliance as too old.
    expect(releaseVerdict([null, FROZEN], "2026.06.12-2")).toBeNull();
    expect(releaseVerdict([undefined, "dev"], "2026.06.12-2")).toBeNull();
    expect(releaseVerdict([], "2026.06.12-2")).toBeNull();
  });
});
