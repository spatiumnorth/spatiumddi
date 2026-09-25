// Release version strings, and whether a build includes a release (#1183).
//
// Mirrors backend/app/core/versions.py; keep the two in step.
//
// SpatiumDDI releases are CalVer (YYYY.MM.DD-N) until 1.0.0 and SemVer from
// then on (#1182). Every SemVer release is newer than every CalVer one.
// Builds that are not releases report other strings: a nightly reports
// 0.0.0-nightly-YYYYMMDD+<sha> (built from main on that date), and a local
// or dev build reports "dev", "dev-<sha>-<rand>", "latest" or a 0.x
// placeholder. Never compare version strings as strings: "1.0.0" >
// "2026.09.04-1" is false, and so is "1.0.10" > "1.0.9".

const CALVER_RE = /^(\d{4})\.(\d{2})\.(\d{2})(?:-(\d+))?$/;
const SEMVER_RE =
  /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$/;
const NIGHTLY_RE =
  /^0\.0\.0-nightly-(\d{4})(\d{2})(\d{2})(?:\+[0-9A-Za-z.-]+)?$/;

type CalVer = { scheme: "calver"; parts: number[]; taggedOn: number };
type SemVer = { scheme: "semver"; parts: number[]; pre: string[] | null };
export type Release = CalVer | SemVer;

/** YYYYMMDD as a number, or null if it is not a real date. */
function dayNumber(year: string, month: string, day: string): number | null {
  const y = Number(year);
  const m = Number(month);
  const d = Number(day);
  const date = new Date(Date.UTC(y, m - 1, d));
  if (
    date.getUTCFullYear() !== y ||
    date.getUTCMonth() !== m - 1 ||
    date.getUTCDate() !== d
  ) {
    return null;
  }
  return y * 10000 + m * 100 + d;
}

/**
 * The release `version` names, or null if it names none: the empty string,
 * dev and nightly builds, placeholders like 0.1.0, and anything unparseable.
 * A SemVer release starts at 1.0.0, so the 0.x placeholders never parse.
 */
export function parseRelease(
  version: string | null | undefined,
): Release | null {
  const value = (version ?? "").trim();
  let m = CALVER_RE.exec(value);
  if (m) {
    const taggedOn = dayNumber(m[1], m[2], m[3]);
    if (taggedOn === null) return null;
    return {
      scheme: "calver",
      parts: [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4] ?? 0)],
      taggedOn,
    };
  }
  m = SEMVER_RE.exec(value);
  if (m) {
    if (Number(m[1]) < 1) return null;
    return {
      scheme: "semver",
      parts: [Number(m[1]), Number(m[2]), Number(m[3])],
      pre: m[4] ? m[4].split(".") : null,
    };
  }
  return null;
}

function compareNumbers(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0);
    if (diff !== 0) return Math.sign(diff);
  }
  return 0;
}

/** SemVer §11: a pre-release sorts before its release; numeric identifiers
 * sort numerically and before alphanumeric ones. */
function comparePre(a: string[] | null, b: string[] | null): number {
  if (a === null || b === null) return a === b ? 0 : a === null ? 1 : -1;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const an = /^\d+$/.test(a[i]);
    const bn = /^\d+$/.test(b[i]);
    if (an && bn) {
      const diff = Number(a[i]) - Number(b[i]);
      if (diff !== 0) return Math.sign(diff);
    } else if (an !== bn) {
      return an ? -1 : 1;
    } else if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return Math.sign(a.length - b.length);
}

/** Negative, zero or positive as `a` is older than, equal to or newer than `b`. */
export function compareReleases(a: Release, b: Release): number {
  if (a.scheme !== b.scheme) return a.scheme === "calver" ? -1 : 1;
  const byParts = compareNumbers(a.parts, b.parts);
  if (byParts !== 0 || a.scheme === "calver" || b.scheme === "calver")
    return byParts;
  return comparePre(a.pre, b.pre);
}

/** The day a nightly was cut from main, as YYYYMMDD, or null if `version`
 * is not a nightly. */
export function nightlyBuildDay(
  version: string | null | undefined,
): number | null {
  const m = NIGHTLY_RE.exec((version ?? "").trim());
  return m ? dayNumber(m[1], m[2], m[3]) : null;
}

/**
 * Whether a build reporting `version` has everything in `release`: true or
 * false when that is known, null when it is not. Null covers a dev build, an
 * unparseable string, a nightly cut on the release's own date (it may have
 * been built before the tag), and a nightly measured against a SemVer
 * release (a SemVer tag carries no date). A nightly is built from main, so it
 * has every CalVer release tagged before its date.
 */
export function includesRelease(
  version: string | null | undefined,
  release: string,
): boolean | null {
  const target = parseRelease(release);
  if (target === null) throw new Error(`not a release version: ${release}`);
  const built = parseRelease(version);
  if (built !== null) return compareReleases(built, target) >= 0;
  const nightly = nightlyBuildDay(version);
  if (
    nightly === null ||
    target.scheme !== "calver" ||
    nightly === target.taggedOn
  ) {
    return null;
  }
  return nightly > target.taggedOn;
}

/**
 * The first of `versions` whose answer to includesRelease is known, with that
 * answer; null if none is known. Callers list the most authoritative source
 * first, as the backend's nonce gate does (installed appliance version, then
 * the supervisor's).
 */
export function releaseVerdict(
  versions: (string | null | undefined)[],
  release: string,
): { version: string; includes: boolean } | null {
  for (const version of versions) {
    const includes = includesRelease(version, release);
    if (includes !== null) return { version: version as string, includes };
  }
  return null;
}
