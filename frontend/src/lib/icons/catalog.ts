import { CORE_ICON_PATHS } from "./core";

// #5022 - built-in icons are stored as ``mdi:<name>`` (the namespace leaves
// room for other sets); the API validates the name against the pinned set.

export const ICON_PREFIX = "mdi:";

export type IconSource =
  | "explicit"
  | "device_class"
  | "ip_role"
  | "linked_ip"
  | "none";

/** Where an automatic icon comes from, worded for the picker and tooltips. */
export const ICON_SOURCE_LABEL: Record<IconSource, string> = {
  explicit: "set on this row",
  device_class: "device class",
  ip_role: "IP role",
  linked_ip: "linked IP address",
  none: "nothing",
};

/** ``mdi:printer`` -> ``printer``; null for an empty or foreign value. */
export function iconName(value: string | null | undefined): string | null {
  if (!value || !value.startsWith(ICON_PREFIX)) return null;
  const name = value.slice(ICON_PREFIX.length);
  return name || null;
}

export function iconValue(name: string): string {
  return `${ICON_PREFIX}${name}`;
}

/** ``access-point`` -> ``Access point``. */
export function iconLabel(value: string | null | undefined): string {
  const name = iconName(value);
  if (!name) return "";
  const words = name.replace(/-/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function isCoreIcon(name: string): boolean {
  return name in CORE_ICON_PATHS;
}

export const CORE_ICON_NAMES: readonly string[] = Object.keys(CORE_ICON_PATHS);

// ── Lazy path data ──────────────────────────────────────────────────────────
// One chunk per first letter (digits share one), loaded when an icon outside
// the core set is first drawn. The loaders are spelled out so the bundler can
// see every chunk; a template-string import would not be split.
const BUCKETS: Record<
  string,
  () => Promise<{ default: Record<string, string> }>
> = {
  _: () => import("virtual:mdi-paths/_"),
  a: () => import("virtual:mdi-paths/a"),
  b: () => import("virtual:mdi-paths/b"),
  c: () => import("virtual:mdi-paths/c"),
  d: () => import("virtual:mdi-paths/d"),
  e: () => import("virtual:mdi-paths/e"),
  f: () => import("virtual:mdi-paths/f"),
  g: () => import("virtual:mdi-paths/g"),
  h: () => import("virtual:mdi-paths/h"),
  i: () => import("virtual:mdi-paths/i"),
  j: () => import("virtual:mdi-paths/j"),
  k: () => import("virtual:mdi-paths/k"),
  l: () => import("virtual:mdi-paths/l"),
  m: () => import("virtual:mdi-paths/m"),
  n: () => import("virtual:mdi-paths/n"),
  o: () => import("virtual:mdi-paths/o"),
  p: () => import("virtual:mdi-paths/p"),
  q: () => import("virtual:mdi-paths/q"),
  r: () => import("virtual:mdi-paths/r"),
  s: () => import("virtual:mdi-paths/s"),
  t: () => import("virtual:mdi-paths/t"),
  u: () => import("virtual:mdi-paths/u"),
  v: () => import("virtual:mdi-paths/v"),
  w: () => import("virtual:mdi-paths/w"),
  x: () => import("virtual:mdi-paths/x"),
  y: () => import("virtual:mdi-paths/y"),
  z: () => import("virtual:mdi-paths/z"),
};

const bucketKey = (name: string) =>
  /^[a-z]/.test(name) ? name.charAt(0) : "_";

const bucketCache = new Map<string, Promise<Record<string, string>>>();
const resolved = new Map<string, string>();
const listeners = new Set<() => void>();

/** The path for ``name`` if it is already in memory (core set or loaded). */
export function cachedIconPath(name: string): string | undefined {
  return CORE_ICON_PATHS[name] ?? resolved.get(name);
}

/** Load the bucket holding ``name``; resolves to its path or null. */
export function loadIconPath(name: string): Promise<string | null> {
  const known = cachedIconPath(name);
  if (known) return Promise.resolve(known);
  const key = bucketKey(name);
  let p = bucketCache.get(key);
  if (!p) {
    p = BUCKETS[key]()
      .then((m) => m.default)
      .catch((err) => {
        // A failed chunk fetch may be retried by the next draw.
        bucketCache.delete(key);
        throw err;
      });
    bucketCache.set(key, p);
  }
  return p.then((paths) => {
    for (const [n, d] of Object.entries(paths)) resolved.set(n, d);
    listeners.forEach((l) => l());
    return paths[name] ?? null;
  });
}

export function subscribeIconPaths(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

// ── Search metadata (picker only) ───────────────────────────────────────────
export type IconMetaRow = { name: string; haystack: string };

let metaPromise: Promise<IconMetaRow[]> | null = null;

export function loadIconMeta(): Promise<IconMetaRow[]> {
  metaPromise ??= import("virtual:mdi-meta")
    .then((m) =>
      m.default.map(([name, aliases, tags]) => ({
        name,
        haystack: `${name.replace(/-/g, " ")} ${aliases.replace(/-/g, " ")} ${tags}`,
      })),
    )
    .catch((err) => {
      metaPromise = null;
      throw err;
    });
  return metaPromise;
}

/** Names matching every word of ``query`` (name, alias or tag); names that
 *  START with the query rank first. Empty query -> []. */
export function searchIcons(rows: IconMetaRow[], query: string): string[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [];
  const q = words.join("-");
  const hits = rows.filter((r) => words.every((w) => r.haystack.includes(w)));
  hits.sort((a, b) => {
    const ra = a.name.startsWith(q) ? 0 : a.name.includes(words[0]) ? 1 : 2;
    const rb = b.name.startsWith(q) ? 0 : b.name.includes(words[0]) ? 1 : 2;
    return ra - rb || (a.name < b.name ? -1 : 1);
  });
  return hits.map((r) => r.name);
}

/** What the row would draw with no explicit icon, for the first choice. */
export type AutoIcon = { icon: string | null; source: IconSource };

export function automaticLabel(auto: AutoIcon | undefined): string {
  if (!auto || !auto.icon) return "Automatic (none)";
  return `Automatic (currently: ${iconLabel(auto.icon)}, from ${ICON_SOURCE_LABEL[auto.source]})`;
}
