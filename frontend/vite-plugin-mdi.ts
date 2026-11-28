import { readFileSync } from "fs";
import { createRequire } from "module";
import type { Plugin } from "vite";

// #5022 - the Material Design Icons set, served to the app as VIRTUAL modules
// so the ~7,000 path strings never sit in the main bundle and no generated
// file is committed:
//
//   virtual:mdi-meta        names + search aliases/tags (small; the picker)
//   virtual:mdi-paths/<k>   name -> SVG path for the icons whose name starts
//                           with <k> (a-z, or "_" for a digit); one lazy chunk
//                           per bucket, loaded only for icons actually shown.
//
// Icons marked deprecated in @mdi/svg's metadata are the brand logos; they are
// left out (the backend refuses them too: backend/app/data/mdi_icons.json).
const require_ = createRequire(import.meta.url);

const META_ID = "virtual:mdi-meta";
const PATHS_PREFIX = "virtual:mdi-paths/";

type Meta = {
  name: string;
  deprecated: boolean;
  aliases: string[];
  tags: string[];
};

function load() {
  const meta = JSON.parse(
    readFileSync(require_.resolve("@mdi/svg/meta.json"), "utf-8"),
  ) as Meta[];
  const src = readFileSync(require_.resolve("@mdi/js/mdi.js"), "utf-8");
  const paths = new Map<string, string>();
  for (const m of src.matchAll(/^export var mdi(\w+) = "([^"]*)";$/gm)) {
    paths.set(m[1], m[2]);
  }
  const pascal = (n: string) =>
    n
      .split("-")
      .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
      .join("");
  const icons = meta
    .filter((m) => !m.deprecated)
    .map((m) => ({ ...m, path: paths.get(pascal(m.name)) }))
    .filter((m): m is Meta & { path: string } => typeof m.path === "string");
  return icons;
}

export const bucketOf = (name: string) =>
  /^[a-z]/.test(name) ? name.charAt(0) : "_";

export function mdiVirtual(): Plugin {
  let icons: ReturnType<typeof load> | null = null;
  const get = () => (icons ??= load());
  return {
    name: "spatiumddi-mdi-virtual",
    resolveId(id) {
      if (id === META_ID || id.startsWith(PATHS_PREFIX)) return `\0${id}`;
      return null;
    },
    load(id) {
      if (id === `\0${META_ID}`) {
        // Compact rows: [name, aliases joined by space, tags joined by space].
        const rows = get().map((m) => [
          m.name,
          m.aliases.join(" "),
          m.tags.join(" ").toLowerCase(),
        ]);
        return `export default ${JSON.stringify(rows)};`;
      }
      if (id.startsWith(`\0${PATHS_PREFIX}`)) {
        const key = id.slice(PATHS_PREFIX.length + 1);
        const out: Record<string, string> = {};
        for (const m of get())
          if (bucketOf(m.name) === key) out[m.name] = m.path;
        return `export default ${JSON.stringify(out)};`;
      }
      return null;
    },
  };
}
