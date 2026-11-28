/* global console */
// Regenerates backend/app/data/mdi_icons.json (#5022): the list of icon names
// the API accepts as ``mdi:<name>``, taken from the pinned @mdi/js and filtered
// by @mdi/svg's metadata (deprecated icons are brand logos; trademarks are not
// covered by the icon licence and a brand logo is not a device kind).
//
//   cd frontend && node scripts/gen-mdi-icons.mjs
//
// backend/tests/test_mdi_icon_catalog_5022.py fails CI when the version in the
// output differs from the @mdi/js version in package-lock.json.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const pkg = JSON.parse(
  readFileSync(resolve(root, "node_modules/@mdi/js/package.json"), "utf8"),
);
const svg = JSON.parse(
  readFileSync(resolve(root, "node_modules/@mdi/svg/package.json"), "utf8"),
);
if (pkg.version !== svg.version) {
  throw new Error(
    `@mdi/js ${pkg.version} and @mdi/svg ${svg.version} must be pinned together`,
  );
}
const meta = JSON.parse(
  readFileSync(resolve(root, "node_modules/@mdi/svg/meta.json"), "utf8"),
);
const src = readFileSync(resolve(root, "node_modules/@mdi/js/mdi.js"), "utf8");
const exported = new Set(
  [...src.matchAll(/^export var (mdi\w+) =/gm)].map((m) => m[1]),
);

const pascal = (n) =>
  "mdi" +
  n
    .split("-")
    .map((p) => p.charAt(0).toUpperCase() + p.slice(1))
    .join("");

const icons = [];
for (const m of meta) {
  if (m.deprecated) continue;
  if (!exported.has(pascal(m.name))) {
    throw new Error(
      `@mdi/svg lists ${m.name} but @mdi/js exports no ${pascal(m.name)}`,
    );
  }
  const row = { name: m.name };
  if (m.tags.length) row.tags = [...m.tags].sort();
  if (m.aliases.length) row.aliases = [...m.aliases].sort();
  icons.push(row);
}
icons.sort((a, b) => (a.name < b.name ? -1 : 1));

const out = resolve(root, "../backend/app/data/mdi_icons.json");
writeFileSync(
  out,
  JSON.stringify({ package: "@mdi/js", version: pkg.version, icons }) + "\n",
);
console.log(
  `${icons.length} icons (${meta.length - icons.length} deprecated excluded) -> ${out}`,
);
