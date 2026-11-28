// The backend validates icon names against backend/app/data/mdi_icons.json,
// generated from the pinned @mdi/js by scripts/gen-mdi-icons.mjs (#5022). A
// stored name only means something against one version of the set, so a bump
// of the pin (Dependabot) that did not regenerate the list fails here.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(__dirname, "../../..");
const pkg = JSON.parse(
  readFileSync(resolve(root, "frontend/package.json"), "utf8"),
);
const catalog = JSON.parse(
  readFileSync(resolve(root, "backend/app/data/mdi_icons.json"), "utf8"),
);

describe("@mdi/js pin and the backend icon list", () => {
  it("pins @mdi/js exactly", () => {
    expect(pkg.dependencies["@mdi/js"]).toMatch(/^\d+\.\d+\.\d+$/);
  });
  it("pins @mdi/svg (generator metadata) to the same version", () => {
    expect(pkg.devDependencies["@mdi/svg"]).toBe(pkg.dependencies["@mdi/js"]);
  });
  it("has a backend list generated for that version", () => {
    expect(catalog.version).toBe(pkg.dependencies["@mdi/js"]);
  });
});
