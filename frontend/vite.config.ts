import path from "path";
import { fileURLToPath } from "url";
import { defineConfig } from "vitest/config";
import type { Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { copyFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import license, { type Dependency } from "rollup-plugin-license";

const pkg = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf-8"),
) as {
  version: string;
};

// Prefer the release-workflow stamp (VITE_APP_VERSION build arg) over
// the value baked into package.json — package.json is a convenience
// default for local `npm run dev`, not the release source of truth.
const appVersion = process.env.VITE_APP_VERSION || pkg.version;

// #2895 — the legal files the About page shows: NOTICE, LICENSE and the npm
// notice list. They are written to ``dist-legal/``, deliberately OUTSIDE
// ``dist/``: everything in ``dist/`` is the public web root, and these are for
// signed-in users only (someone probing the server must not learn which
// libraries it runs). The frontend image copies ``dist-legal/`` to
// /usr/share/spatiumddi/legal, which nginx serves at ``/legal/`` only after
// asking the api whether the caller has a session. Nothing here is imported by
// the app, so none of it lands in a JS chunk either.
//
// NOTICE and LICENSE live once, at the repo root; the build copies them rather
// than keeping a second copy in frontend/ that would drift. The Docker build
// context is the repo root for exactly this reason (see frontend/Dockerfile).
// A plain ``npm run dev`` serves nothing for them and the page says so.
// Published with a ``.txt`` suffix so nginx types them text/plain.
//
// A build that cannot find them FAILS rather than shipping an About page
// whose NOTICE says "not available in this build": that is the page the
// Apache-2.0 §4(d) obligation rests on, and a missing file must not look
// like a successful build.
const LEGAL_FILES = ["NOTICE", "LICENSE"];
const LEGAL_OUT_DIR = fileURLToPath(new URL("./dist-legal", import.meta.url));

function legalFiles(): Plugin {
  const roots = [
    fileURLToPath(new URL("..", import.meta.url)),
    fileURLToPath(new URL("./legal", import.meta.url)),
  ];
  return {
    name: "spatiumddi-legal-files",
    apply: "build",
    closeBundle() {
      const out = LEGAL_OUT_DIR;
      mkdirSync(out, { recursive: true });
      for (const name of LEGAL_FILES) {
        const src = roots
          .map((r) => `${r}/${name}`)
          .find((candidate) => existsSync(candidate));
        if (!src) {
          throw new Error(
            `#2895: ${name} not found in ${roots.join(" or ")}; the About ` +
              "page needs it. Build the image from the repo root " +
              "(docker build -f frontend/Dockerfile .).",
          );
        }
        copyFileSync(src, `${out}/${name}.txt`);
      }
    },
  };
}

// Some packages declare a licence in package.json but publish no LICENSE
// file (qrcode-generator, react-remove-scroll-bar and victory-vendor at the
// time of writing), so the plugin has no text to copy and the list would name
// the licence without carrying the permission notice MIT requires to travel
// with the copy. For those, the standard text of the declared licence is
// appended, marked as such, after the package's own author line.
const STANDARD_TEXT: Record<string, string> = {
  MIT: `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`,
  ISC: `Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.`,
};

function thirdPartyText(dependencies: Dependency[]): string {
  return dependencies
    .map((dep) => {
      const own = dep.text();
      if (dep.licenseText) return own;
      const ids = (dep.license ?? "")
        .replace(/[()]/g, " ")
        .split(/\s+/)
        .filter((id) => id in STANDARD_TEXT);
      if (ids.length === 0) return own;
      const appended = ids
        .map(
          (id) =>
            `Standard ${id} licence text (the package publishes no licence ` +
            `file):\n===\n\n${STANDARD_TEXT[id]}`,
        )
        .join("\n\n");
      return `${own}\n${appended}`;
    })
    .join("\n\n---\n\n");
}

export default defineConfig({
  plugins: [
    react(),
    // #2895 — Vite strips licence comments from the minified bundle, so
    // MIT / BSD / ISC notices stop travelling with the copies we serve.
    // This lists exactly the packages that ended up in the bundle (not
    // devDependencies) with their licence text, beside the app.
    license({
      thirdParty: {
        includePrivate: false,
        // A bundled package that declares no licence at all is a decision
        // for a human, not a line to skip.
        // (``test`` must reject them: the plugin only consults
        // ``failOnUnlicensed`` for a dependency its test has refused.)
        allow: {
          test: (dep) =>
            Boolean(dep.license?.trim()) &&
            dep.license?.trim().toUpperCase() !== "UNLICENSED",
          failOnUnlicensed: true,
        },
        output: {
          file: `${LEGAL_OUT_DIR}/third-party-npm.txt`,
          template: thirdPartyText,
        },
      },
    }),
    legalFiles(),
  ],
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
  },
  // #996 — component tests need a DOM. The pre-existing suites
  // (``lib/enrolment``, ``lib/qr``) are pure logic and ran happily under
  // vitest's default ``node`` environment; ``HeaderMenu`` is a keyboard-
  // driven menu whose failure modes (an arrow key that does not wrap, a
  // disabled item that still takes focus, a trigger that renders for an
  // empty menu) are invisible to review and to ``tsc`` alike — the same
  // argument #906 used for decoding the QR it renders.
  //
  // ``environment`` is per-file via a ``@vitest-environment`` docblock
  // rather than global: jsdom costs ~1s of setup per file and the two
  // existing pure-logic suites have no use for it.
  test: {
    globals: true,
    // Node 26 ships its own global `localStorage` (Web Storage), which
    // is undefined unless --localstorage-file is given and shadows
    // jsdom's, so tests calling localStorage.clear() throw. Turn
    // Node's off for the test workers so jsdom's is used. Node 22.4+
    // accepts the flag as a no-op for behaviour (the feature is off
    // by default there). Node 20 doesn't know the flag and refuses to
    // start a worker given it, so pass it only where it is accepted.
    execArgv: process.allowedNodeEnvironmentFlags.has(
      "--no-experimental-webstorage",
    )
      ? ["--no-experimental-webstorage"]
      : [],
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      // Backend endpoints also live outside /api — notably
      // /health/* (platform health) and /metrics. The production
      // nginx config proxies these to the API (see
      // default.conf.template → `location ~ ^/(health|metrics)`),
      // but the Vite dev proxy only forwarded /api, so requests to
      // /health/platform fell through to the SPA fallback and
      // returned index.html — crashing the dashboard's platform
      // health card. Mirror those two proxy entries here.
      "/health": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/metrics": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
