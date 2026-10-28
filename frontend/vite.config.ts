import path from "path";
import { fileURLToPath } from "url";
import { defineConfig } from "vitest/config";
import type { Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { copyFileSync, existsSync, mkdirSync, readFileSync } from "fs";
import license from "rollup-plugin-license";

const pkg = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf-8"),
) as {
  version: string;
};

// Prefer the release-workflow stamp (VITE_APP_VERSION build arg) over
// the value baked into package.json — package.json is a convenience
// default for local `npm run dev`, not the release source of truth.
const appVersion = process.env.VITE_APP_VERSION || pkg.version;

// #2895 — the legal files the About page serves. They live once, at the
// repo root; the build copies them into dist/ rather than keeping a second
// copy in frontend/public/ that would drift. The Docker build context is the
// repo root for exactly this reason (see frontend/Dockerfile). A plain
// ``npm run dev`` serves nothing for them and the page says so.
// Published with a ``.txt`` suffix: nginx types an extension-less file
// ``application/octet-stream`` and the browser would download it instead of
// showing it, and a ``location`` block just to retype it would have to be
// mirrored into the chart's and the appliance's copies of the nginx config.
const LEGAL_FILES = ["NOTICE", "LICENSE"];

function legalFiles(): Plugin {
  const roots = [
    fileURLToPath(new URL("..", import.meta.url)),
    fileURLToPath(new URL("./legal", import.meta.url)),
  ];
  return {
    name: "spatiumddi-legal-files",
    apply: "build",
    closeBundle() {
      const out = fileURLToPath(new URL("./dist/legal", import.meta.url));
      mkdirSync(out, { recursive: true });
      for (const name of LEGAL_FILES) {
        const src = roots
          .map((r) => `${r}/${name}`)
          .find((candidate) => existsSync(candidate));
        if (src) copyFileSync(src, `${out}/${name}.txt`);
      }
    },
  };
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
        output: {
          file: fileURLToPath(
            new URL("./dist/third-party-licenses.txt", import.meta.url),
          ),
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
