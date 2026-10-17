import path from "path";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { readFileSync } from "fs";

const pkg = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf-8"),
) as {
  version: string;
};

// Prefer the release-workflow stamp (VITE_APP_VERSION build arg) over
// the value baked into package.json — package.json is a convenience
// default for local `npm run dev`, not the release source of truth.
const appVersion = process.env.VITE_APP_VERSION || pkg.version;

export default defineConfig({
  plugins: [react()],
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
