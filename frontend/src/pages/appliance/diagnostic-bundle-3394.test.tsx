/**
 * @vitest-environment jsdom
 *
 * The diagnostic bundle download goes through the API client (#3394): a plain
 * <a href> navigation carries no bearer and answered "Not authenticated".
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AxiosError, type AxiosAdapter } from "axios";

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

const { api, applianceDiagnosticsApi } = await import("@/lib/api");
const { LogsTab } = await import("@/pages/appliance/LogsTab");

const original = api.defaults.adapter;
let calls: string[] = [];
let click: ReturnType<typeof vi.fn>;
let saved: string[] = [];

function setAdapter(impl: AxiosAdapter) {
  api.defaults.adapter = ((cfg) => {
    calls.push(`${cfg.method} ${cfg.url}`);
    return impl(cfg);
  }) as AxiosAdapter;
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <LogsTab />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  // jsdom's Blob has no text(); rethrowBlobError needs it.
  if (!Blob.prototype.text) {
    Blob.prototype.text = function (this: Blob) {
      return new Promise<string>((resolve) => {
        const r = new FileReader();
        r.onload = () => resolve(String(r.result));
        r.readAsText(this);
      });
    };
  }
  calls = [];
  saved = [];
  click = vi.fn(function (this: HTMLAnchorElement) {
    saved.push(this.download);
  });
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
    click as never,
  );
  URL.createObjectURL = vi.fn(() => "blob:x");
  URL.revokeObjectURL = vi.fn();
  // other cards on the tab; any other route just fails quietly
  vi.spyOn(applianceDiagnosticsApi, "listLogs").mockResolvedValue({
    sources: [],
  } as never);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  api.defaults.adapter = original;
});

const respond = (headers: Record<string, string>) =>
  ((cfg) =>
    Promise.resolve({
      data: new Blob(["zip"]),
      status: 200,
      statusText: "OK",
      headers,
      config: cfg,
    })) as AxiosAdapter;

describe("diagnostic bundle download (#3394)", () => {
  it("is a button, fetched through the client, saved under the server's filename", async () => {
    setAdapter(
      respond({
        // the shape app.core.content_disposition sends: both forms
        "content-disposition":
          'attachment; filename="spatium-diagnostic-20261103-101500.zip"; ' +
          "filename*=UTF-8''spatium-diagnostic-20261103-101500.zip",
      }),
    );
    renderTab();
    const btn = await screen.findByRole("button", { name: /Download bundle/ });
    expect(document.querySelector('a[href*="/api/v1"]')).toBeNull();
    fireEvent.click(btn);
    await vi.waitFor(() =>
      expect(saved).toEqual(["spatium-diagnostic-20261103-101500.zip"]),
    );
    expect(calls).toContain("get /appliance/diagnostics/bundle");
  });

  it("falls back to a timestamped filename", async () => {
    setAdapter(respond({}));
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /Download/ }));
    await vi.waitFor(() => expect(saved).toHaveLength(1));
    expect(saved[0]).toMatch(/^spatium-diagnostic-\d{8}-\d{6}\.zip$/);
  });

  it("shows a busy state while the bundle builds", async () => {
    setAdapter(() => new Promise(() => {}));
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /Download/ }));
    const busy = await screen.findByRole("button", { name: /Building/ });
    expect((busy as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the decoded reason when refused", async () => {
    setAdapter((cfg) =>
      Promise.reject(
        new AxiosError(
          "Request failed with status code 403",
          "ERR_BAD_REQUEST",
          cfg,
          null,
          {
            status: 403,
            statusText: "Forbidden",
            headers: {},
            config: cfg,
            data: new Blob([
              JSON.stringify({
                detail: "Permission denied: admin on appliance",
              }),
            ]),
          },
        ),
      ),
    );
    renderTab();
    fireEvent.click(await screen.findByRole("button", { name: /Download/ }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(/Permission denied: admin on appliance/);
    expect(saved).toHaveLength(0);
  });
});
