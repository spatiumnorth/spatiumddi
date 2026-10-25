/**
 * @vitest-environment jsdom
 *
 * InfluxDB target form: stored secrets and refused saves (#1989, #1990, #1993).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { InfluxDBTarget } from "@/lib/api";

const api = { list: vi.fn(), update: vi.fn(), create: vi.fn() };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: {
      ...actual.settingsApi,
      listInfluxTargets: () => api.list(),
      updateInfluxTarget: (id: string, body: unknown) => api.update(id, body),
      createInfluxTarget: (body: unknown) => api.create(body),
    },
  };
});

const { InfluxDBTargets } = await import("@/components/InfluxDBTargets");

const BASE: InfluxDBTarget = {
  id: "t1",
  name: "grafana",
  enabled: true,
  version: "v1",
  url: "http://192.0.2.10:8086",
  verify_tls: true,
  timeout_seconds: 10,
  database: "ddi",
  username: "u",
  password_set: true,
  org: "",
  bucket: "",
  token_set: true,
  measurement_prefix: "spatiumddi_",
  push_interval_seconds: 60,
  push_dns_metrics: true,
  push_dhcp_metrics: true,
  push_subnet_utilization: true,
  push_dhcp_scope_leases: true,
  last_push_at: null,
  last_success_at: null,
  last_push_points: 0,
  last_push_error: null,
  last_dns_bucket_at: null,
  last_dhcp_bucket_at: null,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};

function mount(target: InfluxDBTarget) {
  api.list.mockResolvedValue([target]);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <InfluxDBTargets isSuperadmin />
    </QueryClientProvider>,
  );
}

async function openEdit(target: InfluxDBTarget) {
  mount(target);
  await screen.findByText("grafana");
  fireEvent.click(screen.getByTitle("Edit"));
}

async function save() {
  await act(async () => {
    fireEvent.click(screen.getByText("Save"));
  });
}

afterEach(() => {
  cleanup();
  api.list.mockReset();
  api.update.mockReset();
  api.create.mockReset();
});

describe("stored secrets", () => {
  it("typing in the password field and clearing it keeps the secret", async () => {
    await openEdit(BASE);
    const pw = screen.getByPlaceholderText("(stored — leave blank to keep)");
    fireEvent.change(pw, { target: { value: "x" } });
    fireEvent.change(pw, { target: { value: "" } });
    api.update.mockResolvedValue(BASE);
    await save();
    const body = api.update.mock.calls[0][1] as Record<string, unknown>;
    expect("password" in body).toBe(false);
    expect(body.clear_password).toBeUndefined();
  });

  it("typing in the token field and clearing it keeps the secret", async () => {
    const v2 = { ...BASE, version: "v2" as const, bucket: "b", org: "o" };
    await openEdit(v2);
    const tok = screen.getByPlaceholderText("(stored — leave blank to keep)");
    fireEvent.change(tok, { target: { value: "x" } });
    fireEvent.change(tok, { target: { value: "" } });
    api.update.mockResolvedValue(v2);
    await save();
    const body = api.update.mock.calls[0][1] as Record<string, unknown>;
    expect("token" in body).toBe(false);
    expect(body.clear_token).toBeUndefined();
  });

  it("clears the password only through the explicit control", async () => {
    await openEdit(BASE);
    fireEvent.click(screen.getByLabelText("Clear stored password"));
    api.update.mockResolvedValue(BASE);
    await save();
    const body = api.update.mock.calls[0][1] as Record<string, unknown>;
    expect(body.clear_password).toBe(true);
    expect("password" in body).toBe(false);
  });

  // The clear checkbox's label must not sit inside the field's label: that
  // renamed the field "Password Clear stored password" (ddi-pg walk of #2001).
  it("keeps the secret fields named exactly Password and Token", async () => {
    await openEdit(BASE);
    const pw = screen.getByLabelText("Password", { exact: true });
    expect(pw.getAttribute("type")).toBe("password");
    expect(screen.getByLabelText("Clear stored password")).toBeTruthy();
    cleanup();
    await openEdit({ ...BASE, version: "v2" as const, bucket: "b", org: "o" });
    const tok = screen.getByLabelText("Token", { exact: true });
    expect(tok.getAttribute("type")).toBe("password");
    expect(screen.getByLabelText("Clear stored token")).toBeTruthy();
  });

  it("sends a newly typed password", async () => {
    await openEdit(BASE);
    fireEvent.change(
      screen.getByPlaceholderText("(stored — leave blank to keep)"),
      { target: { value: "new" } },
    );
    api.update.mockResolvedValue(BASE);
    await save();
    const body = api.update.mock.calls[0][1] as Record<string, unknown>;
    expect(body.password).toBe("new");
  });
});

describe("a refused save", () => {
  it("shows the server's reason as text and keeps the dialog open", async () => {
    await openEdit(BASE);
    api.update.mockRejectedValue({
      response: {
        data: {
          detail: [
            {
              type: "value_error",
              loc: ["body", "url"],
              msg: "Value error, url must start with http:// or https://",
              input: "192.0.2.10:8086",
            },
          ],
        },
      },
    });
    await save();
    expect(
      screen.getByText(/url: Value error, url must start with http/),
    ).toBeTruthy();
    expect(screen.queryByText(/\[object Object\]/)).toBeNull();
    expect(screen.getByText("Save")).toBeTruthy();
  });
});

describe("Last push column", () => {
  it("says never for a target whose pushes all failed", async () => {
    mount({
      ...BASE,
      last_push_at: new Date(Date.now() - 31 * 60000).toISOString(),
      last_push_error: "ConnectTimeout",
    });
    await screen.findByText("grafana");
    expect(screen.getByText("never")).toBeTruthy();
    expect(screen.queryByText(/pts/)).toBeNull();
    expect(screen.getByText(/last attempt failed 31m ago/)).toBeTruthy();
  });

  it("shows the last successful push beside a later failure", async () => {
    mount({
      ...BASE,
      last_push_at: new Date(Date.now() - 60000).toISOString(),
      last_success_at: new Date(Date.now() - 3600000).toISOString(),
      last_push_points: 42,
      last_push_error: "HTTP 401",
    });
    await screen.findByText("grafana");
    expect(screen.getByText(/1h ago/)).toBeTruthy();
    expect(screen.getByText("(42 pts)")).toBeTruthy();
    expect(screen.getByText(/last attempt failed 1m ago/)).toBeTruthy();
  });
});

// #2751: an empty stored prefix writes unprefixed names; the field must not
// offer the default "spatiumddi_" as if that were what the target writes.
describe("measurement prefix", () => {
  it("says an empty prefix writes unprefixed names", async () => {
    await openEdit({ ...BASE, measurement_prefix: "" });
    expect(screen.queryByPlaceholderText("spatiumddi_")).toBeNull();
    expect(screen.getByText(/no prefix/i)).toBeTruthy();
  });

  it("shows no empty-prefix note when a prefix is stored", async () => {
    await openEdit(BASE);
    expect(screen.queryByText(/no prefix/i)).toBeNull();
  });
});
