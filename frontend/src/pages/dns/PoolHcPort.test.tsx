/**
 * @vitest-environment jsdom
 *
 * The pool dialog's Target port (#4307). The API stores no port as null, and
 * the health checker reads that as the scheme's port (443 for HTTPS). The
 * dialog used to start that field at 80 and compare it with the stored null,
 * so an untouched Save wrote 80 and moved an HTTPS check off 443.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DNSPool, DNSServerGroup, DNSZone } from "@/lib/api";

const STORED = {
  id: "pool-1",
  group_id: "g1",
  zone_id: "z1",
  name: "web",
  description: "",
  record_name: "www",
  record_type: "A",
  ttl: 30,
  enabled: true,
  hc_type: "https",
  hc_target_port: null,
  hc_path: "/",
  hc_method: "GET",
  hc_verify_tls: false,
  hc_expected_status_codes: [200],
  hc_interval_seconds: 30,
  hc_timeout_seconds: 5,
  hc_unhealthy_threshold: 2,
  hc_healthy_threshold: 2,
  members: [],
} as unknown as DNSPool;

const createPool = vi.fn((_g: string, _z: string, data: unknown) =>
  Promise.resolve({ id: "pool-1", ...(data as object) }),
);
const updatePool = vi.fn((_id: string, data: unknown) =>
  Promise.resolve({ ...STORED, ...(data as object) }),
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      createPool: (g: string, z: string, data: unknown) =>
        createPool(g, z, data),
      updatePool: (id: string, data: unknown) => updatePool(id, data),
      getPool: () => Promise.resolve(STORED),
    },
    sitesApi: {
      ...actual.sitesApi,
      list: () => new Promise<never>(() => {}),
    },
  };
});

const { PoolModal } = await import("./PoolsView");

function open(pool?: Partial<DNSPool>) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const row = pool ? ({ ...STORED, ...pool } as DNSPool) : undefined;
  if (row) STORED.hc_target_port = row.hc_target_port;
  render(
    <QueryClientProvider client={qc}>
      <PoolModal
        group={{ id: "g1" } as DNSServerGroup}
        zone={{ id: "z1" } as DNSZone}
        pool={row}
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
}

const field = (label: string) =>
  screen.getByText(label, { selector: "label" }).nextElementSibling as
    | HTMLInputElement
    | HTMLSelectElement;

async function editing() {
  await waitFor(() => screen.getByText("Target port", { selector: "label" }));
}

const save = () => fireEvent.submit(field("Name").form!);

afterEach(() => {
  cleanup();
  createPool.mockClear();
  updatePool.mockClear();
  STORED.hc_target_port = null;
});

describe("edit pool Target port (#4307)", () => {
  it("shows an empty port with the scheme default named", async () => {
    open({});
    await editing();
    const port = field("Target port") as HTMLInputElement;
    expect(port.value).toBe("");
    expect(port.placeholder).toBe("443 (HTTPS default)");
  });

  it("an untouched Save sends no port", async () => {
    open({});
    await editing();
    save();
    await new Promise((r) => setTimeout(r, 50));
    expect(updatePool).not.toHaveBeenCalled();
  });

  it("a rename sends only the name", async () => {
    open({});
    await editing();
    fireEvent.change(field("Name"), { target: { value: "web2" } });
    save();
    await waitFor(() => expect(updatePool).toHaveBeenCalledTimes(1));
    expect(updatePool.mock.calls[0][1]).toEqual({ name: "web2" });
  });

  it("sends a port the operator typed", async () => {
    open({});
    await editing();
    fireEvent.change(field("Target port"), { target: { value: "8443" } });
    save();
    await waitFor(() => expect(updatePool).toHaveBeenCalledTimes(1));
    expect(updatePool.mock.calls[0][1]).toEqual({ hc_target_port: 8443 });
  });

  it("sends null when a stored port is cleared", async () => {
    open({ hc_target_port: 8443 });
    await editing();
    expect((field("Target port") as HTMLInputElement).value).toBe("8443");
    fireEvent.change(field("Target port"), { target: { value: "" } });
    save();
    await waitFor(() => expect(updatePool).toHaveBeenCalledTimes(1));
    expect(updatePool.mock.calls[0][1]).toEqual({ hc_target_port: null });
  });
});

describe("new pool Target port (#4307)", () => {
  it("creates an HTTPS pool with no port", async () => {
    open();
    fireEvent.change(field("Name"), { target: { value: "web" } });
    fireEvent.change(field("Type"), { target: { value: "https" } });
    expect((field("Target port") as HTMLInputElement).value).toBe("");
    save();
    await waitFor(() => expect(createPool).toHaveBeenCalledTimes(1));
    expect(
      (createPool.mock.calls[0][2] as { hc_target_port: unknown })
        .hc_target_port,
    ).toBeNull();
  });

  it("blocks a TCP check with no port", async () => {
    open();
    fireEvent.change(field("Name"), { target: { value: "web" } });
    save();
    await waitFor(() =>
      screen.getByText("A TCP health check needs a target port."),
    );
    expect(createPool).not.toHaveBeenCalled();
  });
});
