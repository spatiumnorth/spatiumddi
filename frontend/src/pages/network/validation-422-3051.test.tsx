/**
 * @vitest-environment jsdom
 *
 * A 422's ``detail`` is an ARRAY of objects (#3051). Two pages stored it and
 * rendered it as a React child, so a port of 70000 or a negative circuit
 * bandwidth threw "Objects are not valid as a React child" and the error
 * boundary replaced the whole page. These tests send that exact 422 and check
 * the page shows the field's message and is still on screen.
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
import { MemoryRouter } from "react-router-dom";

function validationError(field: string, msg: string) {
  return Object.assign(new Error("Request failed with status code 422"), {
    response: {
      status: 422,
      data: {
        detail: [
          { type: "value_error", loc: ["body", field], msg, input: 70000 },
        ],
      },
    },
  });
}

const PROVIDER = { id: "p1", name: "Cogent", kind: "transit" };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const handlers: Record<string, () => Promise<unknown>> = {
    "providersApi.list": async () => ({ items: [PROVIDER], total: 1 }),
    "multicastApi.listPorts": async () => [],
    "circuitsApi.create": async () => {
      throw validationError(
        "bandwidth_mbps_down",
        "Input should be greater than or equal to 0",
      );
    },
    "multicastApi.createPort": async () => {
      throw validationError(
        "port_start",
        "Input should be less than or equal to 65535",
      );
    },
    "authApi.myPermissions": async () => ({ is_superadmin: true, grants: [] }),
  };
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (handlers[`${name}.${String(method)}`] ?? pending),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { PortsTab } = await import("./MulticastGroupsPage");
const { CircuitEditorModal } = await import("./CircuitsPage");

afterEach(cleanup);

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("a 422 array is shown, not rendered raw (#3051)", () => {
  it("multicast port out of range shows the message and keeps the page", async () => {
    wrap(<PortsTab groupId="g1" />);
    fireEvent.change(await screen.findByPlaceholderText("Port"), {
      target: { value: "70000" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "port_start: Input should be less than or equal to 65535",
      ),
    );
    // Still mounted: the form is there, no boundary fallback replaced it.
    expect(screen.getByRole("button", { name: "Add" })).toBeTruthy();
  });

  it("circuit negative bandwidth shows the message and keeps the dialog", async () => {
    wrap(<CircuitEditorModal existing={null} onClose={() => {}} />);
    fireEvent.change(screen.getByPlaceholderText(/NYC-LON primary/), {
      target: { value: "ckt" },
    });
    const provider = await screen.findByRole("option", { name: /Cogent/ });
    fireEvent.change(provider.closest("select") as HTMLSelectElement, {
      target: { value: "p1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(document.body.textContent).toContain(
        "bandwidth_mbps_down: Input should be greater than or equal to 0",
      ),
    );
    expect(screen.getByRole("button", { name: "Create" })).toBeTruthy();
  });
});
