/**
 * @vitest-environment jsdom
 *
 * Integration sync-interval fields (#2110). `parseInt(...) || N` read "1h" as
 * 1 second and turned a cleared field into the default without saying so.
 * One 60 s page (UniFi) and one 300 s page (PAN-OS) stand for the eleven that
 * share the shape; each is checked in create and edit mode.
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
import type { ReactElement } from "react";

const calls = {
  unifiCreate: vi.fn((d: unknown) =>
    Promise.resolve({ id: "u1", ...(d as object) }),
  ),
  unifiUpdate: vi.fn((_id: string, d: unknown) =>
    Promise.resolve({ id: "u1", ...(d as object) }),
  ),
  panosCreate: vi.fn((d: unknown) =>
    Promise.resolve({ id: "p1", ...(d as object) }),
  ),
  panosUpdate: vi.fn((_id: string, d: unknown) =>
    Promise.resolve({ id: "p1", ...(d as object) }),
  ),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    unifiApi: {
      ...actual.unifiApi,
      createController: (d: unknown) => calls.unifiCreate(d),
      updateController: (id: string, d: unknown) => calls.unifiUpdate(id, d),
    },
    panosApi: {
      ...actual.panosApi,
      create: (d: unknown) => calls.panosCreate(d),
      update: (id: string, d: unknown) => calls.panosUpdate(id, d),
    },
    dnsApi: { ...actual.dnsApi, listGroups: () => Promise.resolve([]) },
    ipamApi: { ...actual.ipamApi, listSpaces: () => Promise.resolve([]) },
  };
});

const { ControllerModal } = await import("./unifi/UnifiPage");
const { FirewallModal } = await import("./panos/PanosPage");

function mount(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

function intervalInput(): HTMLInputElement {
  return screen.getByText("Sync interval (seconds)", { selector: "label" })
    .nextElementSibling as HTMLInputElement;
}

function submit() {
  fireEvent.submit(intervalInput().form!);
}

afterEach(() => {
  cleanup();
  Object.values(calls).forEach((m) => m.mockClear());
});

const cases = [
  {
    name: "UniFi (60 s default)",
    def: "60",
    create: () => mount(<ControllerModal onClose={() => {}} />),
    edit: () =>
      mount(
        <ControllerModal
          controller={{ id: "u1", sync_interval_seconds: 90 } as never}
          onClose={() => {}}
        />,
      ),
    created: calls.unifiCreate,
    updated: () => calls.unifiUpdate.mock.calls[0]?.[1],
    updateFn: calls.unifiUpdate,
  },
  {
    name: "PAN-OS (300 s default)",
    def: "300",
    create: () => mount(<FirewallModal onClose={() => {}} />),
    edit: () =>
      mount(
        <FirewallModal
          firewall={{ id: "p1", sync_interval_seconds: 120 } as never}
          onClose={() => {}}
        />,
      ),
    created: calls.panosCreate,
    updated: () => calls.panosUpdate.mock.calls[0]?.[1],
    updateFn: calls.panosUpdate,
  },
];

describe.each(cases)("$name sync interval (#2110)", (c) => {
  it("opens on the default, and on the stored value when editing", () => {
    c.create();
    expect(intervalInput().value).toBe(c.def);
    cleanup();
    c.edit();
    expect(intervalInput().value).toBe(c === cases[0] ? "90" : "120");
  });

  // A number input hands back "" for "1h" (jsdom and browsers alike), so the
  // shapes that reach the handler are the ones a number input can hold.
  it.each(["1.5", "-1", "29", "1e1"])(
    "refuses %j with a reason and sends nothing",
    async (text) => {
      c.create();
      fireEvent.change(intervalInput(), { target: { value: text } });
      submit();
      await waitFor(() =>
        expect(
          screen.getByText(/^Sync interval must be a whole number/),
        ).toBeTruthy(),
      );
      expect(c.created).not.toHaveBeenCalled();
    },
  );

  it("says a cleared field is required rather than saving the default", async () => {
    c.edit();
    fireEvent.change(intervalInput(), { target: { value: "" } });
    submit();
    await waitFor(() => screen.getByText("Sync interval is required."));
    expect(c.updateFn).not.toHaveBeenCalled();
  });

  it("sends 1e3 as the number 1000", async () => {
    c.create();
    fireEvent.change(intervalInput(), { target: { value: "1e3" } });
    submit();
    await waitFor(() => expect(c.created).toHaveBeenCalledTimes(1));
    expect(
      (c.created.mock.calls[0][0] as { sync_interval_seconds: unknown })
        .sync_interval_seconds,
    ).toBe(1000);
  });

  it("an edit that leaves the field alone sends the stored number", async () => {
    c.edit();
    submit();
    await waitFor(() => expect(c.updateFn).toHaveBeenCalledTimes(1));
    expect(
      (c.updated() as { sync_interval_seconds: unknown }).sync_interval_seconds,
    ).toBe(c === cases[0] ? 90 : 120);
  });
});
