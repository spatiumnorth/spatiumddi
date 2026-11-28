/**
 * @vitest-environment jsdom
 *
 * A new zone made under a view-pinned zone opens on the parent's view.
 *
 * Sub-zone and the zone tree's "Create zone here" opened Add Zone on "No
 * view" whatever view the parent zone was pinned to. Saved as it opened, the
 * child was stored with no view, which the bundle builder renders into every
 * view of the group. These tests check what the dialog opens on, what it
 * sends, and that "No view" says what it serves.
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
import type { DNSView, DNSZone } from "@/lib/api";

const createZone = vi.fn((_groupId: string, data: Record<string, unknown>) =>
  Promise.resolve({ id: "zone-new", ...data }),
);
const pending = () => new Promise<never>(() => {});
let listedZones: unknown[] = [];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      classifyZoneName: pending,
      listGroups: () => Promise.resolve([]),
      listZones: () => Promise.resolve(listedZones),
      getZoneDnssecInfo: pending,
      listDnssecPolicies: pending,
      createZone: (groupId: string, data: Record<string, unknown>) =>
        createZone(groupId, data),
    },
    domainsApi: { ...actual.domainsApi, list: pending },
    customersApi: { ...actual.customersApi, list: pending },
  };
});

const { ZoneModal } = await import("./DNSPage");
const { ancestorViewId } = await import("@/lib/dnsNames");

const views = [
  { id: "v-pin", name: "pin" },
  { id: "v-other", name: "other" },
] as DNSView[];

function open(props: { initialName?: string; initialViewId?: string | null }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ZoneModal groupId="grp-1" views={views} onClose={() => {}} {...props} />
    </QueryClientProvider>,
  );
}

function control(label: string): HTMLInputElement | HTMLSelectElement {
  return screen.getByText(label, { selector: "label" }).nextElementSibling as
    | HTMLInputElement
    | HTMLSelectElement;
}

async function save() {
  fireEvent.submit(control("View (optional)").form!);
  await waitFor(() => expect(createZone).toHaveBeenCalledTimes(1));
  return createZone.mock.calls[0][1];
}

afterEach(() => {
  cleanup();
  listedZones = [];
  createZone.mockClear();
});

describe("Add Zone under a view-pinned zone", () => {
  it("Sub-zone opens on the parent's view and sends it when left alone", async () => {
    open({ initialName: ".corp.example.com", initialViewId: "v-pin" });
    expect(control("View (optional)").value).toBe("v-pin");
    fireEvent.change(control("Zone Name (FQDN)"), {
      target: { value: "lab.corp.example.com" },
    });
    expect(await save()).toMatchObject({
      name: "lab.corp.example.com",
      view_id: "v-pin",
    });
  });

  it("still lets the operator pick No view, and says what that serves", async () => {
    open({ initialName: ".corp.example.com", initialViewId: "v-pin" });
    expect(
      screen.queryByText(/served to the clients of every view/),
    ).toBeNull();
    fireEvent.change(control("View (optional)"), { target: { value: "" } });
    expect(
      screen.getByText(/served to the clients of every view/),
    ).toBeTruthy();
    fireEvent.change(control("Zone Name (FQDN)"), {
      target: { value: "lab.corp.example.com" },
    });
    expect(await save()).toMatchObject({ view_id: null });
  });

  it("a parent with no view opens on No view, with the hint", () => {
    open({ initialName: ".corp.example.com", initialViewId: null });
    expect(control("View (optional)").value).toBe("");
    expect(
      screen.getByText(/served to the clients of every view/),
    ).toBeTruthy();
  });
});

describe("ancestorViewId (the tree's Create zone here)", () => {
  const z = (name: string, view_id: string | null) =>
    ({ name, view_id }) as Pick<DNSZone, "name" | "view_id">;

  it("takes the view of the nearest zone above a folder", () => {
    const zones = [
      z("example.com.", null),
      z("corp.example.com.", "v-pin"),
      z("deep.mid.corp.example.com.", "v-pin"),
    ];
    expect(ancestorViewId("mid.corp.example.com", zones)).toBe("v-pin");
  });

  it("nearest wins over a farther ancestor in another view", () => {
    const zones = [z("example.com.", "v-other"), z("corp.example.com.", null)];
    expect(ancestorViewId("mid.corp.example.com", zones)).toBeNull();
    expect(ancestorViewId("x.example.org", zones)).toBeNull();
  });

  it("is case-insensitive and ignores a trailing dot", () => {
    expect(
      ancestorViewId("Mid.CORP.example.com.", [
        z("corp.example.com.", "v-pin"),
      ]),
    ).toBe("v-pin");
  });

  it("gives no view when the nearest name is in several views", () => {
    const zones = [
      z("corp.example.com.", "v-pin"),
      z("corp.example.com.", "v-other"),
    ];
    expect(ancestorViewId("mid.corp.example.com", zones)).toBeNull();
  });
});
