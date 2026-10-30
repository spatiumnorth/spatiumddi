/**
 * @vitest-environment jsdom
 *
 * Add Zone and New Server Group start from the DNS defaults Settings holds
 * (#3087): Default Zone Type, Default Zone TTL and Recursive by Default were
 * stored and read by nothing, so both dialogs used constants.
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
import type { DNSZone } from "@/lib/api";

const createZone = vi.fn((_g: string, data: Record<string, unknown>) =>
  Promise.resolve({ id: "z", ...data }),
);
const createGroup = vi.fn((data: Record<string, unknown>) =>
  Promise.resolve({ id: "g", ...data }),
);
const pending = () => new Promise<never>(() => {});
let stored: Record<string, unknown> = {};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: { ...actual.settingsApi, get: () => Promise.resolve(stored) },
    dnsApi: {
      ...actual.dnsApi,
      classifyZoneName: pending,
      listGroups: () => Promise.resolve([]),
      getZoneDnssecInfo: pending,
      listDnssecPolicies: pending,
      createZone: (g: string, d: Record<string, unknown>) => createZone(g, d),
      createGroup: (d: Record<string, unknown>) => createGroup(d),
    },
    domainsApi: { ...actual.domainsApi, list: pending },
    customersApi: { ...actual.customersApi, list: pending },
  };
});

const { ZoneModal, GroupModal } = await import("./DNSPage");

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

function control(label: string): HTMLInputElement | HTMLSelectElement {
  return screen.getByText(label, { selector: "label" }).nextElementSibling as
    | HTMLInputElement
    | HTMLSelectElement;
}

afterEach(() => {
  cleanup();
  stored = {};
  createZone.mockClear();
  createGroup.mockClear();
});

describe("Add Zone", () => {
  it("pre-fills Type and TTL from Settings", async () => {
    stored = { dns_default_zone_type: "forward", dns_default_ttl: 5400 };
    wrap(<ZoneModal groupId="g1" views={[]} onClose={() => {}} />);
    await waitFor(() => expect(control("Type").value).toBe("forward"));
    expect(control("Default TTL (seconds)").value).toBe("5400");
  });

  it("keeps what the operator picked over the stored default", async () => {
    stored = { dns_default_zone_type: "forward", dns_default_ttl: 5400 };
    wrap(<ZoneModal groupId="g1" views={[]} onClose={() => {}} />);
    await waitFor(() => expect(control("Type").value).toBe("forward"));
    fireEvent.change(control("Type"), { target: { value: "primary" } });
    fireEvent.change(control("Default TTL (seconds)"), {
      target: { value: "60" },
    });
    expect(control("Type").value).toBe("primary");
    expect(control("Default TTL (seconds)").value).toBe("60");
  });

  it("shows an existing zone's own values, not the defaults", async () => {
    stored = { dns_default_zone_type: "forward", dns_default_ttl: 5400 };
    const zone = { name: "a.example.com.", zone_type: "primary", ttl: 300 };
    wrap(
      <ZoneModal
        groupId="g1"
        views={[]}
        zone={zone as unknown as DNSZone}
        onClose={() => {}}
      />,
    );
    expect(control("Type").value).toBe("primary");
    expect(control("Default TTL (seconds)").value).toBe("300");
  });
});

describe("New Server Group", () => {
  const recursion = () =>
    screen.getByLabelText("Allow recursion") as HTMLInputElement;

  it("pre-fills Allow recursion from Settings and sends it", async () => {
    stored = { dns_recursive_by_default: false };
    wrap(<GroupModal onClose={() => {}} />);
    await waitFor(() => expect(recursion().checked).toBe(false));
    fireEvent.change(control("Name"), { target: { value: "g" } });
    fireEvent.submit(control("Name").form!);
    await waitFor(() => expect(createGroup).toHaveBeenCalledTimes(1));
    expect(createGroup.mock.calls[0][0]).toMatchObject({ is_recursive: false });
  });

  it("keeps a tick the operator made", async () => {
    stored = { dns_recursive_by_default: false };
    wrap(<GroupModal onClose={() => {}} />);
    await waitFor(() => expect(recursion().checked).toBe(false));
    fireEvent.click(recursion());
    expect(recursion().checked).toBe(true);
  });
});
