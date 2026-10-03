/**
 * @vitest-environment jsdom
 *
 * Add Zone's Kind follows the zone's name (#1310).
 *
 * The dialog pre-filled Kind "Forward lookup" whatever the name, so a zone
 * named under in-addr.arpa that an operator created with Kind left alone was
 * stored kind "forward". The API's own classifier calls that name reverse,
 * and the zone's Add Record pre-fills PTR. IPAM publishes PTR records only
 * into kind "reverse" zones, so the zone never received one. These tests type
 * a name the way an operator does and check what the dialog SHOWS against
 * what it SENDS.
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
import { zoneKindForName } from "@/lib/dnsNames";

const createZone = vi.fn((_groupId: string, data: Record<string, unknown>) =>
  Promise.resolve({ id: "zone-new", ...data }),
);
const updateZone = vi.fn(
  (_groupId: string, zoneId: string, data: Record<string, unknown>) =>
    Promise.resolve({ id: zoneId, ...data }),
);
const pending = () => new Promise<never>(() => {});

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      // The name's scope hint arrives later than an operator saves: the
      // kind must not wait for it.
      classifyZoneName: pending,
      getZoneDnssecInfo: pending,
      listDnssecPolicies: pending,
      createZone: (groupId: string, data: Record<string, unknown>) =>
        createZone(groupId, data),
      updateZone: (
        groupId: string,
        zoneId: string,
        data: Record<string, unknown>,
      ) => updateZone(groupId, zoneId, data),
    },
    domainsApi: { ...actual.domainsApi, list: pending },
    customersApi: { ...actual.customersApi, list: pending },
  };
});

const { ZoneModal } = await import("./DNSPage");

function open(zone?: DNSZone) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ZoneModal groupId="grp-1" views={[]} zone={zone} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

/** The control a `<Field label>` wraps (the label has no `htmlFor`). */
function control(label: string): HTMLInputElement | HTMLSelectElement {
  return screen.getByText(label, { selector: "label" }).nextElementSibling as
    | HTMLInputElement
    | HTMLSelectElement;
}

function typeName(name: string) {
  fireEvent.change(control("Zone Name (FQDN)"), { target: { value: name } });
}

function pickKind(kind: "forward" | "reverse") {
  fireEvent.change(control("Kind"), { target: { value: kind } });
}

/** Submit, and wait for the one request the dialog sends. */
async function save() {
  fireEvent.submit(control("Kind").form!);
  await waitFor(() =>
    expect(createZone.mock.calls.length + updateZone.mock.calls.length).toBe(1),
  );
}

afterEach(() => {
  cleanup();
  createZone.mockClear();
  updateZone.mockClear();
});

describe("Add Zone's Kind", () => {
  it.each([
    ["81.98.10.in-addr.arpa", "reverse"],
    ["8.b.d.0.1.0.0.2.ip6.arpa", "reverse"],
    ["corp.example.com", "forward"],
  ])("shows and sends the kind of %s, left alone: %s", async (name, kind) => {
    open();
    typeName(name);

    expect(control("Kind").value).toBe(kind);
    await save();
    expect(createZone.mock.calls[0][1]).toMatchObject({ name, kind });
  });

  it("follows the name only until the operator picks a kind", async () => {
    open();
    typeName("lab.example.com");
    pickKind("reverse");
    typeName("rev.lab.example.com");
    expect(control("Kind").value).toBe("reverse");

    typeName("81.98.10.in-addr.arpa");
    pickKind("forward");
    expect(control("Kind").value).toBe("forward");
    await save();
    // Sent as picked: the API, which owns the rule, answers a contradiction.
    expect(createZone.mock.calls[0][1]).toMatchObject({ kind: "forward" });
  });

  it("keeps the old default for a zone that is not primary", () => {
    // IPAM cannot write into a secondary, stub or forward zone, and its PTR
    // lookup does not look at the type: those keep "forward" unless picked.
    open();
    typeName("81.98.10.in-addr.arpa");
    expect(control("Kind").value).toBe("reverse");
    fireEvent.change(control("Type"), { target: { value: "secondary" } });
    expect(control("Kind").value).toBe("forward");
    fireEvent.change(control("Type"), { target: { value: "forward" } });
    expect(control("Kind").value).toBe("forward");
    fireEvent.change(control("Type"), { target: { value: "primary" } });
    expect(control("Kind").value).toBe("reverse");
  });

  it("shows an existing zone's kind as it is stored", async () => {
    open({
      id: "zone-1",
      group_id: "grp-1",
      view_id: null,
      name: "88.98.10.in-addr.arpa.",
      zone_type: "primary",
      kind: "forward",
      ttl: 3600,
      primary_ns: "",
      admin_email: "",
      dnssec_enabled: false,
      color: null,
      forwarders: [],
      forward_only: true,
      masters: [],
      domain_id: null,
      customer_id: null,
    } as unknown as DNSZone);

    expect(control("Kind").value).toBe("forward");
    await save();
    expect(updateZone.mock.calls[0][2]).toMatchObject({ kind: "forward" });
  });
});

describe("zoneKindForName", () => {
  it.each([
    ["81.98.10.in-addr.arpa", "reverse"],
    ["81.98.10.in-addr.arpa.", "reverse"],
    ["8.b.d.0.1.0.0.2.ip6.arpa", "reverse"],
    ["10.IN-ADDR.ARPA", "reverse"],
    ["in-addr.arpa", "reverse"],
    ["ip6.arpa.", "reverse"],
    [" 81.98.10.in-addr.arpa ", "reverse"],
    ["corp.example.com", "forward"],
    ["home.arpa", "forward"],
    ["notin-addr.arpa", "forward"],
    ["in-addr.arpa.example.com", "forward"],
    ["", "forward"],
  ])("%s → %s", (name, kind) => {
    expect(zoneKindForName(name)).toBe(kind);
  });
});
