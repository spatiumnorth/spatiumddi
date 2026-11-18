/**
 * @vitest-environment jsdom
 *
 * A secondary zone's per-primary TSIG key and TLS hostname (#3568): the
 * dialog offers them per master, sends them keyed by the master entry, and an
 * edit that clears them sends the clearing.
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
  Promise.resolve({ id: "zone-new", ...data }),
);
const updateZone = vi.fn(
  (_g: string, zoneId: string, data: Record<string, unknown>) =>
    Promise.resolve({ id: zoneId, ...data }),
);
const pending = () => new Promise<never>(() => {});
let listedZones: unknown[] = [];

const KEYS = [
  {
    id: "k1",
    group_id: "grp-1",
    name: "xfer.example.",
    algorithm: "hmac-sha256",
    purpose: null,
    notes: "",
    last_rotated_at: null,
    created_at: "2026-11-01T00:00:00Z",
    modified_at: "2026-11-01T00:00:00Z",
    secret: null,
  },
];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      classifyZoneName: pending,
      listGroups: () => Promise.resolve([]),
      listZones: () => Promise.resolve(listedZones),
      listTSIGKeys: () => Promise.resolve(KEYS),
      getZoneDnssecInfo: pending,
      listDnssecPolicies: pending,
      createZone: (g: string, d: Record<string, unknown>) => createZone(g, d),
      updateZone: (g: string, z: string, d: Record<string, unknown>) =>
        updateZone(g, z, d),
    },
    domainsApi: { ...actual.domainsApi, list: pending },
    customersApi: { ...actual.customersApi, list: pending },
  };
});

const { ZoneModal } = await import("./DNSPage");

function open(zone?: DNSZone) {
  listedZones = zone ? [zone] : [];
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ZoneModal groupId="grp-1" views={[]} zone={zone} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

function control(label: string): HTMLInputElement | HTMLSelectElement {
  return screen.getByText(label, { selector: "label" }).nextElementSibling as
    | HTMLInputElement
    | HTMLSelectElement;
}

afterEach(() => {
  cleanup();
  createZone.mockClear();
  updateZone.mockClear();
});

describe(
  "Secondary zone per-primary options (#3568)",
  { timeout: 30000 },
  () => {
    it("sends the key and hostname chosen for each master", async () => {
      open();
      fireEvent.change(control("Zone Name (FQDN)"), {
        target: { value: "sec.example.com" },
      });
      fireEvent.change(control("Type"), { target: { value: "secondary" } });
      fireEvent.change(
        control("Master IPs (comma- or space-separated; ip or ip@port)"),
        { target: { value: "192.0.2.10, 192.0.2.11@853" } },
      );
      const keySelect = (await screen.findByLabelText(
        "TSIG key for 192.0.2.10",
      )) as HTMLSelectElement;
      await waitFor(() => expect(keySelect.options.length).toBeGreaterThan(1), {
        timeout: 10000,
      });
      fireEvent.change(keySelect, { target: { value: "xfer.example." } });
      fireEvent.change(
        screen.getByLabelText("TLS hostname for 192.0.2.11@853"),
        {
          target: { value: "ns1.example.com" },
        },
      );
      fireEvent.submit(control("Kind").form!);
      await waitFor(() => expect(createZone).toHaveBeenCalledTimes(1), {
        timeout: 10000,
      });
      expect(createZone.mock.calls[0][1]).toMatchObject({
        masters: ["192.0.2.10", "192.0.2.11@853"],
        master_options: {
          "192.0.2.10": { tsig_key: "xfer.example." },
          "192.0.2.11@853": { tls_hostname: "ns1.example.com" },
        },
      });
    });

    it("sends no master_options when none is set", async () => {
      open();
      fireEvent.change(control("Zone Name (FQDN)"), {
        target: { value: "sec.example.com" },
      });
      fireEvent.change(control("Type"), { target: { value: "secondary" } });
      fireEvent.change(
        control("Master IPs (comma- or space-separated; ip or ip@port)"),
        { target: { value: "192.0.2.10" } },
      );
      fireEvent.submit(control("Kind").form!);
      await waitFor(() => expect(createZone).toHaveBeenCalledTimes(1), {
        timeout: 10000,
      });
      expect(createZone.mock.calls[0][1]).not.toHaveProperty("master_options");
    });

    it("clearing a stored hostname on edit sends the cleared map", async () => {
      open({
        id: "zone-1",
        group_id: "grp-1",
        view_id: null,
        name: "sec.example.com.",
        zone_type: "secondary",
        kind: "forward",
        ttl: 3600,
        primary_ns: "",
        admin_email: "",
        dnssec_enabled: false,
        color: null,
        forwarders: [],
        forward_only: true,
        masters: ["192.0.2.10"],
        master_options: { "192.0.2.10": { tls_hostname: "ns1.example.com" } },
        domain_id: null,
        customer_id: null,
      } as unknown as DNSZone);
      const host = (await screen.findByLabelText(
        "TLS hostname for 192.0.2.10",
      )) as HTMLInputElement;
      expect(host.value).toBe("ns1.example.com");
      fireEvent.change(host, { target: { value: "" } });
      fireEvent.submit(control("Kind").form!);
      await waitFor(() => expect(updateZone).toHaveBeenCalledTimes(1), {
        timeout: 10000,
      });
      expect(updateZone.mock.calls[0][2]).toEqual({ master_options: {} });
    });
  },
);
