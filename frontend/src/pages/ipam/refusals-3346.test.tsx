/**
 * @vitest-environment jsdom
 *
 * A refused delete / check says why where the operator pressed (#3346):
 * IP spaces list, subnet Aliases + Address sets panels, the DNSBL
 * "Check now", and the NAT mapping delete.
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
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
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
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
  useModuleOn: () => true,
}));

const { IPSpacesPage } = await import("./IPSpacesPage");
const { AliasesSubnetPanel, AddressSetsSubnetPanel, EditAddressModal } =
  await import("./IPAMPage");
const { ReputationSection } = await import("./IPDetailModal");
const { NATPage } = await import("./NATPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const refusal = (status: number, detail: unknown) => ({
  response: { status, data: { detail } },
});
const superadmin = () => {
  answers.authApi = {
    myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
  };
};
const reason = async (text: string) => {
  const alert = await screen.findByRole("alert", {}, { timeout: 3000 });
  expect(alert.textContent).toContain(text);
};

describe("refused deletes and checks show the server's reason (#3346)", () => {
  it("IP Spaces: delete refused", async () => {
    answers.ipamApi = {
      listSpaces: () =>
        Promise.resolve([
          { id: "s1", name: "lab", description: "", is_default: false },
        ]),
      deleteSpace: () =>
        Promise.reject(refusal(409, "IP space 'lab' still has blocks")),
    };
    open(<IPSpacesPage />);
    fireEvent.click(await screen.findByLabelText("Delete IP space"));
    await reason("IP space 'lab' still has blocks");
  });

  it("Subnet aliases: delete refused", async () => {
    superadmin();
    answers.ipamApi = {
      listSubnetAliases: () =>
        Promise.resolve([
          {
            id: "a1",
            ip_address_id: "i1",
            fqdn: "www.example.test",
            record_type: "CNAME",
            value: "h.example.test",
            ip_address: "10.0.0.5",
            ip_hostname: "h",
          },
        ]),
      deleteAlias: () =>
        Promise.reject(refusal(403, "Permission denied on dns_record")),
    };
    open(<AliasesSubnetPanel subnetId="sn1" />);
    fireEvent.click(await screen.findByTitle("Delete alias"));
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    await reason("Permission denied on dns_record");
  });

  it("Address sets: delete refused", async () => {
    superadmin();
    answers.addressSetsApi = {
      list: () =>
        Promise.resolve([
          {
            id: "as1",
            name: "printers",
            description: "",
            subnet_id: "sn1",
            customer_id: null,
            site_id: null,
            range_kind: "explicit",
            start_address: null,
            end_address: null,
            explicit_addresses: ["10.0.0.5"],
            tags: {},
            custom_fields: {},
            created_at: "",
            modified_at: "",
          },
        ]),
      remove: () =>
        Promise.reject(refusal(403, "Requires admin on address_set")),
    };
    open(<AddressSetsSubnetPanel subnet={{ id: "sn1" } as never} />);
    fireEvent.click(await screen.findByTitle("Delete address set"));
    const confirm = await screen.findAllByRole("button", { name: "Delete" });
    fireEvent.click(confirm[confirm.length - 1]);
    await reason("Requires admin on address_set");
  });

  it("DNSBL Check now: refused", async () => {
    superadmin();
    answers.dnsblApi = {
      byIp: () => Promise.resolve({ entries: [], listed_count: 0 }),
      checkNow: () => Promise.reject(refusal(403, "Requires write on dnsbl")),
    };
    open(<ReputationSection address="192.0.2.7" />);
    const btn = await screen.findByRole("button", { name: /Check now/ });
    await waitFor(() =>
      expect((btn as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(btn);
    await reason("Requires write on dnsbl");
  });

  it("NAT mappings: delete refused", async () => {
    superadmin();
    answers.natApi = {
      list: () =>
        Promise.resolve({
          total: 1,
          page: 1,
          per_page: 50,
          items: [
            {
              id: "n1",
              name: "web-nat",
              kind: "1to1",
              internal_ip: "10.0.0.5",
              internal_ip_address_id: null,
              internal_subnet_id: null,
              internal_subnet_cidr: null,
              internal_subnet_name: null,
              internal_port_start: null,
              internal_port_end: null,
              external_ip: "192.0.2.5",
              external_ip_address_id: null,
              external_port_start: null,
              external_port_end: null,
              protocol: "any",
              device_label: null,
              description: null,
              tags: [],
              custom_fields: {},
              created_at: "",
              modified_at: "",
            },
          ],
        }),
      delete: () =>
        Promise.reject(refusal(403, "Requires delete on nat_mapping")),
    };
    open(<NATPage />);
    await screen.findByText("web-nat");
    const trash = document.querySelector(
      "button[title*='Delete']",
    ) as HTMLButtonElement;
    await waitFor(() => expect(trash.disabled).toBe(false));
    fireEvent.click(trash);
    const del = await screen.findAllByRole("button", { name: "Delete" });
    fireEvent.click(del[del.length - 1]);
    await reason("Requires delete on nat_mapping");
  });

  it("Edit address: alias delete refused", async () => {
    superadmin();
    const addr = {
      id: "i1",
      subnet_id: "sn1",
      address: "10.0.0.5",
      status: "allocated",
      hostname: "h",
      description: "",
      mac_address: null,
      role: null,
      custom_fields: {},
      reserved_until: null,
      static_assignment_id: null,
    };
    answers.ipamApi = {
      getAddress: () => Promise.resolve(addr),
      listAliases: () =>
        Promise.resolve([
          {
            id: "a1",
            ip_address_id: "i1",
            fqdn: "www.example.test",
            record_type: "CNAME",
            value: "h.example.test",
          },
        ]),
      getEffectiveSubnetDns: () =>
        Promise.resolve({ dns_group_ids: [], dns_additional_zone_ids: [] }),
      deleteAlias: () =>
        Promise.reject(refusal(403, "Permission denied on dns_record")),
    };
    open(<EditAddressModal address={addr as never} onClose={() => {}} />);
    fireEvent.click(await screen.findByTitle("Delete alias"));
    await reason("Permission denied on dns_record");
  });
});

// The refusal belongs to the attempt it answered: closing the confirm
// and opening it again (or retrying successfully) must not show it.
describe("a refusal does not linger into the next attempt (#3346)", () => {
  const noAlert = () => expect(screen.queryByRole("alert")).toBeNull();

  it("Subnet aliases: cancel then reopen starts clean", async () => {
    superadmin();
    answers.ipamApi = {
      listSubnetAliases: () =>
        Promise.resolve([
          {
            id: "a1",
            ip_address_id: "i1",
            fqdn: "www.example.test",
            record_type: "CNAME",
            value: "h.example.test",
            ip_address: "10.0.0.5",
            ip_hostname: "h",
          },
        ]),
      deleteAlias: () =>
        Promise.reject(refusal(403, "Permission denied on dns_record")),
    };
    open(<AliasesSubnetPanel subnetId="sn1" />);
    fireEvent.click(await screen.findByTitle("Delete alias"));
    fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
    await reason("Permission denied on dns_record");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(await screen.findByTitle("Delete alias"));
    await screen.findByRole("button", { name: "Delete" });
    noAlert();
  });

  it("Address sets: cancel then reopen starts clean", async () => {
    superadmin();
    answers.addressSetsApi = {
      list: () =>
        Promise.resolve([
          {
            id: "as1",
            name: "printers",
            description: "",
            subnet_id: "sn1",
            customer_id: null,
            site_id: null,
            range_kind: "explicit",
            start_address: null,
            end_address: null,
            explicit_addresses: ["10.0.0.5"],
            tags: {},
            custom_fields: {},
            created_at: "",
            modified_at: "",
          },
        ]),
      remove: () =>
        Promise.reject(refusal(403, "Requires admin on address_set")),
    };
    open(<AddressSetsSubnetPanel subnet={{ id: "sn1" } as never} />);
    fireEvent.click(await screen.findByTitle("Delete address set"));
    const del = await screen.findAllByRole("button", { name: "Delete" });
    fireEvent.click(del[del.length - 1]);
    await reason("Requires admin on address_set");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(await screen.findByTitle("Delete address set"));
    await screen.findAllByRole("button", { name: "Delete" });
    noAlert();
  });

  it("NAT mappings: cancel then reopen starts clean", async () => {
    superadmin();
    answers.natApi = {
      list: () =>
        Promise.resolve({
          total: 1,
          page: 1,
          per_page: 50,
          items: [
            {
              id: "n1",
              name: "web-nat",
              kind: "1to1",
              internal_ip: "10.0.0.5",
              internal_ip_address_id: null,
              internal_subnet_id: null,
              internal_subnet_cidr: null,
              internal_subnet_name: null,
              internal_port_start: null,
              internal_port_end: null,
              external_ip: "192.0.2.5",
              external_ip_address_id: null,
              external_port_start: null,
              external_port_end: null,
              protocol: "any",
              device_label: null,
              description: null,
              tags: [],
              custom_fields: {},
              created_at: "",
              modified_at: "",
            },
          ],
        }),
      delete: () =>
        Promise.reject(refusal(403, "Requires delete on nat_mapping")),
    };
    open(<NATPage />);
    await screen.findByText("web-nat");
    const trash = document.querySelector(
      "button[title*='Delete']",
    ) as HTMLButtonElement;
    await waitFor(() => expect(trash.disabled).toBe(false));
    fireEvent.click(trash);
    const del = await screen.findAllByRole("button", { name: "Delete" });
    fireEvent.click(del[del.length - 1]);
    await reason("Requires delete on nat_mapping");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    fireEvent.click(trash);
    await screen.findAllByRole("button", { name: "Delete" });
    noAlert();
  });

  it("Edit address: a successful retry clears the refusal", async () => {
    superadmin();
    const addr = {
      id: "i1",
      subnet_id: "sn1",
      address: "10.0.0.5",
      status: "allocated",
      hostname: "h",
      description: "",
      mac_address: null,
      role: null,
      custom_fields: {},
      reserved_until: null,
      static_assignment_id: null,
    };
    let calls = 0;
    answers.ipamApi = {
      getAddress: () => Promise.resolve(addr),
      listAliases: () =>
        Promise.resolve([
          {
            id: "a1",
            ip_address_id: "i1",
            fqdn: "www.example.test",
            record_type: "CNAME",
            value: "h.example.test",
          },
        ]),
      getEffectiveSubnetDns: () =>
        Promise.resolve({ dns_group_ids: [], dns_additional_zone_ids: [] }),
      deleteAlias: () =>
        calls++ === 0
          ? Promise.reject(refusal(409, "Alias is locked"))
          : Promise.resolve(undefined),
    };
    open(<EditAddressModal address={addr as never} onClose={() => {}} />);
    fireEvent.click(await screen.findByTitle("Delete alias"));
    await reason("Alias is locked");
    fireEvent.click(screen.getByTitle("Delete alias"));
    await waitFor(() => expect(calls).toBe(2));
    await waitFor(noAlert);
  });
});
