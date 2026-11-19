/**
 * @vitest-environment jsdom
 *
 * A confirm whose action the server refuses says why, in an announced line
 * inside the open dialog (#4353, #4354). Before, Delete DNSSEC policy, Delete
 * Custom Field, the two pool deletes and Detach resource read no error (Detach
 * even closed at the press), and Remove import metadata drew its refusal as a
 * plain span nothing announces.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { DNSPool, DNSPoolListEntry, DNSZone } from "@/lib/api";

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

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
  useModuleOn: () => true,
}));

const { DNSSECPoliciesPage } = await import("@/pages/dns/DNSSECPoliciesPage");
const { CustomFieldsPage } = await import("@/pages/admin/CustomFieldsPage");
const { ImportedChip } = await import("@/pages/ipam/IPAMPage");
const { ResourcesTab } = await import("@/pages/network/ServicesPage");
const { ConfirmDeleteModal } = await import("@/pages/dns/DNSPoolsPage");
const { ConfirmDelete } = await import("@/pages/dns/PoolsView");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const refuse = (detail: string, status = 409) =>
  vi.fn(() => Promise.reject({ response: { status, data: { detail } } }));

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

// The refusal sits in an announced line inside the dialog, which stays open
// with its confirm button usable again.
async function expectAnnounced(
  dialogName: RegExp,
  reason: string,
  buttonName: string,
) {
  const dialog = await screen.findByRole("dialog", { name: dialogName });
  const alert = await within(dialog).findByRole("alert");
  expect(alert.textContent).toContain(reason);
  expect(
    (
      within(dialog).getByRole("button", {
        name: buttonName,
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(false);
}

describe("a refused confirm says why in an announced line", () => {
  it("Delete DNSSEC policy", async () => {
    const del = refuse("Policy is in use");
    answers.dnsApi = {
      listDnssecPolicies: () =>
        Promise.resolve([
          {
            id: "p1",
            name: "pol-one",
            description: "",
            is_builtin: false,
            algorithm: "ECDSAP256SHA256",
            ksk_lifetime_days: 365,
            zsk_lifetime_days: 30,
            nsec3: false,
            nsec3_iterations: 0,
            nsec3_salt_length: 0,
            nsec3_optout: false,
            created_at: "",
            modified_at: "",
          },
        ]),
      deleteDnssecPolicy: del,
    };
    open(<DNSSECPoliciesPage />);
    await screen.findByText("pol-one");
    fireEvent.click(screen.getByRole("button", { name: /Delete/ }));
    const dialog = await screen.findByRole("dialog", {
      name: "Delete DNSSEC policy?",
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(del).toHaveBeenCalled());
    await expectAnnounced(/Delete DNSSEC policy/, "Policy is in use", "Delete");
  });

  it("Delete Custom Field", async () => {
    const del = refuse("Field is in use");
    answers.authApi = {
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    };
    answers.customFieldsApi = {
      list: () =>
        Promise.resolve([
          {
            id: "f1",
            resource_type: "subnet",
            name: "cf_probe",
            label: "cf probe",
            field_type: "text",
            options: null,
            is_required: false,
            is_searchable: false,
            default_value: null,
            display_order: 0,
            description: "",
          },
        ]),
      delete: del,
    };
    open(<CustomFieldsPage />);
    await screen.findByText("cf_probe");
    fireEvent.click(screen.getByTitle(/Delete/));
    const dialog = await screen.findByRole("dialog", {
      name: "Delete Custom Field?",
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(del).toHaveBeenCalled());
    await expectAnnounced(/Delete Custom Field/, "Field is in use", "Delete");
  });

  it("Remove import metadata", async () => {
    answers.ipamApi = {
      getSubnet: refuse("Subnet not found", 404),
    };
    open(
      <ImportedChip
        fields={{ import_source: "x" }}
        kind="subnet"
        id="s1"
        onUpdated={() => {}}
      />,
    );
    fireEvent.click(screen.getByLabelText(/Remove import metadata/));
    fireEvent.click(await screen.findByRole("button", { name: "Remove" }));
    await expectAnnounced(
      /Remove import metadata/,
      "Subnet not found",
      "Remove",
    );
  });

  it("Detach resource stays open and says why", async () => {
    const detach = refuse("Resource link not found", 404);
    answers.servicesApi = { detachResource: detach };
    open(
      <ResourcesTab
        service={
          {
            id: "svc1",
            resources: [
              {
                id: "l1",
                resource_kind: "subnet",
                resource_id: "s1",
                role: null,
              },
            ],
          } as never
        }
        onChange={() => {}}
      />,
    );
    fireEvent.click(await screen.findByTitle("Detach"));
    const dialog = await screen.findByRole("dialog", {
      name: "Detach resource",
    });
    fireEvent.click(within(dialog).getByRole("button", { name: "Detach" }));
    await waitFor(() => expect(detach).toHaveBeenCalled());
    await expectAnnounced(
      /Detach resource/,
      "Resource link not found",
      "Detach",
    );
  });

  it("the two pool delete dialogs draw an error prop as an alert", () => {
    const entry = {
      id: "p1",
      name: "pool-one",
      record_name: "www",
      zone_name: "example.com.",
      record_type: "A",
      enabled: true,
      member_count: 1,
      live_count: 1,
    } as unknown as DNSPoolListEntry;
    const pool = {
      id: "p1",
      name: "pool-one",
      record_name: "www",
      record_type: "A",
      enabled: true,
      members: [],
    } as unknown as DNSPool;
    render(
      <ConfirmDeleteModal
        pool={entry}
        pending={false}
        error="Pool is referenced"
        onConfirm={() => {}}
        onClose={() => {}}
      />,
    );
    expect(screen.getByRole("alert").textContent).toBe("Pool is referenced");
    cleanup();
    render(
      <ConfirmDelete
        pool={pool}
        zone={{ name: "example.com." } as DNSZone}
        pending={false}
        error="Pool is referenced"
        onConfirm={() => {}}
        onClose={() => {}}
      />,
    );
    expect(screen.getByRole("alert").textContent).toBe("Pool is referenced");
  });
});
