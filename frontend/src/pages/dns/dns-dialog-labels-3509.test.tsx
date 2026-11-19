/**
 * @vitest-environment jsdom
 *
 * #3509: the DNS page's own Field helper drew each label beside its box,
 * with no htmlFor and without wrapping it, so the label named nothing. Edit
 * Zone's "Default TTL (seconds)" box had no accessible name, only its
 * placeholder, and so did every box of the zone, record and view dialogs
 * and the server group's options. Each label now names its box, as the DHCP
 * (#1994) and IPAM (#3340) dialogs' labels do. A label over a picker or a
 * checkbox row names the group around it.
 *
 * Every API call stays pending unless a test answers it.
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
import type { DNSRecord, DNSZone } from "@/lib/api";

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
}));

const { OptionsTab, RecordModal, ViewModal, ZoneModal } =
  await import("./DNSPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}

function open(ui: ReactNode, isSuperadmin = true) {
  answer("authApi", "myPermissions", () =>
    Promise.resolve({ is_superadmin: isSuperadmin, grants: [] }),
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Each box a Field draws that nothing names: not a label of its own, not
 *  an aria-label, not the labelled group around a picker or a checkbox row.
 *  A Field is its wrapper div with the field's label first. */
function boxesNamedByNothing(): string[] {
  const fields = Array.from(
    document.querySelectorAll("div.space-y-1 > label.text-xs.font-medium"),
  )
    .filter((l) => l === l.parentElement!.firstElementChild)
    .map((l) => l.parentElement!);
  return fields.flatMap((field) =>
    Array.from(
      field.querySelectorAll<HTMLInputElement>("input, select, textarea"),
    )
      .filter(
        (box) =>
          box.type !== "hidden" &&
          !box.labels?.length &&
          !box.getAttribute("aria-label") &&
          !box.getAttribute("aria-labelledby") &&
          !box.closest("[role=group][aria-labelledby]"),
      )
      .map(
        (box) =>
          `${field.firstElementChild!.textContent}: <${box.tagName.toLowerCase()}>`,
      ),
  );
}

/** No label names nothing, points at a missing id, or shares an id. */
function expectLabelsSound() {
  const labelled = new Set(
    Array.from(document.querySelectorAll("[aria-labelledby]")).flatMap((e) =>
      e.getAttribute("aria-labelledby")!.split(/\s+/),
    ),
  );
  const orphans = Array.from(document.querySelectorAll("label"))
    .filter(
      (l) =>
        !l.control &&
        !l.querySelector("input,select,textarea") &&
        !(l.id && labelled.has(l.id)),
    )
    .map((l) => l.textContent);
  expect(orphans).toEqual([]);
  for (const l of Array.from(document.querySelectorAll("label[for]"))) {
    expect(document.getElementById(l.getAttribute("for")!)).not.toBeNull();
  }
  const ids = Array.from(document.querySelectorAll("[id]")).map((e) => e.id);
  expect(new Set(ids).size).toBe(ids.length);
}

const zone = {
  id: "zone-1",
  group_id: "grp-1",
  view_id: null,
  name: "corp.example.test.",
  zone_type: "primary",
  kind: "forward",
  ttl: 7200,
  primary_ns: "ns1.corp.example.test.",
  admin_email: "hostmaster@corp.example.test",
  dnssec_enabled: false,
  color: null,
  forwarders: [],
  forward_only: true,
  masters: [],
  domain_id: null,
  customer_id: null,
} as unknown as DNSZone;

describe("Edit Zone (#3509)", () => {
  function openEditZone() {
    answer("dnsApi", "listGroups", () =>
      Promise.resolve([{ id: "grp-1", server_drivers: ["bind9"] }]),
    );
    answer("dnsApi", "listZones", () => Promise.resolve([zone]));
    open(
      <ZoneModal groupId="grp-1" views={[]} zone={zone} onClose={() => {}} />,
    );
  }

  it("Default TTL (seconds) is found by its label and holds the zone's TTL", async () => {
    openEditZone();
    const ttl = (await screen.findByLabelText(
      "Default TTL (seconds)",
    )) as HTMLInputElement;
    expect(ttl.tagName).toBe("INPUT");
    expect(ttl.value).toBe("7200");
  });

  it("every box of the dialog is named by its label", async () => {
    openEditZone();
    await screen.findByText("Default TTL (seconds)");
    for (const [label, value] of [
      // The dialog shows the name without its trailing dot.
      ["Zone Name (FQDN)", "corp.example.test"],
      ["Primary NS", "ns1.corp.example.test."],
      ["Admin Email", "hostmaster@corp.example.test"],
    ]) {
      expect((screen.getByLabelText(label) as HTMLInputElement).value).toBe(
        value,
      );
    }
    expect(screen.getByLabelText("Kind").tagName).toBe("SELECT");
    expect(screen.getByLabelText("Customer (optional)").tagName).toBe("DIV");
    expect(boxesNamedByNothing()).toEqual([]);
    expectLabelsSound();
  });
});

describe("Add Record (#3509)", () => {
  it("Value names the box for an A record and for a LUA snippet", async () => {
    open(
      <RecordModal
        groupId="grp-1"
        zoneId="zone-1"
        zoneName="corp.example.test."
        onClose={() => {}}
      />,
    );
    expect((await screen.findByLabelText("Value")).tagName).toBe("INPUT");
    expect(boxesNamedByNothing()).toEqual([]);
    expectLabelsSound();

    // LUA is offered once the permissions answer says superadmin (#3637).
    await waitFor(() =>
      expect(
        within(screen.getByLabelText("Type")).queryByRole("option", {
          name: "LUA",
        }),
      ).not.toBeNull(),
    );
    fireEvent.change(screen.getByLabelText("Type"), {
      target: { value: "LUA" },
    });
    expect(screen.getByLabelText("Value").tagName).toBe("TEXTAREA");
    // The snippet picker beside it keeps its own name.
    expect(screen.getByLabelText("Insert LUA snippet template").tagName).toBe(
      "SELECT",
    );
    expect(boxesNamedByNothing()).toEqual([]);
    expectLabelsSound();
  });
});

describe("Add Record LUA type (#3637)", () => {
  it("is not offered to a user who is not a superadmin", async () => {
    open(
      <RecordModal
        groupId="grp-1"
        zoneId="zone-1"
        zoneName="corp.example.test."
        onClose={() => {}}
      />,
      false,
    );
    expect((await screen.findByLabelText("Value")).tagName).toBe("INPUT");
    const type = screen.getByLabelText("Type");
    expect(within(type).queryByRole("option", { name: "LUA" })).toBeNull();
    expect(
      within(type).queryByRole("option", { name: "ALIAS" }),
    ).not.toBeNull();
  });
});

describe("Edit Record LUA snippet (#3637)", () => {
  const lua: DNSRecord = {
    id: "rec-1",
    zone_id: "zone-1",
    view_id: null,
    name: "p1",
    fqdn: "p1.corp.example.test.",
    record_type: "LUA",
    value: "A \"'192.0.2.1'\"",
    ttl: 300,
    priority: null,
    weight: null,
    port: null,
    auto_generated: false,
    tailscale_tenant_id: null,
    pool_member_id: null,
    created_at: "2026-11-06T00:00:00.000Z",
    modified_at: "2026-11-06T00:00:00.000Z",
  };

  function openEdit(isSuperadmin: boolean) {
    answer("authApi", "myPermissions", () =>
      Promise.resolve({ is_superadmin: isSuperadmin, grants: [] }),
    );
    // The dialog re-reads the row from the records list before it opens.
    const qc = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
          queryFn: ({ queryKey }) =>
            queryKey[0] === "dns-records" ? [lua] : [],
        },
      },
    });
    qc.setQueryData(["dns-records", "zone-1"], [lua]);
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <RecordModal
            groupId="grp-1"
            zoneId="zone-1"
            zoneName="corp.example.test."
            record={lua}
            onClose={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  it("is read-only, with no snippet picker, for a user who is not a superadmin", async () => {
    openEdit(false);
    const value = await screen.findByLabelText("Value");
    expect(value.tagName).toBe("TEXTAREA");
    expect((value as HTMLTextAreaElement).readOnly).toBe(true);
    expect(screen.queryByLabelText("Insert LUA snippet template")).toBeNull();
  });

  it("is editable, with the snippet picker, for a superadmin", async () => {
    openEdit(true);
    await waitFor(() =>
      expect(
        (screen.getByLabelText("Value") as HTMLTextAreaElement).readOnly,
      ).toBe(false),
    );
    expect(screen.getByLabelText("Insert LUA snippet template")).not.toBeNull();
  });
});

describe("New View (#3509)", () => {
  it("every box is named, the Recursion checkbox by its own row", async () => {
    open(<ViewModal groupId="grp-1" view={null} onClose={() => {}} />);
    for (const label of ["Name", "Order", "Description"]) {
      expect(["INPUT", "TEXTAREA"], label).toContain(
        (await screen.findByLabelText(label)).tagName,
      );
    }
    const recursion = screen.getByRole("group", { name: "Recursion" });
    expect(
      within(recursion).getByRole("checkbox", {
        name: "Answer recursive queries",
      }),
    ).toBeTruthy();
    expect(boxesNamedByNothing()).toEqual([]);
    expectLabelsSound();
  });
});

describe("the server group's options (#3509)", () => {
  it("the resolver preset and the upstream resolvers are named by their labels", async () => {
    answer("dnsApi", "getOptions", () =>
      Promise.resolve({
        forwarders: ["1.1.1.1"],
        allow_query: [],
        allow_recursion: [],
        allow_transfer: [],
        rrl_exempt_clients: [],
        forward_policy: "first",
        forward_transport: "do53",
        dnssec_validation: "auto",
        recursion_enabled: true,
        dot_port: 853,
        doh_port: 443,
        doq_port: 853,
        doh_path: "/dns-query",
        tls_certificate_id: null,
      }),
    );
    answer("dnsApi", "forwarderPresets", () =>
      Promise.resolve({ version: "test", presets: [] }),
    );
    answer("dnsApi", "listServers", () => Promise.resolve([]));
    open(<OptionsTab groupId="grp-1" />);
    const resolvers = (await screen.findByLabelText(
      "Upstream resolvers (one per line)",
    )) as HTMLTextAreaElement;
    expect(resolvers.tagName).toBe("TEXTAREA");
    expect(resolvers.value).toBe("1.1.1.1");
    expect(screen.getByLabelText("Use a well-known resolver").tagName).toBe(
      "SELECT",
    );
    expect(screen.getByLabelText("Forward policy").tagName).toBe("SELECT");
    expect(boxesNamedByNothing()).toEqual([]);
    expectLabelsSound();
  });
});
