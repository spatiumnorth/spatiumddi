/**
 * @vitest-environment jsdom
 *
 * The request portal says what happened in words (#3246, #3251, #3252,
 * #3253).
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

import type { ProvisioningRequest, RequestKind } from "@/lib/api";

const rows = vi.fn();
const approve = vi.fn();
const submit = vi.fn();
const getTemplate = vi.fn();
const catalog = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: { ...actual.authApi, me: async () => ({ id: "u9" }) },
    ipamApi: {
      ...actual.ipamApi,
      getTemplate: (id: string) => getTemplate(id),
    },
    requestsApi: {
      ...actual.requestsApi,
      list: () => rows(),
      catalog: () => catalog(),
      approve: (...a: unknown[]) => approve(...a),
      submit: (...a: unknown[]) => submit(...a),
    },
  };
});

vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({ can: () => true, isSuperadmin: false }),
}));

import RequestsPage from "./RequestsPage";

function req(over: Partial<ProvisioningRequest>): ProvisioningRequest {
  return {
    id: "r1",
    operation: "allocate_subnet",
    resource_type: "subnet",
    resource_display: "Carve `10.199.0.0/28` (a /28)",
    args: {},
    preview_text: "Carve `10.199.0.0/28` (a /28)",
    justification: null,
    state: "pending",
    requested_by_user_id: "u1",
    requested_by_display: "alice",
    decided_by_user_id: null,
    decided_by_display: null,
    decision_note: null,
    result: null,
    error: null,
    expires_at: "2026-12-01T00:00:00Z",
    decided_at: null,
    executed_at: null,
    created_at: "2026-10-01T00:00:00Z",
    modified_at: "2026-10-01T00:00:00Z",
    ...over,
  };
}

function prop(title: string, description: string, extra = {}) {
  return { title, description, type: "string", ...extra };
}

const KINDS: RequestKind[] = [
  {
    kind: "subnet",
    label: "New subnet",
    operation: "allocate_subnet",
    description: "Carve a subnet.",
    category: "ipam",
    args_schema: {
      required: ["block_id", "prefix_len"],
      properties: {
        block_id: prop("Block Id", "UUID of the parent IP block to carve", {
          "x-resource": "ip_block",
        }),
        prefix_len: { title: "Prefix Len", type: "integer", description: "x" },
        template_id: prop("Template Id", "Optional IPAM template UUID"),
      },
    },
  },
  {
    kind: "ip_address",
    label: "IP address",
    operation: "create_ip_address",
    description: "Reserve an IP.",
    category: "ipam",
    args_schema: {
      required: ["subnet_id", "address"],
      properties: {
        subnet_id: prop(
          "Subnet Id",
          "UUID of the subnet to create the address in",
          {
            "x-resource": "subnet",
          },
        ),
        address: prop("Address", "The IP address as a string"),
        status: prop(
          "Status",
          "IP status: 'allocated' (default), 'reserved', or 'static_dhcp'",
        ),
        mac_address: prop("Mac Address", "MAC"),
        fqdn: prop("Fqdn", "Fully-qualified"),
      },
    },
  },
  {
    kind: "dns_record",
    label: "DNS record",
    operation: "create_dns_record",
    description: "Create a record.",
    category: "dns",
    args_schema: {
      required: ["zone_id", "name", "record_type", "value"],
      properties: {
        zone_id: prop("Zone Id", "UUID of the parent DNS zone.", {
          "x-resource": "dns_zone",
        }),
        name: prop("Name", "Use ``@`` for the zone apex. Do NOT include ``x``"),
        record_type: prop("Record Type", "Record type — A / AAAA"),
        value: prop("Value", "Right-hand-side value."),
        ttl: {
          title: "Ttl",
          type: "integer",
          description: "None inherits the zone's default",
        },
      },
    },
  },
  {
    kind: "dhcp_reservation",
    label: "DHCP reservation",
    operation: "create_dhcp_static",
    description: "Pin a MAC.",
    category: "dhcp",
    args_schema: {
      required: ["scope_id", "ip_address", "mac_address"],
      properties: {
        scope_id: prop("Scope Id", "UUID of the parent DHCP scope.", {
          "x-resource": "dhcp_scope",
        }),
        ip_address: prop("Ip Address", "IP to reserve"),
        mac_address: prop("Mac Address", "MAC address"),
      },
    },
  },
];

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <RequestsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  for (const m of [rows, approve, submit, getTemplate, catalog]) m.mockReset();
});

describe("a failed approval is said at the moment of approving (#3246)", () => {
  it("keeps the dialog open and shows the reason", async () => {
    rows.mockResolvedValue([req({})]);
    approve.mockResolvedValue(
      req({
        state: "failed",
        error: "Address 10.199.5.60 is already allocated in subnet.",
      }),
    );
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Approve and provision" }),
    );
    expect(await screen.findByText(/could not be provisioned/i)).toBeTruthy();
    expect(screen.getByText(/already allocated in subnet/)).toBeTruthy();
    // still open: the dialog title is on screen
    expect(screen.getAllByText("Approve and provision").length).toBeGreaterThan(
      0,
    );
  });

  it("closes the dialog when the approval worked", async () => {
    rows.mockResolvedValue([req({})]);
    approve.mockResolvedValue(req({ state: "executed" }));
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Approve and provision" }),
    );
    await waitFor(() =>
      expect(screen.queryByText("Note (optional)")).toBeNull(),
    );
  });
});

describe("a failed approval never reads as a success (#3246)", () => {
  async function approveWith(result: () => Promise<unknown>) {
    rows.mockResolvedValue([req({})]);
    approve.mockImplementation(result);
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Approve and provision" }),
    );
  }

  it("says so when a failed request carries no reason", async () => {
    await approveWith(async () => req({ state: "failed", error: null }));
    expect(await screen.findByText(/no reason was recorded/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Close" })).toBeTruthy();
    expect(
      (
        screen.getByRole("button", {
          name: "Approve and provision",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });

  it.each([
    [
      "a 409",
      { response: { status: 409, data: { detail: "Request is not pending" } } },
      /Request is not pending/,
    ],
    [
      "a 500",
      {
        response: { status: 500, data: { detail: "Internal Server Error" } },
        message: "Request failed with status code 500",
      },
      /Internal Server Error/,
    ],
    ["a network error", { message: "Network Error" }, /Network Error/],
  ])("keeps the dialog open with the error on %s", async (_, err, shown) => {
    await approveWith(async () => {
      throw err;
    });
    expect(await screen.findByText(shown)).toBeTruthy();
    expect(screen.getByText("Note (optional)")).toBeTruthy();
  });
});

describe("the list shows each request once, in plain words (#3252)", () => {
  it("prints the text once, with no Markdown", async () => {
    const text = "Create **A** record `host-a` in zone `example.test.`";
    rows.mockResolvedValue([
      req({ resource_display: text, preview_text: text }),
    ]);
    renderPage();
    await screen.findByText(/Create A record host-a in zone example.test./);
    expect(screen.getAllByText(/Create A record host-a/).length).toBe(1);
    expect(document.body.textContent).not.toMatch(/\*\*|`/);
  });

  it("keeps a wildcard record name's asterisk", async () => {
    const text = "Create **A** record `*.lab` in zone `example.test.`";
    rows.mockResolvedValue([
      req({ resource_display: text, preview_text: text }),
    ]);
    renderPage();
    expect(
      await screen.findByText("Create A record *.lab in zone example.test."),
    ).toBeTruthy();
  });

  it("headlines the subnet an executed request carved", async () => {
    rows.mockResolvedValue([
      req({
        state: "executed",
        resource_display: "Carve `10.199.0.0/28` (a /28)",
        preview_text: "Carve `10.199.0.16/28` (a /28)",
      }),
    ]);
    renderPage();
    await screen.findByText(/10\.199\.0\.16\/28/);
    expect(document.body.textContent).not.toContain("10.199.0.0/28");
  });

  it("names an empty state by the filter's own label", async () => {
    rows.mockResolvedValue([]);
    renderPage();
    fireEvent.change(await screen.findByDisplayValue("Pending"), {
      target: { value: "executed" },
    });
    expect(
      await screen.findByText(/No requests in state "Provisioned"/),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain('"executed"');
  });
});

describe("the approver is shown the template (#3251)", () => {
  it("names it on the row and in the dialog", async () => {
    getTemplate.mockResolvedValue({ id: "t1", name: "Branch office" });
    rows.mockResolvedValue([req({ args: { template_id: "t1" } })]);
    renderPage();
    expect(await screen.findByText("Branch office")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(screen.getAllByTestId("request-template").length).toBe(2),
    );
  });

  it("shows the id when the template cannot be read, never undefined", async () => {
    getTemplate.mockRejectedValue({ response: { status: 403 } });
    rows.mockResolvedValue([req({ args: { template_id: "tpl-42" } })]);
    renderPage();
    const line = await screen.findByTestId("request-template");
    await waitFor(() => expect(getTemplate).toHaveBeenCalled());
    await waitFor(() => expect(line.textContent).toContain("tpl-42"));
    expect(line.textContent).not.toMatch(/undefined|…/);
  });

  it("shows the id while the lookup is still pending", async () => {
    getTemplate.mockReturnValue(new Promise(() => {}));
    rows.mockResolvedValue([req({ args: { template_id: "tpl-43" } })]);
    renderPage();
    const line = await screen.findByTestId("request-template");
    expect(line.textContent).toContain("tpl-43");
    expect(line.textContent).not.toMatch(/undefined|…/);
  });

  it("shows nothing when the request names no template", async () => {
    rows.mockResolvedValue([req({ args: {} })]);
    renderPage();
    await screen.findByText(/Carve 10.199.0.0\/28/);
    expect(screen.queryByTestId("request-template")).toBeNull();
  });
});

describe("the New request form speaks in words (#3253)", () => {
  async function openForm(kindLabel: string) {
    catalog.mockResolvedValue(KINDS);
    rows.mockResolvedValue([]);
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /New request/ }));
    const select = await screen.findByDisplayValue("Select…");
    await screen.findByRole("option", { name: kindLabel });
    fireEvent.change(select, {
      target: { value: KINDS.find((k) => k.label === kindLabel)!.kind },
    });
  }

  it.each(KINDS.map((k) => k.label))(
    "%s has no schema words",
    async (label) => {
      await openForm(label);
      await screen.findByText(/^(Block|Subnet|Zone|Scope)/);
      const text = document.body.textContent ?? "";
      expect(text).not.toMatch(
        /UUID of|``|\bBlock Id\b|\bPrefix Len\b|\bTtl\b/,
      );
      expect(text).not.toMatch(/Fqdn|\bIp Address\b|\bMac Address\b|\w+ Id\b/);
    },
  );

  it("offers status as a choice of all seven", async () => {
    await openForm("IP address");
    const options = (
      await screen.findAllByRole("option", { name: "Static DHCP" })
    ).length;
    expect(options).toBe(1);
    const status = screen
      .getByRole("option", { name: "Static DHCP" })
      .closest("select") as HTMLSelectElement;
    // Seven statuses plus the blank "—", each read in words but submitted
    // as the API's value.
    expect(status.options.length).toBe(8);
    expect(
      (screen.getByRole("option", { name: "Static DHCP" }) as HTMLOptionElement)
        .value,
    ).toBe("static_dhcp");
    expect(screen.queryByRole("option", { name: "static_dhcp" })).toBeNull();
  });

  it("explains a refusal in the form's own labels", async () => {
    // The server's 422 field errors (#3253), as requests/service.py answers.
    submit.mockRejectedValue({
      response: {
        status: 422,
        data: {
          detail: [
            {
              type: "missing",
              loc: ["body", "args", "subnet_id"],
              msg: "Field required",
            },
            {
              type: "missing",
              loc: ["body", "args", "address"],
              msg: "Field required",
            },
            {
              type: "value_error",
              loc: ["body", "args", "status"],
              msg: "Value error, status must be one of: allocated, reserved",
            },
          ],
        },
      },
    });
    await openForm("IP address");
    fireEvent.click(screen.getByRole("button", { name: "Submit request" }));
    const err = await screen.findByText(/Subnet is required/);
    expect(err.textContent).toContain("IP address is required");
    expect(err.textContent).toContain("Status must be one of: allocated");
    expect(err.textContent).not.toMatch(
      /Value error|Field required|subnet_id|address:/,
    );
  });
});
