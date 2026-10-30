/**
 * @vitest-environment jsdom
 *
 * A holder whose grant names ONE block, space, customer, site or provider can
 * reach that item in the console and edit it (#3134, the console half of
 * #3039).
 *
 * The API lets `{read|write, ip_block, X}` through to `GET /blocks` (narrowed
 * to X) and `GET`/`PUT /blocks/X`, while `GET /spaces` and `GET /subnets`
 * answer 403. The console used to show only "You don't have permission to see
 * IP spaces", wait for all three lists before opening `?block=X`, and ask
 * "write on IP blocks" with no id for Edit, which a scoped grant never
 * matches. Likewise Edit Space and the customer / site / provider row Edit.
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
import type { IPBlock, IPSpace } from "@/lib/api";

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

const { IPAMPage } = await import("./IPAMPage");
const { CustomersPage } = await import("../network/CustomersPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
  sessionStorage.clear();
});

const block = {
  id: "blk-x",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.88.0.0/16",
  name: "team-block",
  description: "",
  dns_group_ids: [],
  custom_fields: {},
  tags: {},
} as unknown as IPBlock;

const space = {
  id: "sp-x",
  name: "team-space",
  description: "",
  custom_fields: {},
  tags: {},
} as unknown as IPSpace;

const refused = () =>
  Promise.reject(
    Object.assign(new Error("forbidden"), {
      response: { status: 403, data: { detail: "Permission denied" } },
    }),
  );

function grants(type: string, readId: string, writeId = readId) {
  return () =>
    Promise.resolve({
      is_superadmin: false,
      grants: [
        { action: "read", resource_type: type, resource_id: readId },
        { action: "write", resource_type: type, resource_id: writeId },
      ],
    });
}

function mount(ui: React.ReactNode, url = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const settle = () => new Promise((r) => setTimeout(r, 50));

function blockScoped(writeId = "blk-x") {
  answers.authApi = { myPermissions: grants("ip_block", "blk-x", writeId) };
  answers.ipamApi = {
    listSpaces: refused,
    listSubnets: refused,
    listBlocks: () => Promise.resolve([block]),
  };
}

describe("a grant scoped to one block", () => {
  it("lists the block under the refused spaces and opens it with Edit enabled", async () => {
    blockScoped();
    mount(<IPAMPage />, "/ipam");

    const list = await screen.findByRole("list", {
      name: "Blocks and subnets you can open",
    });
    fireEvent.click(within(list).getByText("10.88.0.0/16"));

    const edit = (await screen.findByRole("button", {
      name: "Edit",
    })) as HTMLButtonElement;
    await waitFor(() => expect(edit.disabled).toBe(false));
  });

  it("opens /ipam?block=X although spaces and subnets are refused", async () => {
    blockScoped();
    mount(<IPAMPage />, "/ipam?block=blk-x");

    const edit = (await screen.findByRole("button", {
      name: "Edit",
    })) as HTMLButtonElement;
    await waitFor(() => expect(edit.disabled).toBe(false));
    // The structural tools stay on the type-level write the server asks.
    expect(
      (
        screen.getByRole("button", {
          name: "Add child block",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });

  it("keeps Edit disabled when the write grant names a different block", async () => {
    blockScoped("blk-other");
    mount(<IPAMPage />, "/ipam?block=blk-x");

    const edit = (await screen.findByRole("button", {
      name: "Edit",
    })) as HTMLButtonElement;
    await settle();
    expect(edit.disabled).toBe(true);
  });
});

describe("a grant scoped to one space", () => {
  it("opens the space with Edit Space enabled", async () => {
    answers.authApi = { myPermissions: grants("ip_space", "sp-x") };
    answers.ipamApi = {
      listSpaces: () => Promise.resolve([space]),
      listBlocks: refused,
      listSubnets: refused,
    };
    mount(<IPAMPage />, "/ipam?space=sp-x");

    const edit = (await screen.findByRole("button", {
      name: "Edit Space",
    })) as HTMLButtonElement;
    await waitFor(() => expect(edit.disabled).toBe(false));
  });
});

describe("a grant scoped to one customer", () => {
  it("enables Edit on that customer's row and keeps Delete off", async () => {
    answers.authApi = { myPermissions: grants("customer", "c1") };
    answers.customersApi = {
      list: () =>
        Promise.resolve({
          items: [
            {
              id: "c1",
              name: "acme",
              account_number: null,
              status: "active",
              contact_email: null,
              contact_phone: null,
            },
          ],
          total: 1,
        }),
    };
    mount(<CustomersPage />);

    const edit = (await screen.findByTitle("Edit")) as HTMLButtonElement;
    await waitFor(() => expect(edit.disabled).toBe(false));
    const del = screen.getByTitle(
      "Requires delete permission on customers",
    ) as HTMLButtonElement;
    expect(del.disabled).toBe(true);
  });
});
