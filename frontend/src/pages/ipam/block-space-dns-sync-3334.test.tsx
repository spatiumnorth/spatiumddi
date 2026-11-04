/**
 * @vitest-environment jsdom
 *
 * A block's and a space's Sync DNS are offered only to a holder the server
 * would let through, as the subnet's are since #2571 (#3334). The preview
 * reads the block (or space) and its addresses, and Apply runs the reverse
 * zone backfill and the commit, both write on IP blocks (or IP spaces), all
 * at the type level (`_IPAM_ROUTE_TYPES` in `api/v1/ipam/router.py`). The
 * built-in Viewer (read on everything) used to get both buttons enabled,
 * open the dialog, press Apply and meet two refusals.
 *
 * And when the backfill is refused, the dialog's note says the server's
 * reason, not the HTTP client's "Request failed with status code 403".
 * Real `usePermissions`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
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

const { IPAMPage, DnsSyncModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
  sessionStorage.clear();
});

const space = {
  id: "sp-1",
  name: "lab-space",
  description: "",
  custom_fields: {},
  tags: {},
} as unknown as IPSpace;

const block = {
  id: "blk-1",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.88.0.0/16",
  name: "lab-block",
  description: "",
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 65536,
  dns_group_ids: [],
  custom_fields: {},
  tags: {},
} as unknown as IPBlock;

type G = [string, string, string | null];

/** The built-in Viewer role: read on everything. */
const VIEWER: G[] = [["read", "*", null]];

function signInAs(grants: G[] | "superadmin") {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type, resource_id]) => ({
                action,
                resource_type,
                resource_id,
              })),
            },
      ),
  };
  answers.ipamApi = {
    listSpaces: () => Promise.resolve([space]),
    getSpace: () => Promise.resolve(space),
    listBlocks: () => Promise.resolve([block]),
    getBlock: () => Promise.resolve(block),
    listSubnets: () => Promise.resolve([]),
  };
}

function mount(ui: ReactNode, url = "/") {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

// Let the permission set land: `can()` is false while it loads, so a
// disabled button proves nothing until then.
const settle = () =>
  act(async () => {
    await new Promise((r) => setTimeout(r, 80));
  });

async function syncDnsButton(url: string) {
  mount(<IPAMPage />, url);
  const button = (await screen.findByRole(
    "button",
    { name: "Sync DNS" },
    { timeout: 4000 },
  )) as HTMLButtonElement;
  await settle();
  return button;
}

const NEEDS_BLOCK =
  "Requires read permission on IP blocks and IP addresses, and write permission on IP blocks";
const NEEDS_SPACE =
  "Requires read permission on IP spaces and IP addresses, and write permission on IP spaces";

describe("a block's Sync DNS (#3334)", () => {
  it("is not offered to a Viewer: disabled, with the reason, and opens nothing", async () => {
    signInAs(VIEWER);
    const button = await syncDnsButton("/ipam?block=blk-1");
    expect(button.disabled).toBe(true);
    expect(button.title).toBe(NEEDS_BLOCK);
    fireEvent.click(button);
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("stays disabled for a write grant scoped to this one block (the server asks at the type level)", async () => {
    signInAs([...VIEWER, ["write", "ip_block", "blk-1"]]);
    const button = await syncDnsButton("/ipam?block=blk-1");
    expect(button.disabled).toBe(true);
    expect(button.title).toBe(NEEDS_BLOCK);
  });

  it("is offered to a holder with write on IP blocks, and opens the dialog", async () => {
    signInAs([...VIEWER, ["write", "ip_block", null]]);
    const button = await syncDnsButton("/ipam?block=blk-1");
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    expect((await screen.findByRole("dialog")).textContent ?? "").toContain(
      "across all subnets in this block",
    );
  });

  it("is offered to a superadmin", async () => {
    signInAs("superadmin");
    expect((await syncDnsButton("/ipam?block=blk-1")).disabled).toBe(false);
  });
});

describe("a space's Sync DNS (#3334)", () => {
  it("is not offered to a Viewer: disabled, with the reason, and opens nothing", async () => {
    signInAs(VIEWER);
    const button = await syncDnsButton("/ipam?space=sp-1");
    expect(button.disabled).toBe(true);
    expect(button.title).toBe(NEEDS_SPACE);
    fireEvent.click(button);
    await settle();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("stays disabled for a write grant scoped to this one space", async () => {
    signInAs([...VIEWER, ["write", "ip_space", "sp-1"]]);
    const button = await syncDnsButton("/ipam?space=sp-1");
    expect(button.disabled).toBe(true);
    expect(button.title).toBe(NEEDS_SPACE);
  });

  it("is offered to a holder with write on IP spaces, and opens the dialog", async () => {
    signInAs([...VIEWER, ["write", "ip_space", null]]);
    const button = await syncDnsButton("/ipam?space=sp-1");
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    expect((await screen.findByRole("dialog")).textContent ?? "").toContain(
      "across all subnets in this space",
    );
  });
});

// One mismatched row, so the dialog offers Apply (1).
const PREVIEW = {
  subnet_id: "sn-1",
  forward_zone_id: null,
  forward_zone_name: null,
  reverse_zone_id: null,
  reverse_zone_name: null,
  missing: [],
  mismatched: [
    {
      record_id: "rec-1",
      ip_id: "ip-1",
      ip_address: "10.88.1.10",
      record_type: "A",
      zone_id: "z-1",
      zone_name: "lab.example.",
      current_name: "h1",
      current_value: "10.88.1.99",
      expected_name: "h1",
      expected_value: "10.88.1.10",
    },
  ],
  stale: [],
};

const REASON = "Permission denied: need 'write' on each of ['ip_block']";

// What axios hands the caller for a refused request: its own message, and
// the server's answer under `response`.
const refused = () =>
  Promise.reject(
    Object.assign(new Error("Request failed with status code 403"), {
      response: { status: 403, data: { detail: REASON } },
    }),
  );

async function applyWithBackfill(backfill: Answer, commit: Answer) {
  answers.ipamApi = {
    dnsSyncPreviewBlock: () => Promise.resolve(PREVIEW),
    backfillReverseZonesBlock: backfill,
    dnsSyncCommitBlock: commit,
  };
  mount(
    <DnsSyncModal
      scope={{ kind: "block", id: "blk-1", label: "10.88.0.0/16" }}
      onClose={() => {}}
    />,
  );
  const apply = await screen.findByRole("button", { name: "Apply (1)" });
  await act(async () => {
    fireEvent.click(apply);
  });
  return (await screen.findByText(/Reverse-zone backfill skipped:/))
    .textContent;
}

describe("the Sync DNS dialog's backfill note (#3334)", () => {
  it("says the server's reason when the backfill is refused", async () => {
    const note = await applyWithBackfill(refused, refused);
    expect(note).toBe(`Reverse-zone backfill skipped: ${REASON}`);
    expect(note).not.toContain("Request failed with status code");
    // The commit's own refusal is said beside it, as #3323 made it.
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(REASON),
    );
  });

  it("keeps the error's own message when the answer carries no reason", async () => {
    const note = await applyWithBackfill(
      () => Promise.reject(new Error("Network Error")),
      () => Promise.resolve({ created: 0, updated: 1, deleted: 0, errors: [] }),
    );
    expect(note).toBe("Reverse-zone backfill skipped: Network Error");
  });
});
