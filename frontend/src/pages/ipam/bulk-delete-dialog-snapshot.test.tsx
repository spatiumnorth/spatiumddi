/**
 * @vitest-environment jsdom
 *
 * A delete the two-person approval queue took says so (#1915).
 *
 * With `governance.approvals` on and a policy matching, DELETE on an IP
 * space / block / subnet answers 202 with a queued change request and the
 * object stays. The IPAM tree's Delete… dialogs, Edit Space and Edit Block
 * read the response as "deleted": they closed on the 202 with no word,
 * while Edit Subnet said "Submitted for approval" — in its red error box.
 *
 * Each now says so in a neutral status box (a queued request is not an
 * error), leaves the object where it is, and stops offering to send the
 * delete again, since a second click would file a second change request.
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
import type { IPBlock, IPSpace, Subnet } from "@/lib/api";

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

// Radix's context menu opens fine under jsdom but then stalls the event loop
// for ~25 s (layout reads jsdom does slowly), so each row's menu is rendered
// inline as plain buttons. What is under test is the dialog the item opens.
vi.mock("@/components/ui/context-menu", () => {
  const Pass = ({ children }: { children?: ReactNode }) => <>{children}</>;
  return {
    ContextMenu: Pass,
    ContextMenuTrigger: Pass,
    ContextMenuPortal: Pass,
    ContextMenuGroup: Pass,
    ContextMenuContent: Pass,
    ContextMenuLabel: () => null,
    ContextMenuSeparator: () => null,
    ContextMenuItem: ({
      children,
      onSelect,
    }: {
      children?: ReactNode;
      onSelect?: () => void;
    }) => (
      <button type="button" onClick={() => onSelect?.()}>
        {children}
      </button>
    ),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { BlockDetailView, SpaceTableView } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const QUEUED = Promise.resolve({
  status: 202,
  data: { change_request_id: "cr-1", state: "pending", preview_text: "x" },
});

const topDialog = () => screen.getAllByRole("dialog").at(-1)!;

// #2046 — a bulk delete the approval queue takes clears the page's
// selection while the dialog stays open to say so. The dialog must keep
// describing what was submitted, not recount an empty selection.
describe("space bulk delete dialog after the approval queue took it", () => {
  const space = { id: "sp-1", name: "lab" } as IPSpace;
  const block = {
    id: "b-1",
    space_id: "sp-1",
    parent_block_id: null,
    network: "10.73.0.0/16",
    utilization_percent: 0,
    total_ips: 65536,
    allocated_ips: 0,
  } as IPBlock;
  const mk = (n: number) =>
    ({
      id: `sn-${n}`,
      space_id: "sp-1",
      block_id: "b-1",
      network: `10.73.${n}.0/24`,
      utilization_percent: 0,
      total_ips: 254,
      allocated_ips: 0,
    }) as Subnet;

  async function walk(
    queued: boolean,
    respond?: (id: string, force?: boolean) => Promise<unknown>,
  ) {
    const deleteSubnet = vi.fn<Answer>((...args) =>
      respond
        ? respond(args[0] as string, args[1] as boolean | undefined)
        : queued
          ? QUEUED
          : Promise.resolve({ status: 204, data: "" }),
    );
    answers.ipamApi = {
      listBlocks: () => Promise.resolve([block]),
      listSubnets: () => Promise.resolve([mk(5), mk(6)]),
      deleteSubnet,
    };
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <SpaceTableView
            space={space}
            onSelectSubnet={() => {}}
            onSelectBlock={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByText("10.73.5.0/24");
    fireEvent.click(screen.getByLabelText("Select all selectable rows"));
    fireEvent.click(
      await screen.findByRole("button", { name: /^Delete \(2\)/ }),
    );
    expect(topDialog().textContent).toMatch(/Delete 2 subnets/);
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Continue" }),
    );
    fireEvent.click(within(topDialog()).getByRole("checkbox"));
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Move to Trash" }),
    );
    return deleteSubnet;
  }

  it("still says 2 subnets once the selection clears", async () => {
    const deleteSubnet = await walk(true);
    const notice = await within(topDialog()).findByRole("status");
    expect(notice.textContent).toMatch(/2 of 2 submitted for approval/);
    expect(deleteSubnet).toHaveBeenCalledTimes(2);
    const text = topDialog().textContent ?? "";
    expect(text).toMatch(/This will move 2 subnets to Trash/);
    expect(text).toMatch(/I understand 2 subnets will be moved to Trash/);
    expect(text).not.toMatch(/\b0\b/);
  });

  it("a real delete still closes the dialog", async () => {
    await walk(false);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("counts a later delete afresh once the dialog is closed", async () => {
    await walk(true);
    await within(topDialog()).findByRole("status");
    fireEvent.click(within(topDialog()).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    fireEvent.click(screen.getByLabelText("Select 10.73.5.0/24"));
    fireEvent.click(
      await screen.findByRole("button", { name: /^Delete \(1\)/ }),
    );
    expect(within(topDialog()).getByRole("heading").textContent).toBe(
      "Delete 1 subnet",
    );
    expect(topDialog().textContent).toMatch(/This will move 1 subnet to/);
  });

  it("a retry after a partial failure resends only what failed", async () => {
    const deleteSubnet = await walk(false, (id) =>
      id === "sn-6"
        ? Promise.reject({ response: { data: { detail: "in use" } } })
        : Promise.resolve({ status: 204, data: "" }),
    );
    await within(topDialog()).findByText(/1 of 2 items could not be deleted/);
    expect(topDialog().textContent).toMatch(/This will move 1 subnet to Trash/);
    deleteSubnet.mockClear();
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Move to Trash" }),
    );
    await waitFor(() => expect(deleteSubnet).toHaveBeenCalledTimes(1));
    expect(deleteSubnet).toHaveBeenCalledWith("sn-6", true);
  });
});

// #2046 — the block view has the same dialog, mixing subnets and empty
// child blocks.
describe("block bulk delete dialog after the approval queue took it", () => {
  const parent = {
    id: "b-1",
    space_id: "sp-1",
    parent_block_id: null,
    network: "10.73.0.0/16",
    utilization_percent: 0,
    total_ips: 65536,
    allocated_ips: 0,
  } as IPBlock;
  const child = {
    ...parent,
    id: "b-2",
    parent_block_id: "b-1",
    network: "10.73.128.0/17",
  } as IPBlock;
  const subnet = {
    id: "sn-5",
    space_id: "sp-1",
    block_id: "b-1",
    network: "10.73.5.0/24",
    utilization_percent: 0,
    total_ips: 254,
    allocated_ips: 0,
  } as Subnet;

  it("still says 1 subnet + 1 block once the selection clears", async () => {
    const deleteSubnet = vi.fn(() => QUEUED);
    const deleteBlock = vi.fn(() => QUEUED);
    answers.ipamApi = { deleteSubnet, deleteBlock };
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <BlockDetailView
            block={parent}
            spaceName="lab"
            ancestors={[]}
            allBlocks={[parent, child]}
            allSubnets={[subnet]}
            onSelectSpace={() => {}}
            onSelectBlock={() => {}}
            onSelectSubnet={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByText("10.73.5.0/24");
    fireEvent.click(screen.getByLabelText("Select all selectable rows"));
    fireEvent.click(
      await screen.findByRole("button", { name: /^Delete \(2\)/ }),
    );
    expect(topDialog().textContent).toMatch(/Delete 1 subnet \+ 1 block/);
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Continue" }),
    );
    fireEvent.click(within(topDialog()).getByRole("checkbox"));
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Move to Trash" }),
    );
    const notice = await within(topDialog()).findByRole("status");
    expect(notice.textContent).toMatch(/2 of 2 submitted for approval/);
    expect(deleteSubnet).toHaveBeenCalledWith("sn-5", true);
    expect(deleteBlock).toHaveBeenCalledWith("b-2");
    const text = topDialog().textContent ?? "";
    expect(text).toMatch(/This will move 1 subnet and 1 empty block to Trash/);
    expect(text).toMatch(/I understand 1 subnet \+ 1 block will be moved/);
    expect(text).not.toMatch(/\b0\b/);
  });
});
