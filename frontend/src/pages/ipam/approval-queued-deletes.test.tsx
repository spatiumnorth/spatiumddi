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

const { EditSpaceModal, EditBlockModal, EditSubnetModal, SpaceSection } =
  await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const QUEUED = Promise.resolve({
  status: 202,
  data: { change_request_id: "cr-1", state: "pending", preview_text: "x" },
});

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const topDialog = () => screen.getAllByRole("dialog").at(-1)!;

/** Tick the final step's box and press its destructive button. */
async function confirmMoveToTrash() {
  fireEvent.click(within(topDialog()).getByRole("checkbox"));
  const confirm = within(topDialog()).getByRole("button", {
    name: "Move to Trash",
  }) as HTMLButtonElement;
  await waitFor(() => expect(confirm.disabled).toBe(false));
  fireEvent.click(confirm);
}

async function walkDelete(openLabel: RegExp) {
  fireEvent.click(await screen.findByRole("button", { name: "Danger zone" }));
  fireEvent.click(screen.getByRole("button", { name: openLabel }));
  fireEvent.click(
    within(topDialog()).getByRole("button", { name: "Continue" }),
  );
  await confirmMoveToTrash();
}

/** The queued message is a neutral status, not an error, and the dialog
 *  no longer offers to send the delete a second time. */
async function expectQueuedNotice(deleteCall: ReturnType<typeof vi.fn>) {
  const notice = await within(topDialog()).findByRole("status");
  expect(notice.textContent).toMatch(/Submitted for approval/);
  expect(notice.className).not.toMatch(/destructive/);
  expect(
    (
      within(topDialog()).getByRole("button", {
        name: "Move to Trash",
      }) as HTMLButtonElement
    ).disabled,
  ).toBe(true);
  expect(
    within(topDialog()).getByRole("button", { name: "Close" }),
  ).toBeTruthy();
  expect(deleteCall).toHaveBeenCalledTimes(1);
}

describe("a delete the approval queue took", () => {
  it("Edit Space says it was submitted and does not report it deleted", async () => {
    const deleteSpace = vi.fn(() => QUEUED);
    const space = { id: "sp-1", name: "s" } as IPSpace;
    // The Danger-zone Delete is gated on delete on this item (#3134); this
    // test is about what the delete does, so sign in as a superadmin.
    answers.authApi = {
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    };
    answers.ipamApi = { deleteSpace, getSpace: () => Promise.resolve(space) };
    const onDeleted = vi.fn();
    open(
      <EditSpaceModal space={space} onClose={() => {}} onDeleted={onDeleted} />,
    );
    await walkDelete(/^Delete this IP space/);
    await expectQueuedNotice(deleteSpace);
    expect(onDeleted).not.toHaveBeenCalled();
  });

  it("Edit Block says it was submitted and does not report it deleted", async () => {
    const deleteBlock = vi.fn(() => QUEUED);
    const block = {
      id: "b-1",
      space_id: "sp-1",
      network: "10.0.0.0/8",
    } as IPBlock;
    // The Danger-zone Delete is gated on delete on this item (#3134); this
    // test is about what the delete does, so sign in as a superadmin.
    answers.authApi = {
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    };
    answers.ipamApi = { deleteBlock, getBlock: () => Promise.resolve(block) };
    const onDeleted = vi.fn();
    open(
      <EditBlockModal block={block} onClose={() => {}} onDeleted={onDeleted} />,
    );
    await walkDelete(/^Delete this block/);
    await expectQueuedNotice(deleteBlock);
    expect(onDeleted).not.toHaveBeenCalled();
  });

  it("Edit Subnet says it in a status, not its error box", async () => {
    const deleteSubnet = vi.fn(() => QUEUED);
    answers.ipamApi = { deleteSubnet };
    // #2571 — the Danger-zone Delete is gated on `delete` on `subnet`; this
    // test is about the 202 the approval queue answers, so sign in as a
    // superadmin who may press it.
    answers.authApi = {
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    };
    const onDeleted = vi.fn();
    open(
      <EditSubnetModal
        subnet={
          {
            id: "sn-1",
            space_id: "sp-1",
            block_id: "b-1",
            network: "10.73.5.0/24",
          } as Subnet
        }
        onClose={() => {}}
        onDeleted={onDeleted}
      />,
    );
    // Permissions arrive asynchronously; the button is disabled until then.
    fireEvent.click(screen.getByRole("button", { name: "Danger zone" }));
    const del = screen.getByRole("button", {
      name: /^Delete this subnet/,
    }) as HTMLButtonElement;
    await waitFor(() => expect(del.disabled).toBe(false));
    fireEvent.click(del);
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Continue" }),
    );
    await confirmMoveToTrash();
    await expectQueuedNotice(deleteSubnet);
    expect(onDeleted).not.toHaveBeenCalled();
  });
});

describe("the IPAM tree's Delete… on a delete the approval queue took", () => {
  const space = { id: "sp-1", name: "lab" } as IPSpace;
  const block = {
    id: "b-1",
    space_id: "sp-1",
    parent_block_id: null,
    network: "10.73.0.0/16",
  } as IPBlock;
  const subnet = {
    id: "sn-1",
    space_id: "sp-1",
    block_id: "b-1",
    network: "10.73.5.0/24",
    utilization_percent: 0,
    total_ips: 254,
  } as Subnet;

  function openTree(onSelectSubnet = vi.fn()) {
    open(
      <SpaceSection
        space={space}
        selectedSubnetId={subnet.id}
        selectedBlockId={null}
        isSpaceSelected={false}
        onSelectSpace={() => {}}
        onSelectSubnet={onSelectSubnet}
        onSelectBlock={() => {}}
      />,
    );
    return onSelectSubnet;
  }

  /** Pick the Delete… of the row naming `network`, Continue, confirm. */
  async function startDelete(network: string) {
    // The tree's rows render their menus inline here (see the mock above);
    // each row's Delete… follows its own network in document order.
    await screen.findByText(network);
    const items = screen.getAllByText("Delete…");
    const row = screen.getAllByText(network)[0];
    const item = items.find(
      (el) =>
        row.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING,
    )!;
    fireEvent.click(item);
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Continue" }),
    );
    await confirmMoveToTrash();
  }

  it("a subnet stays selected and the dialog says it was submitted", async () => {
    const deleteSubnet = vi.fn(() => QUEUED);
    answers.ipamApi = {
      listBlocks: () => Promise.resolve([block]),
      listSubnets: () => Promise.resolve([subnet]),
      deleteSubnet,
    };
    const onSelectSubnet = openTree();
    await startDelete(subnet.network);
    await expectQueuedNotice(deleteSubnet);
    expect(onSelectSubnet).not.toHaveBeenCalledWith(null);
  });

  it("a block: the dialog says it was submitted", async () => {
    const deleteBlock = vi.fn(() => QUEUED);
    answers.ipamApi = {
      listBlocks: () => Promise.resolve([block]),
      listSubnets: () => Promise.resolve([subnet]),
      deleteBlock,
    };
    openTree();
    await startDelete(block.network);
    await expectQueuedNotice(deleteBlock);
  });

  it("a real delete still closes the dialog and clears the selection", async () => {
    answers.ipamApi = {
      listBlocks: () => Promise.resolve([block]),
      listSubnets: () => Promise.resolve([subnet]),
      deleteSubnet: () => Promise.resolve({ status: 204, data: "" }),
    };
    const onSelectSubnet = openTree();
    await startDelete(subnet.network);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(onSelectSubnet).toHaveBeenCalledWith(null);
  });
});
