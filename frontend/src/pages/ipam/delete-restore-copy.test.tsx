/**
 * @vitest-environment jsdom
 *
 * IPAM delete dialogs do not promise a restore the user cannot do (#1930).
 *
 * Every IPAM delete goes to Trash, and Trash's list and restore endpoints
 * are superadmin-only (backend/app/api/v1/admin/trash.py). The dialogs said
 * "You can restore them from Administration → Trash", promising an IPAM
 * Editor an undo they cannot perform. These tests render the real IPAM
 * surfaces as a non-superadmin, walk each delete through its steps, and read
 * what the operator reads: it names a superadmin and never says "you can
 * restore". The same wording as the DNS zone delete (#1880).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
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

// An IPAM Editor: every IPAM permission, not a superadmin.
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

// Radix's context menu stalls jsdom; render each row's menu inline.
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

const {
  EditSpaceModal,
  EditBlockModal,
  EditSubnetModal,
  SpaceSection,
  IPAMPage,
} = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
  localStorage.clear();
  sessionStorage.clear();
});

function open(ui: ReactNode, url = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const words = (el: Element) =>
  (el.textContent ?? "").replace(/\s+/g, " ").trim();
const topDialog = () => screen.getAllByRole("dialog").at(-1)!;

const PROMISES_SELF_RESTORE = /\byou can restore\b/i;

function expectNamesSuperadmin(said: string) {
  expect(said, `never names who can restore: "${said}"`).toMatch(
    /superadmin can restore/i,
  );
  expect(said).not.toMatch(PROMISES_SELF_RESTORE);
}

const space = { id: "sp-1", name: "lab" } as IPSpace;
const block = {
  id: "b-1",
  space_id: "sp-1",
  parent_block_id: null,
  network: "10.73.0.0/16",
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 65536,
} as IPBlock;
const subnet = {
  id: "sn-1",
  space_id: "sp-1",
  block_id: "b-1",
  network: "10.73.5.0/24",
  utilization_percent: 0,
  allocated_ips: 0,
  total_ips: 254,
} as Subnet;

describe("Edit modals' Danger zone and delete steps", () => {
  async function walk(openLabel: RegExp) {
    fireEvent.click(await screen.findByRole("button", { name: "Danger zone" }));
    let said = words(topDialog());
    expectNamesSuperadmin(said);
    fireEvent.click(screen.getByRole("button", { name: openLabel }));
    said = words(topDialog());
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Continue" }),
    );
    said += ` ${words(topDialog())}`;
    expectNamesSuperadmin(said);
  }

  it("subnet", async () => {
    open(
      <EditSubnetModal
        subnet={subnet}
        onClose={() => {}}
        onDeleted={() => {}}
      />,
    );
    await walk(/^Delete this subnet/);
  });

  it("block", async () => {
    open(
      <EditBlockModal block={block} onClose={() => {}} onDeleted={() => {}} />,
    );
    await walk(/^Delete this block/);
  });

  it("space", async () => {
    answers.ipamApi = { getSpace: () => Promise.resolve(space) };
    open(
      <EditSpaceModal space={space} onClose={() => {}} onDeleted={() => {}} />,
    );
    await walk(/^Delete this IP space/);
  });
});

describe("the IPAM tree's Delete…", () => {
  async function startDelete(network: string) {
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
    expectNamesSuperadmin(words(topDialog()));
  }

  function openTree() {
    answers.ipamApi = {
      listBlocks: () => Promise.resolve([block]),
      listSubnets: () => Promise.resolve([subnet]),
    };
    open(
      <SpaceSection
        space={space}
        selectedSubnetId={subnet.id}
        selectedBlockId={null}
        isSpaceSelected={false}
        onSelectSpace={() => {}}
        onSelectSubnet={() => {}}
        onSelectBlock={() => {}}
      />,
    );
  }

  it("subnet", async () => {
    openTree();
    await startDelete(subnet.network);
  });

  it("block", async () => {
    openTree();
    await startDelete(block.network);
  });
});

describe("bulk delete on the real IPAM page", () => {
  function pageAnswers() {
    answers.ipamApi = {
      listSpaces: () => Promise.resolve([space]),
      listBlocks: () => Promise.resolve([block]),
      listSubnets: () => Promise.resolve([subnet]),
      getSpace: () => Promise.resolve(space),
      getBlock: () => Promise.resolve(block),
    };
  }

  it.each([
    ["block detail", "/ipam?block=b-1"],
    ["space table", "/ipam?space=sp-1"],
  ])("%s: says who can restore", async (_n, url) => {
    pageAnswers();
    open(<IPAMPage />, url);
    fireEvent.click(await screen.findByLabelText(`Select ${subnet.network}`));
    fireEvent.click(
      await screen.findByRole("button", { name: /^Delete \(1\)/ }),
    );
    expectNamesSuperadmin(words(topDialog()));
    fireEvent.click(
      within(topDialog()).getByRole("button", { name: "Continue" }),
    );
    expectNamesSuperadmin(words(topDialog()));
  });
});
