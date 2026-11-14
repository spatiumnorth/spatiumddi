/**
 * @vitest-environment jsdom
 *
 * Every single create / edit dialog for an IP address, subnet, block and
 * space carries a key/value tag editor (#4107). An edit that leaves the
 * editor alone sends no ``tags`` (the update endpoints replace the whole
 * object), and removing a row sends the object without that key.
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
}));

const {
  EditAddressModal,
  AddAddressModal,
  EditSubnetModal,
  CreateSubnetModal,
  EditBlockModal,
  CreateBlockModal,
  EditSpaceModal,
  CreateSpaceModal,
} = await import("@/pages/ipam/IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const stored = { env: "prod", team: "net" };

// Fresh-row reads answer with the row itself, so the form seeds from it.
const row = (r: Record<string, unknown>) => () => Promise.resolve(r);

function typeInto(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function addTag(i: number, k: string, v: string) {
  fireEvent.click(screen.getByRole("button", { name: /Add tag/ }));
  typeInto(`Tag key ${i}`, k);
  typeInto(`Tag value ${i}`, v);
}

const save = (name: RegExp) =>
  fireEvent.click(screen.getByRole("button", { name }));

describe("IPAM dialogs carry a tag editor (#4107)", () => {
  describe("Edit address", () => {
    const addr = {
      id: "a-1",
      subnet_id: "sn-1",
      address: "10.0.0.5",
      hostname: "host-a",
      description: "",
      mac_address: null,
      status: "allocated",
      custom_fields: {},
      tags: stored,
    };
    const setup = () => {
      const updateAddress = vi.fn((..._a: unknown[]) => Promise.resolve(addr));
      answers.ipamApi = { getAddress: row(addr), updateAddress };
      open(<EditAddressModal address={addr as never} onClose={() => {}} />);
      return updateAddress;
    };

    it("sends the edited tags, an added one and a removed one", async () => {
      const updateAddress = setup();
      expect(await screen.findByDisplayValue("prod")).toBeTruthy();
      fireEvent.click(screen.getByLabelText("Remove tag row 2"));
      await addTag(2, "owner", "alice");
      save(/^Save/);
      await waitFor(() => expect(updateAddress).toHaveBeenCalled());
      const body = updateAddress.mock.calls[0][1] as Record<string, unknown>;
      expect(body.tags).toEqual({ env: "prod", owner: "alice" });
    });

    it("an untouched Save does not send tags", async () => {
      const updateAddress = setup();
      await screen.findByDisplayValue("prod");
      typeInto("Tag value 1", "prod"); // same value
      fireEvent.change(screen.getByDisplayValue("host-a"), {
        target: { value: "host-b" },
      });
      save(/^Save/);
      await waitFor(() => expect(updateAddress).toHaveBeenCalled());
      expect(updateAddress.mock.calls[0][1]).not.toHaveProperty("tags");
    });
  });

  describe("Allocate address", () => {
    it("sends the tags it was given", async () => {
      const createAddress = vi.fn((..._a: unknown[]) =>
        Promise.resolve({ id: "x", address: "10.0.0.9" }),
      );
      answers.ipamApi = { createAddress };
      open(
        <AddAddressModal
          subnetId="sn-1"
          nextAvailable={false}
          onClose={() => {}}
        />,
      );
      await addTag(1, "env", "lab");
      fireEvent.change(screen.getByPlaceholderText(/10\./), {
        target: { value: "10.0.0.9" },
      });
      fireEvent.change(screen.getByPlaceholderText("Required"), {
        target: { value: "h1" },
      });
      save(/^Allocate/);
      await waitFor(() => expect(createAddress).toHaveBeenCalled());
      expect(
        (createAddress.mock.calls[0][0] as Record<string, unknown>).tags,
      ).toEqual({ env: "lab" });
    });
  });

  describe("Edit subnet", () => {
    const subnet = {
      id: "sn-1",
      space_id: "sp-1",
      block_id: "b-1",
      network: "10.0.0.0/24",
      name: "lan",
      description: "",
      status: "active",
      custom_fields: {},
      tags: stored,
    };
    const setup = () => {
      const updateSubnet = vi.fn((..._a: unknown[]) => Promise.resolve(subnet));
      answers.ipamApi = {
        getSubnet: row(subnet),
        updateSubnet,
        effectiveFields: () =>
          Promise.resolve({
            subnet_id: "sn-1",
            tags: { ...stored, site: "hq" },
            custom_fields: {},
            tag_sources: { env: "subnet", team: "subnet", site: "block:b-1" },
            custom_field_sources: {},
          }),
        listSpaces: () => Promise.resolve([]),
        listBlocks: () => Promise.resolve([]),
      };
      open(<EditSubnetModal subnet={subnet as never} onClose={() => {}} />);
      return updateSubnet;
    };

    it("sends the edited tags and shows inherited ones", async () => {
      const updateSubnet = setup();
      await screen.findByDisplayValue("prod");
      expect(await screen.findByText(/site: hq/)).toBeTruthy();
      fireEvent.click(screen.getByLabelText("Remove tag row 1"));
      save(/^Save/);
      await waitFor(() => expect(updateSubnet).toHaveBeenCalled());
      expect((updateSubnet.mock.calls[0][1] as { tags: unknown }).tags).toEqual(
        { team: "net" },
      );
    });

    it("an untouched Save does not send tags", async () => {
      const updateSubnet = setup();
      await screen.findByDisplayValue("prod");
      fireEvent.change(screen.getByDisplayValue("lan"), {
        target: { value: "lan2" },
      });
      save(/^Save/);
      await waitFor(() => expect(updateSubnet).toHaveBeenCalled());
      expect(updateSubnet.mock.calls[0][1]).not.toHaveProperty("tags");
    });
  });

  describe("Create subnet", () => {
    it("renders the editor", async () => {
      answers.ipamApi = {
        listBlocks: () => Promise.resolve([]),
        listTemplates: () => Promise.resolve([]),
      };
      open(<CreateSubnetModal spaceId="sp-1" onClose={() => {}} />);
      expect(await screen.findByText("Add tag")).toBeTruthy();
    });
  });

  describe("Edit block", () => {
    const block = {
      id: "b-1",
      space_id: "sp-1",
      network: "10.0.0.0/8",
      name: "corp",
      description: "",
      custom_fields: {},
      tags: stored,
    };
    const setup = () => {
      const updateBlock = vi.fn((..._a: unknown[]) => Promise.resolve(block));
      answers.ipamApi = {
        getBlock: row(block),
        updateBlock,
        effectiveBlockFields: () =>
          Promise.resolve({
            block_id: "b-1",
            tags: { ...stored, region: "emea" },
            custom_fields: {},
            tag_sources: {
              env: "block:b-1",
              team: "block:b-1",
              region: "space:sp-1",
            },
            custom_field_sources: {},
          }),
        listSpaces: () => Promise.resolve([]),
        listBlocks: () => Promise.resolve([]),
      };
      open(
        <EditBlockModal
          block={block as never}
          onClose={() => {}}
          onDeleted={() => {}}
        />,
      );
      return updateBlock;
    };

    it("sends the edited tags and shows inherited ones", async () => {
      const updateBlock = setup();
      await screen.findByDisplayValue("prod");
      expect(await screen.findByText(/region: emea/)).toBeTruthy();
      await addTag(3, "owner", "bob");
      save(/^Save/);
      await waitFor(() => expect(updateBlock).toHaveBeenCalled());
      expect((updateBlock.mock.calls[0][1] as { tags: unknown }).tags).toEqual({
        ...stored,
        owner: "bob",
      });
    });

    it("an untouched Save does not send tags", async () => {
      const updateBlock = setup();
      await screen.findByDisplayValue("prod");
      fireEvent.change(screen.getByDisplayValue("corp"), {
        target: { value: "corp2" },
      });
      save(/^Save/);
      await waitFor(() => expect(updateBlock).toHaveBeenCalled());
      expect(updateBlock.mock.calls[0][1]).not.toHaveProperty("tags");
    });
  });

  describe("Create block", () => {
    it("sends the tags it was given", async () => {
      const createBlock = vi.fn((..._a: unknown[]) =>
        Promise.resolve({ id: "b-2" }),
      );
      answers.ipamApi = {
        createBlock,
        listBlocks: () => Promise.resolve([]),
        listTemplates: () => Promise.resolve([]),
      };
      open(<CreateBlockModal spaceId="sp-1" onClose={() => {}} />);
      await addTag(1, "env", "lab");
      fireEvent.change(screen.getByPlaceholderText(/10\.0\.0\.0\/8/), {
        target: { value: "10.0.0.0/8" },
      });
      save(/^Create/);
      await waitFor(() => expect(createBlock).toHaveBeenCalled());
      expect(
        (createBlock.mock.calls[0][0] as Record<string, unknown>).tags,
      ).toEqual({ env: "lab" });
    });
  });

  describe("Edit space", () => {
    const space = {
      id: "sp-1",
      name: "corp",
      description: "",
      is_default: false,
      tags: stored,
    };
    const setup = () => {
      const updateSpace = vi.fn((..._a: unknown[]) => Promise.resolve(space));
      answers.ipamApi = { getSpace: row(space), updateSpace };
      open(
        <EditSpaceModal
          space={space as never}
          onClose={() => {}}
          onDeleted={() => {}}
        />,
      );
      return updateSpace;
    };

    it("sends the edited tags", async () => {
      const updateSpace = setup();
      await screen.findByDisplayValue("prod");
      typeInto("Tag value 1", "stage");
      save(/^Save/);
      await waitFor(() => expect(updateSpace).toHaveBeenCalled());
      expect((updateSpace.mock.calls[0][1] as { tags: unknown }).tags).toEqual({
        env: "stage",
        team: "net",
      });
    });

    it("an untouched Save does not send tags", async () => {
      const updateSpace = setup();
      await screen.findByDisplayValue("prod");
      fireEvent.change(screen.getByDisplayValue("corp"), {
        target: { value: "corp2" },
      });
      save(/^Save/);
      await waitFor(() => expect(updateSpace).toHaveBeenCalled());
      expect(updateSpace.mock.calls[0][1]).not.toHaveProperty("tags");
    });
  });

  describe("Create space", () => {
    it("sends the tags it was given", async () => {
      const createSpace = vi.fn((..._a: unknown[]) =>
        Promise.resolve({ id: "sp-2" }),
      );
      answers.ipamApi = { createSpace };
      open(<CreateSpaceModal onClose={() => {}} />);
      await addTag(1, "env", "lab");
      fireEvent.change(screen.getByPlaceholderText("e.g. Corporate"), {
        target: { value: "lab" },
      });
      save(/^Create/);
      await waitFor(() => expect(createSpace).toHaveBeenCalled());
      expect(
        (createSpace.mock.calls[0][0] as Record<string, unknown>).tags,
      ).toEqual({ env: "lab" });
    });
  });
});
