/**
 * @vitest-environment jsdom
 *
 * Holds panel on the block view (#4492): lists the block's active holds and
 * drives create / edit / convert / release through the holds API.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { IPBlock, SubnetHold } from "@/lib/api";

const api = vi.hoisted(() => ({
  list: vi.fn(),
  create: vi.fn(),
  update: vi.fn(),
  release: vi.fn(),
  convert: vi.fn(),
}));
const perm = vi.hoisted(() => ({ write: true }));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, subnetHoldsApi: api };
});
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({ can: () => perm.write }),
  };
});

const { HoldsPanel } = await import("./HoldsPanel");

const block = {
  id: "b1",
  space_id: "s1",
  network: "10.0.0.0/16",
} as unknown as IPBlock;

function hold(over: Partial<SubnetHold> = {}): SubnetHold {
  return {
    id: "h1",
    space_id: "s1",
    block_id: "b1",
    network: "10.0.8.0/22",
    reason: "Project Falcon",
    status: "active",
    expires_at: null,
    expired: false,
    owner_user_id: null,
    owner_group_id: null,
    customer_id: null,
    converted_subnet_id: null,
    created_at: "",
    modified_at: "",
    ...over,
  };
}

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <HoldsPanel block={block} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  perm.write = true;
});

describe("HoldsPanel", () => {
  it("lists only this block's holds and flags an expired one", async () => {
    api.list.mockResolvedValue([
      hold({ expired: true, expires_at: "2020-01-01T00:00:00Z" }),
      hold({ id: "h2", block_id: "other", network: "10.1.0.0/24" }),
    ]);
    mount();
    expect(await screen.findByText("10.0.8.0/22")).toBeTruthy();
    expect(screen.queryByText("10.1.0.0/24")).toBeNull();
    expect(screen.getByText("Expired")).toBeTruthy();
  });

  it("creates a hold", async () => {
    api.list.mockResolvedValue([]);
    api.create.mockResolvedValue(hold());
    mount();
    fireEvent.click(await screen.findByText("+ Hold a CIDR"));
    fireEvent.change(screen.getByPlaceholderText("10.0.8.0/22"), {
      target: { value: "10.0.8.0/22" },
    });
    fireEvent.change(screen.getByLabelText(/Reason/), {
      target: { value: "Falcon" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Hold" }));
    await waitFor(() =>
      expect(api.create).toHaveBeenCalledWith(
        expect.objectContaining({
          space_id: "s1",
          network: "10.0.8.0/22",
          reason: "Falcon",
        }),
      ),
    );
  });

  it("edits a hold and clears its expiry when the date is emptied", async () => {
    api.list.mockResolvedValue([hold()]);
    api.update.mockResolvedValue(hold());
    mount();
    fireEvent.click(await screen.findByText("Edit"));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(api.update).toHaveBeenCalledWith("h1", {
        reason: "Project Falcon",
        clear_expiry: true,
      }),
    );
  });

  it("converts a hold to a subnet", async () => {
    api.list.mockResolvedValue([hold()]);
    api.convert.mockResolvedValue(hold({ status: "converted" }));
    mount();
    fireEvent.click(await screen.findByText("Convert to subnet"));
    fireEvent.change(screen.getByLabelText(/Subnet name/), {
      target: { value: "falcon" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Convert" }));
    await waitFor(() =>
      expect(api.convert).toHaveBeenCalledWith("h1", { name: "falcon" }),
    );
  });

  it("releases only after the confirmation, and shows a refusal inside it", async () => {
    api.list.mockResolvedValue([hold()]);
    api.release.mockRejectedValue({
      response: { data: { detail: "Nope" }, status: 409 },
    });
    mount();
    fireEvent.click(await screen.findByText("Release"));
    expect(api.release).not.toHaveBeenCalled();
    fireEvent.click(screen.getAllByRole("button", { name: "Release" }).pop()!);
    await waitFor(() => expect(api.release).toHaveBeenCalledWith("h1"));
    expect(await screen.findByRole("alert")).toBeTruthy();
  });

  it("disables the actions without write permission", async () => {
    perm.write = false;
    api.list.mockResolvedValue([hold()]);
    mount();
    const edit = await screen.findByText("Edit");
    expect((edit as HTMLButtonElement).disabled).toBe(true);
  });
});
