/**
 * @vitest-environment jsdom
 *
 * An Esc on a suggestion reached with Tab belongs to the open list, not to
 * the dialog around it (#3157, on top of #2720's Esc in the field).
 */
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listOptionCodes: () =>
      Promise.resolve([
        { code: 1, name: "subnet-mask", description: "Subnet mask" },
        { code: 2, name: "time-offset", description: "Time offset" },
      ]),
  },
  searchApi: {
    types: () => Promise.resolve([]),
    search: () =>
      Promise.resolve({
        results: [
          {
            type: "ip_address",
            id: "ip1",
            display: "10.0.0.1",
            hostname: "h1",
            subnet_network: "10.0.0.0/24",
            space_name: "default",
          },
        ],
      }),
  },
}));

import { DHCPOptionsEditor } from "@/pages/dhcp/DHCPOptionsEditor";
import { IPAddressPicker } from "@/components/IPAddressPicker";
import { Modal } from "@/components/ui/modal";

afterEach(cleanup);

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function OptionsDialog({ onClose }: { onClose: () => void }) {
  const [v, setV] = useState<
    { code: number; name?: string; value: string | string[] }[]
  >([]);
  return (
    <Modal title="New Option Template" onClose={onClose}>
      <input aria-label="name" />
      <DHCPOptionsEditor value={v} onChange={setV} />
    </Modal>
  );
}

function PickerDialog({ onClose }: { onClose: () => void }) {
  const [id, setId] = useState<string | null>(null);
  return (
    <Modal title="New thing" onClose={onClose}>
      <IPAddressPicker value={id} onChange={setId} />
    </Modal>
  );
}

describe("Esc on a suggestion reached with Tab (#3157)", () => {
  it("DHCP option list: closes the list, the dialog stays", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    wrap(<OptionsDialog onClose={onClose} />);
    await user.type(screen.getByLabelText("name"), "tmpl");
    await user.click(screen.getByRole("button", { name: /Custom options/ }));
    await user.click(screen.getByRole("button", { name: /Add custom option/ }));
    const box = screen.getByPlaceholderText("Search code or name…");
    await user.click(box);
    await screen.findByText("subnet-mask");
    expect(document.activeElement).toBe(box);
    await user.tab();
    expect(document.activeElement).toBe(
      screen.getByText("subnet-mask").closest("button"),
    );
    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.queryByText("subnet-mask")).toBeNull();
    expect((screen.getByLabelText("name") as HTMLInputElement).value).toBe(
      "tmpl",
    );
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("IP picker: closes the list, the dialog stays", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    wrap(<PickerDialog onClose={onClose} />);
    await user.type(screen.getByPlaceholderText(/Search by IP/), "10.0");
    await screen.findByText("h1 · 10.0.0.0/24 · default");
    await user.tab();
    expect(document.activeElement).toBe(
      screen.getByText("10.0.0.1").closest("button"),
    );
    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.queryByText("h1 · 10.0.0.0/24 · default")).toBeNull();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
