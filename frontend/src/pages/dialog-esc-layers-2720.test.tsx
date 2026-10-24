/**
 * @vitest-environment jsdom
 *
 * Esc belongs to the innermost layer (#2720) and the search palette is drawn
 * above the dialog it opened over (#2721).
 */
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", () => ({
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
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));
vi.mock("@/components/copilot/useAiAvailable", () => ({
  useAiAvailable: () => false,
}));

import { GlobalSearch } from "@/components/GlobalSearch";
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

function Form({ onClose }: { onClose: () => void }) {
  const [id, setId] = useState<string | null>(null);
  return (
    <Modal title="New thing" onClose={onClose}>
      <input aria-label="name" />
      <IPAddressPicker value={id} onChange={setId} />
    </Modal>
  );
}

describe("Esc inside a dialog (#2720)", () => {
  it("one Esc closes an open suggestion list, the next closes the dialog", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    wrap(<Form onClose={onClose} />);
    const box = screen.getByPlaceholderText(/Search by IP/);
    await user.type(box, "10.0");
    await screen.findByText("h1 · 10.0.0.0/24 · default");
    await user.keyboard("{Escape}");
    expect(screen.queryByText("h1 · 10.0.0.0/24 · default")).toBeNull();
    expect(onClose).not.toHaveBeenCalled();
    expect((box as HTMLInputElement).value).toBe("10.0");
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("an Esc that ends an IME composition leaves the dialog open", () => {
    const onClose = vi.fn();
    wrap(<Form onClose={onClose} />);
    const name = screen.getByLabelText("name");
    name.focus();
    fireEvent.keyDown(name, { key: "Escape", isComposing: true });
    fireEvent.keyDown(name, { key: "Escape", keyCode: 229 });
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.keyDown(name, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("the search palette over a dialog (#2721)", () => {
  it("is mounted after the dialog, so it paints above it", async () => {
    const user = userEvent.setup();
    wrap(
      <>
        <GlobalSearch />
        <Modal title="New IP Space" onClose={() => {}}>
          <input aria-label="name" />
        </Modal>
      </>,
    );
    await user.keyboard("{Control>}k{/Control}");
    const palette = await screen.findByRole("dialog", { name: "Search" });
    const dialog = screen.getByRole("dialog", { name: "New IP Space" });
    const top = (el: HTMLElement) => {
      let n: HTMLElement = el;
      while (n.parentElement && n.parentElement !== document.body)
        n = n.parentElement;
      return n;
    };
    // Same z-index, so the later sibling of <body> paints on top. Both must
    // be direct body children, with the palette last.
    expect(
      top(dialog).compareDocumentPosition(top(palette)) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(top(palette).parentElement).toBe(document.body);
    expect(top(dialog).parentElement).toBe(document.body);
  });
});
