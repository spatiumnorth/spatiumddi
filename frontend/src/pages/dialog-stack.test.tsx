/**
 * @vitest-environment jsdom
 *
 * The dialog stacks QA drove (#1947, #1948), through the real components:
 * Add Network Device → the IP space picker's New → New IP Space; the search
 * palette over a dialog; the header's Keyboard shortcuts overlay.
 *
 * `offsetParent` is stubbed as in `modal-stack.test.tsx`: jsdom reports it
 * null for everything, which made main's focus trap see no controls and
 * swallow every Tab, so a Shift+Tab test passed there whatever it did.
 */
import { useState } from "react";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", () => ({
  // The shortcuts overlay reads the caller's grants (#3103).
  authApi: {
    myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
  },
  ipamApi: { listSpaces: () => Promise.resolve([]) },
  networkApi: {},
  searchApi: {
    types: () => Promise.resolve([]),
    search: () => Promise.resolve({ results: [] }),
  },
}));
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));
vi.mock("@/components/copilot/useAiAvailable", () => ({
  useAiAvailable: () => false,
}));

import { DeviceFormModal } from "./network/DeviceFormModal";
import { GlobalSearch } from "@/components/GlobalSearch";
import { KeyboardShortcutsHelp } from "@/components/KeyboardShortcutsOverlay";
import { Modal } from "@/components/ui/modal";

const realOffsetParent = Object.getOwnPropertyDescriptor(
  HTMLElement.prototype,
  "offsetParent",
);
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "offsetParent", {
    configurable: true,
    get(this: HTMLElement) {
      return this.isConnected ? this.parentNode : null;
    },
  });
});
afterAll(() => {
  if (realOffsetParent) {
    Object.defineProperty(
      HTMLElement.prototype,
      "offsetParent",
      realOffsetParent,
    );
  }
});
afterEach(cleanup);

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>{ui}</QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("Esc closes only the topmost dialog (#1947)", () => {
  it("New IP Space over Add Network Device: the device form keeps its name", async () => {
    function Page() {
      const [open, setOpen] = useState(true);
      return open ? <DeviceFormModal onClose={() => setOpen(false)} /> : null;
    }
    const user = userEvent.setup();
    wrap(<Page />);
    await user.type(screen.getByPlaceholderText("core-sw-01"), "qa-marker");
    await user.click(screen.getByTitle("Create a new IP space"));
    expect(screen.getByRole("dialog", { name: "New IP Space" })).toBeTruthy();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "New IP Space" })).toBeNull();
    expect(
      screen.getByRole("dialog", { name: "Add Network Device" }),
    ).toBeTruthy();
    expect(
      (screen.getByPlaceholderText("core-sw-01") as HTMLInputElement).value,
    ).toBe("qa-marker");

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("the search palette over a dialog: Esc closes the palette only", async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    wrap(
      <>
        <GlobalSearch />
        <Modal title="New IP Space" onClose={onClose}>
          <input aria-label="name" />
        </Modal>
      </>,
    );
    await user.keyboard("{Control>}k{/Control}");
    const palette = await screen.findByPlaceholderText(/Search IP, hostname/);
    palette.focus();
    await user.keyboard("{Escape}");
    expect(screen.queryByPlaceholderText(/Search IP, hostname/)).toBeNull();
    expect(onClose).not.toHaveBeenCalled();

    // Esc with focus elsewhere in the palette (not its input) too.
    await user.keyboard("{Control>}k{/Control}");
    await screen.findByPlaceholderText(/Search IP, hostname/);
    (document.activeElement as HTMLElement | null)?.blur();
    await user.keyboard("{Escape}");
    expect(screen.queryByPlaceholderText(/Search IP, hostname/)).toBeNull();
    expect(onClose).not.toHaveBeenCalled();

    // With the palette gone, Esc reaches the dialog again.
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("Shift+Tab stays inside a dialog (#1948)", () => {
  it("the header's Keyboard shortcuts", async () => {
    const user = userEvent.setup();
    wrap(
      <>
        <a href="/x">view all →</a>
        <KeyboardShortcutsHelp />
      </>,
    );
    await user.click(
      screen.getByRole("button", { name: "Show keyboard shortcuts" }),
    );
    const dlg = screen.getByRole("dialog", { name: "Keyboard shortcuts" });
    expect(dlg.contains(document.activeElement)).toBe(true);
    await user.tab({ shift: true });
    expect(dlg.contains(document.activeElement)).toBe(true);
  });
});
