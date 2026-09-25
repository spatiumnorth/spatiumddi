/**
 * @vitest-environment jsdom
 *
 * Every hand-built dialog shell is a named, modal dialog (#1156).
 *
 * The shared `Modal` renders `role="dialog"`, `aria-modal`, a name, a
 * labelled close button and a focus trap, and closes on Esc. The shells that
 * draw their own card — the custom shapes on `useDraggableModal` +
 * `MODAL_BACKDROP_CLS`, and the page-local `fixed inset-0` overlays — had
 * none of it: assistive technology announced a heading and an unnamed
 * button, and page code that asks "is a dialog open?" (the shortcuts
 * overlay's `[role="dialog"][aria-modal="true"]` guard) could not see them.
 * These open one shell of each kind the way an operator does and hold it to
 * the shared `Modal`'s contract.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { IPSpace, Subnet } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  formatApiError: (e: unknown) => String(e),
  ipamApi: {
    getEffectiveSubnetDns: () => Promise.resolve({ dns_group_ids: [] }),
    findFreeSpace: () => Promise.resolve({ candidates: [] }),
  },
  dnsApi: { listZones: () => Promise.resolve([]) },
  backupTargetsApi: {
    list: () => Promise.resolve([]),
    listKinds: () => Promise.resolve([]),
  },
  backupApi: { listSections: () => Promise.resolve([]) },
}));

const { FindFreeModal } = await import("@/pages/ipam/SubnetOpsModals");
const { BulkAllocateModal } = await import("@/pages/ipam/BulkAllocateModal");
const { BackupTargetsSection } =
  await import("@/pages/admin/BackupTargetsSection");

const SPACE = { id: "space-1", name: "campus" } as IPSpace;
const SUBNET = {
  id: "sub-1",
  network: "10.98.1.0/24",
  name: "staff",
} as Subnet;

function withClient(ui: ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

/** The shared Modal's contract, as `modalDialogProblems` checks it on a
 *  live console: a dialog named by its title, modal, with a named close
 *  button, visible to page code, holding the focus. */
function expectDialog(name: RegExp): HTMLElement {
  const dlg = screen.getByRole("dialog", { name });
  expect(dlg.getAttribute("aria-modal")).toBe("true");
  expect(
    within(dlg).getByRole("button", { name: "Close dialog" }),
  ).toBeTruthy();
  expect(document.querySelector('[role="dialog"][aria-modal="true"]')).toBe(
    dlg,
  );
  expect(dlg.contains(document.activeElement)).toBe(true);
  return dlg;
}

function pressEscape() {
  fireEvent.keyDown(window, { key: "Escape" });
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("hand-built dialog shells (#1156)", () => {
  it("block → Tools → Find Free… is a named, modal dialog", () => {
    const onClose = vi.fn();
    withClient(<FindFreeModal space={SPACE} onClose={onClose} />);
    expectDialog(/^Find free space in campus$/);
    pressEscape();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("subnet → Tools → Bulk allocate… is a named, modal dialog", () => {
    const onClose = vi.fn();
    withClient(<BulkAllocateModal subnet={SUBNET} onClose={onClose} />);
    expectDialog(/^Bulk allocate — 10\.98\.1\.0\/24 \(staff\)$/);
    pressEscape();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("Backup → Add target is a named, modal dialog that Esc and its close button dismiss", async () => {
    withClient(<BackupTargetsSection />);
    fireEvent.click(await screen.findByRole("button", { name: /Add target/ }));
    const dlg = expectDialog(/^Add backup target$/);
    // The form's own autoFocus (Name) is kept: focus lands inside, not on
    // the card.
    expect(document.activeElement?.tagName).toBe("INPUT");
    pressEscape();
    expect(screen.queryByRole("dialog")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: /Add target/ }));
    fireEvent.click(
      within(
        screen.getByRole("dialog", { name: /^Add backup target$/ }),
      ).getByRole("button", { name: "Close dialog" }),
    );
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(dlg.isConnected).toBe(false);
  });
});
