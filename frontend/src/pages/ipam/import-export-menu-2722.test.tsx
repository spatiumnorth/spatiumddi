/**
 * @vitest-environment jsdom
 *
 * The subnet's Import / Export menu is a header menu like Sync and Tools
 * beside it (#2722): Esc and an outside click close it, one is open at a
 * time, and the import dialog hands focus back to its trigger.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("@/lib/api", async (orig) => ({
  ...(await orig<object>()),
  ipamIoApi: { download: vi.fn(), downloadPdf: vi.fn() },
}));

import { SubnetImportExportButton } from "./ImportExportModals";
import { HeaderMenu } from "@/components/ui/header-menu";
import type { Subnet } from "@/lib/api";

afterEach(cleanup);

const subnet = { id: "s1", network: "10.0.0.0/24" } as unknown as Subnet;

function Header() {
  return (
    <div>
      <SubnetImportExportButton subnet={subnet} onCommitted={() => {}} />
      <HeaderMenu
        label="Tools"
        items={[{ key: "t", label: "Bulk allocate…", onSelect: () => {} }]}
      />
      <p>page body</p>
    </div>
  );
}

const trigger = () => screen.getByRole("button", { name: /Import \/ Export/ });
const importItem = () => screen.queryByText("Import IP addresses…");

describe("subnet Import / Export menu", () => {
  it("closes on Esc, however it was opened", async () => {
    const user = userEvent.setup();
    render(<Header />);
    await user.click(trigger());
    expect(importItem()).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(importItem()).toBeNull();
  });

  it("closes on a click elsewhere", async () => {
    const user = userEvent.setup();
    render(<Header />);
    await user.click(trigger());
    fireEvent.mouseDown(screen.getByText("page body"));
    expect(importItem()).toBeNull();
  });

  it("is not open beside another header menu", async () => {
    const user = userEvent.setup();
    render(<Header />);
    await user.click(trigger());
    await user.click(screen.getByRole("button", { name: /Tools/ }));
    expect(importItem()).toBeNull();
    expect(screen.getByText("Bulk allocate…")).toBeTruthy();
  });

  it("returns focus to its trigger when the import dialog closes", async () => {
    const user = userEvent.setup();
    render(<Header />);
    await user.click(trigger());
    await user.click(screen.getByText("Import IP addresses…"));
    expect(screen.getByRole("dialog")).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger());
  });

  it("keeps the menu open while the Include IP addresses option is toggled", async () => {
    const user = userEvent.setup();
    render(<Header />);
    await user.click(trigger());
    const box = screen.getByRole("menuitemcheckbox", {
      name: /Include IP addresses/,
    });
    expect(box.getAttribute("aria-checked")).toBe("true");
    await user.click(box);
    expect(box.getAttribute("aria-checked")).toBe("false");
    expect(importItem()).toBeTruthy();
  });
});
