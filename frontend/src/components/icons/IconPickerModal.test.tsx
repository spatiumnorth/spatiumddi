/**
 * @vitest-environment jsdom
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import IconPickerModal from "./IconPickerModal";
import { automaticLabel } from "@/lib/icons/catalog";
import { IconField } from "./IconField";

afterEach(cleanup);

describe("automaticLabel (#5022)", () => {
  it("names what Automatic currently resolves to and why", () => {
    expect(
      automaticLabel({ icon: "mdi:printer", source: "device_class" }),
    ).toBe("Automatic (currently: Printer, from device class)");
  });
  it("says none when nothing resolves", () => {
    expect(automaticLabel({ icon: null, source: "none" })).toBe(
      "Automatic (none)",
    );
    expect(automaticLabel(undefined)).toBe("Automatic (none)");
  });
});

function open(
  props: Partial<React.ComponentProps<typeof IconPickerModal>> = {},
) {
  const onSelect = vi.fn();
  const onClose = vi.fn();
  render(
    <IconPickerModal
      current={null}
      auto={{ icon: "mdi:printer", source: "device_class" }}
      onSelect={onSelect}
      onClose={onClose}
      {...props}
    />,
  );
  return { onSelect, onClose };
}

describe("IconPickerModal (#5022)", () => {
  it("offers Automatic first, then the core device set", () => {
    open();
    const options = screen.getAllByRole("option");
    expect(options[0].textContent).toBe(
      "Automatic (currently: Printer, from device class)",
    );
    expect(options.length).toBeGreaterThan(40);
    expect(screen.getByRole("option", { name: "Printer" })).toBeTruthy();
  });

  it("selects Automatic with Enter (the first choice is active)", async () => {
    const { onSelect } = open({ current: "mdi:cctv" });
    await userEvent.keyboard("{Enter}");
    expect(onSelect).toHaveBeenCalledWith(null);
  });

  it("moves through the grid with the arrow keys and picks with Enter", async () => {
    const { onSelect } = open();
    const search = screen.getByRole("combobox", { name: "Search icons" });
    const options = screen.getAllByRole("option");
    await userEvent.keyboard("{ArrowRight}");
    expect(search.getAttribute("aria-activedescendant")).toBe(options[1].id);
    await userEvent.keyboard("{ArrowRight}{ArrowLeft}{Enter}");
    expect(onSelect).toHaveBeenCalledWith(
      expect.stringMatching(/^mdi:[a-z0-9-]+$/),
    );
    // ArrowUp from the first row returns to Automatic.
    onSelect.mockClear();
    await userEvent.keyboard("{ArrowUp}{Enter}");
    expect(onSelect).toHaveBeenCalledWith(null);
  });

  it("searches the full set, including names outside the core set", async () => {
    const { onSelect } = open();
    await userEvent.type(
      screen.getByRole("combobox", { name: "Search icons" }),
      "account network",
    );
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: "Account network" }),
      ).toBeTruthy(),
    );
    await userEvent.click(
      screen.getByRole("option", { name: "Account network" }),
    );
    expect(onSelect).toHaveBeenCalledWith("mdi:account-network");
  });

  it("says so when nothing matches", async () => {
    open();
    await userEvent.type(
      screen.getByRole("combobox", { name: "Search icons" }),
      "zzzzqqqq",
    );
    await waitFor(() =>
      expect(screen.getByText("No icons match.")).toBeTruthy(),
    );
  });

  it("closes with Escape", async () => {
    const { onClose } = open();
    await userEvent.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalled();
  });
});

describe("IconField (#5022)", () => {
  it("opens the picker lazily and reports the choice", async () => {
    const onChange = vi.fn();
    render(<IconField value={null} onChange={onChange} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    await userEvent.click(screen.getByRole("button"));
    const printer = await screen.findByRole("option", { name: "Printer" });
    await userEvent.click(printer);
    expect(onChange).toHaveBeenCalledWith("mdi:printer");
  });
});
