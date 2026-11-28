/**
 * @vitest-environment jsdom
 */
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { CORE_ICON_PATHS } from "@/lib/icons/core";
import { EntityIcon } from "./EntityIcon";
import { IconCell } from "./IconCell";

afterEach(cleanup);

describe("EntityIcon (#5022)", () => {
  it("draws a core icon as an inline path in currentColor, in a fixed box", () => {
    render(<EntityIcon icon="mdi:printer" />);
    const svg = screen.getByRole("img", { name: "Printer" });
    expect(svg.getAttribute("fill")).toBe("currentColor");
    expect(svg.getAttribute("width")).toBe("16");
    expect(svg.getAttribute("height")).toBe("16");
    expect(svg.querySelector("path")?.getAttribute("d")).toBe(
      CORE_ICON_PATHS["printer"],
    );
  });

  it("uses the 20 px box for headers and an explicit label when given", () => {
    render(<EntityIcon icon="mdi:cctv" size={20} label="Security camera" />);
    const svg = screen.getByRole("img", { name: "Security camera" });
    expect(svg.getAttribute("width")).toBe("20");
  });

  it("is hidden from assistive tech when decorative", () => {
    const { container } = render(<EntityIcon icon="mdi:printer" decorative />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("aria-hidden")).toBe("true");
    expect(svg.getAttribute("role")).toBeNull();
    expect(screen.queryByRole("img")).toBeNull();
  });

  it("draws nothing for an empty or foreign value", () => {
    const { container } = render(
      <>
        <EntityIcon icon={null} />
        <EntityIcon icon="custom:abc" />
      </>,
    );
    expect(container.querySelector("svg")).toBeNull();
  });

  it("lazy-loads the path of an icon outside the core set", async () => {
    expect("account-network" in CORE_ICON_PATHS).toBe(false);
    const { container } = render(<EntityIcon icon="mdi:account-network" />);
    const svg = container.querySelector("svg")!;
    // The box is there at once so a row does not shift...
    expect(svg.getAttribute("width")).toBe("16");
    // ...and the path arrives from the lazy chunk.
    await waitFor(() =>
      expect(svg.querySelector("path")?.getAttribute("d")).toMatch(/^M/),
    );
  });
});

describe("IconCell (#5022)", () => {
  it("shows the effective icon with its source in the tooltip", () => {
    const { container } = render(
      <IconCell icon="mdi:printer" source="device_class" />,
    );
    expect(container.querySelector("span[title]")?.getAttribute("title")).toBe(
      "Printer (device class)",
    );
    expect(screen.getByRole("img", { name: "Printer" })).toBeTruthy();
  });

  it("is empty when nothing resolves", () => {
    const { container } = render(<IconCell icon={null} source="none" />);
    expect(container.innerHTML).toBe("");
  });
});
