/**
 * @vitest-environment jsdom
 */
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { BigYellowBanner } from "./ResizeModals";

describe("BigYellowBanner (#2416)", () => {
  it("subnet: tells clients to take the new netmask and offers no resize revert", () => {
    const { container } = render(
      <BigYellowBanner newCidr="10.0.0.0/23" kind="subnet" />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("reconfigured with the new netmask");
    expect(text).toContain("delete the subnet and recreate it");
    expect(text).not.toContain("run the resize again");
    expect(text).not.toContain("To revert");
  });

  it("block: says child subnets are unchanged and no client needs reconfiguring", () => {
    const { container } = render(
      <BigYellowBanner newCidr="10.0.0.0/23" kind="block" />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("Child subnets are unchanged");
    expect(text).not.toContain("reconfigured with the new netmask");
    expect(text).toContain("delete the block and recreate it");
  });
});
