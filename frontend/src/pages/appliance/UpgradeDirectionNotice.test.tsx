/**
 * @vitest-environment jsdom
 *
 * #2068 — the same-version note must not promise a re-write or a reboot.
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import { UpgradeDirectionNotice } from "./UpgradeDirectionNotice";

afterEach(cleanup);

describe("UpgradeDirectionNotice", () => {
  it("same version says nothing is written and no reboot happens", () => {
    const { container } = render(
      <UpgradeDirectionNotice direction="same" tag="1.0.0" installed="1.0.0" />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("This node already runs 1.0.0");
    expect(text).toContain("Nothing will be written");
    expect(text).not.toMatch(/re-write/i);
    expect(text).not.toMatch(/reboot into it/i);
  });

  it("backward keeps the rollback warning", () => {
    const { container } = render(
      <UpgradeDirectionNotice
        direction="backward"
        tag="0.9.0"
        installed="1.0.0"
      />,
    );
    expect(container.textContent).toContain("this is a rollback");
  });

  it("renders nothing for a forward move", () => {
    const { container } = render(
      <UpgradeDirectionNotice
        direction="forward"
        tag="1.1.0"
        installed="1.0.0"
      />,
    );
    expect(container.textContent).toBe("");
  });
});
