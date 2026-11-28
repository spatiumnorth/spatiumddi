/**
 * @vitest-environment jsdom
 */
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { IconCell } from "@/components/icons/IconCell";
import { SHOW_ICONS_KEY, useLocalBoolPref } from "./useLocalPref";

// The icon column of the IP table and the record list: a first cell that
// draws the row's effective icon and goes away with the per-user toggle.
function Column({ icon }: { icon: string | null }) {
  const [show, setShow] = useLocalBoolPref(SHOW_ICONS_KEY, true);
  return (
    <div>
      <label>
        <input
          type="checkbox"
          checked={show}
          onChange={(e) => setShow(e.target.checked)}
        />
        Show icons
      </label>
      <table>
        <tbody>
          <tr>
            {show && (
              <td>
                <IconCell icon={icon} source="device_class" />
              </td>
            )}
            <td>10.0.0.5</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

beforeEach(() => localStorage.clear());
afterEach(cleanup);

describe("icon column toggle (#5022)", () => {
  it("shows the effective icon, hides with the toggle and remembers it", async () => {
    const { unmount } = render(<Column icon="mdi:printer" />);
    expect(screen.getByRole("img", { name: "Printer" })).toBeTruthy();
    await userEvent.click(screen.getByLabelText("Show icons"));
    expect(screen.queryByRole("img")).toBeNull();
    expect(localStorage.getItem(SHOW_ICONS_KEY)).toBe("0");
    unmount();
    render(<Column icon="mdi:printer" />);
    expect(screen.queryByRole("img")).toBeNull();
    await act(async () => {
      await userEvent.click(screen.getByLabelText("Show icons"));
    });
    expect(screen.getByRole("img", { name: "Printer" })).toBeTruthy();
  });

  it("leaves a row without an effective icon empty", () => {
    render(<Column icon={null} />);
    expect(screen.queryByRole("img")).toBeNull();
  });
});
