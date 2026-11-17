/**
 * @vitest-environment jsdom
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ListEmpty } from "./list-read-error";

const hint = 'Click "New thing" to add one.';

describe("ListEmpty hint + gate (#3885)", () => {
  it("draws the button instruction for a reader who may use it", () => {
    render(
      <ListEmpty error={null} what="things" gate={{}} hint={hint}>
        No things yet.
      </ListEmpty>,
    );
    expect(screen.getByText(/No things yet\./).textContent).toContain(hint);
  });

  it("drops the instruction when the button is disabled", () => {
    render(
      <ListEmpty
        error={null}
        what="things"
        gate={{ disabled: true, title: "Requires write" }}
        hint={hint}
      >
        No things yet.
      </ListEmpty>,
    );
    const el = screen.getByText(/No things yet\./);
    expect(el.textContent).toBe("No things yet.");
    expect(screen.queryByText(/New thing/)).toBeNull();
  });
});
