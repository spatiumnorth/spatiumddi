/**
 * @vitest-environment jsdom
 *
 * A dialog keeps keyboard focus when its own focused button is disabled
 * while the request runs, so a refusal leaves focus inside the open dialog
 * (#3155, on top of #2723's removed-control case).
 */
import { useState } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Modal } from "./modal";

afterEach(cleanup);

function Refusable() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  return (
    <Modal title="Delete thing" onClose={() => {}}>
      {error && <p role="alert">{error}</p>}
      <button
        disabled={pending}
        onClick={() => {
          setPending(true);
          setTimeout(() => {
            setPending(false);
            setError("refused");
          }, 20);
        }}
      >
        Delete
      </button>
    </Modal>
  );
}

describe("focus after a refused request (#3155)", () => {
  it("is inside the dialog once the focused button was disabled", async () => {
    const user = userEvent.setup();
    render(<Refusable />);
    const dialog = screen.getByRole("dialog", { name: "Delete thing" });
    const btn = screen.getByRole("button", { name: "Delete" });
    btn.focus();
    await user.keyboard("{Enter}");
    await screen.findByRole("alert");
    await act(async () => {
      await new Promise((r) => setTimeout(r, 30));
    });
    await waitFor(() => {
      expect(document.activeElement).not.toBe(document.body);
      expect(dialog.contains(document.activeElement)).toBe(true);
    });
    // A disabled button never keeps focus.
    expect(document.activeElement).not.toBe(btn);
  });
});
