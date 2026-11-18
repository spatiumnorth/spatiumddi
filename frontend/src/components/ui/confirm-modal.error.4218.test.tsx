/**
 * @vitest-environment jsdom
 *
 * ConfirmModal's `error` is drawn inside the open dialog as an alert (#4218).
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { ConfirmModal } from "./confirm-modal";

afterEach(cleanup);

describe("ConfirmModal error (#4218)", () => {
  it("announces the refusal inside the dialog", () => {
    render(
      <ConfirmModal
        open
        title="Delete thing?"
        message="gone"
        error="Still in use"
        onConfirm={() => {}}
        onClose={() => {}}
      />,
    );
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("alert").textContent).toBe("Still in use");
  });

  it("draws no alert without an error", () => {
    render(
      <ConfirmModal
        open
        title="Delete thing?"
        message="gone"
        onConfirm={() => {}}
        onClose={() => {}}
      />,
    );
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
