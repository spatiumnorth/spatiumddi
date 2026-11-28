/**
 * @vitest-environment jsdom
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { CustomFieldMultiSelect } from "./CustomFieldMultiSelect";

afterEach(() => cleanup());

describe("CustomFieldMultiSelect (#4288)", () => {
  it("ticks what is stored and sends the list on change", () => {
    const onChange = vi.fn();
    render(
      <CustomFieldMultiSelect
        label="Sites"
        options={["a", "b", "c"]}
        value={["a"]}
        onChange={onChange}
      />,
    );
    expect((screen.getByLabelText("a") as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText("b") as HTMLInputElement).checked).toBe(
      false,
    );
    fireEvent.click(screen.getByLabelText("b"));
    expect(onChange).toHaveBeenLastCalledWith(["a", "b"]);
    fireEvent.click(screen.getByLabelText("a"));
    expect(onChange).toHaveBeenLastCalledWith([]);
  });
});
