/**
 * @vitest-environment jsdom
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FormError } from "./form-error";

describe("FormError (#3821)", () => {
  it("announces the refusal as an alert", () => {
    render(<FormError>Group name already in use</FormError>);
    expect(screen.getByRole("alert").textContent).toBe(
      "Group name already in use",
    );
  });

  it("renders nothing without a message", () => {
    const { container } = render(<FormError>{null}</FormError>);
    expect(container.innerHTML).toBe("");
  });
});
