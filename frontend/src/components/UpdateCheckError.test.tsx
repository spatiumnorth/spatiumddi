/** @vitest-environment jsdom */
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { UpdateCheckError } from "./UpdateCheckError";

const base = {
  latest_checked_at: "2026-10-23T10:00:00Z",
  release_check_enabled: true,
  latest_check_error: null as string | null,
};

describe("UpdateCheckError", () => {
  it("renders the stored error", () => {
    render(
      <UpdateCheckError info={{ ...base, latest_check_error: "HTTP 403" }} />,
    );
    expect(screen.getByRole("status").textContent).toContain("HTTP 403");
  });
  it("renders nothing without an error", () => {
    const { container } = render(<UpdateCheckError info={base} />);
    expect(container.innerHTML).toBe("");
  });
  it("renders nothing when the check is turned off", () => {
    const { container } = render(
      <UpdateCheckError
        info={{
          ...base,
          release_check_enabled: false,
          latest_check_error: "HTTP 403",
        }}
      />,
    );
    expect(container.innerHTML).toBe("");
  });
  it("compact form carries the error in its title", () => {
    render(
      <UpdateCheckError
        compact
        info={{ ...base, latest_check_error: "boom" }}
      />,
    );
    expect(screen.getByRole("status").getAttribute("title")).toContain("boom");
  });
});
