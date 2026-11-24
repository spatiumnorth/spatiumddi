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
  it("unreachable renders neutral grey, not the amber warning", () => {
    const info = {
      ...base,
      latest_check_error: "Could not connect to api.github.com:443",
      latest_check_error_kind: "unreachable" as const,
    };
    const { unmount } = render(<UpdateCheckError compact info={info} />);
    const chip = screen.getByRole("status");
    expect(chip.textContent).toContain("GitHub unreachable");
    expect(chip.textContent).not.toContain("check failed");
    expect(chip.className).not.toContain("amber");
    expect(chip.getAttribute("title")).toContain("turn the release check off");
    unmount();
    render(<UpdateCheckError info={info} />);
    const banner = screen.getByRole("status");
    expect(banner.textContent).toContain("GitHub isn't reachable");
    expect(banner.className).not.toContain("amber");
  });
  it("an HTTP error keeps the amber warning", () => {
    render(
      <UpdateCheckError
        compact
        info={{
          ...base,
          latest_check_error: "HTTP 500",
          latest_check_error_kind: "http",
        }}
      />,
    );
    const chip = screen.getByRole("status");
    expect(chip.textContent).toContain("check failed");
    expect(chip.className).toContain("amber");
  });
});
