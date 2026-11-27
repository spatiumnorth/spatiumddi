/**
 * @vitest-environment jsdom
 *
 * #4659: a pairing code minted while appliance registration is off says so.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { PairingCodeCreated } from "@/lib/api";
import { GeneratedView } from "./PairingTab";

afterEach(cleanup);

const code = (warning?: string | null): PairingCodeCreated => ({
  id: "1",
  code: "12345678",
  persistent: false,
  enabled: true,
  expires_at: null,
  max_claims: null,
  note: null,
  created_at: "2026-11-20T00:00:00Z",
  warning,
});

describe("GeneratedView registration warning (#4659)", () => {
  it("shows the warning and a way to the setting", () => {
    const onClose = vi.fn();
    render(
      <GeneratedView
        code={code("Appliance registration is off, so it cannot register.")}
        onClose={onClose}
      />,
    );
    expect(screen.getByRole("alert").textContent).toContain(
      "Appliance registration is off",
    );
    fireEvent.click(screen.getByText("Go to the registration setting"));
    expect(onClose).toHaveBeenCalled();
  });

  it("shows nothing when registration is on", () => {
    render(<GeneratedView code={code(null)} onClose={() => {}} />);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
