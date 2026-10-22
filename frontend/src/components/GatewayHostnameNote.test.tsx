/** @vitest-environment jsdom */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { GatewayHostnameNote } from "./GatewayHostnameNote";
import { GATEWAY_FORWARD_SKIPPED_NOTE } from "@/lib/gatewayDns";

afterEach(cleanup);

describe("GatewayHostnameNote", () => {
  it("renders the advisory text as a note, not an alert", () => {
    render(<GatewayHostnameNote />);
    const el = screen.getByRole("note");
    expect(el.textContent).toBe(GATEWAY_FORWARD_SKIPPED_NOTE);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
