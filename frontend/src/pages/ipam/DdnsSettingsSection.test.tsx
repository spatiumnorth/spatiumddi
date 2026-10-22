/**
 * @vitest-environment jsdom
 *
 * The DDNS TTL override shows why a value is refused (#2086). The caller
 * reads the same text with parseTtlInput and refuses to save; here the
 * section's own display and what it reports are checked.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { parseTtlInput } from "@/lib/dnsNames";

const { DdnsSettingsSection } = await import("./IPAMPage");

function open(ttlText: string, onTtlTextChange = vi.fn()) {
  render(
    <DdnsSettingsSection
      enabled
      policy="client_or_generated"
      domainOverride={null}
      ttlText={ttlText}
      onEnabledChange={() => {}}
      onPolicyChange={() => {}}
      onDomainOverrideChange={() => {}}
      onTtlTextChange={onTtlTextChange}
    />,
  );
  return onTtlTextChange;
}

afterEach(cleanup);

describe("DDNS TTL override (#2086)", () => {
  it.each(["1h", "1.5", "-1", "2147483648"])(
    "shows a reason for %j",
    (text) => {
      open(text);
      expect(screen.getByRole("alert").textContent).toMatch(
        /TTL override must be a whole number/,
      );
      expect(typeof parseTtlInput(text)).toBe("string");
    },
  );

  it("shows nothing for blank (inherit) and for 1e3 (1000)", () => {
    open("");
    expect(screen.queryByRole("alert")).toBeNull();
    cleanup();
    open("1e3");
    expect(screen.queryByRole("alert")).toBeNull();
    expect(parseTtlInput("1e3")).toBe(1000);
    expect(parseTtlInput("")).toBeNull();
  });

  it("hands the text up untouched, not a parsed number", () => {
    const on = open("");
    fireEvent.change(screen.getByPlaceholderText("300"), {
      target: { value: "1h" },
    });
    expect(on).toHaveBeenCalledWith("1h");
  });
});
