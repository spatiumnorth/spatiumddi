/**
 * @vitest-environment jsdom
 */
import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { useCredentialReask } from "./useCredentialReask";

describe("useCredentialReask (#4135)", () => {
  const base = { host: "a.example", port: 443 };

  it("is off until a destination field differs, and only asks for a stored credential", () => {
    const { result, rerender } = renderHook(
      ({ dest }) => useCredentialReask(dest, base),
      { initialProps: { dest: { ...base } } },
    );
    expect(result.current.reask).toBe(false);
    expect(result.current.asks(true)).toBe(false);
    rerender({ dest: { ...base, host: "b.example" } });
    expect(result.current.reask).toBe(true);
    expect(result.current.asks(true)).toBe(true);
    // Nothing stored, nothing to re-enter.
    expect(result.current.asks(false)).toBe(false);
    expect(result.current.asks(undefined)).toBe(false);
  });

  it("compares as text, so a port edited to the same number is not a move", () => {
    const { result } = renderHook(() =>
      useCredentialReask({ host: "a.example", port: "443" }, base),
    );
    expect(result.current.reask).toBe(false);
  });

  it("never asks on a create form (no baseline)", () => {
    const { result } = renderHook(() =>
      useCredentialReask({ host: "x" }, null),
    );
    expect(result.current.reask).toBe(false);
  });

  it("clears the credential on a move and again when the address is restored", () => {
    const onChange = vi.fn();
    const { result, rerender } = renderHook(
      ({ dest }) => useCredentialReask(dest, base, onChange),
      { initialProps: { dest: { ...base } } },
    );
    expect(onChange).not.toHaveBeenCalled();
    rerender({ dest: { ...base, port: 8443 } });
    expect(onChange).toHaveBeenLastCalledWith(true);
    act(() => rerender({ dest: { ...base } }));
    expect(result.current.reask).toBe(false);
    expect(onChange).toHaveBeenLastCalledWith(false);
    expect(onChange).toHaveBeenCalledTimes(2);
  });
});
