/**
 * @vitest-environment jsdom
 */
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useDebouncedValue } from "./useDebouncedValue";

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe("useDebouncedValue", () => {
  it("holds the old value until the input has been quiet for the delay", () => {
    const { result, rerender } = renderHook(
      ({ v }) => useDebouncedValue(v, 300),
      { initialProps: { v: "" } },
    );
    rerender({ v: "1" });
    rerender({ v: "12" });
    rerender({ v: "127" });
    act(() => {
      vi.advanceTimersByTime(299);
    });
    expect(result.current).toBe("");
    act(() => {
      vi.advanceTimersByTime(2);
    });
    expect(result.current).toBe("127");
  });
});
