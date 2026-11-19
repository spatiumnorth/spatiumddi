/**
 * @vitest-environment jsdom
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { IPAMTemplate } from "@/lib/api";
import {
  EMPTY,
  ReapplyConfirmModal,
  toCreatePayload,
} from "./IPAMTemplatesPage";

const withTtl = (ddns_ttl: string) =>
  toCreatePayload({ ...EMPTY, name: "t", ddns_ttl });

describe("template ddns_ttl (#2086)", () => {
  it.each(["1h", "1.5", "-1", "2147483648", "abc"])(
    "refuses %j with a reason, never sending a truncated value",
    (text) => {
      expect(() => withTtl(text)).toThrow(/TTL override must be a whole/);
    },
  );

  it("reads 1e3 as 1000", () => {
    expect(withTtl("1e3").ddns_ttl).toBe(1000);
  });

  it("keeps blank as no override", () => {
    expect(withTtl("").ddns_ttl).toBeNull();
    expect(withTtl("  ").ddns_ttl).toBeNull();
  });

  it("accepts 3600", () => {
    expect(withTtl("3600").ddns_ttl).toBe(3600);
  });
});

describe("Reapply dialog (#3895)", () => {
  const tpl = { id: "t1", name: "blk" } as IPAMTemplate;
  const base = {
    template: tpl,
    onClose: () => {},
    onConfirm: () => {},
    busy: false,
    result: null,
    error: "",
  };

  it("lists each skipped instance with its reason and the cap", () => {
    render(
      <ReapplyConfirmModal
        {...base}
        result={{
          template_id: "t1",
          target_kind: "block",
          instances_total: 201,
          instances_processed: 199,
          instances_skipped: 1,
          cap_reached: true,
          skipped: [
            {
              target_id: "b1",
              network: "10.46.0.0/16",
              reason: "child overlaps",
            },
          ],
        }}
      />,
    );
    expect(screen.getByRole("status").textContent).toMatch(/skipped 1/);
    expect(screen.getByText(/child overlaps/)).toBeTruthy();
    expect(screen.getByText(/10\.46\.0\.0\/16/)).toBeTruthy();
    expect(screen.getByText(/200 handled per call/)).toBeTruthy();
  });

  it("shows a refused reapply's reason", () => {
    render(<ReapplyConfirmModal {...base} error="Forbidden thing" />);
    expect(screen.getByRole("alert").textContent).toBe("Forbidden thing");
  });
});
