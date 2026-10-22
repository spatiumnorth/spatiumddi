import { describe, expect, it } from "vitest";
import { EMPTY, toCreatePayload } from "./IPAMTemplatesPage";

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
