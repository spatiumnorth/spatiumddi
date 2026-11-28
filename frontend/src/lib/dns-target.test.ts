import { describe, expect, it } from "vitest";
import { isNameTargetType, resolveTarget } from "./dns-target";

describe("dns-target (#5021)", () => {
  it("knows the name-target types", () => {
    for (const t of ["CNAME", "MX", "NS", "SRV", "PTR", "DNAME"])
      expect(isNameTargetType(t)).toBe(true);
    for (const t of ["A", "AAAA", "TXT", "CAA"])
      expect(isNameTargetType(t)).toBe(false);
  });
  it("qualifies a dotted relative name and flags it", () => {
    expect(resolveTarget("target.example.com", "corp.test.")).toEqual({
      fqdn: "target.example.com.corp.test.",
      relative: true,
      looksLikeOutsideName: true,
    });
  });
  it("leaves an absolute name alone", () => {
    expect(resolveTarget("target.example.com.", "corp.test.")).toEqual({
      fqdn: "target.example.com.",
      relative: false,
      looksLikeOutsideName: false,
    });
  });
  it("treats @ and a single label as relative without a flag", () => {
    expect(resolveTarget("www", "corp.test.")).toEqual({
      fqdn: "www.corp.test.",
      relative: true,
      looksLikeOutsideName: false,
    });
    expect(resolveTarget("@", "corp.test")).toEqual({
      fqdn: "corp.test.",
      relative: true,
      looksLikeOutsideName: false,
    });
  });
  it("is null when empty, and has no fqdn without a zone", () => {
    expect(resolveTarget("  ", "corp.test.")).toBeNull();
    expect(resolveTarget("a.b", undefined)?.fqdn).toBeNull();
  });
});
