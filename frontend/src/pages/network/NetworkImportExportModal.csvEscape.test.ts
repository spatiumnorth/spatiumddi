import { describe, expect, it } from "vitest";
import { csvEscape } from "./NetworkImportExportModal";

describe("csvEscape", () => {
  it("prefixes cells that start with a formula character", () => {
    expect(csvEscape("=SUM(A1)")).toBe("'=SUM(A1)");
    expect(csvEscape("+1")).toBe("'+1");
    expect(csvEscape("@x")).toBe("'@x");
    expect(csvEscape("-x")).toBe("'-x");
  });
  it("leaves ordinary cells alone and still quotes commas", () => {
    expect(csvEscape("core-sw")).toBe("core-sw");
    expect(csvEscape(161)).toBe("161");
    expect(csvEscape("a,b")).toBe('"a,b"');
  });
});
