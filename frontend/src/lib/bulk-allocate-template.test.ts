import { describe, expect, it } from "vitest";
import {
  expandTemplate,
  hostLabelError,
  storedHostname,
  templateFormatError,
} from "./bulk-allocate-template";

describe("bulk allocate template (#2071)", () => {
  it("refuses a name ending in a hyphen", () => {
    expect(
      hostLabelError(expandTemplate("web{n}-", "10.0.0.1", 1, false)),
    ).toMatch(/web1-/);
  });
  it("refuses format specs the server does not mirror", () => {
    expect(templateFormatError("web{n:_}")).toMatch(/not supported/);
    expect(templateFormatError("web{n:,}")).toMatch(/not supported/);
    expect(templateFormatError("web{n:5d}")).toMatch(/not supported/);
    expect(templateFormatError("web{n!r}")).toMatch(/conversions/);
  });
  it("accepts and expands the supported forms like the server", () => {
    for (const t of ["web{n}", "web{n:03d}", "web{n:x}", "h-{oct3}-{oct4}"]) {
      expect(templateFormatError(t)).toBeNull();
    }
    expect(expandTemplate("Web-{n:03d}", "10.0.0.1", 7, false)).toBe("Web-007");
    expect(storedHostname("Web-007")).toBe("web-007");
    expect(hostLabelError("web-007")).toBeNull();
    expect(hostLabelError("a".repeat(64))).not.toBeNull();
  });
});
