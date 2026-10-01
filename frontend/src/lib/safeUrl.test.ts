import { describe, expect, it } from "vitest";

import { safeExternalHref } from "@/lib/safeUrl";

describe("safeExternalHref", () => {
  it.each([
    ["https://lg.example.net/", "https://lg.example.net/"],
    ["http://www.example.com", "http://www.example.com/"],
    ["HTTPS://Example.COM/Path", "https://example.com/Path"],
  ])("links %s", (value, href) => {
    expect(safeExternalHref(value)).toBe(href);
  });

  it.each([
    "javascript:alert(1)",
    "JAVASCRIPT:alert(1)",
    "JaVaScRiPt:alert(1)",
    " javascript:alert(1)",
    "java\tscript:alert(1)",
    "java\nscript:alert(1)",
    "\u0001javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    "file:///etc/passwd",
  ])("refuses %j", (value) => {
    expect(safeExternalHref(value)).toBeNull();
  });

  // Legitimate looking-glass schemes on PeeringDB: shown, not linked.
  it.each(["telnet://route-views.routeviews.org", "ssh://lg.example.net"])(
    "does not link %s",
    (value) => {
      expect(safeExternalHref(value)).toBeNull();
    },
  );

  it.each([
    "www.example.com",
    "/relative/path",
    "//example.com",
    "http://",
    "",
  ])("refuses malformed or relative %j", (value) => {
    expect(safeExternalHref(value)).toBeNull();
  });

  it("refuses null and undefined", () => {
    expect(safeExternalHref(null)).toBeNull();
    expect(safeExternalHref(undefined)).toBeNull();
  });
});
