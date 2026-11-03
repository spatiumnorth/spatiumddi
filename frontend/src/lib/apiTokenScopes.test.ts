import { describe, expect, it } from "vitest";
import { API_TOKEN_SCOPES } from "./api";

describe("API token scope picker", () => {
  it("does not offer the retired agent scope", () => {
    expect(API_TOKEN_SCOPES.map((s) => s.value)).toEqual([
      "read",
      "ipam:write",
      "dns:write",
      "dhcp:write",
    ]);
  });
});
