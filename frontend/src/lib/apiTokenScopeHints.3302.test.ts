/**
 * The token dialog's scope hints state what the gate enforces (#3302): the
 * read-only hint no longer claims "no mutations anywhere" of a scope that also
 * admits read-only POSTs and MCP, and every write scope says it grants no reads.
 */
import { describe, expect, it } from "vitest";

import { API_TOKEN_SCOPES } from "./api";

const hint = (v: string) => API_TOKEN_SCOPES.find((s) => s.value === v)!.hint;

describe("API_TOKEN_SCOPES hints", () => {
  it("read-only names the POSTs and MCP it admits and the outbound it refuses", () => {
    const h = hint("read");
    expect(h).toMatch(/read-only POSTs/);
    expect(h).toMatch(/MCP/);
    expect(h).toMatch(/another host/);
    expect(h).not.toMatch(/no mutations anywhere/i);
  });

  it.each(["ipam:write", "dns:write", "dhcp:write"])(
    "%s says it grants no reads and cannot use MCP alone",
    (scope) => {
      expect(hint(scope)).toMatch(/Grants no reads: add Read-only/);
      expect(hint(scope)).toMatch(/cannot use MCP/);
    },
  );
});
