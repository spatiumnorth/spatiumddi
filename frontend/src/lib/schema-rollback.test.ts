import { describe, expect, it } from "vitest";

import { schemaRollbackRefusal } from "@/lib/schema-rollback";

const refusal = {
  code: "schema_rollback_unsafe",
  verdict: "incompatible",
  target_version: "2026.09.04-1",
  target_head: "f3b8d21c74ae",
  head_source: "bundled",
  database_revision: "e6b2d94f1a37",
  message: "…cannot run on it…",
};

function axiosError(status: number, detail: unknown) {
  return {
    message: `Request failed with status code ${status}`,
    response: { status, data: { detail } },
  };
}

describe("schemaRollbackRefusal (#1227)", () => {
  it("recognises the refusal by its code", () => {
    expect(schemaRollbackRefusal(axiosError(409, refusal))).toMatchObject({
      target_version: "2026.09.04-1",
      database_revision: "e6b2d94f1a37",
    });
  });

  it("ignores every other 409, including one that mentions the same words", () => {
    // Keyed on detail.code, never on prose: a string detail or another
    // structured 409 must not open the confirmation that retries with the
    // acknowledgement.
    expect(schemaRollbackRefusal(axiosError(409, refusal.message))).toBeNull();
    expect(
      schemaRollbackRefusal(axiosError(409, { ...refusal, code: "other" })),
    ).toBeNull();
  });

  it("ignores the code on a status that is not 409, and non-HTTP errors", () => {
    expect(schemaRollbackRefusal(axiosError(422, refusal))).toBeNull();
    expect(schemaRollbackRefusal(new Error("network"))).toBeNull();
    expect(schemaRollbackRefusal(undefined)).toBeNull();
  });
});
