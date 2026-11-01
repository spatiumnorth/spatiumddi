import { describe, expect, it } from "vitest";

import { formatApiError, rethrowBlobError } from "@/lib/api";
import { exportErrorMessage } from "@/lib/refusal";

describe("rethrowBlobError (#3255)", () => {
  it("decodes a Blob error body so the server's reason is readable", async () => {
    const err = {
      message: "Request failed with status code 403",
      response: {
        status: 403,
        data: new Blob([JSON.stringify({ detail: "Permission denied: x" })]),
      },
    };
    await expect(rethrowBlobError(err)).rejects.toBe(err);
    expect(formatApiError(err)).toBe("Permission denied: x");
    expect(exportErrorMessage(err, "the report")).toMatch(
      /not permitted to export the report \(Permission denied: x\)/,
    );
  });
});
