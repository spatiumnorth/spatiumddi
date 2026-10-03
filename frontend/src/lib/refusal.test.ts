/**
 * Telling a refused read from an empty one and from a failure (#1343).
 *
 * The pages' tests (pages/refused-list-reads.test.tsx) hold each page to
 * what it shows; these pin the rules those pages share: what counts as a
 * refusal, what the sentence says for each kind of failure, and that only a
 * refusal stops a poll.
 */

import { describe, expect, it } from "vitest";
import {
  apiErrorStatus,
  isRefused,
  listReadErrorMessage,
  pollUnlessRefused,
} from "./refusal";

function answered(status: number, detail?: unknown) {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    response: { status, data: detail === undefined ? {} : { detail } },
  });
}

describe("apiErrorStatus / isRefused", () => {
  it("reads the status the server answered with", () => {
    expect(apiErrorStatus(answered(403))).toBe(403);
    expect(apiErrorStatus(answered(500))).toBe(500);
  });

  it("has no status for a request that got no answer", () => {
    expect(apiErrorStatus(new Error("Network Error"))).toBeUndefined();
    expect(apiErrorStatus(null)).toBeUndefined();
    expect(apiErrorStatus(undefined)).toBeUndefined();
  });

  it("calls only a 403 a refusal", () => {
    expect(isRefused(answered(403))).toBe(true);
    expect(isRefused(answered(401))).toBe(false);
    expect(isRefused(answered(404))).toBe(false);
    expect(isRefused(new Error("Network Error"))).toBe(false);
  });
});

describe("listReadErrorMessage", () => {
  it("says the reader may not see the list, with the server's reason", () => {
    expect(
      listReadErrorMessage(answered(403, "Superadmin required"), "users"),
    ).toBe("You don't have permission to see users (Superadmin required).");
  });

  it("leaves out FastAPI's bare default, which adds nothing", () => {
    expect(
      listReadErrorMessage(answered(403, "Forbidden"), "the targets"),
    ).toBe("You don't have permission to see the targets.");
  });

  it("does not quote axios's own message as the server's reason", () => {
    expect(listReadErrorMessage(answered(403), "the trash")).toBe(
      "You don't have permission to see the trash.",
    );
  });

  it("calls any other failure a failure, with its reason, never empty", () => {
    const msg = listReadErrorMessage(
      answered(500, "Internal Server Error"),
      "the trash",
    );
    expect(msg).toBe("Couldn't load the trash: Internal Server Error");
    expect(listReadErrorMessage(new Error("Network Error"), "users")).toBe(
      "Couldn't load users: Network Error",
    );
  });
});

describe("pollUnlessRefused", () => {
  const every30s = pollUnlessRefused(30_000);

  it("keeps polling while the read is answered or has not failed", () => {
    expect(every30s({ state: { error: null } })).toBe(30_000);
  });

  it("stops once the read is refused", () => {
    expect(every30s({ state: { error: answered(403) } })).toBe(false);
  });

  it("keeps polling through a failure that may be transient", () => {
    expect(every30s({ state: { error: answered(503) } })).toBe(30_000);
    expect(every30s({ state: { error: new Error("Network Error") } })).toBe(
      30_000,
    );
  });
});
