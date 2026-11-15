/**
 * @vitest-environment jsdom
 *
 * #3817: a large agentless zone's push is queued, not sent in the request,
 * so the sync result must say the records are pending delivery in the
 * background, not that they were pushed or queued "for the agent".
 */
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { SyncResultModal } from "./DNSPage";

const base = {
  ok: true as const,
  server_records: 0,
  existing_in_db: 0,
  imported: 0,
  skipped_unsupported: 0,
  imported_records: [],
  push_candidates: 3,
  pushed: 3,
  pushed_records: [
    { name: "a", fqdn: "a.example.com.", record_type: "A", value: "192.0.2.1" },
  ],
  push_errors: [],
};

afterEach(cleanup);

describe("SyncResultModal queued push (#3817)", () => {
  it("says queued records are delivered in the background", () => {
    render(
      <SyncResultModal
        zoneName="example.com."
        drivers={["technitium_api"]}
        onClose={() => {}}
        result={{ ...base, queued_for_agent: true } as never}
      />,
    );
    expect(screen.getByText("Queued for delivery")).toBeTruthy();
    expect(screen.queryByText("Queued for agent")).toBeNull();
    expect(
      screen.getByText(/delivered to the server in the background/),
    ).toBeTruthy();
  });

  it("keeps Pushed for an inline push", () => {
    render(
      <SyncResultModal
        zoneName="example.com."
        drivers={["technitium_api"]}
        onClose={() => {}}
        result={{ ...base, queued_for_agent: false } as never}
      />,
    );
    expect(screen.getByText("Pushed")).toBeTruthy();
    expect(screen.queryByText(/not yet on the server/)).toBeNull();
  });
});
