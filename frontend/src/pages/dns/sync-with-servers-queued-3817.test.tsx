/**
 * @vitest-environment jsdom
 *
 * #3817: the group's Sync with Servers dialog must not report records that
 * are only queued for background delivery as "pushed" with an ok status.
 */
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import type { DNSServerGroup } from "@/lib/api";
import { SyncWithServersResultModal } from "./DNSPage";

afterEach(cleanup);

const group = { id: "g1", name: "cloud" } as unknown as DNSServerGroup;

function show(
  queued: boolean,
  pushErrors: string[] = [],
  zoneError: string | null = null,
  extraZone = false,
) {
  const result = {
    servers_attempted: 1,
    servers_succeeded: 1,
    total_imported: 0,
    total_pushed: 250,
    total_queued: queued ? 250 : 0,
    total_push_errors: 0,
    total_zones_imported: 0,
    total_zones_pushed_to_server: 0,
    items: [
      {
        server_id: "s1",
        server_name: "tech",
        driver: "technitium_api",
        error: null,
        result: {
          zones_attempted: extraZone ? 2 : 1,
          zones_succeeded: 1,
          zones_failed: 0,
          total_imported: 0,
          total_pushed: 250,
          total_queued: queued ? 250 : 0,
          total_push_errors: 0,
          zones_on_server: [],
          new_zones_on_server: [],
          zones_imported: [],
          zones_skipped_system: [],
          zones_pushed_to_server: [],
          zones_push_to_server_errors: [],
          items: [
            {
              zone: "big.example.com",
              imported: 0,
              pushed: 250,
              server_records: 0,
              push_errors: pushErrors,
              queued_for_agent: queued,
              error: zoneError,
            },
            ...(extraZone
              ? [
                  {
                    zone: "ok.example.com",
                    imported: 0,
                    pushed: 0,
                    server_records: 1,
                    push_errors: [],
                    error: null,
                  },
                ]
              : []),
          ],
        },
      },
    ],
  };
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <SyncWithServersResultModal
          group={group}
          result={result as never}
          error={null}
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("Sync with servers modal queued push (#3817)", () => {
  it("separates queued records from pushed and does not say ok", () => {
    show(true);
    expect(screen.getByText("Queued for delivery")).toBeTruthy();
    expect(screen.getByText(/^queued, not yet on the server$/)).toBeTruthy();
    expect(screen.getByText("250 queued")).toBeTruthy();
    expect(screen.queryByText("ok")).toBeNull();
  });

  it("keeps the plain pushed wording for an inline push", () => {
    show(false);
    expect(screen.queryByText("Queued for delivery")).toBeNull();
    expect(screen.getByText("ok")).toBeTruthy();
  });

  it("announces records a server refused inside a synced zone (#4942)", () => {
    show(false, ["A www: REFUSED"]);
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("A www: REFUSED");
    expect(alert.textContent).toContain("big.example.com");
    expect(document.querySelector("details")?.hasAttribute("open")).toBe(true);
  });

  it("opens the section and says so when a zone failed (#4953)", () => {
    show(false, [], "AXFR refused", true);
    expect(document.querySelector("details")?.hasAttribute("open")).toBe(true);
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toContain("AXFR refused");
    expect(screen.getByText("2 zones, 1 failed")).toBeTruthy();
    const fig = screen.getByText("Zones failed").parentElement;
    expect(fig?.textContent).toContain("1");
  });

  it("shows no failure text for a clean sync (#4953)", () => {
    show(false);
    expect(screen.queryByText(/\d+ failed/)).toBeNull();
    expect(
      screen.getByText("Zones failed").parentElement?.textContent,
    ).toContain("0");
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
