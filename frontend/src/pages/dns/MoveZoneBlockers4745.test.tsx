/**
 * @vitest-environment jsdom
 *
 * #4745 - a Move zone preview blocker is announced (role="alert"), not just
 * drawn in a box while Move zone goes disabled.
 */
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const preview = {
  zone_name: "example.com.",
  target_group_name: "Other",
  name_collision: true,
  dnssec_unsupported_drivers: [],
  acl_names_lost: [],
  key_names_lost: [],
  required_acknowledgements: [],
  warnings: [],
  acl_keys_lost: [],
  source_drivers: [],
  target_drivers: [],
  records_widened_by_view: {},
  technitium_api_refusal: "Technitium cannot take this zone.",
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    dnsApi: {
      ...actual.dnsApi,
      listGroups: () =>
        Promise.resolve([
          { id: "g1", name: "Home" },
          { id: "g2", name: "Other" },
        ]),
      previewZoneMove: () => Promise.resolve(preview),
    },
  };
});

import { MoveZoneModal } from "./DNSPage";

afterEach(cleanup);

describe("MoveZoneModal blockers", () => {
  it("announces each preview blocker as an alert", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <MoveZoneModal
            zone={{ id: "z1", group_id: "g1", name: "example.com." } as never}
            onClose={() => {}}
            onMoved={() => {}}
          />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    await screen.findByRole("option", { name: "Other" });
    await user.selectOptions(screen.getByRole("combobox"), "g2");
    const collision = await screen.findByText(/already has a zone/);
    expect(collision.closest('[role="alert"]')).not.toBeNull();
    const refusal = screen.getByText("Technitium cannot take this zone.");
    expect(refusal.getAttribute("role")).toBe("alert");
  });
});
