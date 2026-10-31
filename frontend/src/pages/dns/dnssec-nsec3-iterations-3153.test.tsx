/**
 * @vitest-environment jsdom
 *
 * #3153 — a DNSSEC policy's NSEC3 iterations are fixed at 0 (BIND 9.20
 * refuses any other value and rejects the whole named.conf over it), so the
 * form cannot send anything else, even when editing a row saved with more.
 */
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

const updateDnssecPolicy = vi.fn();

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
      listDnssecPolicies: () =>
        Promise.resolve([
          {
            id: "p-1",
            name: "old",
            description: "",
            is_builtin: false,
            algorithm: "ecdsap256sha256",
            ksk_lifetime_days: 0,
            zsk_lifetime_days: 90,
            nsec3: true,
            nsec3_iterations: 151,
            nsec3_salt_length: 8,
            nsec3_optout: false,
            created_at: "2026-10-01T00:00:00Z",
            modified_at: "2026-10-01T00:00:00Z",
          },
        ]),
      updateDnssecPolicy: (...a: unknown[]) => updateDnssecPolicy(...a),
    },
  };
});

import { DNSSECPoliciesPage } from "./DNSSECPoliciesPage";

afterEach(() => {
  cleanup();
  updateDnssecPolicy.mockReset();
});

describe("DNSSEC policy NSEC3 iterations (#3153)", () => {
  it("shows iterations as a fixed 0 and saves 0 for a row stored with 151", async () => {
    updateDnssecPolicy.mockResolvedValue({});
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <DNSSECPoliciesPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const edit = await screen.findByRole("button", { name: "Edit" });
    await waitFor(() =>
      expect((edit as HTMLButtonElement).disabled).toBe(false),
    );
    await userEvent.click(edit);
    const input = (await screen.findByLabelText(
      "Iterations",
    )) as HTMLInputElement;
    expect(input.value).toBe("0");
    expect(input.disabled).toBe(true);
    await userEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() => expect(updateDnssecPolicy).toHaveBeenCalled());
    expect(updateDnssecPolicy.mock.calls[0][1].nsec3_iterations).toBe(0);
  });
});
