/**
 * @vitest-environment jsdom
 *
 * #2225 — the new-code dialog asks how many appliances, each code row shows
 * who used it, and refused joins are listed with a plain-words reason.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const m = vi.hoisted(() => ({
  create: vi.fn(),
  list: vi.fn(),
  listAttempts: vi.fn(),
  dismissAttempt: vi.fn(),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    appliancePairingApi: { ...actual.appliancePairingApi, ...m },
    authApi: {
      ...actual.authApi,
      me: vi.fn().mockResolvedValue({ is_superadmin: true }),
    },
    settingsApi: {
      ...actual.settingsApi,
      get: vi.fn().mockResolvedValue({ supervisor_registration_enabled: true }),
    },
  };
});

const { PairingTab } = await import("@/pages/appliance/PairingTab");
const { codeRequestFor, attemptReasonText } =
  await import("@/pages/appliance/pairingCodes");

const codeRow = (over: object) => ({
  id: "c1",
  code_last_two: "42",
  persistent: false,
  enabled: true,
  state: "claimed",
  expires_at: null,
  max_claims: null,
  claim_count: 1,
  claims: [],
  revoked_at: null,
  note: null,
  created_at: "2026-11-01T00:00:00Z",
  created_by_user_id: null,
  ...over,
});

function mount() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <PairingTab />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  Object.values(m).forEach((f) => f.mockReset());
  m.listAttempts.mockResolvedValue({ attempts: [] });
});
afterEach(cleanup);

describe("codeRequestFor", () => {
  it("maps a count onto persistent + max_claims", () => {
    expect(codeRequestFor(1)).toEqual({ persistent: false, max_claims: null });
    expect(codeRequestFor(3)).toEqual({ persistent: true, max_claims: 3 });
    expect(codeRequestFor("unlimited")).toEqual({
      persistent: true,
      max_claims: null,
    });
  });
});

describe("Pairing codes tab", () => {
  it("asks how many appliances and sends max_claims for two", async () => {
    m.list.mockResolvedValue({ codes: [] });
    m.create.mockResolvedValue({
      id: "n",
      code: "12345678",
      persistent: true,
      enabled: true,
      expires_at: null,
      max_claims: 2,
      note: null,
      created_at: "2026-11-01T00:00:00Z",
    });
    mount();
    fireEvent.click(await screen.findByText("New pairing code"));
    expect(
      screen.getByText("How many appliances will join with this code?"),
    ).toBeTruthy();
    expect(screen.getByText(/second one is refused/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Number of appliances"), {
      target: { value: "2" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Generate/ }));
    await waitFor(() => expect(m.create).toHaveBeenCalled());
    expect(m.create.mock.calls[0][0]).toMatchObject({
      persistent: true,
      max_claims: 2,
    });
  });

  it("shows who used each code", async () => {
    m.list.mockResolvedValue({
      codes: [
        codeRow({
          claims: [
            {
              appliance_id: "a",
              hostname: "node2",
              claimed_at: "2026-11-01T14:02:00Z",
            },
          ],
        }),
        codeRow({
          id: "c2",
          persistent: true,
          max_claims: 5,
          claim_count: 2,
          state: "pending",
          claims: [
            {
              appliance_id: "b",
              hostname: "n3",
              claimed_at: "2026-11-01T14:03:00Z",
            },
            {
              appliance_id: "c",
              hostname: "n4",
              claimed_at: "2026-11-01T14:04:00Z",
            },
          ],
        }),
      ],
    });
    mount();
    expect(await screen.findByText("node2")).toBeTruthy();
    expect(screen.getByText("2 of 5 used")).toBeTruthy();
    expect(screen.getByText("n3, n4")).toBeTruthy();
  });

  it("lists refused joins with the reason and can dismiss one", async () => {
    m.list.mockResolvedValue({ codes: [] });
    m.dismissAttempt.mockResolvedValue(undefined);
    m.listAttempts.mockResolvedValue({
      attempts: [
        {
          id: "x1",
          reason: "already_used",
          hostname: "node3",
          source_ip: "10.0.0.3",
          attempts: 4,
          first_attempted_at: "2026-11-01T14:00:00Z",
          last_attempted_at: "2026-11-01T14:10:00Z",
          pairing_code_id: "c1",
          code_last_two: "42",
          code_note: null,
          used_by: ["node2"],
        },
      ],
    });
    mount();
    expect(await screen.findByText("code already used by node2")).toBeTruthy();
    expect(screen.getByText("node3")).toBeTruthy();
    expect(screen.getByText("••42")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(m.dismissAttempt.mock.calls[0][0]).toBe("x1"));
  });
});

describe("attemptReasonText", () => {
  it("says the unknown-code case plainly", () => {
    expect(
      attemptReasonText({ reason: "unknown_code", used_by: [] } as never),
    ).toBe("unknown code");
  });
});
