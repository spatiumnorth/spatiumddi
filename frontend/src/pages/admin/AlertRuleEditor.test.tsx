/**
 * @vitest-environment jsdom
 *
 * Alert rule editor (#1986, #1993, #1994).
 *
 * - An unchanged Save stores nothing new: the editor shows the stored
 *   values (a stored null stays empty), and sends only what changed.
 * - A 422 with FastAPI's validation list renders as text; the dialog stays
 *   open instead of the page crashing with React error #31.
 * - Every visible label names its control.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import type { AlertRule } from "@/lib/api";

const updateRule = vi.fn();
const createRule = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    alertsApi: {
      ...actual.alertsApi,
      updateRule: (...a: unknown[]) => updateRule(...a),
      createRule: (...a: unknown[]) => createRule(...a),
    },
  };
});

const { RuleEditorModal } = await import("./AlertsPage");

function rule(over: Partial<AlertRule>): AlertRule {
  return {
    id: "r1",
    name: "r1",
    description: "",
    enabled: false,
    rule_type: "voice_lease_count_below",
    threshold_percent: null,
    threshold_days: null,
    min_free_addresses: null,
    server_type: null,
    classification: null,
    change_scope: null,
    last_scanned_audit_at: null,
    severity: "info",
    notify_syslog: false,
    notify_webhook: false,
    notify_smtp: false,
    created_at: "2026-10-16T00:00:00Z",
    modified_at: "2026-10-16T00:00:00Z",
    ...over,
  };
}

function mount(existing: AlertRule | null) {
  const onClose = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient()}>
      <RuleEditorModal existing={existing} onClose={onClose} />
    </QueryClientProvider>,
  );
  return onClose;
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("unchanged Save (#1986)", () => {
  it.each([
    ["voice_lease_count_below", {}],
    ["ip_free_but_responding", { threshold_days: 5 }],
    ["stale_ip_count", {}],
    ["subnet_utilization", { threshold_percent: 80 }],
    [
      "compliance_change",
      { classification: "pci_scope", change_scope: "create" },
    ],
    ["server_unreachable", { server_type: "dns" }],
  ] as const)("%s sends nothing", async (rule_type, over) => {
    const onClose = mount(
      rule({ rule_type: rule_type as AlertRule["rule_type"], ...over }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateRule).not.toHaveBeenCalled();
  });

  it("shows a stored null as empty, not as a default", () => {
    mount(rule({ rule_type: "voice_lease_count_below" }));
    expect(
      (screen.getByLabelText("Minimum active leases") as HTMLInputElement)
        .value,
    ).toBe("");
  });

  it("sends only the changed field", async () => {
    updateRule.mockResolvedValue(rule({}));
    mount(rule({ rule_type: "stale_ip_count" }));
    fireEvent.change(screen.getByLabelText("Stale window (days)"), {
      target: { value: "45" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateRule).toHaveBeenCalled());
    expect(updateRule).toHaveBeenCalledWith("r1", { threshold_days: 45 });
  });
});

describe("refused save (#1993)", () => {
  it("renders a 422 list as text and keeps the dialog open", async () => {
    createRule.mockRejectedValue({
      response: {
        data: {
          detail: [
            {
              type: "value_error",
              loc: ["body", "threshold_percent"],
              msg: "threshold_percent must be 0..100",
              input: 150,
            },
          ],
        },
      },
    });
    const onClose = mount(null);
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "x" },
    });
    fireEvent.change(screen.getByLabelText("Threshold (%)"), {
      target: { value: "150" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText(
        "threshold_percent: threshold_percent must be 0..100",
      ),
    ).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
  });
});

describe("labels name their controls (#1994)", () => {
  it("finds each control by its visible label", () => {
    mount(null);
    for (const l of [
      "Name",
      "Description",
      "Rule type",
      "Threshold (%)",
      "Severity",
    ])
      expect(screen.getByLabelText(l)).toBeTruthy();
  });
});
