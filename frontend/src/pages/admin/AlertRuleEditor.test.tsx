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

import type { AlertParamSpec, AlertRule, AlertRuleTypeSpec } from "@/lib/api";

const int = (
  name: AlertParamSpec["name"],
  label: string,
  over: Partial<AlertParamSpec> = {},
): AlertParamSpec => ({
  name,
  label,
  kind: "integer",
  unit: null,
  min: null,
  max: null,
  default: null,
  initial: null,
  hint: null,
  options: [],
  ...over,
});
const sel = (
  name: AlertParamSpec["name"],
  label: string,
  options: string[],
  over: Partial<AlertParamSpec> = {},
): AlertParamSpec => ({
  ...int(name, label, over),
  kind: "select",
  options: options.map((o) => ({ value: o, label: o })),
});
const t = (
  rule_type: string,
  params: AlertParamSpec[],
  group = "G",
): AlertRuleTypeSpec => ({
  rule_type,
  label: rule_type,
  group,
  description: null,
  params,
});
// What the backend serves — a few types, including one the old hand-kept
// frontend union never knew (ip_free_but_responding, #1997).
const CATALOGUE: AlertRuleTypeSpec[] = [
  t("subnet_utilization", [
    int("threshold_percent", "Threshold (%)", { default: 90, unit: "%" }),
  ]),
  t("voice_lease_count_below", [
    int("threshold_percent", "Minimum active leases", {
      default: 1,
      initial: 10,
    }),
  ]),
  t("stale_ip_count", [
    int("threshold_percent", "Stale IP count threshold", { default: 10 }),
    int("threshold_days", "Stale window (days)", { default: 90 }),
  ]),
  t("ip_free_but_responding", [
    int("threshold_days", "Recency window (days)", { default: 1 }),
  ]),
  t("domain_nameserver_drift", []),
  // Its evaluator default (200) is above what the API accepts (0..100).
  t("dns_query_rate_spike", [
    int("threshold_percent", "Increase over prior window (%)", {
      default: 200,
      min: 0,
      max: 100,
    }),
    int("min_free_addresses", "Minimum queries", { default: 1000, min: 1 }),
  ]),
  t("server_unreachable", [
    sel("server_type", "Server type", ["any", "dns", "dhcp"], {
      default: "any",
    }),
  ]),
  {
    ...t("cluster_upgrade_failed", []),
    description: "Seeded by the platform; it has no parameters to set.",
    system_driven: true,
  },
  t("compliance_change", [
    sel("classification", "Classification", ["pci_scope", "hipaa_scope"], {
      initial: "pci_scope",
    }),
    sel("change_scope", "Change scope", ["any_change", "create", "delete"], {
      default: "any_change",
    }),
  ]),
];

const updateRule = vi.fn();
const createRule = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    alertsApi: {
      ...actual.alertsApi,
      ruleTypes: () => Promise.resolve(CATALOGUE),
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
    // A stored null a select can only show as its default value.
    ["server_unreachable", {}],
    [
      "compliance_change",
      { classification: "hipaa_scope", change_scope: null },
    ],
  ] as const)("%s sends nothing", async (rule_type, over) => {
    const onClose = mount(
      rule({ rule_type: rule_type as AlertRule["rule_type"], ...over }),
    );
    const save = screen.getByRole("button", { name: "Save" });
    await waitFor(() =>
      expect((save as HTMLButtonElement).disabled).toBe(false),
    );
    fireEvent.click(save);
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateRule).not.toHaveBeenCalled();
  });

  it("shows a stored null as empty, not as a default", async () => {
    mount(rule({ rule_type: "voice_lease_count_below" }));
    expect(
      (
        (await screen.findByLabelText(
          "Minimum active leases",
        )) as HTMLInputElement
      ).value,
    ).toBe("");
  });

  it("sends only the changed field", async () => {
    updateRule.mockResolvedValue(rule({}));
    mount(rule({ rule_type: "stale_ip_count" }));
    fireEvent.change(await screen.findByLabelText("Stale window (days)"), {
      target: { value: "45" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateRule).toHaveBeenCalled());
    expect(updateRule).toHaveBeenCalledWith("r1", { threshold_days: 45 });
  });
});

describe("clearing a value (#1986)", () => {
  it("sends null when a stored threshold is cleared", async () => {
    updateRule.mockResolvedValue(rule({}));
    mount(rule({ rule_type: "subnet_utilization", threshold_percent: 80 }));
    fireEvent.change(await screen.findByLabelText("Threshold (%)"), {
      target: { value: "" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateRule).toHaveBeenCalled());
    expect(updateRule).toHaveBeenCalledWith("r1", { threshold_percent: null });
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
    fireEvent.change(await screen.findByLabelText("Threshold (%)"), {
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
  it("finds each control by its visible label", async () => {
    mount(null);
    await screen.findByLabelText("Threshold (%)");
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

describe("types the old frontend union did not know (#1997)", () => {
  it("shows threshold_days for ip_free_but_responding", async () => {
    mount(rule({ rule_type: "ip_free_but_responding", threshold_days: 5 }));
    const input = (await screen.findByLabelText(
      "Recency window (days)",
    )) as HTMLInputElement;
    expect(input.value).toBe("5");
  });

  it("an untouched Save on it sends nothing", async () => {
    const onClose = mount(
      rule({ rule_type: "ip_free_but_responding", threshold_days: 5 }),
    );
    await screen.findByLabelText("Recency window (days)");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateRule).not.toHaveBeenCalled();
  });

  it("an untouched Save on a stored null sends nothing and keeps it empty", async () => {
    const onClose = mount(rule({ rule_type: "ip_free_but_responding" }));
    const input = (await screen.findByLabelText(
      "Recency window (days)",
    )) as HTMLInputElement;
    expect(input.value).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateRule).not.toHaveBeenCalled();
  });

  it("editing it sends only that field", async () => {
    updateRule.mockResolvedValue(rule({}));
    mount(rule({ rule_type: "ip_free_but_responding", threshold_days: 5 }));
    fireEvent.change(await screen.findByLabelText("Recency window (days)"), {
      target: { value: "3" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateRule).toHaveBeenCalled());
    expect(updateRule).toHaveBeenCalledWith("r1", { threshold_days: 3 });
  });

  it("a type with no parameters says so", async () => {
    mount(rule({ rule_type: "domain_nameserver_drift" }));
    expect(await screen.findByText("No adjustable parameters.")).toBeTruthy();
  });

  it("lists catalogue types in the New-rule picker", async () => {
    mount(null);
    const select = (await screen.findByLabelText(
      "Rule type",
    )) as HTMLSelectElement;
    await waitFor(() =>
      expect(Array.from(select.options).map((o) => o.value)).toContain(
        "ip_free_but_responding",
      ),
    );
  });
});

describe("a new rule starts from the catalogue (#1997)", () => {
  async function create(ruleType: string) {
    createRule.mockResolvedValue(rule({}));
    mount(null);
    const select = (await screen.findByLabelText(
      "Rule type",
    )) as HTMLSelectElement;
    await waitFor(() =>
      expect(Array.from(select.options).map((o) => o.value)).toContain(
        ruleType,
      ),
    );
    fireEvent.change(select, { target: { value: ruleType } });
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "x" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() => expect(createRule).toHaveBeenCalled());
    return createRule.mock.calls[0][0] as Record<string, unknown>;
  }

  it("uses the evaluator default when there is no initial", async () => {
    const body = await create("ip_free_but_responding");
    expect(body.rule_type).toBe("ip_free_but_responding");
    expect(body.threshold_days).toBe(1);
  });

  it("uses initial over the default", async () => {
    expect((await create("voice_lease_count_below")).threshold_percent).toBe(
      10,
    );
  });

  it("leaves a default the API would refuse empty", async () => {
    const body = await create("dns_query_rate_spike");
    expect(body.threshold_percent).toBeNull();
    expect(body.min_free_addresses).toBe(1000);
  });

  it("sends a compliance rule's classification and scope", async () => {
    const body = await create("compliance_change");
    expect(body.classification).toBe("pci_scope");
    expect(body.change_scope).toBe("any_change");
  });

  it("sends only this type's parameters", async () => {
    const body = await create("domain_nameserver_drift");
    for (const k of [
      "threshold_percent",
      "threshold_days",
      "min_free_addresses",
      "server_type",
      "classification",
      "change_scope",
    ])
      expect(k in body).toBe(false);
  });
});

describe("editing a catalogue-only type (#1997)", () => {
  it("clearing its value sends null", async () => {
    updateRule.mockResolvedValue(rule({}));
    mount(rule({ rule_type: "ip_free_but_responding", threshold_days: 5 }));
    fireEvent.change(await screen.findByLabelText("Recency window (days)"), {
      target: { value: "" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateRule).toHaveBeenCalled());
    expect(updateRule).toHaveBeenCalledWith("r1", { threshold_days: null });
  });

  it("an unchanged Save keeps a stored value above the API bound", async () => {
    // The seeded query-rate rule stores 200, which the editor cannot send.
    const onClose = mount(
      rule({ rule_type: "dns_query_rate_spike", threshold_percent: 200 }),
    );
    await screen.findByLabelText("Increase over prior window (%)");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(updateRule).not.toHaveBeenCalled();
  });

  it("changing a compliance rule's classification sends just that", async () => {
    updateRule.mockResolvedValue(rule({}));
    mount(
      rule({
        rule_type: "compliance_change",
        classification: "pci_scope",
        change_scope: null,
      }),
    );
    fireEvent.change(await screen.findByLabelText("Classification"), {
      target: { value: "hipaa_scope" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateRule).toHaveBeenCalled());
    expect(updateRule).toHaveBeenCalledWith("r1", {
      classification: "hipaa_scope",
    });
  });

  it("a compliance rule with a null classification sends the shown one", async () => {
    updateRule.mockResolvedValue(rule({}));
    mount(rule({ rule_type: "compliance_change" }));
    await screen.findByLabelText("Classification");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateRule).toHaveBeenCalled());
    expect(updateRule).toHaveBeenCalledWith("r1", {
      classification: "pci_scope",
    });
  });
});

describe("a platform-driven rule type (#2748)", () => {
  it("is described, not blamed on a feature module", async () => {
    mount(rule({ rule_type: "cluster_upgrade_failed", enabled: true }));
    expect(await screen.findByText(/has no parameters to set/)).toBeTruthy();
    expect(screen.queryByText(/feature module/)).toBeNull();
    expect(screen.queryByText(/does not describe rule type/)).toBeNull();
  });

  it("still explains a type the catalogue lacks as a module that is off", async () => {
    mount(rule({ rule_type: "some_gated_type" }));
    expect(await screen.findByText(/feature module/)).toBeTruthy();
  });

  it("is not offered when creating a rule", async () => {
    mount(null);
    await screen.findByRole("option", { name: "subnet_utilization" });
    expect(
      screen.queryByRole("option", { name: "cluster_upgrade_failed" }),
    ).toBeNull();
  });
});
