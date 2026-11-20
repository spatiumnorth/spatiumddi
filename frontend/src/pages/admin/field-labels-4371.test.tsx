/**
 * @vitest-environment jsdom
 *
 * #4371: the page-local `Field` helpers drew a label beside the control with
 * no htmlFor / id, so the webhook form's Secret, Timeout and Max attempts had
 * no accessible name (and ~25 other forms the same). They now all use the one
 * shared labelled Field (components/ui/field.tsx).
 *
 * Every API call stays pending.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          { get: (_t, m) => (typeof m === "symbol" ? undefined : pending) },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { SubscriptionEditor } = await import("./WebhooksPage");
const { CreateTimeBoundGrantModal } =
  await import("./CreateTimeBoundGrantModal");
const { Field } = await import("@/components/ui/field");

afterEach(cleanup);

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("webhook subscription form labels (#4371)", () => {
  it("names Name, Description, URL, Secret, Timeout and Max attempts by their labels", () => {
    wrap(
      <SubscriptionEditor
        existing={null}
        eventTypeVocab={["ipam.subnet.created"]}
        onClose={() => {}}
      />,
    );
    const expected: [string, string, string?][] = [
      ["Name", "INPUT"],
      ["Description", "INPUT"],
      ["URL", "INPUT"],
      ["Secret (optional)", "INPUT", "password"],
      ["Timeout (seconds)", "INPUT", "number"],
      ["Max attempts", "INPUT", "number"],
    ];
    for (const [label, tag, type] of expected) {
      const el = screen.getByLabelText(label) as HTMLInputElement;
      expect(el.tagName, label).toBe(tag);
      if (type) expect(el.type, label).toBe(type);
    }
    expect(screen.getByRole("combobox", { name: "Enabled" })).toBeTruthy();
    expect(
      screen.getByRole("spinbutton", { name: "Max attempts" }),
    ).toBeTruthy();
  });

  it("a click on a label focuses its control", async () => {
    wrap(
      <SubscriptionEditor
        existing={null}
        eventTypeVocab={[]}
        onClose={() => {}}
      />,
    );
    await userEvent.click(screen.getByText("Timeout (seconds)"));
    expect(document.activeElement).toBe(
      screen.getByLabelText("Timeout (seconds)"),
    );
  });
});

describe("other forms on the shared Field (#4371)", () => {
  it("the time-bound grant dialog's selects and inputs are named", () => {
    wrap(
      <CreateTimeBoundGrantModal
        groupId="g"
        groupName="ops"
        onClose={() => {}}
      />,
    );
    for (const label of ["Action", "Resource type", "Expires at"]) {
      expect(screen.getByLabelText(label), label).toBeTruthy();
    }
    expect(
      screen.getByLabelText("Reason (recorded in the audit log)"),
    ).toBeTruthy();
  });

  it("keeps a control's own id and groups a multi-control body", () => {
    render(
      <>
        <Field label="Own">
          <input id="mine" />
        </Field>
        <Field label="Several">
          <input aria-label="a" />
          <input aria-label="b" />
        </Field>
      </>,
    );
    expect((screen.getByLabelText("Own") as HTMLElement).id).toBe("mine");
    expect(screen.getByRole("group", { name: "Several" })).toBeTruthy();
  });
});
