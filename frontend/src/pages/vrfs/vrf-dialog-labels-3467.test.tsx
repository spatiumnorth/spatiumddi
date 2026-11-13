/**
 * @vitest-environment jsdom
 *
 * #3467: the New VRF and Edit VRF dialogs drew each label beside its field,
 * with no htmlFor and no id on the field. No field had an accessible name, a
 * search by label found nothing, and a click on a label focused nothing.
 * Each label now names its field, as the DHCP (#1994) and IPAM (#3340)
 * dialogs' labels do.
 *
 * Every API call stays pending unless a test answers it.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { VRF } from "@/lib/api";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

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
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { VRFEditorModal } = await import("./VRFsPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

async function open(existing: VRF | null) {
  // Edit reads the VRF when it opens (#3869).
  if (existing) answers.vrfsApi = { get: () => Promise.resolve(existing) };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <VRFEditorModal existing={existing} onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByLabelText("Name");
}

const stored = {
  id: "vrf-1",
  name: "PROD-CUST-001",
  description: "production tenant",
  route_distinguisher: "65000:100",
  import_targets: ["65000:100"],
  export_targets: ["65000:200"],
  asn_id: null,
  customer_id: null,
  tags: {},
  custom_fields: {},
} as unknown as VRF;

/** What a label names: its control, or the group it labels. */
function named(label: string): HTMLElement {
  return screen.getByLabelText(label);
}

describe("the VRF dialog's labels (#3467)", () => {
  it("Edit VRF: each text field is found by its label and shows the VRF's value", async () => {
    await open(stored);
    const values: [string, string, string][] = [
      ["Name", "INPUT", "PROD-CUST-001"],
      ["Description", "TEXTAREA", "production tenant"],
      ["Route distinguisher (RD)", "INPUT", "65000:100"],
      ["Import RTs", "INPUT", "65000:100"],
      ["Export RTs", "INPUT", "65000:200"],
    ];
    for (const [label, tag, value] of values) {
      const field = named(label) as HTMLInputElement;
      expect(field.tagName, label).toBe(tag);
      expect(field.value, label).toBe(value);
    }
  });

  it("New VRF: each text field is found by its label", async () => {
    await open(null);
    for (const label of [
      "Name",
      "Description",
      "Route distinguisher (RD)",
      "Import RTs",
      "Export RTs",
    ]) {
      expect(["INPUT", "TEXTAREA"], label).toContain(named(label).tagName);
    }
  });

  it("the Origin ASN and Customer pickers are named by their labels", async () => {
    await open(stored);
    for (const label of ["Origin ASN", "Customer"]) {
      const el = named(label);
      // A picker component is named as a group around its select (#3340);
      // a plain select is named itself.
      const select = el.tagName === "SELECT" ? el : el.querySelector("select");
      expect(select, label).not.toBeNull();
    }
  });

  it("a click on a label focuses its field", async () => {
    const user = userEvent.setup();
    await open(stored);
    await user.click(screen.getByText("Description", { selector: "label" }));
    expect(document.activeElement).toBe(named("Description"));
    await user.click(screen.getByText("Export RTs", { selector: "label" }));
    expect(document.activeElement).toBe(named("Export RTs"));
  });

  it("no label names nothing, points at a missing id, or shares an id", async () => {
    await open(stored);
    const labelled = new Set(
      Array.from(document.querySelectorAll("[aria-labelledby]")).flatMap((e) =>
        e.getAttribute("aria-labelledby")!.split(/\s+/),
      ),
    );
    const orphans = Array.from(document.querySelectorAll("label"))
      .filter(
        (l) =>
          !l.control &&
          !l.querySelector("input,select,textarea") &&
          !(l.id && labelled.has(l.id)),
      )
      .map((l) => l.textContent);
    expect(orphans).toEqual([]);
    for (const l of Array.from(document.querySelectorAll("label[for]"))) {
      expect(document.getElementById(l.getAttribute("for")!)).not.toBeNull();
    }
    const ids = Array.from(document.querySelectorAll("[id]")).map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
