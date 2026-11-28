/**
 * @vitest-environment jsdom
 *
 * The AV reserved-range and flow Edit dialogs read the row when they open and
 * a Save sends only what the operator changed (#4379). Before, they seeded
 * from the click-time list row and sent every field, so a value another client stored
 * since the list loaded was put back by an unrelated Save.
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
import { MemoryRouter } from "react-router-dom";

const h = vi.hoisted(() => ({
  range: vi.fn(),
  flow: vi.fn(),
  rangeReads: 0,
  flowReads: 0,
}));

const RANGE = {
  id: "r1",
  space_id: "s1",
  cidr: "239.69.0.0/16",
  av_protocol: "dante",
  name: "Dante old",
  description: "",
  exclusive: true,
  vlan_id: null,
  tags: {},
  created_at: "",
  modified_at: "",
};
const RANGE_FRESH = { ...RANGE, name: "Dante changed elsewhere" };
const FLOW = {
  id: "f1",
  group_id: "g1",
  av_protocol: "dante",
  av_flow_label: "Cam old",
  ptp_domain: null,
  seen_via: "manual",
  notes: "",
  custom_fields: { k: "v" },
  created_at: "",
  modified_at: "",
  group_address: "239.69.1.1",
  group_name: "",
  group_application: "",
  space_id: "s1",
  vlan_id: null,
};
const FLOW_FRESH = { ...FLOW, av_flow_label: "Cam changed elsewhere" };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    avApi: {
      ...actual.avApi,
      presets: () =>
        Promise.resolve({
          protocols: [
            { av_protocol: "dante", label: "Dante", default_cidr: null },
          ],
          flow_sources: ["manual"],
          ptp_domain_min: 0,
          ptp_domain_max: 255,
        }),
      // The first read of each list is the page's; later ones are the dialog's.
      listReservedRanges: () => {
        h.rangeReads += 1;
        return Promise.resolve([h.rangeReads === 1 ? RANGE : RANGE_FRESH]);
      },
      listFlows: () => {
        h.flowReads += 1;
        return Promise.resolve({
          items: [h.flowReads === 1 ? FLOW : FLOW_FRESH],
          total: 1,
          limit: 50,
          offset: 0,
        });
      },
      updateReservedRange: (...a: unknown[]) => {
        h.range(...a);
        return Promise.resolve(RANGE_FRESH);
      },
      upsertFlow: (...a: unknown[]) => {
        h.flow(...a);
        return Promise.resolve(FLOW_FRESH);
      },
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: true,
      isLoading: false,
    }),
  };
});

const { AVFlowsPage } = await import("./AVFlowsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  h.rangeReads = 0;
  h.flowReads = 0;
});

async function open(title: string, value: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AVFlowsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  // Both lists have loaded once before the dialog is opened.
  await screen.findByTitle("Edit reserved range", {}, { timeout: 10000 });
  await screen.findByTitle("Edit AV flow", {}, { timeout: 10000 });
  fireEvent.click(screen.getByTitle(title));
  return (await screen.findByDisplayValue(
    value,
    {},
    { timeout: 10000 },
  )) as HTMLInputElement;
}

describe("AV reserved range Edit dialog (#4379)", { timeout: 30000 }, () => {
  it("shows what is stored now, not the click-time list row", async () => {
    const name = await open("Edit reserved range", "Dante changed elsewhere");
    expect(name.value).toBe("Dante changed elsewhere");
  });

  it("an unrelated change sends only that field", async () => {
    await open("Edit reserved range", "Dante changed elsewhere");
    fireEvent.change(screen.getByDisplayValue("239.69.0.0/16"), {
      target: { value: "239.70.0.0/16" },
    });
    fireEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(() => expect(h.range).toHaveBeenCalledTimes(1), {
      timeout: 10000,
    });
    expect(h.range).toHaveBeenCalledWith("r1", { cidr: "239.70.0.0/16" });
  });

  it("a Save with nothing changed sends nothing", async () => {
    await open("Edit reserved range", "Dante changed elsewhere");
    fireEvent.click(screen.getByRole("button", { name: /save/i }));
    await waitFor(
      () =>
        expect(
          screen.queryByDisplayValue("Dante changed elsewhere"),
        ).toBeNull(),
      { timeout: 10000 },
    );
    expect(h.range).not.toHaveBeenCalled();
  });
});

describe("AV flow Edit dialog (#4379)", { timeout: 30000 }, () => {
  it("shows what is stored now, not the click-time list row", async () => {
    const label = await open("Edit AV flow", "Cam changed elsewhere");
    expect(label.value).toBe("Cam changed elsewhere");
  });

  it("an unrelated change keeps the fresh label and the custom fields", async () => {
    await open("Edit AV flow", "Cam changed elsewhere");
    fireEvent.change(screen.getByPlaceholderText("e.g. 0"), {
      target: { value: "5" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(h.flow).toHaveBeenCalledTimes(1), {
      timeout: 10000,
    });
    expect(h.flow).toHaveBeenCalledWith(
      "g1",
      expect.objectContaining({
        av_flow_label: "Cam changed elsewhere",
        ptp_domain: 5,
        custom_fields: { k: "v" },
      }),
    );
  });

  it("a Save with nothing changed sends nothing", async () => {
    await open("Edit AV flow", "Cam changed elsewhere");
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(
      () =>
        expect(screen.queryByDisplayValue("Cam changed elsewhere")).toBeNull(),
      { timeout: 10000 },
    );
    expect(h.flow).not.toHaveBeenCalled();
  });
});
