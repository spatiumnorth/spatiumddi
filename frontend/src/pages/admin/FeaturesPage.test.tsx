/**
 * @vitest-environment jsdom
 *
 * Features page — disabling a module is confirmed and explained (#1068).
 *
 * The regression worth catching is the cheap one: a toggle wired straight
 * to the mutation. That looks correct in review and in `tsc`, and the only
 * symptom is that a whole subsystem vanishes on one stray click with no
 * explanation of whether the data went with it.
 *
 * Rendering the real component is the only way to see it, so these tests
 * assert on what the operator gets: no mutation until confirmation, the
 * data-preservation answer stated, dependent modules named, and the extra
 * acknowledgement on the two core subsystems.
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
import type { FeatureModuleEntry } from "@/lib/api";

const toggle = vi.fn();
const list = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    featureModulesApi: {
      list: () => list(),
      toggle: (...a: unknown[]) => toggle(...a),
      approvalsLock: () =>
        Promise.resolve({ approvals_protect_controls: false }),
    },
  };
});

vi.mock("@/hooks/usePermissions", async () => ({
  ...(await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  )),
  usePermissions: () => ({ can: () => true, isSuperadmin: true }),
}));

function mod(
  id: string,
  label: string,
  group: string,
  enabled: boolean,
  requires: string[] = [],
): FeatureModuleEntry {
  return {
    id,
    label,
    group,
    description: `${label} description`,
    default_enabled: true,
    enabled,
    requires,
  };
}

const CATALOG: FeatureModuleEntry[] = [
  mod("core.dhcp", "DHCP", "DHCP", true),
  mod("dhcp.import", "DHCP configuration import", "DHCP", true, ["core.dhcp"]),
  mod("ipv6.router_advertisements", "IPv6 RAs", "Network", true, ["core.dhcp"]),
  mod("reports.top_n", "Top-N reports", "Compliance", true),
];

async function renderPage() {
  list.mockResolvedValue(CATALOG);
  const { FeaturesPage } = await import("./FeaturesPage");
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <FeaturesPage />
    </QueryClientProvider>,
  );
  await screen.findByText("DHCP description");
}

function toggleFor(label: string): HTMLElement {
  return screen.getByLabelText(`Disable ${label}`);
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("disabling a module", () => {
  it("does not fire the mutation until the operator confirms", async () => {
    await renderPage();
    fireEvent.click(toggleFor("Top-N reports"));

    expect(toggle).not.toHaveBeenCalled();
    await screen.findByText(/Turn off Top-N reports\?/);
  });

  it("answers the question operators actually have: no data is deleted", async () => {
    await renderPage();
    fireEvent.click(toggleFor("Top-N reports"));

    await screen.findByText(/No data is deleted\./);
    expect(screen.getByText(/answer/)).toBeTruthy();
  });

  it("names every dependent module that switches off with it", async () => {
    await renderPage();
    fireEvent.click(toggleFor("DHCP"));

    await screen.findByText(/Turn off DHCP\?/);
    // Both labels appear in the catalogue rows behind the modal too, so
    // assert on the dependents SENTENCE rather than on the label alone —
    // otherwise this passes whether or not the modal lists anything.
    await screen.findByText(/2 dependent features will switch off with it:/);
    const listed = screen.getByText(
      (_t, el) =>
        el?.tagName === "P" &&
        (el.textContent ?? "").includes("Their own settings are kept"),
    );
    expect(listed.textContent).toContain("DHCP configuration import");
    expect(listed.textContent).toContain("IPv6 RAs");
  });

  it("requires the extra acknowledgement for a core subsystem", async () => {
    await renderPage();
    fireEvent.click(toggleFor("DHCP"));
    await screen.findByText(/Turn off DHCP\?/);

    const confirm = screen.getByRole("button", { name: /Turn off DHCP/ });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByRole("checkbox"));
    await waitFor(() =>
      expect((confirm as HTMLButtonElement).disabled).toBe(false),
    );

    fireEvent.click(confirm);
    await waitFor(() =>
      expect(toggle).toHaveBeenCalledWith("core.dhcp", false, undefined),
    );
  });

  it("does not ask for an acknowledgement on an ordinary module", async () => {
    await renderPage();
    fireEvent.click(toggleFor("Top-N reports"));
    await screen.findByText(/Turn off Top-N reports\?/);

    expect(screen.queryByRole("checkbox")).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: /Turn off Top-N reports/ }),
    );
    await waitFor(() => expect(toggle).toHaveBeenCalled());
  });

  it("turning a module back ON is not gated — it only ever restores", async () => {
    list.mockResolvedValue([
      mod("reports.top_n", "Top-N reports", "Compliance", false),
    ]);
    const { FeaturesPage } = await import("./FeaturesPage");
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <FeaturesPage />
      </QueryClientProvider>,
    );
    await screen.findByText("Top-N reports description");

    fireEvent.click(screen.getByLabelText("Enable Top-N reports"));
    await waitFor(() =>
      expect(toggle).toHaveBeenCalledWith("reports.top_n", true, undefined),
    );
    expect(screen.queryByText(/No data is deleted/)).toBeNull();
  });
});
