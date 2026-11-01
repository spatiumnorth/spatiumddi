/**
 * @vitest-environment jsdom
 *
 * Exports the user is refused are not offered enabled when the page's own
 * read was refused, and a started export that fails says why in words
 * (#3255).
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

const refusal = (detail: string) => ({
  response: { status: 403, data: { detail } },
  message: "Request failed with status code 403",
});
const m = {
  policies: vi.fn(),
  exportPdf: vi.fn(),
  erls: vi.fn(),
  download: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    conformityApi: {
      ...actual.conformityApi,
      listPolicies: () => m.policies(),
      summary: vi.fn().mockResolvedValue(null),
      listCheckKinds: vi.fn().mockResolvedValue([]),
      listResults: vi.fn().mockResolvedValue([]),
      exportPdf: (f?: string) => m.exportPdf(f),
    },
    e911Api: {
      ...actual.e911Api,
      listErls: () => m.erls(),
      listBindings: vi.fn().mockResolvedValue({ items: [], total: 0 }),
      download: (k: string) => m.download(k),
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
      can: () => false,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

const { ConformityPage } = await import("@/pages/admin/ConformityPage");
const { E911Page } = await import("@/pages/network/E911Page");

function show(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  Object.values(m).forEach((f) => f.mockReset());
  vi.restoreAllMocks();
});

describe("Conformity Export PDF", () => {
  it("is disabled when the policy read is refused", async () => {
    m.policies.mockRejectedValue(refusal("Permission denied"));
    show(<ConformityPage />);
    await screen.findByText(/don't have permission to see/);
    const btn = screen.getByRole("button", { name: /Export PDF/ });
    expect((btn as HTMLButtonElement).disabled).toBe(true);
  });

  it("says 'not permitted' with the server's reason when refused anyway", async () => {
    m.policies.mockResolvedValue([]);
    m.exportPdf.mockRejectedValue(
      refusal("Permission denied: need 'read' on 'conformity'"),
    );
    const alert = vi.spyOn(window, "alert").mockImplementation(() => {});
    show(<ConformityPage />);
    fireEvent.click(await screen.findByRole("button", { name: /Export PDF/ }));
    await waitFor(() => expect(alert).toHaveBeenCalled());
    const text = String(alert.mock.calls[0][0]);
    expect(text).toMatch(/not permitted/);
    expect(text).toMatch(/need 'read' on 'conformity'/);
    expect(text).not.toMatch(/status code/);
  });

  it("says 'unavailable' for a 5xx", async () => {
    m.policies.mockResolvedValue([]);
    m.exportPdf.mockRejectedValue({
      response: { status: 503, data: {} },
      message: "Request failed with status code 503",
    });
    const alert = vi.spyOn(window, "alert").mockImplementation(() => {});
    show(<ConformityPage />);
    fireEvent.click(await screen.findByRole("button", { name: /Export PDF/ }));
    await waitFor(() => expect(alert).toHaveBeenCalled());
    expect(String(alert.mock.calls[0][0])).toMatch(/unavailable/);
  });
});

describe("E911 exports", () => {
  it("are disabled when the ERL read is refused", async () => {
    m.erls.mockRejectedValue(refusal("Permission denied"));
    show(<E911Page />);
    await screen.findByText(/don't have permission to see/);
    for (const name of [/CSV/, /IOS snippets/]) {
      const btn = screen.getByRole("button", { name });
      expect((btn as HTMLButtonElement).disabled).toBe(true);
    }
  });

  it("show the refusal in words when an export fails", async () => {
    m.erls.mockResolvedValue({ items: [], total: 0 });
    m.download.mockRejectedValue(
      refusal("Permission denied: need 'read' on 'e911_location'"),
    );
    show(<E911Page />);
    fireEvent.click(await screen.findByRole("button", { name: /CSV/ }));
    expect(await screen.findByText(/not permitted to export/)).toBeTruthy();
    expect(screen.getByText(/need 'read' on 'e911_location'/)).toBeTruthy();
  });
});
