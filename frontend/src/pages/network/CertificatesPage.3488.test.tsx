/**
 * @vitest-environment jsdom
 *
 * A target's detail opens from the keyboard (#3488): the row carries a real
 * button, so Tab reaches it and Enter / Space (a button's native click) open it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

const TARGET = {
  id: "t1",
  host: "example.test",
  port: 443,
  display_name: null,
  state: "ok",
  issuer_cn: "Test CA",
  not_after: "2027-01-01T00:00:00Z",
  days_remaining: 60,
  source: "manual",
  last_checked_at: "2026-11-01T00:00:00Z",
  serial_number: "SERIAL-3488",
  sans_json: ["a.example.test"],
  tags: {},
};

// Same host:port, told apart only by SNI (the table's dedupe key is
// host + port + server_name), so each row's button needs its own name.
const SNI_A = { ...TARGET, id: "t2", port: 8443, server_name: "a.sni.test" };
const SNI_B = { ...TARGET, id: "t3", port: 8443, server_name: "b.sni.test" };

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
                : name === "tlsCertsApi" && method === "list"
                  ? async () => ({ items: [TARGET, SNI_A, SNI_B], total: 3 })
                  : name === "authApi" && method === "myPermissions"
                    ? async () => ({ is_superadmin: true, grants: [] })
                    : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ enabled: () => true, ready: true }),
}));

const { CertificatesPage } = await import("./CertificatesPage");

afterEach(cleanup);

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/network/certificates"]}>
        <CertificatesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("CertificatesPage keyboard access (#3488)", () => {
  it("opens the detail from a focusable button, not only a row click", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={["/network/certificates"]}>
          <CertificatesPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const btn = await screen.findByRole("button", {
      name: "View certificate details for example.test:443",
    });
    btn.focus();
    expect(document.activeElement).toBe(btn);
    // A button's Enter / Space keypress dispatches a click; jsdom does not
    // synthesise it, so assert the element is a native button and click it.
    expect(btn.tagName).toBe("BUTTON");
    expect(btn.getAttribute("type")).toBe("button");
    fireEvent.click(btn);
    expect(await screen.findByText(/Subject alternative names/)).toBeTruthy();
  });

  it("names each row's button uniquely when targets differ only by SNI", async () => {
    renderPage();
    const names = (
      await screen.findAllByRole("button", {
        name: /^View certificate details for /,
      })
    ).map((b) => b.getAttribute("aria-label"));
    expect(names).toEqual([
      "View certificate details for example.test:443",
      "View certificate details for example.test:8443 (SNI a.sni.test)",
      "View certificate details for example.test:8443 (SNI b.sni.test)",
    ]);
    expect(new Set(names).size).toBe(names.length);
  });

  it("moves focus into the dialog and returns it to the button on close", async () => {
    renderPage();
    const btn = await screen.findByRole("button", {
      name: "View certificate details for example.test:443",
    });
    btn.focus();
    fireEvent.click(btn);
    const dialog = await screen.findByRole("dialog");
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(dialog.contains(document.activeElement)).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(btn);
  });
});
