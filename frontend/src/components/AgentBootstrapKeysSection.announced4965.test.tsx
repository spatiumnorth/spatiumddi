/**
 * @vitest-environment jsdom
 *
 * A refused Reveal keys is announced (role="alert") (#4965).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const reveal = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, agentBootstrapKeysApi: { reveal } };
});
vi.mock("@/hooks/usePermissions", () => ({
  NEEDS_SUPERADMIN: "needs superadmin",
  permissionGate: () => ({}),
  usePermissions: () => ({ isSuperadmin: true, hasPermission: () => true }),
}));

const { AgentBootstrapKeysSection } =
  await import("./AgentBootstrapKeysSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("a refused Reveal keys is announced (#4965)", () => {
  it("announces the wrong-password refusal", async () => {
    reveal.mockRejectedValueOnce({
      isAxiosError: true,
      response: {
        status: 403,
        data: { detail: "Password or authenticator code is incorrect" },
      },
    });
    const { container } = render(
      <QueryClientProvider
        client={
          new QueryClient({ defaultOptions: { mutations: { retry: false } } })
        }
      >
        <AgentBootstrapKeysSection />
      </QueryClientProvider>,
    );
    fireEvent.change(container.querySelector('input[type="password"]')!, {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: /reveal keys/i }));
    const alert = await screen.findByRole("alert", {}, { timeout: 10000 });
    expect(alert.textContent).toContain(
      "Password or authenticator code is incorrect",
    );
  });
});
