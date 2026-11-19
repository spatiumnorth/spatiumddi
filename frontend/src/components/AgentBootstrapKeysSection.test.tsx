/**
 * @vitest-environment jsdom
 *
 * Agent bootstrap keys asks only a superadmin for a password (#2527). The
 * reveal route is superadmin-only and audits a refusal, so a Viewer used to
 * be asked for its password, offered "Reveal keys", and refused after.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const myPermissions = vi.fn();
const reveal = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: { ...actual.authApi, myPermissions },
    agentBootstrapKeysApi: { reveal },
  };
});

const { AgentBootstrapKeysSection } =
  await import("./AgentBootstrapKeysSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

async function show(superadmin: boolean) {
  myPermissions.mockResolvedValue(
    superadmin
      ? { is_superadmin: true, grants: [] }
      : {
          is_superadmin: false,
          grants: [{ action: "read", resource_type: "*", resource_id: null }],
        },
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <AgentBootstrapKeysSection />
    </QueryClientProvider>,
  );
  await act(async () => {});
  await act(async () => {});
}

describe("Agent bootstrap keys form", () => {
  it("is not offered to a Viewer: no password can be typed, Reveal is disabled with its reason", async () => {
    await show(false);
    const pw = document.querySelector(
      'input[type="password"]',
    ) as HTMLInputElement;
    // The fieldset disables its inputs; `.disabled` reflects only the attribute.
    expect(pw.matches(":disabled")).toBe(true);
    fireEvent.change(pw, { target: { value: "hunter2" } });
    const b = screen.getByRole("button", {
      name: /Reveal keys/,
    }) as HTMLButtonElement;
    expect(b.disabled).toBe(true);
    expect(b.title).toBe("Requires superadmin");
    fireEvent.submit(b.closest("form")!);
    expect(reveal).not.toHaveBeenCalled();
  });

  it("is usable by a superadmin", async () => {
    await show(true);
    const pw = document.querySelector(
      'input[type="password"]',
    ) as HTMLInputElement;
    await waitFor(() => expect(pw.matches(":disabled")).toBe(false));
    fireEvent.change(pw, { target: { value: "hunter2" } });
    const b = screen.getByRole("button", {
      name: /Reveal keys/,
    }) as HTMLButtonElement;
    expect(b.disabled).toBe(false);
    expect(b.title).toBe("");
  });
});
