/**
 * @vitest-environment jsdom
 *
 * Reset to defaults follows the API's superadmin gate (#2526). The catalog
 * read is superadmin-only, so for a Viewer the read is refused, "using
 * defaults" is unknown, and the button used to be enabled for a platform-wide
 * write the API refuses. A refused save is also said in words.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const list = vi.fn();
const update = vi.fn();
const myPermissions = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    aiToolCatalogApi: { list, update },
    authApi: { ...actual.authApi, myPermissions },
  };
});

const { AIToolCatalogPage } = await import("./AIToolCatalogPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function refused(detail: string) {
  return { response: { status: 403, data: { detail } } };
}

async function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <AIToolCatalogPage />
    </QueryClientProvider>,
  );
  await act(async () => {});
  await act(async () => {});
}

describe("Tool Catalog Reset to defaults", () => {
  it("is disabled with its reason for a Viewer whose read was refused", async () => {
    myPermissions.mockResolvedValue({
      is_superadmin: false,
      grants: [{ action: "read", resource_type: "*", resource_id: null }],
    });
    list.mockRejectedValue(refused("Superadmin required"));
    await show();
    const b = screen.getByRole("button", {
      name: /Reset to defaults/,
    }) as HTMLButtonElement;
    expect(b.disabled).toBe(true);
    expect(b.title).toBe("Requires superadmin");
  });

  it("is enabled for a superadmin on an explicit list, and a refused save is said", async () => {
    myPermissions.mockResolvedValue({ is_superadmin: true, grants: [] });
    list.mockResolvedValue({
      platform_override: ["find_subnets"],
      total: 1,
      tools: [],
    });
    update.mockRejectedValue(refused("Superadmin required"));
    await show();
    const b = screen.getByRole("button", {
      name: /Reset to defaults/,
    }) as HTMLButtonElement;
    expect(b.disabled).toBe(false);
    await act(async () => {
      fireEvent.click(b);
    });
    await act(async () => {});
    expect(screen.getByRole("alert").textContent).toContain(
      "Superadmin required",
    );
  });
});
