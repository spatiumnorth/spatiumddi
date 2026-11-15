/**
 * @vitest-environment jsdom
 *
 * Edit site for a site-scoped writer whose parent site is refused to it: the
 * Parent site select drew "none" while the site has a parent (#4188). It keeps
 * the stored parent selected, said as not visible, and Save still sends it.
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
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};
function answer(api: string, method: string, fn: Answer) {
  (answers[api] ??= {})[method] = fn;
}
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

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const { SiteEditorModal } = await import("./SitesPage");

const update = vi.fn(async (..._args: unknown[]) => ({}));
const CHILD = {
  id: "c-1",
  name: "child",
  code: null,
  kind: "datacenter",
  region: null,
  parent_site_id: "p-hidden",
  notes: "",
};

describe("Edit site with an unreadable parent (#4188)", () => {
  it("keeps the parent selected and sends it unchanged", async () => {
    answer("sitesApi", "update", update as Answer);
    open(
      <SiteEditorModal
        existing={CHILD as never}
        sites={[CHILD as never]}
        onClose={() => {}}
      />,
    );
    const select = screen.getByText("Parent site")
      .nextElementSibling as HTMLSelectElement;
    expect(select.value).toBe("p-hidden");
    expect(select.selectedOptions[0].textContent).toBe(
      "Linked (not visible to your role)",
    );
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    expect(update.mock.calls[0][1]).toMatchObject({
      parent_site_id: "p-hidden",
    });
  });

  it("adds no such option when the parent is in the list", () => {
    const parent = { ...CHILD, id: "p-1", name: "hq", parent_site_id: null };
    open(
      <SiteEditorModal
        existing={{ ...CHILD, parent_site_id: "p-1" } as never}
        sites={[parent as never, CHILD as never]}
        onClose={() => {}}
      />,
    );
    expect(screen.queryByText("Linked (not visible to your role)")).toBeNull();
  });
});
