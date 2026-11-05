/**
 * @vitest-environment jsdom
 *
 * Closing the Delete saved view confirmation returns keyboard focus to the
 * Views trigger (#3484): the trash button that opened it is unmounted with
 * the panel, so the modal's own focus return has nothing to restore.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const views = [
  { id: "v1", page: "sites", name: "Mine", payload: {}, is_default: false },
];
const remove = vi.fn((id: string) => Promise.resolve(id));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    savedViewsApi: {
      list: () => Promise.resolve(views),
      create: vi.fn(),
      update: vi.fn(),
      remove: (id: string) => remove(id),
    },
  };
});
vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { SavedViewsMenu } = await import("@/components/SavedViewsMenu");

afterEach(() => {
  cleanup();
  remove.mockClear();
});

async function openConfirm() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <SavedViewsMenu page="sites" currentPayload={{}} onApply={() => {}} />
    </QueryClientProvider>,
  );
  const user = userEvent.setup();
  const trigger = screen.getByRole("button", { name: /Views/ });
  trigger.focus();
  await user.keyboard("{Enter}");
  await screen.findByText("Mine");
  await user.tab(); // apply
  await user.tab(); // default star
  await user.tab(); // delete
  expect(document.activeElement).toBe(
    screen.getByRole("button", { name: "Delete view" }),
  );
  await user.keyboard("{Enter}");
  await screen.findByRole("dialog");
  return { user, trigger };
}

describe("Delete saved view focus (#3484)", () => {
  it("Cancel returns focus to the Views trigger", async () => {
    const { user, trigger } = await openConfirm();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("Esc returns focus to the Views trigger", async () => {
    const { user, trigger } = await openConfirm();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("a successful delete returns focus to the Views trigger", async () => {
    const { user, trigger } = await openConfirm();
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(remove).toHaveBeenCalledWith("v1");
    expect(document.activeElement).toBe(trigger);
  });

  it("a refused delete keeps the dialog open with the reason and focus inside", async () => {
    remove.mockImplementationOnce(() =>
      Promise.reject({ response: { data: { detail: "View is locked" } } }),
    );
    const { user, trigger } = await openConfirm();
    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "View is locked",
    );
    const dialog = screen.getByRole("dialog");
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).not.toBe(trigger);
    // Cancel after the refusal still lands on the trigger.
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });

  it("a delete landing after Esc does not pull focus back", async () => {
    let finish: (v: string) => void = () => {};
    remove.mockImplementationOnce(
      () => new Promise<string>((r) => (finish = r)),
    );
    const { user, trigger } = await openConfirm();
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
    const elsewhere = document.createElement("button");
    document.body.appendChild(elsewhere);
    elsewhere.focus();
    expect(remove).toHaveBeenCalledTimes(1);
    await act(async () => {
      finish("v1");
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(document.activeElement).toBe(elsewhere);
    elsewhere.remove();
  });
});
