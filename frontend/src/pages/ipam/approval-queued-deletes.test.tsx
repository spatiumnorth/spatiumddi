/**
 * @vitest-environment jsdom
 *
 * A delete the two-person approval queue took says so (#1915).
 *
 * With `governance.approvals` on and a policy matching, DELETE on an IP
 * space / block / subnet answers 202 with a queued change request and the
 * object stays. The IPAM delete dialogs read the response as "deleted":
 * they closed on the 202 with no word, while Edit Subnet said "Submitted
 * for approval".
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { ReactNode } from "react";
import type { IPBlock, IPSpace } from "@/lib/api";

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

const { EditSpaceModal, EditBlockModal } = await import("./IPAMPage");
const { IPSpacesPage } = await import("./IPSpacesPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const QUEUED = Promise.resolve({
  status: 202,
  data: { change_request_id: "cr-1", state: "pending", preview_text: "x" },
});

function open(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const topDialog = () => screen.getAllByRole("dialog").at(-1)!;

async function walkDelete(openLabel: RegExp) {
  fireEvent.click(screen.getByRole("button", { name: "Danger zone" }));
  fireEvent.click(screen.getByRole("button", { name: openLabel }));
  fireEvent.click(
    within(topDialog()).getByRole("button", { name: "Continue" }),
  );
  fireEvent.click(within(topDialog()).getByRole("checkbox"));
  const confirm = within(topDialog())
    .getAllByRole("button")
    .filter((b) => !/^(Cancel|Close)/.test(b.textContent ?? ""))
    .at(-1) as HTMLButtonElement;
  await waitFor(() => expect(confirm.disabled).toBe(false));
  fireEvent.click(confirm);
}

describe("a delete the approval queue took", () => {
  it("Edit Space says it was submitted and does not report it deleted", async () => {
    const deleteSpace = vi.fn(() => QUEUED);
    answers.ipamApi = { deleteSpace };
    const onDeleted = vi.fn();
    open(
      <EditSpaceModal
        space={{ id: "sp-1", name: "s" } as IPSpace}
        onClose={() => {}}
        onDeleted={onDeleted}
      />,
    );
    await walkDelete(/^Delete this IP space/);
    await screen.findByText(/Submitted for approval/);
    expect(onDeleted).not.toHaveBeenCalled();
  });

  it("Edit Block says it was submitted and does not report it deleted", async () => {
    const deleteBlock = vi.fn(() => QUEUED);
    answers.ipamApi = { deleteBlock };
    const onDeleted = vi.fn();
    open(
      <EditBlockModal
        block={
          { id: "b-1", space_id: "sp-1", network: "10.0.0.0/8" } as IPBlock
        }
        onClose={() => {}}
        onDeleted={onDeleted}
      />,
    );
    await walkDelete(/^Delete this block/);
    await screen.findByText(/Submitted for approval/);
    expect(onDeleted).not.toHaveBeenCalled();
  });

  it("the IP Spaces list says so too", async () => {
    answers.ipamApi = {
      listSpaces: () =>
        Promise.resolve([
          { id: "sp-1", name: "lab", description: "", is_default: false },
        ]),
      deleteSpace: () => QUEUED,
    };
    open(<IPSpacesPage />);
    const row = (await screen.findByText("lab")).closest("tr")!;
    fireEvent.click(within(row).getByRole("button"));
    await screen.findByText(/Submitted for approval/);
  });
});
