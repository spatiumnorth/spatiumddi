/**
 * @vitest-environment jsdom
 *
 * The VRF editor's ASN picker while the permissions are unread (#3546): the
 * picker says so rather than "your role cannot read ASNs", and Save sends the
 * linked ASN back unchanged, never cleared, whether the read failed or is
 * still running.
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
import type { VRF } from "@/lib/api";

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

const { VRFEditorModal } = await import("./VRFsPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const STAMP = "2026-11-05T00:00:00Z";
const VRF_ROW = {
  id: "vrf1",
  name: "blue",
  description: "old",
  route_distinguisher: null,
  import_targets: [],
  export_targets: [],
  asn_id: "asn-linked",
  customer_id: null,
  tags: {},
  created_at: STAMP,
  modified_at: STAMP,
} as unknown as VRF;

function openEditor() {
  answers.vrfsApi = { get: () => Promise.resolve(VRF_ROW) };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <VRFEditorModal existing={VRF_ROW} onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function asnSelect(): HTMLSelectElement {
  const sel = screen
    .getAllByRole("combobox")
    .find((el) => (el as HTMLSelectElement).title !== "");
  if (!sel) throw new Error("no titled select");
  return sel as HTMLSelectElement;
}

async function saveAndReadBody(): Promise<Record<string, unknown>> {
  const update = vi.fn(() => Promise.resolve(VRF_ROW));
  answers.vrfsApi = { update, get: () => Promise.resolve(VRF_ROW) };
  fireEvent.change(screen.getByDisplayValue("old"), {
    target: { value: "new" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(update).toHaveBeenCalled());
  const call = update.mock.calls[0] as unknown as [string, object];
  return call[1] as Record<string, unknown>;
}

describe("VRF editor ASN picker with unread permissions (#3546)", () => {
  it("a failed read says so, and Save keeps the linked ASN", async () => {
    answers.authApi = {
      myPermissions: () => Promise.reject(new Error("Network Error")),
    };
    openEditor();
    await waitFor(() =>
      expect(asnSelect().title).toContain("could not be read"),
    );
    const sel = asnSelect();
    expect(sel.disabled).toBe(true);
    expect(sel.title).not.toMatch(/role/i);
    expect(sel.selectedOptions[0].textContent).toBe(
      "Linked (could not be read)",
    );
    const body = await saveAndReadBody();
    expect(body).toEqual({ description: "new" }); // the link is not sent, so not cleared
  });

  it("while the read is running it says so, and Save keeps the linked ASN", async () => {
    answers.authApi = { myPermissions: () => new Promise(() => {}) };
    openEditor();
    await waitFor(() => expect(asnSelect().title).toContain("Checking"));
    const sel = asnSelect();
    expect(sel.disabled).toBe(true);
    expect(sel.title).not.toMatch(/role/i);
    expect(sel.selectedOptions[0].textContent).not.toMatch(/role/i);
    const body = await saveAndReadBody();
    expect(body).toEqual({ description: "new" }); // the link is not sent, so not cleared
  });
});
