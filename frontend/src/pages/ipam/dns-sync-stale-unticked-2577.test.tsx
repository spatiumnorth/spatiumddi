/**
 * @vitest-environment jsdom
 *
 * The Sync DNS modal does not pre-select stale records for deletion (#2577).
 *
 * Every stale row used to start ticked, so one click on Apply deleted all of
 * them — including, before the server-side scope fix, other subnets' and
 * other spaces' orphans in a shared forward zone. Missing and mismatched rows
 * still start ticked (publishing what IPAM expects is the common case); a
 * deletion is now an explicit choice.
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
import { MemoryRouter } from "react-router-dom";

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

const { DnsSyncModal } = await import("./IPAMPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const PREVIEW = {
  subnet_id: "sn-1",
  forward_zone_id: "z-1",
  forward_zone_name: "corp.example.",
  reverse_zone_id: null,
  reverse_zone_name: null,
  reverse_zone_names: [],
  missing: [
    {
      ip_id: "ip-1",
      ip_address: "10.1.0.5",
      hostname: "web",
      record_type: "A",
      expected_name: "web",
      expected_value: "10.1.0.5",
      zone_id: "z-1",
      zone_name: "corp.example.",
    },
  ],
  mismatched: [],
  stale: [
    {
      record_id: "rec-stale",
      record_type: "A",
      zone_id: "z-1",
      zone_name: "corp.example.",
      name: "ghost",
      value: "10.1.0.9",
      reason: "ip-deleted",
      ip_id: null,
    },
  ],
};

function checkboxFor(text: string): HTMLInputElement {
  const label = screen.getByText(text).closest("label");
  if (!label) throw new Error(`no row for ${text}`);
  return label.querySelector("input[type=checkbox]") as HTMLInputElement;
}

async function open(commit: Answer) {
  answers.ipamApi = {
    dnsSyncPreview: () => Promise.resolve(PREVIEW),
    dnsSyncCommit: commit,
    backfillReverseZonesSubnet: () =>
      Promise.resolve({ created: [], skipped: 0 }),
  };
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <DnsSyncModal
          scope={{ kind: "subnet", id: "sn-1", label: "10.1.0.0/24" }}
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByText("ghost → 10.1.0.9");
  // The default selection is seeded after the preview loads; on a slow
  // runner a click can land before it settles (#2725). Wait for it.
  await vi.waitFor(() =>
    expect(checkboxFor("web → 10.1.0.5").checked).toBe(true),
  );
}

describe("Sync DNS modal selection (#2577)", () => {
  it("starts stale rows unticked and missing rows ticked", async () => {
    await open(() => new Promise(() => {}));
    expect(checkboxFor("ghost → 10.1.0.9").checked).toBe(false);
    expect(checkboxFor("web → 10.1.0.5").checked).toBe(true);
    expect(screen.getByRole("button", { name: "Apply (1)" })).toBeTruthy();
  });

  it("Apply sends no deletions unless a stale row is ticked", async () => {
    const commit = vi.fn(() =>
      Promise.resolve({ created: 1, updated: 0, deleted: 0, errors: [] }),
    );
    await open(commit);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Apply (1)" }));
    });
    await vi.waitFor(() => expect(commit).toHaveBeenCalled());
    const body = (commit.mock.calls[0] as unknown[])[1] as {
      create_for_ip_ids: string[];
      delete_stale_record_ids: string[];
    };
    expect(body.create_for_ip_ids).toEqual(["ip-1"]);
    expect(body.delete_stale_record_ids).toEqual([]);
  });

  it("deletes a stale row the operator ticks", async () => {
    const commit = vi.fn(() =>
      Promise.resolve({ created: 1, updated: 0, deleted: 1, errors: [] }),
    );
    await open(commit);
    fireEvent.click(checkboxFor("ghost → 10.1.0.9"));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Apply (2)" }));
    });
    await vi.waitFor(() => expect(commit).toHaveBeenCalled());
    const body = (commit.mock.calls[0] as unknown[])[1] as {
      delete_stale_record_ids: string[];
    };
    expect(body.delete_stale_record_ids).toEqual(["rec-stale"]);
  });
});
