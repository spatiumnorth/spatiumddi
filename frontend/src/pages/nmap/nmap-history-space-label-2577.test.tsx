/**
 * @vitest-environment jsdom
 *
 * A pinned sweep opened from History names its own IP space (#2577).
 *
 * History hands the result panel the scan LIST's copy as initial data. That
 * copy used to omit `ip_space_id`, and the app's 30 s `staleTime` kept the
 * panel from re-reading the scan, so the stamp dialog's "Automatic" option was
 * worded as for an unpinned sweep ("skip addresses found in more than one
 * space") while the server stamped into the row's space.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import type { NmapScanRead } from "@/lib/api";

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

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return { ...actual, usePermissions: () => ({ can: () => true }) };
});

const { ResultTab } = await import("./NmapToolsPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

const UNPINNED = "Automatic — skip addresses found in more than one space";

// The list's copy of a sweep launched from an IPAM row in space "corp": it
// carries the row (`ip_address_id`) but, as the list used to, no space.
const LIST_COPY: NmapScanRead = {
  id: "scan-1",
  target_ip: "10.1.0.0/24",
  ip_address_id: "ip-1",
  preset: "subnet_sweep" as NmapScanRead["preset"],
  port_spec: null,
  extra_args: null,
  status: "completed" as NmapScanRead["status"],
  started_at: "2026-10-23T10:00:00.000Z",
  finished_at: "2026-10-23T10:00:05.000Z",
  duration_seconds: 5,
  exit_code: 0,
  command_line: null,
  error_message: null,
  summary: {
    host_state: "up",
    ports: [],
    os: null,
    hosts: [
      {
        address: "10.1.0.5",
        hostname: null,
        host_state: "up",
        ports: [],
        os: null,
      },
    ],
  },
  raw_xml: null,
  raw_stdout: null,
  created_by_user_id: null,
  created_at: "2026-10-23T10:00:00.000Z",
  modified_at: "2026-10-23T10:00:05.000Z",
};

function renderHistoryResult(scan: NmapScanRead) {
  // The app's own default (lib/queryClient.ts): without it the test would
  // refetch regardless and could not see the stale initial data.
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 30_000 } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ResultTab scan={scan} onClear={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("History → stamp dialog names a pinned sweep's space (#2577)", () => {
  it("re-reads the scan instead of trusting the list's copy", async () => {
    answers.nmapApi = {
      getScan: async () => ({
        ...LIST_COPY,
        ip_space_id: "space-corp",
        ip_space_name: "corp",
      }),
    };
    answers.ipamApi = {
      listSpaces: async () => [
        { id: "space-corp", name: "corp" },
        { id: "space-lab", name: "lab" },
      ],
    };
    renderHistoryResult(LIST_COPY);

    fireEvent.click(
      await screen.findByRole("button", { name: /stamp alive hosts/i }),
    );
    expect(
      await screen.findByRole("option", {
        name: "Automatic — the scan's own space (corp)",
      }),
    ).toBeTruthy();
    expect(screen.queryByRole("option", { name: UNPINNED })).toBeNull();
  });

  it("never words a pinned scan as unpinned while its space is unknown", async () => {
    // getScan never answers: only the list's copy is available.
    answers.ipamApi = {
      listSpaces: async () => [
        { id: "space-corp", name: "corp" },
        { id: "space-lab", name: "lab" },
      ],
    };
    renderHistoryResult(LIST_COPY);

    fireEvent.click(
      await screen.findByRole("button", { name: /stamp alive hosts/i }),
    );
    expect(
      await screen.findByRole("option", {
        name: "Automatic — the scan's own space",
      }),
    ).toBeTruthy();
    expect(screen.queryByRole("option", { name: UNPINNED })).toBeNull();
  });

  it("still words an unpinned sweep as unpinned", async () => {
    answers.ipamApi = {
      listSpaces: async () => [
        { id: "space-corp", name: "corp" },
        { id: "space-lab", name: "lab" },
      ],
    };
    renderHistoryResult({ ...LIST_COPY, ip_address_id: null });

    fireEvent.click(
      await screen.findByRole("button", { name: /stamp alive hosts/i }),
    );
    expect(await screen.findByRole("option", { name: UNPINNED })).toBeTruthy();
  });
});
