/**
 * @vitest-environment jsdom
 *
 * A scan is started with write on 'manage_nmap_scans' and watched with read,
 * so the scan form is offered only to a role holding both (#3279). A
 * write-only role would start a scan whose viewer then answers 403.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

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

const { NmapScanForm } = await import("./NmapScanForm");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

type Grants = [string, string][] | "superadmin";

async function open(grants: Grants) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve(
        grants === "superadmin"
          ? { is_superadmin: true, grants: [] }
          : {
              is_superadmin: false,
              grants: grants.map(([action, resource_type]) => ({
                action,
                resource_type,
                resource_id: null,
              })),
            },
      ),
  };
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <NmapScanForm defaultTargetIp="10.0.0.5" onScanStarted={() => {}} />
    </QueryClientProvider>,
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 50));
  });
  return screen.getByRole("button", {
    name: /Scan 10.0.0.5/,
  }) as HTMLButtonElement;
}

describe("nmap scan form (#3279)", () => {
  it("is disabled, with a reason, for a role with write but no read", async () => {
    const btn = await open([["write", "manage_nmap_scans"]]);
    expect(btn.disabled).toBe(true);
    expect(btn.title).toMatch(/read/);
  });

  it("is offered with write and read, with admin, and to a superadmin", async () => {
    expect(
      (
        await open([
          ["write", "manage_nmap_scans"],
          ["read", "manage_nmap_scans"],
        ])
      ).disabled,
    ).toBe(false);
    cleanup();
    expect((await open([["admin", "manage_nmap_scans"]])).disabled).toBe(false);
    cleanup();
    expect((await open("superadmin")).disabled).toBe(false);
  });
});
