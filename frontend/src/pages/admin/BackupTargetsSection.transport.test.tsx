/**
 * @vitest-environment jsdom
 *
 * Making a destination's transport weaker asks for its stored credential
 * again in the Edit dialog, as moving its host does (#4135).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { BackupTarget, BackupTargetKind } from "@/lib/api";

const list = vi.fn<() => Promise<BackupTarget[]>>();
const listKinds = vi.fn<() => Promise<BackupTargetKind[]>>();
const update = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: { list, listKinds, update },
  };
});
vi.mock("./BackupSectionsPicker", () => ({ BackupSectionsPicker: () => null }));

const { BackupTargetsSection } = await import("./BackupTargetsSection");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const f = (name: string, label: string, secret = false) => ({
  name,
  label,
  type: secret ? "password" : "text",
  required: false,
  description: null,
  secret,
});

const KINDS: BackupTargetKind[] = [
  {
    kind: "ftp",
    label: "FTP",
    inherently_write_only: false,
    config_fields: [
      f("host", "Host"),
      f("password", "Password", true),
      f("mode", "Transport mode"),
      f("verify_tls", "Verify TLS certificate"),
    ],
  },
];

async function openEdit(config: Record<string, unknown>) {
  list.mockResolvedValue([
    {
      id: "t-1",
      name: "ftp1",
      description: "",
      kind: "ftp",
      enabled: true,
      config: { host: "h", password: "<set>", ...config },
      passphrase_set: true,
      passphrase_hint: "",
      schedule_cron: null,
      retention_keep_last_n: null,
      retention_keep_days: null,
      write_only: false,
      last_run_status: "never",
    } as unknown as BackupTarget,
  ]);
  listKinds.mockResolvedValue(KINDS);
  const { container } = render(
    <QueryClientProvider client={new QueryClient()}>
      <BackupTargetsSection />
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByTitle("Edit"));
  await screen.findByText("Transport mode");
  return container;
}

function input(container: HTMLElement, label: string): HTMLInputElement {
  const span = Array.from(container.querySelectorAll("span")).find((s) =>
    s.textContent?.startsWith(label),
  );
  return span!.closest("label")!.querySelector("input")!;
}

const save = () => screen.getByRole("button", { name: /^save/i });

describe("Edit asks for the stored credential on a weaker transport", () => {
  it.each([
    [{ mode: "ftps_explicit" }, "Transport mode", "ftp"],
    [
      { mode: "ftps_explicit", verify_tls: "true" },
      "Verify TLS certificate",
      "false",
    ],
  ])("%j -> %s=%s", async (stored, label, value) => {
    const c = await openEdit(stored);
    expect(save()).toHaveProperty("disabled", false);
    fireEvent.change(input(c, label), { target: { value } });
    expect(input(c, "Password").placeholder).toBe(
      "re-enter for the changed transport",
    );
    expect(
      screen.getByText(/less protected transport/, { exact: false }),
    ).toBeTruthy();
    expect(screen.queryByText(/new address/)).toBeNull();
    expect(save()).toHaveProperty("disabled", true);
    fireEvent.change(input(c, "Password"), { target: { value: "pw" } });
    expect(save()).toHaveProperty("disabled", false);
  });

  it("a stronger transport asks for nothing", async () => {
    const c = await openEdit({ mode: "ftp" });
    fireEvent.change(input(c, "Transport mode"), {
      target: { value: "ftps_explicit" },
    });
    expect(input(c, "Password").placeholder).not.toMatch(/re-enter/);
    expect(save()).toHaveProperty("disabled", false);
  });
});
