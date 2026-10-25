/**
 * @vitest-environment jsdom
 *
 * Windows DNS: the edit dialog shows the stored WinRM settings and an
 * untouched save keeps them (it sends no windows_credentials block).
 */
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { DNSServer } from "@/lib/api";

const createServer = vi.fn();
const updateServer = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      ...actual.authApi,
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    dnsApi: {
      ...actual.dnsApi,
      listGroups: () => Promise.resolve([]),
      createServer: (...a: unknown[]) => createServer(...a),
      updateServer: (...a: unknown[]) => updateServer(...a),
    },
  };
});

const { ServerModal } = await import("./DNSPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const STORED = {
  id: "s1",
  group_id: "g1",
  name: "win-dns1",
  driver: "windows_dns",
  host: "dc1.corp.example",
  port: 53,
  api_port: null,
  roles: [],
  notes: "",
  is_enabled: true,
  is_primary: true,
  has_credentials: true,
  winrm_settings: {
    winrm_port: 5986,
    transport: "credssp",
    use_tls: true,
    verify_tls: true,
  },
} as unknown as DNSServer;

function ui(server?: DNSServer) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ServerModal groupId="g1" server={server} onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
const control = <T extends HTMLElement>(label: string) =>
  screen.getByText(label, { selector: "label" }).nextElementSibling as T;
const port = () => control<HTMLInputElement>("WinRM Port");
const transport = () => control<HTMLSelectElement>("Auth Transport");
const useTls = () => control<HTMLInputElement>("Use HTTPS (port 5986)");
const verifyTls = () => control<HTMLInputElement>("Verify TLS certificate");

describe("Windows DNS WinRM settings round-trip", () => {
  it("the edit dialog shows the stored settings", () => {
    ui(STORED);
    expect(port().value).toBe("5986");
    expect(transport().value).toBe("credssp");
    expect(useTls().checked).toBe(true);
    expect(verifyTls().checked).toBe(true);
  });

  it("an untouched save sends no WinRM block", async () => {
    updateServer.mockResolvedValue({ id: "s1" });
    ui(STORED);
    fireEvent.submit(port().form!);
    await waitFor(() => expect(updateServer).toHaveBeenCalled());
    expect(updateServer.mock.calls[0][2]).not.toHaveProperty(
      "windows_credentials",
    );
  });

  it("an edit sends only the setting the operator changed", async () => {
    updateServer.mockResolvedValue({ id: "s1" });
    ui(STORED);
    fireEvent.change(transport(), { target: { value: "ntlm" } });
    fireEvent.submit(port().form!);
    await waitFor(() => expect(updateServer).toHaveBeenCalled());
    expect(updateServer.mock.calls[0][2].windows_credentials).toEqual({
      transport: "ntlm",
    });
  });

  it("a new server sends every setting", async () => {
    createServer.mockResolvedValue({ id: "s2" });
    ui();
    fireEvent.change(control<HTMLInputElement>("Name"), {
      target: { value: "win-dns2" },
    });
    fireEvent.change(control<HTMLSelectElement>("Driver"), {
      target: { value: "windows_dns" },
    });
    fireEvent.change(control<HTMLInputElement>("Host / IP"), {
      target: { value: "dc2.corp.example" },
    });
    fireEvent.change(control<HTMLInputElement>("Username"), {
      target: { value: "CORP\\svc" },
    });
    fireEvent.change(control<HTMLInputElement>("Password"), {
      target: { value: "pw" },
    });
    fireEvent.submit(port().form!);
    await waitFor(() => expect(createServer).toHaveBeenCalled());
    expect(createServer.mock.calls[0][1].windows_credentials).toEqual({
      username: "CORP\\svc",
      password: "pw",
      winrm_port: 5985,
      transport: "ntlm",
      use_tls: false,
      verify_tls: false,
    });
  });
});
