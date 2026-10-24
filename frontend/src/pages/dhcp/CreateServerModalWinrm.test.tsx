/**
 * @vitest-environment jsdom
 *
 * Windows DHCP: the edit dialog shows the stored WinRM settings and an
 * untouched save keeps them (it sends no windows_credentials block).
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
import type { DHCPServer } from "@/lib/api";

const createServer = vi.fn();
const updateServer = vi.fn();
vi.mock("@/lib/api", () => ({
  formatApiError: (e: unknown) => String(e),
  dhcpApi: {
    listGroups: () => Promise.resolve([]),
    createServer: (...a: unknown[]) => createServer(...a),
    updateServer: (...a: unknown[]) => updateServer(...a),
  },
}));

const { CreateServerModal } = await import("./CreateServerModal");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const STORED = {
  id: "s1",
  name: "win-dhcp1",
  description: "",
  driver: "windows_dhcp",
  host: "dhcp1.corp.example",
  port: 67,
  server_group_id: null,
  ha_peer_url: "",
  has_credentials: true,
  winrm_settings: {
    winrm_port: 5986,
    transport: "credssp",
    use_tls: true,
    verify_tls: true,
  },
} as unknown as DHCPServer;

function ui(server?: DHCPServer) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <CreateServerModal server={server} onClose={() => {}} />
    </QueryClientProvider>,
  );
}
const control = <T extends HTMLElement>(label: string) =>
  screen.getByLabelText(label) as T;
const port = () => control<HTMLInputElement>("WinRM Port");
const transport = () => control<HTMLSelectElement>("Auth Transport");
const useTls = () => control<HTMLInputElement>("Use HTTPS (port 5986)");
const verifyTls = () => control<HTMLInputElement>("Verify TLS certificate");

describe("Windows DHCP WinRM settings round-trip", () => {
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
    expect(updateServer.mock.calls[0][1]).not.toHaveProperty(
      "windows_credentials",
    );
  });

  it("an edit sends only the setting the operator changed", async () => {
    updateServer.mockResolvedValue({ id: "s1" });
    ui(STORED);
    fireEvent.click(verifyTls());
    fireEvent.submit(port().form!);
    await waitFor(() => expect(updateServer).toHaveBeenCalled());
    expect(updateServer.mock.calls[0][1].windows_credentials).toEqual({
      verify_tls: false,
    });
  });

  it("a new server sends every setting", async () => {
    createServer.mockResolvedValue({ id: "s2" });
    ui();
    fireEvent.change(control<HTMLSelectElement>("Driver"), {
      target: { value: "windows_dhcp" },
    });
    fireEvent.change(control<HTMLInputElement>("Username"), {
      target: { value: "CORP\\svc" },
    });
    fireEvent.change(control<HTMLInputElement>("Password"), {
      target: { value: "pw" },
    });
    fireEvent.submit(port().form!);
    await waitFor(() => expect(createServer).toHaveBeenCalled());
    expect(createServer.mock.calls[0][0].windows_credentials).toEqual({
      username: "CORP\\svc",
      password: "pw",
      winrm_port: 5985,
      transport: "ntlm",
      use_tls: false,
      verify_tls: false,
    });
  });
});
