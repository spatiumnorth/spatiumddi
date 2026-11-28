/**
 * @vitest-environment jsdom
 *
 * Re-provision to static (#1287): the modal previews the plan, and only the
 * commit button writes, with the target the preview picked.
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

const plan = {
  lease_id: "l1",
  scope_id: "s1",
  subnet: "10.0.0.0/24",
  mac_address: "aa:bb:cc:dd:ee:ff",
  old_ip: "10.0.0.20",
  old_hostname: "ups-default",
  target_ip: "10.0.0.5",
  target_source: "reserved_pool",
  target_reason: "first free address in reserved pool",
  hostname: "ups1",
  fqdn: "ups1.example.com",
  dns_create: ["A ups1.example.com -> 10.0.0.5"],
  dns_remove: ["A ups-default.example.com -> 10.0.0.20"],
  ipam_remove: ["10.0.0.20"],
  ipam_create: "10.0.0.5",
  old_lease: "kept_until_moved",
  servers: ["kea1"],
  expected_move: "Moves at the next renewal.",
  t1_at: null,
  warnings: [],
};
const previewReprovision = vi.fn(() => Promise.resolve(plan));
const commitReprovision = vi.fn(() => Promise.resolve(plan));
const findLeasesByIp = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  dhcpApi: {
    previewReprovision: (...a: unknown[]) =>
      (previewReprovision as (...x: unknown[]) => unknown)(...a),
    commitReprovision: (...a: unknown[]) =>
      (commitReprovision as (...x: unknown[]) => unknown)(...a),
    findLeasesByIp: (...a: unknown[]) =>
      (findLeasesByIp as (...x: unknown[]) => unknown)(...a),
  },
}));

import {
  ReprovisionAddressModal,
  ReprovisionLeaseModal,
} from "./ReprovisionLeaseModal";

const lease = {
  id: "l1",
  ip_address: "10.0.0.20",
  mac_address: "aa:bb:cc:dd:ee:ff",
  hostname: "ups-default",
};

function wrap(ui: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("ReprovisionLeaseModal", () => {
  it("previews on open and commits the previewed target", async () => {
    wrap(<ReprovisionLeaseModal lease={lease} onClose={() => {}} />);
    await screen.findByText("10.0.0.5");
    expect(screen.getByText(/A ups-default.example.com/)).toBeTruthy();
    expect(commitReprovision).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Re-provision" }));
    await waitFor(() =>
      expect(commitReprovision).toHaveBeenCalledWith("l1", {
        target_ip: "10.0.0.5",
        hostname: "ups1",
      }),
    );
    await screen.findByRole("status");
  });

  it("shows the server's refusal and offers no commit", async () => {
    previewReprovision.mockRejectedValueOnce({
      response: { data: { detail: "target is inside a dynamic pool" } },
    });
    wrap(<ReprovisionLeaseModal lease={lease} onClose={() => {}} />);
    await screen.findByText("target is inside a dynamic pool");
    const btn = screen.getByRole("button", {
      name: "Re-provision",
    }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });
});

describe("ReprovisionAddressModal", () => {
  it("resolves the active lease behind an IPAM row", async () => {
    findLeasesByIp.mockResolvedValue({
      items: [{ ...lease, state: "active" }],
    });
    wrap(<ReprovisionAddressModal ip="10.0.0.20" onClose={() => {}} />);
    await screen.findByText("10.0.0.5");
    expect(previewReprovision).toHaveBeenCalledWith("l1", {});
  });

  it("says so when no lease holds the address", async () => {
    findLeasesByIp.mockResolvedValue({ items: [] });
    wrap(<ReprovisionAddressModal ip="10.0.0.20" onClose={() => {}} />);
    await screen.findByText(/No active DHCP lease found/);
  });
});
