/**
 * @vitest-environment jsdom
 *
 * The Device Policy dialog (#1991, #1992, #1994): a lease time that is not a
 * whole number of seconds is refused rather than sent as null ("inherit"); the
 * Device classes hint does not claim a manual-match policy matches nothing;
 * and every visible label names its control.
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

const createDevicePolicy = vi.fn(() => Promise.resolve({}));

vi.mock("@/lib/api", () => ({
  authApi: { myPermissions: () => Promise.resolve({}) },
  dhcpApi: {
    listDeviceObservations: () =>
      Promise.resolve({ total_devices: 0, classes: [] }),
    createDevicePolicy: (...a: unknown[]) =>
      (createDevicePolicy as (...x: unknown[]) => unknown)(...a),
    updateDevicePolicy: () => Promise.resolve({}),
  },
}));

import { DevicePolicyModal } from "./DevicePoliciesTab";

function open() {
  const onClose = vi.fn();
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DevicePolicyModal groupId="g1" onClose={onClose} />
    </QueryClientProvider>,
  );
  return onClose;
}

afterEach(() => {
  cleanup();
  createDevicePolicy.mockClear();
});

describe("DevicePolicyModal", () => {
  it("refuses a lease of 10m instead of sending null", async () => {
    const onClose = open();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "p" } });
    fireEvent.change(screen.getByLabelText("Lease time (seconds)"), {
      target: { value: "10m" },
    });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    expect((await screen.findByRole("alert")).textContent).toMatch(
      /whole number of seconds/,
    );
    expect(createDevicePolicy).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("sends an integer lease, and null for a blank one", async () => {
    open();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "p" } });
    fireEvent.change(screen.getByLabelText("Lease time (seconds)"), {
      target: { value: "600" },
    });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() => expect(createDevicePolicy).toHaveBeenCalledTimes(1));
    const calls = createDevicePolicy.mock.calls as unknown as [
      string,
      { lease_time: number | null },
    ][];
    expect(calls[0][1].lease_time).toBe(600);
  });

  it("sends null for a genuinely blank lease", async () => {
    open();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "p" } });
    fireEvent.click(screen.getByRole("button", { name: /create/i }));
    await waitFor(() => expect(createDevicePolicy).toHaveBeenCalledTimes(1));
    const calls = createDevicePolicy.mock.calls as unknown as [
      string,
      { lease_time: number | null },
    ][];
    expect(calls[0][1].lease_time).toBeNull();
  });

  it("does not say a manual-match policy matches nothing", async () => {
    open();
    await screen.findByText(/No fingerprints collected yet/);
    expect(screen.getByText(/will match nothing/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/Manual match expression/), {
      target: { value: "option[60].hex == 'test'" },
    });
    expect(screen.queryByText(/will match nothing/)).toBeNull();
    expect(screen.getByText(/applies regardless/)).toBeTruthy();
  });

  it("names every control by its visible label", () => {
    open();
    for (const l of [
      "Name",
      "Description",
      "Device classes",
      "Lease time (seconds)",
      "Options (JSON)",
      "Manual match expression (optional)",
    ])
      expect(screen.getAllByLabelText(l)).toHaveLength(1);
  });
});
