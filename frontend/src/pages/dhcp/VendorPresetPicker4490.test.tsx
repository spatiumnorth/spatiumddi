/**
 * @vitest-environment jsdom
 *
 * #4490: the vendor preset picker previews the server-encoded option 43 and
 * hands it back, with the option-60 fence, on apply.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", () => ({
  formatApiError: (e: unknown) => String(e),
  dhcpApi: {
    listVendorPresets: () =>
      Promise.resolve([
        {
          id: "unifi",
          vendor: "Ubiquiti",
          product: "UniFi Network",
          description: "d",
          option_code: 43,
          min_controllers: 1,
          max_controllers: 1,
          controller_label: "UniFi controller IPv4 address",
          vendor_class_match: "ubnt",
          vendor_class_note: "n",
          source: "s",
        },
      ]),
    encodeVendorPreset: (_id: string, ips: string[]) =>
      Promise.resolve({
        preset_id: "unifi",
        option_code: 43,
        value: `0104-${ips[0]}`,
        byte_length: 6,
        vendor_class_match: "ubnt",
      }),
  },
}));

import { VendorPresetPicker } from "./VendorPresetPicker";

afterEach(cleanup);

describe("VendorPresetPicker", () => {
  it("previews the hex and applies it with the class match", async () => {
    const onApply = vi.fn();
    const user = userEvent.setup();
    render(
      <QueryClientProvider client={new QueryClient()}>
        <VendorPresetPicker onApply={onApply} />
      </QueryClientProvider>,
    );
    await user.click(screen.getByText(/Add vendor preset/));
    await user.selectOptions(await screen.findByRole("combobox"), "unifi");
    await user.type(
      screen.getByLabelText("UniFi controller IPv4 address 1"),
      "10.0.0.5",
    );
    await waitFor(() =>
      expect(screen.getByTestId("preset-hex").textContent).toBe(
        "0104-10.0.0.5",
      ),
    );
    await user.click(screen.getByText("Use this value"));
    expect(onApply).toHaveBeenCalledWith({
      value: "0104-10.0.0.5",
      vendor: "Ubiquiti",
      vendorClassMatch: "ubnt",
    });
  });
});
