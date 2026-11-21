/**
 * @vitest-environment jsdom
 *
 * Populate IPAM from DNS (#2251): the dialog previews first, only commits
 * what was previewed, and says it writes no DNS.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const preview = vi.fn();
const commit = vi.fn();
vi.mock("@/lib/api", async (orig) => ({
  ...(await orig<object>()),
  ipamIoApi: {
    previewPopulateFromDns: (b: unknown) => preview(b),
    commitPopulateFromDns: (b: unknown) => commit(b),
  },
  dnsApi: {
    listGroups: vi.fn().mockResolvedValue([{ id: "g1" }]),
    listZones: vi
      .fn()
      .mockResolvedValue([{ id: "z1", name: "corp.test.", kind: "forward" }]),
  },
}));

import { PopulateFromDnsButton } from "./PopulateFromDnsModal";

afterEach(() => {
  cleanup();
  preview.mockReset();
  commit.mockReset();
});

function mount(canWrite = true) {
  const onCommitted = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient()}>
      <PopulateFromDnsButton
        scope={{ subnet_id: "s1" }}
        label="10.0.0.0/24"
        canWrite={canWrite}
        onCommitted={onCommitted}
      />
    </QueryClientProvider>,
  );
  return onCommitted;
}

describe("Populate from DNS dialog", () => {
  it("previews, then commits the same choices, and says no DNS is written", async () => {
    preview.mockResolvedValue({
      records_scanned: 2,
      subnets_in_scope: 1,
      counts: { new: 1, dynamic: 1 },
      reasons: {},
      dynamic_unknown: 0,
      outside: [],
      outside_total: 0,
      total_items: 1,
      items: [
        {
          address: "10.0.0.5",
          subnet: "10.0.0.0/24",
          category: "new",
          reason: "",
          hostname: "web1",
          existing_hostname: null,
          ptr: "none",
          records: [
            {
              id: "r1",
              zone_name: "corp.test.",
              name: "web1",
              fqdn: "web1.corp.test",
              record_type: "A",
              dynamic: false,
            },
          ],
        },
      ],
    });
    commit.mockResolvedValue({
      created: 1,
      linked: 0,
      updated: 0,
      skipped: 1,
      errors: [],
    });
    const user = userEvent.setup();
    const onCommitted = mount();
    await user.click(screen.getByRole("button", { name: /Populate from DNS/ }));
    expect(screen.getByText(/It writes no DNS/)).toBeTruthy();
    const populate = screen.getByRole("button", { name: "Populate IPAM" });
    expect((populate as HTMLButtonElement).disabled).toBe(true);
    await user.selectOptions(screen.getByLabelText("Status"), "reserved");
    await user.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => screen.getByTestId("populate-preview"));
    expect(screen.getByText("web1.corp.test")).toBeTruthy();
    await user.click(populate);
    await waitFor(() => expect(commit).toHaveBeenCalled());
    expect(commit.mock.calls[0][0]).toMatchObject({
      subnet_id: "s1",
      status: "reserved",
      dynamic_action: "skip",
    });
    expect(onCommitted).toHaveBeenCalled();
    expect(screen.getByText(/No DNS record was/)).toBeTruthy();
  });

  it("is disabled without write permission", () => {
    mount(false);
    expect(
      (
        screen.getByRole("button", {
          name: /Populate from DNS/,
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
});
