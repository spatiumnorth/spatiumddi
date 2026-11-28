/**
 * @vitest-environment jsdom
 *
 * #5021 — a name target typed without a trailing dot is relative to the zone;
 * the record dialog says what it resolves to and warns on a dotted one.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listViews: async () => [],
      listZones: async () => [{ id: "z1", view_id: null }],
    },
  };
});

afterEach(cleanup);

async function open() {
  const { RecordModal } = await import("@/pages/dns/DNSPage");
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <RecordModal
          groupId="g1"
          zoneId="z1"
          zoneName="corp.test."
          onClose={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  await screen.findByLabelText("Value");
}

function setType(t: string) {
  fireEvent.change(screen.getByLabelText("Type"), { target: { value: t } });
}
function setValue(v: string) {
  fireEvent.change(screen.getByLabelText("Value"), { target: { value: v } });
}
const warning = () => screen.queryByText(/No trailing dot/);

describe("record dialog name-target hint (#5021)", () => {
  it("warns on a dotted relative CNAME and the button fixes it", async () => {
    await open();
    setType("CNAME");
    setValue("target.example.com");
    expect(screen.getByText("target.example.com.corp.test.")).toBeTruthy();
    expect(warning()).not.toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: /add the trailing dot/i }),
    );
    expect((screen.getByLabelText("Value") as HTMLInputElement).value).toBe(
      "target.example.com.",
    );
    expect(warning()).toBeNull();
    expect(screen.getByText("target.example.com.")).toBeTruthy();
  });
  it("shows the absolute target and no warning for a dotted-final value", async () => {
    await open();
    setType("CNAME");
    setValue("target.example.com.");
    expect(screen.getByText("target.example.com.")).toBeTruthy();
    expect(warning()).toBeNull();
  });
  it("gives @ and www the relative target but no warning", async () => {
    await open();
    setType("CNAME");
    setValue("www");
    expect(screen.getByText("www.corp.test.")).toBeTruthy();
    expect(warning()).toBeNull();
    setValue("@");
    expect(screen.getByText("corp.test.")).toBeTruthy();
    expect(warning()).toBeNull();
  });
  it("shows nothing for A and TXT", async () => {
    await open();
    for (const t of ["A", "TXT"]) {
      setType(t);
      setValue("a.b.c");
      expect(screen.queryByText(/Points to/)).toBeNull();
      expect(warning()).toBeNull();
    }
  });
});
