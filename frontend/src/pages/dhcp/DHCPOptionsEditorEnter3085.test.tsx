/**
 * @vitest-environment jsdom
 *
 * #3085 — Enter in a standard option field submitted the surrounding dialog
 * form before the field's blur committed its text, so the dialog saved the
 * options as they were before the typing.
 */
import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import type { DHCPOption } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  dhcpApi: { listOptionCodes: () => Promise.resolve([]) },
}));
import { DHCPOptionsEditor } from "./DHCPOptionsEditor";

let latest: DHCPOption[] = [];
const submitted: DHCPOption[][] = [];

function Harness() {
  const [v, setV] = useState<DHCPOption[]>([
    { code: 6, name: "dns-servers", value: ["10.98.130.53"] },
  ]);
  latest = v;
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        submitted.push(latest);
      }}
    >
      <DHCPOptionsEditor value={v} onChange={setV} />
    </form>
  );
}

describe("Enter in a DHCP option field (#3085)", () => {
  it("commits the typed text and does not submit the dialog", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Harness />
      </QueryClientProvider>,
    );
    const box = screen.getByText("DNS Servers (option 6)", {
      selector: "label",
    }).nextElementSibling as HTMLInputElement;
    fireEvent.change(box, { target: { value: "10.98.130.53, 10.98.130.54" } });
    // keyDown's default action is what submits a form; the editor must
    // cancel it, so assert on the event too.
    const notCancelled = fireEvent.keyDown(box, { key: "Enter" });
    expect(notCancelled).toBe(false);
    expect(latest.find((o) => o.code === 6)?.value).toEqual([
      "10.98.130.53",
      "10.98.130.54",
    ]);
    expect(submitted).toEqual([]);
  });
});
