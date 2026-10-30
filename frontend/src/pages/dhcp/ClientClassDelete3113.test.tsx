/**
 * @vitest-environment jsdom
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const DETAIL =
  "Cannot delete client class 'cc1': it is still referenced by 1 pool(s).";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dhcpApi: {
      ...actual.dhcpApi,
      listClientClasses: () =>
        Promise.resolve([{ id: "c1", name: "cc1", test: "", options: [] }]),
      deleteClientClass: () =>
        Promise.reject({
          isAxiosError: true,
          response: { status: 409, data: { detail: DETAIL } },
        }),
    },
  };
});
vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return { ...actual, usePermissions: () => ({ can: () => true }) };
});

const { ClientClassesTab } = await import("./DHCPPage");
afterEach(cleanup);

describe("client class delete (#3113)", () => {
  it("shows the server's 409 reason in the dialog", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <ClientClassesTab groupId="g1" />
      </QueryClientProvider>,
    );
    await screen.findByText("cc1");
    const trash = Array.from(
      container.querySelectorAll("tbody td:last-child button"),
    ).pop();
    fireEvent.click(trash as Element);
    fireEvent.click(await screen.findByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText(/still referenced by 1 pool/)).toBeTruthy();
  });
});
