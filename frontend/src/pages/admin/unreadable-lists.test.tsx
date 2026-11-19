/**
 * @vitest-environment jsdom
 *
 * A list the reader may not read is not an empty list (#2437, #1865's
 * class): New Group's Members and /ipam's tree say the read was refused.
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
import { MemoryRouter } from "react-router-dom";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

function refused() {
  return Object.assign(new Error("Request failed with status code 403"), {
    isAxiosError: true,
    response: { status: 403, data: { detail: "Superadmin required" } },
  });
}

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  const pending = () => new Promise(() => {});
  const stubs = Object.fromEntries(
    Object.entries(actual)
      .filter(([name, v]) => name.endsWith("Api") && typeof v === "object")
      .map(([name]) => [
        name,
        new Proxy(
          {},
          {
            get: (_t, method) =>
              typeof method === "symbol"
                ? undefined
                : (...args: unknown[]) =>
                    (answers[name]?.[method] ?? pending)(...args),
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

vi.mock("@/hooks/usePermissions", async () => {
  const actual = await vi.importActual<typeof import("@/hooks/usePermissions")>(
    "@/hooks/usePermissions",
  );
  return {
    ...actual,
    usePermissions: () => ({
      can: () => true,
      isSuperadmin: false,
      isLoading: false,
    }),
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { GroupsPage } = await import("@/pages/admin/GroupsPage");
const { IPAMPage } = await import("@/pages/ipam/IPAMPage");

function open(page: React.ReactElement) {
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  for (const k of Object.keys(answers)) delete answers[k];
});

describe("a refused read is not an empty list", () => {
  it("New Group's Members does not say 'No users' over a 403", async () => {
    answers.groupsApi = { list: () => Promise.resolve([]) };
    answers.rolesApi = { list: () => Promise.resolve([]) };
    answers.usersApi = { list: () => Promise.reject(refused()) };
    open(<GroupsPage />);
    fireEvent.click(await screen.findByRole("button", { name: /New Group/ }));
    await screen.findByText(/don't have permission to see users/);
    expect(screen.queryByText("No users")).toBeNull();
  });

  it("an empty but readable user list still says 'No users'", async () => {
    answers.groupsApi = { list: () => Promise.resolve([]) };
    answers.rolesApi = { list: () => Promise.resolve([]) };
    answers.usersApi = { list: () => Promise.resolve([]) };
    open(<GroupsPage />);
    fireEvent.click(await screen.findByRole("button", { name: /New Group/ }));
    await screen.findByText("No users");
  });

  it("/ipam does not invite a pick from a tree it could not read", async () => {
    answers.ipamApi = { listSpaces: () => Promise.reject(refused()) };
    open(<IPAMPage />);
    await waitFor(() =>
      expect(
        screen.getAllByText(/don't have permission to see IP spaces/).length,
      ).toBeGreaterThan(0),
    );
    expect(
      screen.queryByText("Select a space, block, or subnet from the tree."),
    ).toBeNull();
  });
});
