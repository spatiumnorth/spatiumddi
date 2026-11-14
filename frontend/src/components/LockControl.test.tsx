/**
 * @vitest-environment jsdom
 *
 * The padlock and lock dialog of #3361. A lock needs a reason (the dialog's
 * button stays off without one), the action sits behind the ``lock`` grant on
 * the object's type, and an integration-owned object cannot be locked, so the
 * action is not offered.
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

const { lock, unlock } = vi.hoisted(() => ({ lock: vi.fn(), unlock: vi.fn() }));
let grants: string[] = [];

vi.mock("@/lib/api", async (orig) => {
  const real = await orig<typeof import("@/lib/api")>();
  return { ...real, locksApi: { list: vi.fn(), lock, unlock } };
});
vi.mock("@/hooks/usePermissions", () => ({
  usePermissions: () => ({
    can: (action: string, type: string) => grants.includes(`${action}:${type}`),
  }),
}));

import { LockBadge, LockControl } from "./LockControl";
import { lockTitle } from "@/lib/locks";

function mount(ui: React.ReactElement) {
  return render(
    <QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  lock.mockReset();
  unlock.mockReset();
  grants = [];
});

describe("LockBadge", () => {
  it("says the level, who and why in its title", () => {
    mount(
      <LockBadge
        resource={{
          lock_level: "edit",
          locked_by: "alice",
          lock_reason: "PCI freeze",
        }}
      />,
    );
    const badge = screen.getByTestId("lock-badge");
    expect(badge.getAttribute("title")).toContain("alice");
    expect(badge.getAttribute("title")).toContain("PCI freeze");
  });

  it("draws nothing for an unlocked object", () => {
    mount(<LockBadge resource={{ lock_level: null }} />);
    expect(screen.queryByTestId("lock-badge")).toBeNull();
    expect(lockTitle({})).toBeNull();
  });
});

describe("LockControl", () => {
  const subnet = { id: "s1", lock_level: null } as const;

  it("is not offered without the lock grant, nor for an integration-owned row", () => {
    mount(
      <LockControl
        type="subnet"
        resource={subnet}
        label="10.0.0.0/24"
        onChanged={() => {}}
      />,
    );
    expect(screen.queryByRole("button", { name: /lock/i })).toBeNull();
    cleanup();
    grants = ["lock:subnet"];
    mount(
      <LockControl
        type="subnet"
        resource={subnet}
        label="10.0.0.0/24"
        integrationOwned
        onChanged={() => {}}
      />,
    );
    expect(screen.queryByRole("button", { name: /lock/i })).toBeNull();
  });

  it("will not lock without a reason, then sends level and reason", async () => {
    grants = ["lock:subnet"];
    lock.mockResolvedValue({});
    const changed = vi.fn();
    mount(
      <LockControl
        type="subnet"
        resource={subnet}
        label="10.0.0.0/24"
        onChanged={changed}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Lock" }));
    const submit = screen.getAllByRole("button", { name: "Lock" }).at(-1)!;
    expect((submit as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByPlaceholderText(/change freeze/i), {
      target: { value: "audit hold" },
    });
    expect((submit as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(submit);
    await waitFor(() => expect(lock).toHaveBeenCalled());
    expect(lock.mock.calls[0][0]).toBe("subnet");
    expect(lock.mock.calls[0][1]).toBe("s1");
    expect(lock.mock.calls[0][2]).toMatchObject({
      level: "edit",
      reason: "audit hold",
    });
    await waitFor(() => expect(changed).toHaveBeenCalled());
  });

  it("unlocks with a reason", async () => {
    grants = ["lock:subnet"];
    unlock.mockResolvedValue({});
    mount(
      <LockControl
        type="subnet"
        resource={{
          id: "s1",
          lock_level: "delete",
          locked_by: "bob",
          lock_reason: "x",
        }}
        label="10.0.0.0/24"
        onChanged={() => {}}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Unlock" }));
    fireEvent.change(screen.getByPlaceholderText(/freeze is lifted/i), {
      target: { value: "freeze over" },
    });
    fireEvent.click(screen.getAllByRole("button", { name: "Unlock" }).at(-1)!);
    await waitFor(() =>
      expect(unlock).toHaveBeenCalledWith("subnet", "s1", "freeze over"),
    );
  });
});
