/**
 * @vitest-environment jsdom
 *
 * Active Sessions opens a superadmin on "All users" however the page was
 * reached (#3010). The scope used to be useState's initial value, read once
 * from `me` on the first render: on a page load where `auth-me` had not
 * answered yet (a URL, a bookmark, a reload) a superadmin started on "My
 * sessions" and stayed there, so another user's live session was not listed.
 *
 * The contracts around it: a user who is not a superadmin only ever asks for
 * their own sessions, and a scope the operator picked is kept whatever
 * `auth-me` answers afterwards.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const me = vi.fn();
const listMine = vi.fn();
const listAll = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    ...actual,
    authApi: { ...actual.authApi, me },
    sessionsApi: { ...actual.sessionsApi, listMine, listAll },
  };
});

const { SessionsPage } = await import("./SessionsPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const SUPERADMIN = {
  id: "u-admin",
  username: "admin",
  email: "admin@example.test",
  display_name: "Admin",
  is_superadmin: true,
  force_password_change: false,
  auth_source: "local",
};

const OPERATOR = {
  ...SUPERADMIN,
  id: "u-ops",
  username: "ops",
  email: "ops@example.test",
  display_name: "Ops",
  is_superadmin: false,
};

function session(id: string, username: string, displayName: string) {
  return {
    id,
    user_id: `u-${username}`,
    username,
    display_name: displayName,
    auth_source: "local",
    source_ip: "192.0.2.10",
    user_agent: "Mozilla/5.0 Firefox/131.0",
    created_at: "2026-10-29T00:00:00.000Z",
    last_seen_at: null,
    expires_at: "2099-01-01T00:00:00.000Z",
    revoked: false,
    is_current: false,
  };
}

const ADMIN_SESSION = session("s-admin", "admin", "Admin");
// Another user's live session: listed only by the all-users request.
const BOB_SESSION = session("s-bob", "bob", "Bob Example");

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function mount(qc: QueryClient) {
  render(
    <QueryClientProvider client={qc}>
      <SessionsPage />
    </QueryClientProvider>,
  );
}

function sessionsServed() {
  listMine.mockResolvedValue([ADMIN_SESSION]);
  listAll.mockResolvedValue([ADMIN_SESSION, BOB_SESSION]);
}

function pressed(name: string) {
  return screen.getByRole("button", { name }).getAttribute("aria-pressed");
}

describe("Active Sessions scope (#3010)", () => {
  it("opens a superadmin on All users when auth-me answers after the first render", async () => {
    const auth = deferred<typeof SUPERADMIN>();
    me.mockReturnValue(auth.promise);
    sessionsServed();
    mount(newClient());
    // The first render happens before auth-me has answered, as on a page
    // opened by URL, from a bookmark or by a reload.
    await waitFor(() => expect(me).toHaveBeenCalledTimes(1));

    await act(async () => auth.resolve(SUPERADMIN));

    // Every user's sessions, without the operator touching the toggle.
    expect(await screen.findByText("bob")).toBeTruthy();
    expect(listAll).toHaveBeenCalledWith(false);
    expect(pressed("All users")).toBe("true");
    expect(pressed("My sessions")).toBe("false");
  });

  it("asks for no sessions until auth-me has answered", async () => {
    const auth = deferred<typeof SUPERADMIN>();
    me.mockReturnValue(auth.promise);
    sessionsServed();
    mount(newClient());
    await waitFor(() => expect(me).toHaveBeenCalledTimes(1));

    // Until the page knows who is asking it cannot know which list to show:
    // it says it is loading rather than showing one, or saying none match.
    expect(listMine).not.toHaveBeenCalled();
    expect(listAll).not.toHaveBeenCalled();
    expect(screen.getByText("Loading…")).toBeTruthy();
    expect(
      screen.queryByText("No sessions match the current filter."),
    ).toBeNull();

    await act(async () => auth.resolve(SUPERADMIN));
    expect(await screen.findByText("bob")).toBeTruthy();
    expect(listMine).not.toHaveBeenCalled();
  });

  it("keeps a user who is not a superadmin on their own sessions", async () => {
    const auth = deferred<typeof OPERATOR>();
    me.mockReturnValue(auth.promise);
    listMine.mockResolvedValue([session("s-ops", "ops", "Ops")]);
    listAll.mockResolvedValue([ADMIN_SESSION, BOB_SESSION]);
    mount(newClient());
    await waitFor(() => expect(me).toHaveBeenCalledTimes(1));

    await act(async () => auth.resolve(OPERATOR));

    expect(await screen.findByText("ops")).toBeTruthy();
    expect(listMine).toHaveBeenCalledWith(false);
    expect(listAll).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "All users" })).toBeNull();
  });

  it("keeps My sessions when the operator picked it before auth-me's refetch landed", async () => {
    // A stale auth-me entry from earlier in the session: the page opens on
    // it and refetches it in the background.
    const qc = newClient();
    qc.setQueryData(["auth-me"], SUPERADMIN, {
      updatedAt: Date.now() - 10 * 60_000,
    });
    const refetched = deferred<typeof SUPERADMIN>();
    me.mockReturnValue(refetched.promise);
    sessionsServed();
    mount(qc);
    expect(await screen.findByText("bob")).toBeTruthy();
    await waitFor(() => expect(me).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("button", { name: "My sessions" }));
    await waitFor(() => expect(screen.queryByText("bob")).toBeNull());

    // auth-me answers now, and `me` is a new object.
    await act(async () =>
      refetched.resolve({ ...SUPERADMIN, display_name: "Admin (renamed)" }),
    );
    await waitFor(() =>
      expect(qc.getQueryData(["auth-me"])).toMatchObject({
        display_name: "Admin (renamed)",
      }),
    );

    expect(screen.queryByText("bob")).toBeNull();
    expect(screen.getByText("admin")).toBeTruthy();
  });

  it("keeps My sessions when auth-me refetches after the operator picked it", async () => {
    const qc = newClient();
    qc.setQueryData(["auth-me"], SUPERADMIN);
    me.mockResolvedValue({ ...SUPERADMIN, display_name: "Admin (renamed)" });
    sessionsServed();
    mount(qc);
    expect(await screen.findByText("bob")).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "My sessions" }));
    await waitFor(() => expect(screen.queryByText("bob")).toBeNull());
    const allRequests = listAll.mock.calls.length;

    await act(async () => {
      await qc.refetchQueries({ queryKey: ["auth-me"] });
    });
    expect(me).toHaveBeenCalledTimes(1);
    expect(qc.getQueryData(["auth-me"])).toMatchObject({
      display_name: "Admin (renamed)",
    });

    expect(screen.queryByText("bob")).toBeNull();
    expect(listAll.mock.calls.length).toBe(allRequests);
    expect(screen.getByText("admin")).toBeTruthy();
  });
});
