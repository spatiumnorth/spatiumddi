import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Fake BroadcastChannel: delivers to every OTHER instance of the same name.
const registry = new Map<string, Set<FakeBC>>();
class FakeBC {
  onmessage: ((ev: MessageEvent) => void) | null = null;
  constructor(public name: string) {
    if (!registry.has(name)) registry.set(name, new Set());
    registry.get(name)!.add(this);
  }
  postMessage(data: unknown) {
    for (const other of registry.get(this.name) ?? []) {
      if (other !== this)
        queueMicrotask(() => other.onmessage?.({ data } as MessageEvent));
    }
  }
  close() {
    registry.get(this.name)?.delete(this);
  }
}

// Fake Web Locks: one holder at a time per name, FIFO.
const tails = new Map<string, Promise<unknown>>();
const fakeLocks = {
  request(name: string, cb: () => Promise<unknown>) {
    const prev = tails.get(name) ?? Promise.resolve();
    const run = prev.then(() => cb());
    tails.set(
      name,
      run.catch(() => undefined),
    );
    return run;
  },
};

function jwt(sub: string, expInSec = 600): string {
  const b = (o: object) =>
    btoa(JSON.stringify(o))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  return `${b({ alg: "none" })}.${b({
    sub,
    exp: Math.floor(Date.now() / 1000) + expInSec,
  })}.sig`;
}

type Tab = {
  cross: typeof import("./crossTabAuth");
  auth: typeof import("./authToken");
};

async function openTab(): Promise<Tab> {
  vi.resetModules();
  const cross = await import("./crossTabAuth");
  const auth = await import("./authToken");
  return { cross, auth };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

beforeEach(() => {
  registry.clear();
  tails.clear();
  vi.stubGlobal("BroadcastChannel", FakeBC);
  vi.stubGlobal("navigator", { locks: fakeLocks });
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("crossTabAuth", () => {
  it("two tabs refreshing concurrently make exactly one POST", async () => {
    const a = await openTab();
    const b = await openTab();
    a.auth.setAccessToken(jwt("u1"));
    b.auth.setAccessToken(jwt("u1"));
    const staleA = a.auth.getAccessToken();
    const staleB = b.auth.getAccessToken();
    a.cross.initCrossTabAuth();
    b.cross.initCrossTabAuth();
    const fresh = jwt("u1", 900);
    const post = vi.fn(async () => {
      await flush();
      return { access_token: fresh, force_password_change: false };
    });
    const [ra, rb] = await Promise.all([
      a.cross.sharedRefresh(post, staleA),
      b.cross.sharedRefresh(post, staleB),
    ]);
    expect(post).toHaveBeenCalledTimes(1);
    expect(ra.access_token).toBe(fresh);
    // The second tab gets the broadcast token without its own POST.
    await flush();
    expect(rb.access_token).toBe(fresh);
  });

  it("adopts a broadcast token into a tab that holds a token", async () => {
    const a = await openTab();
    const b = await openTab();
    a.auth.setAccessToken(jwt("u1"));
    b.auth.setAccessToken(jwt("u1"));
    b.cross.initCrossTabAuth();
    const fresh = jwt("u1", 900);
    await a.cross.sharedRefresh(
      async () => ({ access_token: fresh, force_password_change: true }),
      a.auth.getAccessToken(),
    );
    await flush();
    expect(b.auth.getAccessToken()).toBe(fresh);
    expect(b.auth.getAuthSnapshot().mustChangePassword).toBe(true);
  });

  it("ignores a token for a different user", async () => {
    const a = await openTab();
    const b = await openTab();
    const mine = jwt("u2");
    a.auth.setAccessToken(jwt("u1"));
    b.auth.setAccessToken(mine);
    b.cross.initCrossTabAuth();
    await a.cross.sharedRefresh(
      async () => ({ access_token: jwt("u1", 900) }),
      a.auth.getAccessToken(),
    );
    await flush();
    expect(b.auth.getAccessToken()).toBe(mine);
    // ...and its own refresh does not adopt it either.
    const own = jwt("u2", 900);
    const post = vi.fn(async () => ({ access_token: own }));
    const r = await b.cross.sharedRefresh(post, mine);
    expect(post).toHaveBeenCalledTimes(1);
    expect(r.access_token).toBe(own);
  });

  it("propagates logout and goes to /login", async () => {
    const a = await openTab();
    const b = await openTab();
    a.auth.setAccessToken(jwt("u1"));
    b.auth.setAccessToken(jwt("u1"));
    b.cross.initCrossTabAuth();
    const loc = { pathname: "/ipam", href: "/ipam" };
    vi.stubGlobal("window", { location: loc });
    a.cross.initCrossTabAuth();
    a.cross.broadcastLogout();
    await flush();
    expect(b.auth.getAccessToken()).toBeNull();
    expect(loc.href).toBe("/login");
  });

  it("falls back to a plain refresh without Web Locks / BroadcastChannel", async () => {
    vi.stubGlobal("navigator", {});
    vi.stubGlobal("BroadcastChannel", undefined);
    const a = await openTab();
    const fresh = jwt("u1");
    const post = vi.fn(async () => ({ access_token: fresh }));
    const r = await a.cross.sharedRefresh(post, null);
    expect(r.access_token).toBe(fresh);
    expect(post).toHaveBeenCalledTimes(1);
    expect(() => a.cross.broadcastLogout()).not.toThrow();
  });

  it("never writes the token to web storage", async () => {
    const set = vi.fn();
    vi.stubGlobal("localStorage", { setItem: set });
    vi.stubGlobal("sessionStorage", { setItem: set });
    const a = await openTab();
    await a.cross.sharedRefresh(
      async () => ({ access_token: jwt("u1") }),
      null,
    );
    expect(set).not.toHaveBeenCalled();
  });
});
