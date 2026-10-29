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

  it("ignores malformed, mistyped and expired broadcasts", async () => {
    const b = await openTab();
    const mine = jwt("u1");
    b.auth.setAccessToken(mine);
    b.cross.initCrossTabAuth();
    const sender = new FakeBC("spatium-auth");
    const good = jwt("u1", 900);
    const far = Date.now() + 900_000;
    const bad: unknown[] = [
      null,
      "token",
      { type: "token", token: "not-a-jwt", expiresAt: far, mustChange: false },
      {
        type: "token",
        token: `${good}.extra`,
        expiresAt: far,
        mustChange: false,
      },
      { type: "token", token: good, expiresAt: "soon", mustChange: false },
      { type: "token", token: good, expiresAt: far, mustChange: "yes" },
      { type: "token", token: good, expiresAt: Number.NaN, mustChange: false },
      // Sender's expiry in the past.
      {
        type: "token",
        token: good,
        expiresAt: Date.now() - 1,
        mustChange: false,
      },
      // Token's own exp in the past, whatever the sender claims.
      {
        type: "token",
        token: jwt("u1", -60),
        expiresAt: far,
        mustChange: false,
      },
      // No sub claim.
      {
        type: "token",
        token: `${btoa("{}")}.${btoa(JSON.stringify({ exp: 9e9 }))}.s`,
        expiresAt: far,
        mustChange: false,
      },
    ];
    for (const m of bad) sender.postMessage(m);
    await flush();
    expect(b.auth.getAccessToken()).toBe(mine);
    // ...and none of them is adopted by a later refresh either.
    const own = jwt("u1", 900);
    const post = vi.fn(async () => ({ access_token: own }));
    await b.cross.sharedRefresh(post, mine);
    expect(post).toHaveBeenCalledTimes(1);
  });

  it("a signed-out tab neither takes nor silently adopts a broadcast token", async () => {
    const a = await openTab();
    const b = await openTab(); // on /login, no token
    b.cross.initCrossTabAuth();
    a.auth.setAccessToken(jwt("u1"));
    const fresh = jwt("u1", 900);
    await a.cross.sharedRefresh(
      async () => ({ access_token: fresh }),
      a.auth.getAccessToken(),
    );
    await flush();
    expect(b.auth.getAccessToken()).toBeNull();
    // A 401-path refresh in the signed-out tab refreshes for itself.
    const own = jwt("u1", 900);
    const post = vi.fn(async () => ({ access_token: own }));
    const r = await b.cross.sharedRefresh(post, null);
    expect(post).toHaveBeenCalledTimes(1);
    expect(r.access_token).toBe(own);
  });

  it("a boot refresh adopts the token another tab just minted", async () => {
    const a = await openTab();
    const b = await openTab();
    b.cross.initCrossTabAuth();
    a.auth.setAccessToken(jwt("u1"));
    const fresh = jwt("u1", 900);
    await a.cross.sharedRefresh(
      async () => ({ access_token: fresh, force_password_change: true }),
      a.auth.getAccessToken(),
    );
    await flush();
    const post = vi.fn(async () => ({ access_token: jwt("u1", 900) }));
    const r = await b.cross.sharedRefresh(post, null, {
      allowAdoptWithoutToken: true,
    });
    expect(post).not.toHaveBeenCalled();
    expect(r.access_token).toBe(fresh);
    expect(r.force_password_change).toBe(true);
  });

  it("does not adopt a remembered token that has since expired", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const a = await openTab();
      const b = await openTab();
      b.auth.setAccessToken(jwt("u1"));
      b.cross.initCrossTabAuth();
      await a.cross.sharedRefresh(
        async () => ({ access_token: jwt("u1", 60) }),
        jwt("u1"),
      );
      await flush();
      const stale = b.auth.getAccessToken();
      vi.setSystemTime(Date.now() + 120_000);
      const own = jwt("u1", 900);
      const post = vi.fn(async () => ({ access_token: own }));
      const r = await b.cross.sharedRefresh(post, stale);
      expect(post).toHaveBeenCalledTimes(1);
      expect(r.access_token).toBe(own);
    } finally {
      vi.useRealTimers();
    }
  });

  it("forced password change in a broadcast routes the other tab too", async () => {
    const a = await openTab();
    const b = await openTab();
    a.auth.setAccessToken(jwt("u1"));
    b.auth.setAccessToken(jwt("u1"));
    b.cross.initCrossTabAuth();
    expect(b.auth.getAuthSnapshot().mustChangePassword).toBe(false);
    const first = jwt("u1", 900);
    await a.cross.sharedRefresh(
      async () => ({
        access_token: first,
        force_password_change: true,
      }),
      a.auth.getAccessToken(),
    );
    await flush();
    // The flag the route guard (App.tsx ProtectedRoute) redirects on.
    expect(b.auth.getAuthSnapshot().mustChangePassword).toBe(true);
    // ...and a later broadcast clearing it clears it here.
    await a.cross.sharedRefresh(
      async () => ({
        access_token: jwt("u1", 950),
        force_password_change: false,
      }),
      first,
    );
    await flush();
    expect(b.auth.getAuthSnapshot().mustChangePassword).toBe(false);
  });

  it("a failed refresh releases the lock for the next tab", async () => {
    const a = await openTab();
    const b = await openTab();
    const failing = vi.fn(async () => {
      throw new Error("503");
    });
    const own = jwt("u1", 900);
    const ok = vi.fn(async () => ({ access_token: own }));
    const [ra, rb] = await Promise.allSettled([
      a.cross.sharedRefresh(failing, jwt("u1")),
      b.cross.sharedRefresh(ok, jwt("u1")),
    ]);
    expect(ra.status).toBe("rejected");
    expect(rb.status).toBe("fulfilled");
    expect(ok).toHaveBeenCalledTimes(1);
  });

  it("a hung refresh is aborted and releases the lock", async () => {
    const a = await openTab();
    const b = await openTab();
    let aborted = false;
    const hang = (signal: AbortSignal) =>
      new Promise<{ access_token: string }>(() => {
        signal.addEventListener("abort", () => {
          aborted = true;
        });
      });
    const own = jwt("u1", 900);
    const ok = vi.fn(async () => ({ access_token: own }));
    const [ra, rb] = await Promise.allSettled([
      a.cross.sharedRefresh(hang, jwt("u1"), { timeoutMs: 20 }),
      b.cross.sharedRefresh(ok, jwt("u1"), { timeoutMs: 20 }),
    ]);
    expect(ra.status).toBe("rejected");
    expect(aborted).toBe(true);
    expect(rb.status).toBe("fulfilled");
    expect(a.cross.REFRESH_TIMEOUT_MS).toBeGreaterThan(0);
  });

  it("a sign-out heard during a refresh voids it", async () => {
    const a = await openTab();
    const b = await openTab();
    a.auth.setAccessToken(jwt("u1"));
    b.auth.setAccessToken(jwt("u1"));
    a.cross.initCrossTabAuth();
    vi.stubGlobal("window", { location: { pathname: "/login", href: "" } });
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow = async () => {
      await gate;
      return { access_token: jwt("u1", 900) };
    };
    const pending = a.cross.sharedRefresh(slow, a.auth.getAccessToken());
    b.cross.initCrossTabAuth();
    b.cross.broadcastLogout();
    await flush();
    release();
    await expect(pending).rejects.toBeInstanceOf(
      a.cross.SignedOutDuringRefresh,
    );
  });
});
