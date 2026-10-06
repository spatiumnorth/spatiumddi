/**
 * @vitest-environment jsdom
 *
 * The Copilot availability probe asks a route every user may read (#1345).
 *
 * The app shell asks on every page whether to offer "Ask AI". It used to
 * read GET /ai/providers, which is superadmin-only, so every page a
 * non-superadmin opened raised a 403 in the console, and the refusal left
 * the provider count `undefined`, which `!== 0` read as available: a
 * read-only Viewer was offered Ask AI where the admin, rightly, was not.
 *
 * Any signed-in user may chat, so the answer has to reach them too; these
 * pin that the probe asks GET /ai/available, never the provider list, and
 * offers Ask AI only on a yes.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const listProviders = vi.fn();
const available = vi.fn();
const modules = { on: true };

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    aiApi: {
      ...actual.aiApi,
      listProviders: () => listProviders(),
      available: () => available(),
    },
  };
});

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({
    ready: true,
    enabled: (id: string) => (id === "ai.copilot" ? modules.on : true),
  }),
}));

const { AskAIButton } = await import("./AskAIButton");

/** What the server answers a non-superadmin on the provider list. */
function superadminRequired() {
  return Object.assign(new Error("Request failed with status code 403"), {
    status: 403,
    response: { status: 403, data: { detail: "Superadmin required" } },
  });
}

function serverError() {
  return Object.assign(new Error("Request failed with status code 500"), {
    status: 500,
    response: { status: 500, data: { detail: "Internal Server Error" } },
  });
}

async function showAskAI() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <AskAIButton context="Subnet 192.0.2.0/24" />
    </QueryClientProvider>,
  );
}

/** Wait until the probe has been asked and its answer has landed. */
async function probed() {
  await waitFor(() =>
    expect(
      listProviders.mock.calls.length + available.mock.calls.length,
    ).toBeGreaterThan(0),
  );
  await act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });
}

afterEach(() => {
  cleanup();
  listProviders.mockReset();
  available.mockReset();
  modules.on = true;
});

describe("the Copilot availability probe (#1345)", () => {
  it("never asks the superadmin-only provider list, and a no offers no Ask AI", async () => {
    listProviders.mockRejectedValue(superadminRequired());
    available.mockResolvedValue(false);
    await showAskAI();
    await probed();
    expect(listProviders).not.toHaveBeenCalled();
    expect(screen.queryByText("Ask AI")).toBeNull();
  });

  it("offers Ask AI to a user the provider list refuses, when a chat is available", async () => {
    listProviders.mockRejectedValue(superadminRequired());
    available.mockResolvedValue(true);
    await showAskAI();
    expect(await screen.findByText("Ask AI")).toBeTruthy();
  });

  it("reads a probe that failed as unavailable, not as available", async () => {
    listProviders.mockRejectedValue(superadminRequired());
    available.mockRejectedValue(serverError());
    await showAskAI();
    await probed();
    expect(screen.queryByText("Ask AI")).toBeNull();
  });

  it("asks nothing and offers nothing with the Copilot module off (control)", async () => {
    modules.on = false;
    await showAskAI();
    await act(async () => {
      await new Promise((r) => setTimeout(r, 0));
    });
    expect(listProviders).not.toHaveBeenCalled();
    expect(available).not.toHaveBeenCalled();
    expect(screen.queryByText("Ask AI")).toBeNull();
  });
});
