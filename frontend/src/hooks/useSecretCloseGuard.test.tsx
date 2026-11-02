/**
 * @vitest-environment jsdom
 *
 * #3222: every dialog that shows a secret exactly once asks before it closes
 * on a secret the operator has not taken. One shared guard
 * (`useSecretCloseGuard`); these tests drive each dialog that uses it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import type { ApiTokenCreated, ControlPlaneReplaceResult } from "@/lib/api";

const copyMock = vi.hoisted(() => vi.fn());
vi.mock("@/lib/clipboard", () => ({ copyToClipboard: copyMock }));

const api = vi.hoisted(() => ({
  webhookCreate: vi.fn(),
  pairingCreate: vi.fn(),
  regenCodes: vi.fn(),
}));
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    webhooksApi: { ...actual.webhooksApi, create: api.webhookCreate },
    appliancePairingApi: {
      ...actual.appliancePairingApi,
      create: api.pairingCreate,
    },
    authApi: {
      ...actual.authApi,
      mfaRegenerateRecoveryCodes: api.regenCodes,
    },
  };
});

const { RevealTokenModal } = await import("@/pages/admin/ApiTokensPage");
const { SubscriptionEditor } = await import("@/pages/admin/WebhooksPage");
const { RevealedSecretModal } = await import("@/pages/dns/DNSPage");
const { GenerateCodeModal } = await import("@/pages/appliance/PairingTab");
const { ReplacementCodeModal } = await import("@/pages/appliance/FleetTab");
const { RegenerateRecoveryModal } = await import("@/pages/AccountPage");

const ASK = /It won't be shown again — close anyway\?/;

beforeEach(() => {
  copyMock.mockReset();
  Object.values(api).forEach((m) => m.mockReset());
});
afterEach(() => {
  cleanup();
  window.getSelection()?.removeAllRanges();
});

function mount(node: ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

const asking = () => screen.queryByText(ASK) !== null;

/** Select `el`'s text and fire the browser's copy event on it, as Ctrl+C. */
function copyByHand(el: HTMLElement) {
  const range = document.createRange();
  range.selectNodeContents(el);
  const sel = window.getSelection()!;
  sel.removeAllRanges();
  sel.addRange(range);
  fireEvent.copy(el);
}

// ── API token (the original report) ──────────────────────────────────────

describe("API token reveal", () => {
  const TOKEN = {
    id: "tok-1",
    name: "ci-runner",
    prefix: "sddi_abcde",
    token: "sddi_abcdefghijklmnop",
  } as unknown as ApiTokenCreated;

  it("revealing then hiding the token still counts", () => {
    const onClose = vi.fn();
    mount(<RevealTokenModal token={TOKEN} onClose={onClose} />);
    fireEvent.click(screen.getByTitle("Reveal"));
    fireEvent.click(screen.getByTitle("Hide"));
    fireEvent.click(screen.getByRole("button", { name: /I've copied it/ }));
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("Esc on the confirm goes back to the reveal dialog", () => {
    const onClose = vi.fn();
    mount(<RevealTokenModal token={TOKEN} onClose={onClose} />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(asking()).toBe(true);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(asking()).toBe(false);
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: /I've copied it/ })).toBeTruthy();
  });

  it("a manual copy of the token after a failed copy counts", async () => {
    copyMock.mockResolvedValue(false);
    const onClose = vi.fn();
    mount(<RevealTokenModal token={TOKEN} onClose={onClose} />);
    fireEvent.click(screen.getByTitle("Copy to clipboard"));
    await waitFor(() => screen.getByText(/Automatic copy failed/));
    copyByHand(screen.getByText(TOKEN.token));
    fireEvent.click(screen.getByRole("button", { name: /I've copied it/ }));
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

// ── TSIG secret ──────────────────────────────────────────────────────────

describe("TSIG secret reveal", () => {
  const SECRET = "c2VjcmV0LXRzaWctdmFsdWU=";
  const open = (onClose = vi.fn()) => {
    mount(
      <RevealedSecretModal
        name="k1"
        algorithm="hmac-sha256"
        secret={SECRET}
        action="created"
        onClose={onClose}
      />,
    );
    return onClose;
  };

  it("asks before closing an uncopied secret, and Go back keeps it", () => {
    const onClose = open();
    fireEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    expect(asking()).toBe(true);
    const back = screen.getByRole("button", { name: "Go back" });
    expect(document.activeElement).toBe(back);
    fireEvent.click(back);
    expect(asking()).toBe(false);
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByText(SECRET)).toBeTruthy();
  });

  it("the X and Esc ask too; Close without copying closes", () => {
    const onClose = open();
    fireEvent.click(screen.getByLabelText("Close dialog"));
    expect(asking()).toBe(true);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(asking()).toBe(false);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(asking()).toBe(true);
    fireEvent.click(
      screen.getByRole("button", { name: "Close without copying" }),
    );
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("closes directly after a successful copy", async () => {
    copyMock.mockResolvedValue(true);
    const onClose = open();
    fireEvent.click(screen.getByRole("button", { name: /Copy secret/ }));
    await waitFor(() => expect(copyMock).toHaveBeenCalledWith(SECRET));
    await act(async () => {});
    fireEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("a failed copy does not count", async () => {
    copyMock.mockResolvedValue(false);
    const onClose = open();
    fireEvent.click(screen.getByRole("button", { name: /Copy secret/ }));
    await waitFor(() => expect(copyMock).toHaveBeenCalled());
    await act(async () => {});
    fireEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    expect(asking()).toBe(true);
    expect(onClose).not.toHaveBeenCalled();
  });

  it("a manual copy of the secret counts; copying other text does not", () => {
    const onClose = open();
    copyByHand(screen.getByText("hmac-sha256"));
    fireEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    expect(asking()).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Go back" }));
    copyByHand(screen.getByText(SECRET));
    fireEvent.click(screen.getByRole("button", { name: "I have copied it" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

// ── Webhook signing secret ───────────────────────────────────────────────

describe("Webhook secret reveal", () => {
  const GENERATED = "gen-webhook-secret-0123456789abcdef";

  async function create(typedSecret?: string) {
    api.webhookCreate.mockImplementation(async (body: { secret?: string }) => ({
      id: "wh-1",
      secret_plaintext: body.secret || GENERATED,
    }));
    const onClose = vi.fn();
    mount(
      <SubscriptionEditor
        existing={null}
        eventTypeVocab={[]}
        onClose={onClose}
      />,
    );
    fireEvent.change(screen.getByPlaceholderText("e.g. ops-automation"), {
      target: { value: "hook" },
    });
    fireEvent.change(
      screen.getByPlaceholderText("https://automation.example.com/spddi"),
      { target: { value: "https://192.0.2.1/h" } },
    );
    if (typedSecret) {
      const pw = document.querySelector<HTMLInputElement>(
        'input[type="password"]',
      )!;
      fireEvent.change(pw, { target: { value: typedSecret } });
    }
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await screen.findByText(/this is the only chance/);
    return onClose;
  }

  it("asks before closing a generated secret that was not copied", async () => {
    const onClose = await create();
    fireEvent.click(
      screen.getByRole("button", { name: /Done — I've stored the secret/ }),
    );
    expect(asking()).toBe(true);
    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes directly after copying the generated secret", async () => {
    copyMock.mockResolvedValue(true);
    const onClose = await create();
    fireEvent.click(screen.getByRole("button", { name: /Copy/ }));
    await waitFor(() => expect(copyMock).toHaveBeenCalledWith(GENERATED));
    await act(async () => {});
    fireEvent.click(
      screen.getByRole("button", { name: /Done — I've stored the secret/ }),
    );
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("a secret the operator typed closes without asking", async () => {
    const onClose = await create("my-own-secret");
    fireEvent.click(
      screen.getByRole("button", { name: /Done — I've stored the secret/ }),
    );
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("the form step's Cancel is not guarded", () => {
    const onClose = vi.fn();
    mount(
      <SubscriptionEditor
        existing={null}
        eventTypeVocab={[]}
        onClose={onClose}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

// ── Pairing codes ────────────────────────────────────────────────────────

describe("New pairing code", () => {
  async function generate(persistent: boolean) {
    api.pairingCreate.mockResolvedValue({
      id: "pc-1",
      code: "12345678",
      persistent,
      enabled: true,
      expires_at: null,
      max_claims: null,
      note: null,
      created_at: "2026-10-31T00:00:00Z",
    });
    const onClose = vi.fn();
    mount(<GenerateCodeModal onClose={onClose} onCreated={vi.fn()} />);
    if (persistent) fireEvent.click(screen.getByText("Persistent"));
    fireEvent.click(screen.getByRole("button", { name: /Generate/ }));
    await screen.findByText("1234-5678");
    return onClose;
  }

  it("asks before closing an uncopied ephemeral code", async () => {
    const onClose = await generate(false);
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(asking()).toBe(true);
    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes directly once the ephemeral code is copied", async () => {
    copyMock.mockResolvedValue(true);
    const onClose = await generate(false);
    fireEvent.click(screen.getByTitle("Copy"));
    await waitFor(() => expect(copyMock).toHaveBeenCalledWith("1234-5678"));
    await act(async () => {});
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("a persistent code, which can be re-revealed, closes without asking", async () => {
    const onClose = await generate(true);
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("Replacement pairing code", () => {
  const RESULT = {
    evicted: { hostname: "ddi2" },
    pairing_code: "87654321",
    pairing_expires_at: "2026-10-31T01:00:00Z",
  } as unknown as ControlPlaneReplaceResult;

  it("asks before closing an uncopied code", () => {
    const onClose = vi.fn();
    mount(<ReplacementCodeModal result={RESULT} onClose={onClose} />);
    fireEvent.keyDown(window, { key: "Escape" });
    expect(asking()).toBe(true);
    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes directly once the code is copied", async () => {
    copyMock.mockResolvedValue(true);
    const onClose = vi.fn();
    mount(<ReplacementCodeModal result={RESULT} onClose={onClose} />);
    fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    await waitFor(() => expect(copyMock).toHaveBeenCalledWith("87654321"));
    await act(async () => {});
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

// ── Regenerated MFA recovery codes ───────────────────────────────────────

describe("Regenerated recovery codes", () => {
  const CODES = ["aaaa-1111", "bbbb-2222", "cccc-3333"];

  async function regenerate() {
    api.regenCodes.mockResolvedValue({ recovery_codes: CODES });
    const onClose = vi.fn();
    mount(
      <RegenerateRecoveryModal onClose={onClose} onRegenerated={vi.fn()} />,
    );
    fireEvent.change(screen.getByPlaceholderText("000000"), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Generate new codes" }));
    await screen.findByText(CODES[0]);
    return onClose;
  }

  it("the prompt step's Cancel is not guarded", () => {
    const onClose = vi.fn();
    mount(
      <RegenerateRecoveryModal onClose={onClose} onRegenerated={vi.fn()} />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("asks before closing uncopied new codes", async () => {
    const onClose = await regenerate();
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(asking()).toBe(true);
    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes directly after Copy all codes", async () => {
    copyMock.mockResolvedValue(true);
    const onClose = await regenerate();
    fireEvent.click(screen.getByRole("button", { name: /Copy all codes/ }));
    await waitFor(() => expect(copyMock).toHaveBeenCalled());
    await act(async () => {});
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(asking()).toBe(false);
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
