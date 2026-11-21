/**
 * @vitest-environment jsdom
 *
 * SSH lockdown — the wiring around a lockout-capable switch (#1009).
 *
 * `ssh_lockdown` retires the appliance's always-open port-22 floor, so the
 * three things pinned here are the ones whose failure is invisible: an
 * acknowledgement path that can never open, a toggle that cannot be turned
 * off, and a forced save that latches. `tsc` is happy with all three, and so
 * is a reading of the diff — each was found by review, not by the compiler.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  configure,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import type { PlatformSettings } from "@/lib/api";

// Every wait here sits behind a lazily-loaded modal. testing-library's 1 s
// default is enough on an idle box and not on a CI runner mid-way through the
// full suite (the 1.0 s failures in the React 19 PR's run, all three at
// 1030-1046 ms, all three green when the file runs alone).
configure({ asyncUtilTimeout: 5000 });

const update = vi.fn();
vi.mock("@/lib/api", async () => {
  // formatApiError is the thing under test in one case, so use the REAL one:
  // a stub would pass whatever err.message the component read and hide
  // exactly the defect this file exists for.
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: { update: (p: unknown) => update(p) },
  };
});

/** What ``applianceApi.getRemoteAccess`` resolves to for a given test. Set
 *  before render; ``undefined`` models the report being unreadable (a 403 on
 *  a deploy where the caller lacks appliance-read), which must leave the form
 *  rendering rather than blanking it. */
let doors: unknown;

const invalidateQueries = vi.fn();

vi.mock("@tanstack/react-query", () => ({
  useQueryClient: () => ({ setQueryData: vi.fn(), invalidateQueries }),
  useQuery: () => ({ data: doors }),
  useMutation: ({ mutationFn, onSuccess, onError }: never) => {
    const fn = mutationFn as (p: unknown) => Promise<unknown>;
    return {
      isPending: false,
      mutate: (p: unknown) =>
        fn(p).then(
          (r) => (onSuccess as ((r: unknown) => void) | undefined)?.(r),
          (e) => (onError as ((e: unknown) => void) | undefined)?.(e),
        ),
    };
  },
}));

const { SSHSection } = await import("./SSHSection");

/** The shape an AxiosError actually has: `message` is the generic status
 *  line, and the server's sentence lives under `response.data.detail`. */
function axios422(detail: string) {
  return Object.assign(new Error("Request failed with status code 422"), {
    isAxiosError: true,
    response: { status: 422, data: { detail } },
  });
}

const LOCKOUT_DETAIL =
  "Your own address is not inside the allowed networks, so enforcing this " +
  "restriction may close your SSH access to every appliance. You would " +
  "still reach this UI to turn it back off (the Web UI is not " +
  "source-restricted), and the appliance console recovers it either way. " +
  "Re-send with ssh_lockdown_force to proceed.";

/** The #1013 escalation's detail, as ``console_only_detail`` renders it.
 *  Note it does NOT contain "not inside the allowed networks" — routing on
 *  prose rather than on the acknowledgement field would send this one to the
 *  wrong modal, whose tick the server then refuses. */
const CONSOLE_ONLY_DETAIL =
  "Refusing to close the last remote way in. After this change neither the " +
  "Web UI source restriction nor the SSH source restriction would admit the " +
  "address you are connecting from (203.0.113.9). Unless you can reach one " +
  "of those networks another way, the appliance console becomes the only " +
  "way into this fleet — and a VM with no console attached would need a " +
  "rebuild. Web UI allows 10.0.0.0/8; SSH allows 10.0.0.0/8. Add your " +
  "network to one of them, or re-send with acknowledge_console_only=true.";

function report(over: { webUiAdmits?: boolean } = {}) {
  return {
    caller_ip: "203.0.113.9",
    web_ui: {
      name: "web_ui",
      restricted: true,
      allowed_cidrs: ["10.0.0.0/8"],
      admits: over.webUiAdmits ?? false,
    },
    ssh: { name: "ssh", restricted: false, allowed_cidrs: [], admits: true },
    console_only: false,
  };
}

function values(over: Partial<PlatformSettings> = {}): PlatformSettings {
  return {
    ssh_authorized_keys: [],
    ssh_password_auth_enabled: true,
    ssh_allow_root_login: false,
    ssh_port: 22,
    ssh_allowed_source_networks: [],
    ssh_lockdown: false,
    ...over,
  } as PlatformSettings;
}

function setup(over: Partial<PlatformSettings> = {}) {
  render(
    <SSHSection
      values={values(over)}
      isSuperadmin
      applianceMode
      inputCls="input"
    />,
  );
  // Toggle renders a role="switch" <button> with aria-checked — not an
  // <input>, so `.checked` and getByRole("checkbox") both miss it.
  const enforce = screen.getByRole("switch", {
    name: /enforce source restriction/i,
  }) as HTMLButtonElement;
  return {
    enforce,
    isOn: () => enforce.getAttribute("aria-checked") === "true",
  };
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  doors = undefined;
});

describe("the enforcement toggle", () => {
  it("cannot be turned on without a network", () => {
    const { enforce, isOn } = setup({ ssh_allowed_source_networks: [] });
    expect(enforce.disabled).toBe(true);
    expect(isOn()).toBe(false);
  });

  it("can always be turned OFF, even with no networks left", () => {
    // Gating both directions on the list stranded an operator who removed
    // their last CIDR: checked AND disabled, Save 422s, no way out without
    // re-adding a CIDR or reloading.
    const { enforce, isOn } = setup({
      ssh_allowed_source_networks: [],
      ssh_lockdown: true,
    });
    expect(isOn()).toBe(true);
    expect(enforce.disabled).toBe(false);
    fireEvent.click(enforce);
    expect(isOn()).toBe(false);
  });

  it("says why saving as-is would be refused", () => {
    setup({ ssh_allowed_source_networks: [], ssh_lockdown: true });
    expect(screen.getByText(/close SSH from everywhere/i)).toBeTruthy();
  });

  it("is available once a network exists", () => {
    const { enforce } = setup({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    expect(enforce.disabled).toBe(false);
  });
});

describe("the self-lockout acknowledgement", () => {
  async function saveFrom(over: Partial<PlatformSettings>) {
    const { enforce } = setup(over);
    fireEvent.click(enforce);
    fireEvent.click(screen.getByRole("button", { name: /save ssh settings/i }));
    return enforce;
  }

  it("opens the confirmation on the server's 422, quoting its own words", async () => {
    // The defect: on an AxiosError `err.message` is always the generic status
    // line, never the detail — so matching on it never fired and the modal
    // (and ssh_lockdown_force with it) was unreachable from the UI.
    update.mockRejectedValueOnce(axios422(LOCKOUT_DETAIL));
    await saveFrom({ ssh_allowed_source_networks: ["10.0.0.0/8"] });

    await screen.findByText(/not inside the allowed networks/i);
    expect(
      screen.getByRole("button", { name: /enforce anyway/i }),
    ).toBeTruthy();
  });

  it("re-sends with the acknowledgement once confirmed", async () => {
    update.mockRejectedValueOnce(axios422(LOCKOUT_DETAIL));
    update.mockResolvedValueOnce(
      values({
        ssh_allowed_source_networks: ["10.0.0.0/8"],
        ssh_lockdown: true,
      }),
    );
    await saveFrom({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    await screen.findByText(/not inside the allowed networks/i);

    fireEvent.click(
      screen.getByLabelText(/I understand this may close my SSH access/i),
    );
    fireEvent.click(screen.getByRole("button", { name: /enforce anyway/i }));

    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));
    expect(update.mock.calls[0][0].ssh_lockdown_force).toBeUndefined();
    expect(update.mock.calls[1][0].ssh_lockdown_force).toBe(true);
  });

  it("never latches the acknowledgement onto a later save", async () => {
    // It used to be remembered in state and cleared only on success, so a
    // forced save that failed for ANY other reason left every subsequent
    // save silently forced.
    update.mockRejectedValueOnce(axios422(LOCKOUT_DETAIL));
    update.mockRejectedValueOnce(axios422("something else entirely"));
    await saveFrom({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    await screen.findByText(/not inside the allowed networks/i);
    fireEvent.click(
      screen.getByLabelText(/I understand this may close my SSH access/i),
    );
    fireEvent.click(screen.getByRole("button", { name: /enforce anyway/i }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));

    update.mockResolvedValueOnce(values());
    fireEvent.click(screen.getByRole("button", { name: /save ssh settings/i }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(3));
    expect(update.mock.calls[2][0].ssh_lockdown_force).toBeUndefined();
  });

  it("shows an unrelated failure as an error, not as a confirmation", async () => {
    update.mockRejectedValueOnce(axios422("ssh_port must be 1-65535"));
    await saveFrom({ ssh_allowed_source_networks: ["10.0.0.0/8"] });

    await screen.findByText(/ssh_port must be 1-65535/i);
    expect(
      screen.queryByRole("button", { name: /enforce anyway/i }),
    ).toBeNull();
  });
});

describe("the other door (#1013)", () => {
  async function saveFrom(over: Partial<PlatformSettings>) {
    const { enforce } = setup(over);
    fireEvent.click(enforce);
    fireEvent.click(screen.getByRole("button", { name: /save ssh settings/i }));
  }

  it("warns at the point of decision when the Web UI already excludes you", () => {
    doors = report();
    setup({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    expect(screen.getByText(/also/i)).toBeTruthy();
    expect(screen.getByText(/only way in/i, { exact: false })).toBeTruthy();
  });

  it("says nothing when the Web UI still admits you", () => {
    doors = report({ webUiAdmits: true });
    setup({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    expect(screen.queryByText(/only way in/i)).toBeNull();
  });

  it("renders normally when the door report cannot be read", () => {
    // A 403 (no appliance-read) or a non-appliance deploy must leave the
    // form usable rather than blanking the panel.
    doors = undefined;
    const { enforce } = setup({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    expect(enforce.disabled).toBe(false);
    expect(screen.queryByText(/only way in/i)).toBeNull();
  });

  it("routes the escalation to its OWN modal, not the per-door one", async () => {
    // Both 422s arrive as the same status with a different sentence. Routing
    // on prose would open the lockout modal here, whose tick sends
    // ssh_lockdown_force — which the server refuses for this case, so the
    // operator would meet the same refusal again with no way past it.
    update.mockRejectedValueOnce(axios422(CONSOLE_ONLY_DETAIL));
    await saveFrom({ ssh_allowed_source_networks: ["10.0.0.0/8"] });

    await screen.findByText(/last remote way in/i);
    expect(
      screen.getByRole("button", { name: /close the last remote door/i }),
    ).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: /enforce anyway/i }),
    ).toBeNull();
  });

  it("re-sends with the escalation acknowledgement, and only that one", async () => {
    update.mockRejectedValueOnce(axios422(CONSOLE_ONLY_DETAIL));
    update.mockResolvedValueOnce(
      values({
        ssh_allowed_source_networks: ["10.0.0.0/8"],
        ssh_lockdown: true,
      }),
    );
    await saveFrom({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    await screen.findByText(/last remote way in/i);

    fireEvent.click(
      screen.getByLabelText(
        /only the appliance console will reach this fleet/i,
      ),
    );
    fireEvent.click(
      screen.getByRole("button", { name: /close the last remote door/i }),
    );

    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));
    expect(update.mock.calls[1][0].acknowledge_console_only).toBe(true);
    // The smaller tick is NOT sent along: the server does not accept it for
    // this case, and sending both would hide that if it ever changed.
    expect(update.mock.calls[1][0].ssh_lockdown_force).toBeUndefined();
  });

  it("never latches the escalation acknowledgement onto a later save", async () => {
    update.mockRejectedValueOnce(axios422(CONSOLE_ONLY_DETAIL));
    update.mockRejectedValueOnce(axios422("something else entirely"));
    await saveFrom({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    await screen.findByText(/last remote way in/i);
    fireEvent.click(
      screen.getByLabelText(
        /only the appliance console will reach this fleet/i,
      ),
    );
    fireEvent.click(
      screen.getByRole("button", { name: /close the last remote door/i }),
    );
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));

    update.mockResolvedValueOnce(values());
    fireEvent.click(screen.getByRole("button", { name: /save ssh settings/i }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(3));
    expect(update.mock.calls[2][0].acknowledge_console_only).toBeUndefined();
  });

  it("still carries every settings field on the escalation re-send", async () => {
    // The payload was written out once per acknowledgement path; a third
    // copy is how a field lands on Save and goes missing on the path that
    // only runs after a warning.
    update.mockRejectedValueOnce(axios422(CONSOLE_ONLY_DETAIL));
    update.mockResolvedValueOnce(values());
    await saveFrom({
      ssh_allowed_source_networks: ["10.0.0.0/8"],
      ssh_port: 2222,
      ssh_allow_root_login: true,
    });
    await screen.findByText(/last remote way in/i);
    fireEvent.click(
      screen.getByLabelText(
        /only the appliance console will reach this fleet/i,
      ),
    );
    fireEvent.click(
      screen.getByRole("button", { name: /close the last remote door/i }),
    );
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));

    const first = update.mock.calls[0][0];
    const second = update.mock.calls[1][0];
    expect(second).toEqual({ ...first, acknowledge_console_only: true });
  });
});

describe("keeping the other screen honest", () => {
  it("invalidates the door report after a successful save", async () => {
    // The report is derived from BOTH settings, so an SSH save makes it
    // stale. Left cached, the Firewall tab keeps rendering "the SSH
    // allow-list does not exclude this address" after lockdown was just
    // enabled against a scope that excludes the operator — the exact false
    // assurance this guard exists to remove.
    update.mockResolvedValueOnce(
      values({
        ssh_allowed_source_networks: ["10.0.0.0/8"],
        ssh_lockdown: true,
      }),
    );
    const { enforce } = setup({ ssh_allowed_source_networks: ["10.0.0.0/8"] });
    fireEvent.click(enforce);
    fireEvent.click(screen.getByRole("button", { name: /save ssh settings/i }));

    await waitFor(() =>
      expect(invalidateQueries).toHaveBeenCalledWith({
        queryKey: ["appliance", "remote-access"],
      }),
    );
  });
});
