/**
 * @vitest-environment jsdom
 *
 * #4387: a Field whose body is not a single input / select / textarea wraps
 * it in a role="group" named by the label, but the control inside the group
 * got no name of its own, so getByLabelText(<label>) found the group and a
 * screen reader read an unnamed number box or select. The Field now hands its
 * label id to the control (`useFieldControl()` / the function form of
 * `children`), and the Roles permission editor's "Permissions" heading is no
 * longer a <label> that names nothing.
 *
 * Every API call stays pending.
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
            get: (_t, m) =>
              typeof m === "symbol"
                ? undefined
                : name === "authApi" && m === "myPermissions"
                  ? () => Promise.resolve({ is_superadmin: true, grants: [] })
                  : name === "apiTokensApi" && m === "list"
                    ? () => Promise.resolve([])
                    : pending,
          },
        ),
      ]),
  );
  return { ...actual, ...stubs };
});

const { Field, useFieldControl } = await import("@/components/ui/field");
const { ApiTokensPage } = await import("@/pages/admin/ApiTokensPage");
const { RolesPage } = await import("@/pages/admin/RolesPage");
const { ProxmoxPage } = await import("@/pages/proxmox/ProxmoxPage");
const { DockerPage } = await import("@/pages/docker/DockerPage");
const { AVFlowsPage } = await import("@/pages/network/AVFlowsPage");

afterEach(cleanup);

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

/** Click the opener once the permissions answer has enabled it. */
async function open(name: RegExp) {
  await waitFor(() => {
    const b = screen.getAllByRole("button", { name })[0] as HTMLButtonElement;
    expect(b.disabled).toBe(false);
  });
  fireEvent.click(screen.getAllByRole("button", { name })[0]);
  await screen.findByRole("dialog");
}

/** The control a label finds, which must be the control, not its group. */
function control(label: string, tag: string) {
  const el = screen.getByLabelText(label);
  expect(el.getAttribute("role"), label).not.toBe("group");
  expect(el.tagName, label).toBe(tag);
  return el as HTMLInputElement;
}

describe("a Field names the control inside its group (#4387)", () => {
  it("passes the label to a nested control through the function form and the hook", () => {
    function Inner() {
      return <select {...useFieldControl()} />;
    }
    render(
      <>
        <Field label="Inline">
          {(c) => (
            <div>
              <input {...c} />
            </div>
          )}
        </Field>
        <Field label="Component">
          <div>
            <Inner />
          </div>
        </Field>
      </>,
    );
    control("Inline", "INPUT");
    control("Component", "SELECT");
  });

  it("a control outside any Field gets no label props", () => {
    function Bare() {
      return <select data-testid="bare" {...useFieldControl()} />;
    }
    render(<Bare />);
    expect(screen.getByTestId("bare").hasAttribute("aria-labelledby")).toBe(
      false,
    );
  });
});

describe(
  "the listed dialogs name their controls (#4387)",
  { timeout: 15000 },
  () => {
    it("New API Token: Expires and Bind to a resource", async () => {
      wrap(<ApiTokensPage />);
      await open(/New Token/);
      const days = control("Expires", "INPUT");
      expect(days.type).toBe("number");
      control("Bind to a resource (optional)", "SELECT");
    });

    it("Add Proxmox Endpoint and Add Docker Host: IPAM space", async () => {
      wrap(<ProxmoxPage />);
      await open(/Add Endpoint/);
      control("IPAM space", "SELECT");
      cleanup();
      wrap(<DockerPage />);
      await open(/Add Host|Add Docker/);
      control("IPAM space", "SELECT");
    });

    it("New AV flow: Multicast group", async () => {
      wrap(<AVFlowsPage />);
      await open(/New flow/);
      control("Multicast group", "SELECT");
    });

    it("New Role: the Permissions heading names the grant rows, and no label is orphaned", async () => {
      wrap(<RolesPage />);
      await open(/New Role/);
      const dialog = screen.getByRole("dialog");
      expect(screen.getByRole("group", { name: "Permissions" })).toBeTruthy();
      const orphans = [...dialog.querySelectorAll("label")].filter(
        (l) => !l.htmlFor && !l.querySelector("input,select,textarea"),
      );
      expect(orphans.map((l) => l.textContent)).toEqual([]);
    });
  },
);
