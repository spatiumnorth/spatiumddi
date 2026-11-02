/**
 * @vitest-environment jsdom
 *
 * A refused request says why where the operator pressed (#3323): the Subnet
 * Planner editor's validate call (invalid node CIDR, 422), and New IP Space
 * (name already taken, 409).
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
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { ReactNode } from "react";

type Answer = (...args: unknown[]) => unknown;
const answers: Record<string, Record<string, Answer>> = {};

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

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => true }),
}));

const { CreateSpaceModal } = await import("./IPAMPage");
const { SubnetPlannerEditorPage } = await import("./SubnetPlannerEditorPage");

afterEach(() => {
  cleanup();
  for (const name of Object.keys(answers)) delete answers[name];
});

function open(ui: ReactNode, path = "/") {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const refusal = (status: number, detail: unknown) => ({
  response: { status, data: { detail } },
});

describe("New IP Space on a taken name (#3323)", () => {
  it("shows the 409's reason in the dialog", async () => {
    answers.ipamApi = {
      createSpace: () =>
        Promise.reject(refusal(409, "An IP space named 'lab' already exists")),
    };
    open(<CreateSpaceModal onClose={() => {}} />);
    const input = document.querySelector("input") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "lab" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));
    await waitFor(() =>
      expect(screen.getByRole("alert").textContent).toContain(
        "An IP space named 'lab' already exists",
      ),
    );
  });
});

describe("Subnet Planner editor on an invalid node CIDR (#3323)", () => {
  it("says why validation was refused", async () => {
    const tree = {
      id: "n1",
      network: "10.0.0.0/24",
      name: "",
      description: "",
      kind: "subnet",
      children: [],
    };
    answers.ipamApi = {
      getSubnetPlan: () =>
        Promise.resolve({
          id: "p1",
          name: "plan",
          space_id: "s1",
          tree,
          applied_at: null,
        }),
      listSpaces: () => Promise.resolve([]),
      validateSubnetPlanTree: () =>
        Promise.reject(
          refusal(422, [
            {
              loc: ["body", "tree", "network"],
              msg: "Value error, Invalid CIDR: 10.0.0.0/33",
            },
          ]),
        ),
    };
    open(
      <Routes>
        <Route path="/plans/:id" element={<SubnetPlannerEditorPage />} />
      </Routes>,
      "/plans/p1",
    );
    const alert = await screen.findByRole("alert", {}, { timeout: 3000 });
    expect(alert.textContent).toContain("Invalid CIDR: 10.0.0.0/33");
  });

  const planTree = {
    id: "n1",
    network: "10.0.0.0/24",
    name: "",
    description: "",
    kind: "block",
    children: [],
  };
  const planAnswers = (extra: Record<string, Answer>) => {
    answers.authApi = {
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    };
    answers.ipamApi = {
      getSubnetPlan: () =>
        Promise.resolve({
          id: "p1",
          name: "plan",
          space_id: "s1",
          tree: planTree,
          applied_at: null,
        }),
      listSpaces: () => Promise.resolve([]),
      ...extra,
    };
  };
  const openPlan = () =>
    open(
      <Routes>
        <Route path="/plans/:id" element={<SubnetPlannerEditorPage />} />
      </Routes>,
      "/plans/p1",
    );
  const cidrInput = async () => {
    await waitFor(() =>
      expect(screen.getByDisplayValue("10.0.0.0/24")).toBeTruthy(),
    );
    return screen.getByDisplayValue("10.0.0.0/24") as HTMLInputElement;
  };
  const saveButton = () =>
    screen.getByRole("button", { name: /Save/ }) as HTMLButtonElement;

  it("disables Save beside the reason once a typed CIDR is refused", async () => {
    planAnswers({
      validateSubnetPlanTree: (body: unknown) =>
        (body as { tree: { network: string } }).tree.network.endsWith("/33")
          ? Promise.reject(
              refusal(422, [
                {
                  loc: ["body", "tree", "network"],
                  msg: "Value error, Invalid CIDR: 10.0.0.0/33",
                },
              ]),
            )
          : Promise.resolve({ ok: true, conflicts: [] }),
    });
    openPlan();
    fireEvent.change(await cidrInput(), { target: { value: "10.0.0.0/33" } });
    const alert = await screen.findByRole("alert", {}, { timeout: 3000 });
    expect(alert.textContent).toContain("Invalid CIDR: 10.0.0.0/33");
    expect(saveButton().disabled).toBe(true);
  });

  it("says why Save was refused", async () => {
    planAnswers({
      validateSubnetPlanTree: () =>
        Promise.resolve({ ok: true, conflicts: [] }),
      updateSubnetPlan: () =>
        Promise.reject(refusal(409, "Plan was applied in another session")),
    });
    openPlan();
    fireEvent.change(await cidrInput(), { target: { value: "10.0.1.0/24" } });
    await waitFor(() => expect(saveButton().disabled).toBe(false));
    fireEvent.click(saveButton());
    const alert = await screen.findByRole("alert", {}, { timeout: 3000 });
    expect(alert.textContent).toContain("Not saved");
    expect(alert.textContent).toContain("Plan was applied in another session");
  });
});
