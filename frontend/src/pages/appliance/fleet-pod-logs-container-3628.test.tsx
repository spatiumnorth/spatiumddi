/**
 * @vitest-environment jsdom
 *
 * #3628: choosing another pod in Fleet -> Pod logs must not request the new pod
 * with the previous pod's container (kubeapi answers 400 -> 502).
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
import type { ApplianceRow } from "@/lib/api";

const getLogs = vi.fn(async () => "log line");

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    applianceApprovalApi: {
      ...actual.applianceApprovalApi,
      k8sListPods: async () => ({
        pods: [
          {
            name: "pod-a",
            phase: "Running",
            ready: true,
            containers: ["a1", "a2"],
            labels: {},
          },
          {
            name: "pod-b",
            phase: "Running",
            ready: true,
            containers: ["b1"],
            labels: {},
          },
        ],
      }),
      k8sGetPodLogs: (...args: unknown[]) =>
        (getLogs as unknown as (...a: unknown[]) => Promise<string>)(...args),
    },
  };
});

const { PodLogsModal } = await import("./FleetTab");

afterEach(() => {
  cleanup();
  getLogs.mockClear();
});

function renderModal() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={qc}>
      <PodLogsModal
        appliance={{ id: "ap-1", hostname: "node1" } as unknown as ApplianceRow}
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
}

function callsFor(pod: string): (string | undefined)[] {
  return (getLogs.mock.calls as unknown as unknown[][])
    .filter((c) => c[1] === pod)
    .map((c) => (c[2] as { container?: string }).container);
}

describe("Fleet pod logs (#3628)", () => {
  it("never pairs a newly chosen pod with the previous pod's container", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <PodLogsModal
          appliance={
            { id: "ap-1", hostname: "node1" } as unknown as ApplianceRow
          }
          onClose={() => {}}
        />
      </QueryClientProvider>,
    );
    await waitFor(() => expect(getLogs).toHaveBeenCalled());
    // Pick a2 on pod-a, then switch pod.
    const containerSel = (await screen.findByLabelText(
      /Container/,
    )) as HTMLSelectElement;
    fireEvent.change(containerSel, { target: { value: "a2" } });
    await waitFor(() =>
      expect(getLogs).toHaveBeenCalledWith(
        "ap-1",
        "pod-a",
        expect.objectContaining({ container: "a2" }),
      ),
    );
    getLogs.mockClear();
    fireEvent.change(screen.getAllByRole("combobox")[0], {
      target: { value: "pod-b" },
    });
    await waitFor(() => expect(getLogs).toHaveBeenCalled());
    for (const call of getLogs.mock.calls as unknown as unknown[][]) {
      if (call[1] === "pod-b") {
        expect((call[2] as { container?: string }).container).toBe("b1");
      }
    }
    expect(
      (getLogs.mock.calls as unknown as unknown[][]).some(
        (c) =>
          c[1] === "pod-b" &&
          (c[2] as { container?: string }).container === "a2",
      ),
    ).toBe(false);
  });

  it("opening the dialog sends one request, for the first pod's first container", async () => {
    renderModal();
    await waitFor(() => expect(getLogs).toHaveBeenCalled());
    // Let any trailing effect-driven re-request land before counting.
    await new Promise((r) => setTimeout(r, 50));
    // The pre-fix effect sent container=undefined first (a 400 from kubeapi
    // on a multi-container pod), then a1.
    expect(callsFor("pod-a")).toEqual(["a1"]);
  });

  it("switching pod sends exactly one request, for a container the new pod has", async () => {
    renderModal();
    await waitFor(() => expect(callsFor("pod-a")).toEqual(["a1"]));
    fireEvent.change(screen.getAllByRole("combobox")[0], {
      target: { value: "pod-b" },
    });
    await waitFor(() => expect(callsFor("pod-b").length).toBeGreaterThan(0));
    await new Promise((r) => setTimeout(r, 50));
    expect(callsFor("pod-b")).toEqual(["b1"]);
  });
});
