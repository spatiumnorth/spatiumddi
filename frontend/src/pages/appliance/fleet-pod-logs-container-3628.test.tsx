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

afterEach(cleanup);

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
});
