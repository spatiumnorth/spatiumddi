/**
 * @vitest-environment jsdom
 *
 * A refused apply shows inside the confirm that promised it (#2984).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => false }),
}));

const { ApplyConfirmModal } = await import("./SubnetPlannerEditorPage");

afterEach(cleanup);

const tree = {
  id: "r",
  network: "10.0.0.0/16",
  name: "",
  description: "",
  kind: "block",
  children: [],
} as never;

function show(error: unknown) {
  return render(
    <ApplyConfirmModal
      tree={tree}
      spaceName="s"
      onCancel={() => {}}
      onConfirm={() => {}}
      isPending={false}
      error={error}
    />,
  );
}

describe("ApplyConfirmModal", () => {
  it("shows the apply refusal inside the confirm", () => {
    show({
      response: {
        data: {
          detail: "Gateway 10.0.170.1 is not within subnet 10.0.162.0/24",
        },
      },
    });
    expect(
      screen.getByText(/Gateway 10.0.170.1 is not within subnet/),
    ).toBeTruthy();
  });

  it("shows no banner without an error", () => {
    show(null);
    expect(screen.queryByText(/Operation failed/)).toBeNull();
  });
});
