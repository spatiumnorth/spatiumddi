/**
 * @vitest-environment jsdom
 *
 * A DICOM AE row stored before the PS3.5 repertoire check (#4294) must stay
 * editable: the edit form omits an unchanged title from the PATCH and shows
 * a hint instead of blocking Save.
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

const updateAe = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dicomApi: {
      ...actual.dicomApi,
      updateAe: (...a: unknown[]) => updateAe(...a),
    },
  };
});

import { AEModal } from "./DICOMPage";
import type { DICOMApplicationEntity } from "@/lib/api";

afterEach(() => {
  cleanup();
  updateAe.mockReset();
});

const legacy = {
  id: "ae1",
  ae_title: "CT LEGACY",
  ip_address_id: null,
  address: null,
  port: 104,
  notes: "",
} as unknown as DICOMApplicationEntity;

function renderModal() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AEModal mode="edit" ae={legacy} onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AEModal on a legacy invalid title (#4294)", () => {
  it("shows the hint, enables Save and omits the unchanged title", async () => {
    updateAe.mockResolvedValue({});
    renderModal();
    expect(screen.getByText(/rename it when you can/i)).toBeTruthy();
    const save = screen.getByRole("button", { name: /save/i });
    expect((save as HTMLButtonElement).disabled).toBe(false);
    fireEvent.click(save);
    await waitFor(() => expect(updateAe).toHaveBeenCalled());
    const body = updateAe.mock.calls[0][1] as Record<string, unknown>;
    expect("ae_title" in body).toBe(false);
  });

  it("blocks Save when the title is changed to another invalid value", () => {
    renderModal();
    fireEvent.change(screen.getByPlaceholderText(/CT1_RADIOLOGY/), {
      target: { value: "CT OTHER" },
    });
    const save = screen.getByRole("button", { name: /save/i });
    expect((save as HTMLButtonElement).disabled).toBe(true);
  });
});
