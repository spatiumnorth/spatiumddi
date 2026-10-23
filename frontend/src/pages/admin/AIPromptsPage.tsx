import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Sparkles, Trash2, Users } from "lucide-react";
import {
  aiApi,
  type AIPrompt,
  type AIPromptCreate,
  type AIPromptUpdate,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { cn, zebraBodyCls } from "@/lib/utils";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

interface PromptForm {
  name: string;
  description: string;
  prompt_text: string;
  is_shared: boolean;
}

const EMPTY: PromptForm = {
  name: "",
  description: "",
  prompt_text: "",
  is_shared: false,
};

function formFromPrompt(p: AIPrompt): PromptForm {
  return {
    name: p.name,
    description: p.description,
    prompt_text: p.prompt_text,
    is_shared: p.is_shared,
  };
}

function PromptEditor({
  initial,
  mode,
  canShare,
  onClose,
  onSave,
  saving,
  error,
}: {
  initial: PromptForm;
  mode: "create" | "edit";
  canShare: boolean;
  onClose: () => void;
  onSave: (form: PromptForm) => void;
  saving: boolean;
  error?: string;
}) {
  const [form, setForm] = useState<PromptForm>(initial);

  function set<K extends keyof PromptForm>(key: K, v: PromptForm[K]) {
    setForm((p) => ({ ...p, [key]: v }));
  }

  return (
    <Modal
      title={mode === "create" ? "New AI Prompt" : `Edit — ${initial.name}`}
      onClose={onClose}
      wide
    >
      <div className="space-y-4">
        {error && (
          <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Name
          </label>
          <input
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
            placeholder="e.g. Daily IPAM triage"
            className={inputCls}
          />
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Description{" "}
            <span className="text-muted-foreground/60">(optional)</span>
          </label>
          <input
            value={form.description}
            onChange={(e) => set("description", e.target.value)}
            placeholder="What this prompt is for, in one line"
            className={inputCls}
          />
        </div>

        <div>
          <label className="mb-1 block text-xs font-medium text-muted-foreground">
            Prompt text
          </label>
          <textarea
            value={form.prompt_text}
            onChange={(e) => set("prompt_text", e.target.value)}
            placeholder={
              "Loaded into the chat input when the operator picks this prompt.\n\nExample: Walk through every subnet ≥ 80% utilised and list the candidates for resize."
            }
            rows={10}
            className={`${inputCls} font-mono text-xs`}
          />
        </div>

        <label
          className={cn(
            "flex items-start gap-2 text-sm",
            !canShare && "opacity-60",
          )}
        >
          <input
            type="checkbox"
            checked={form.is_shared}
            onChange={(e) => set("is_shared", e.target.checked)}
            disabled={!canShare}
            className="mt-0.5"
          />
          <div>
            <div className="font-medium">Share with all users</div>
            <div className="text-xs text-muted-foreground">
              {canShare
                ? "Shared prompts appear in every operator's picker. Only superadmins can create or modify shared prompts."
                : "Only superadmins can create or modify shared prompts."}
            </div>
          </div>
        </label>

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => onSave(form)}
            disabled={saving || !form.name.trim() || !form.prompt_text.trim()}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {saving ? "Saving…" : mode === "create" ? "Create" : "Save"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function ConfirmDelete({
  prompt,
  onConfirm,
  onClose,
  pending,
}: {
  prompt: AIPrompt;
  onConfirm: () => void;
  onClose: () => void;
  pending: boolean;
}) {
  return (
    <Modal title={`Delete prompt — ${prompt.name}`} onClose={onClose}>
      <p className="text-sm text-muted-foreground">
        This permanently removes the prompt. Users who had it bookmarked will
        lose it. The chat sessions that referenced it are not affected.
      </p>
      <div className="mt-4 flex justify-end gap-2">
        <button
          onClick={onClose}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
        >
          Cancel
        </button>
        <button
          onClick={onConfirm}
          disabled={pending}
          className="rounded-md bg-destructive px-3 py-1.5 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
        >
          {pending ? "Deleting…" : "Delete"}
        </button>
      </div>
    </Modal>
  );
}

export function AIPromptsPage() {
  const qc = useQueryClient();

  // The endpoint enforces the visibility rules; we just consume what
  // it returns. ``is_owner`` on each row drives the edit/delete buttons
  // without a second round-trip.
  const promptsQ = useQuery({
    queryKey: ["ai-prompts"],
    queryFn: aiApi.listPrompts,
  });

  // Whether the current user is a superadmin is implicit in
  // ``is_owner`` over a shared prompt, but the cleaner signal is the
  // ability to share at all. We approximate it: anyone whose existing
  // shared prompts come back as ``is_owner=true`` is at minimum the
  // creator. For a fresh page load with no shared rows yet, fall back
  // to optimistic-allow and let the backend 403 if they aren't.
  const canShare = (promptsQ.data ?? []).some((p) => p.is_shared && p.is_owner)
    ? true
    : true; // optimistic — server enforces.

  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<AIPrompt | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AIPrompt | null>(null);
  const [error, setError] = useState<string>();

  const createMut = useMutation({
    mutationFn: (body: AIPromptCreate) => aiApi.createPrompt(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-prompts"] });
      setShowCreate(false);
      setError(undefined);
    },
    onError: (err: Error) => {
      setError(formatApiError(err));
    },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: AIPromptUpdate }) =>
      aiApi.updatePrompt(id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-prompts"] });
      setEditing(null);
      setError(undefined);
    },
    onError: (err: Error) => {
      setError(formatApiError(err));
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => aiApi.deletePrompt(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-prompts"] });
      setConfirmDelete(null);
    },
  });

  const prompts = promptsQ.data ?? [];

  return (
    <div className="h-full overflow-auto p-6">
      <div className="mx-auto max-w-[1200px] space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
              <Sparkles className="h-5 w-5 text-primary" />
              AI Prompts
            </h1>
            <p className="mt-1 text-xs text-muted-foreground">
              Reusable prompts for the Operator Copilot. Shared prompts appear
              in every user's picker; private prompts are visible only to you.
              Pick from the chat drawer's "Prompts ▾" menu.
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <button
              onClick={() => {
                setError(undefined);
                setShowCreate(true);
              }}
              className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              <Plus className="h-3.5 w-3.5" />
              New prompt
            </button>
          </div>
        </div>

        <div className="rounded-lg border bg-card">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b text-xs uppercase tracking-wider text-muted-foreground">
                <tr>
                  <th className="px-4 py-2 text-left font-medium">Name</th>
                  <th className="px-4 py-2 text-left font-medium">
                    Description
                  </th>
                  <th className="px-4 py-2 text-left font-medium">
                    Visibility
                  </th>
                  <th className="px-4 py-2 text-left font-medium">Modified</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody className={zebraBodyCls}>
                {promptsQ.isLoading && (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-4 py-8 text-center text-xs text-muted-foreground"
                    >
                      Loading…
                    </td>
                  </tr>
                )}
                {!promptsQ.isLoading && prompts.length === 0 && (
                  <tr>
                    <td
                      colSpan={5}
                      className="px-4 py-8 text-center text-xs text-muted-foreground"
                    >
                      No prompts yet — click "New prompt" to create one.
                    </td>
                  </tr>
                )}
                {prompts.map((p) => (
                  <tr key={p.id} className="border-b last:border-0">
                    <td className="px-4 py-2 font-medium">{p.name}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground max-w-md break-words">
                      {p.description || "—"}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {p.is_shared ? (
                        <span className="inline-flex items-center gap-1 rounded bg-emerald-100 px-1.5 py-0.5 text-emerald-700 dark:bg-emerald-950/30 dark:text-emerald-400">
                          <Users className="h-3 w-3" />
                          shared
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-muted-foreground">
                          private
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground tabular-nums whitespace-nowrap">
                      {new Date(p.modified_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex justify-end gap-1">
                        <button
                          disabled={!p.is_owner}
                          title={
                            p.is_owner
                              ? "Edit"
                              : "Only the creator (or a superadmin) can edit this prompt"
                          }
                          onClick={() => {
                            setError(undefined);
                            setEditing(p);
                          }}
                          className="rounded p-1.5 hover:bg-accent disabled:cursor-not-allowed disabled:opacity-30"
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </button>
                        <button
                          disabled={!p.is_owner}
                          title={
                            p.is_owner
                              ? "Delete"
                              : "Only the creator (or a superadmin) can delete this prompt"
                          }
                          onClick={() => setConfirmDelete(p)}
                          className="rounded p-1.5 text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-30 dark:hover:bg-red-950/30"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {showCreate && (
        <PromptEditor
          initial={EMPTY}
          mode="create"
          canShare={canShare}
          onClose={() => setShowCreate(false)}
          onSave={(form) =>
            createMut.mutate({
              name: form.name.trim(),
              description: form.description.trim(),
              prompt_text: form.prompt_text,
              is_shared: form.is_shared,
            })
          }
          saving={createMut.isPending}
          error={error}
        />
      )}
      {editing && (
        <PromptEditor
          initial={formFromPrompt(editing)}
          mode="edit"
          canShare={canShare}
          onClose={() => setEditing(null)}
          onSave={(form) =>
            updateMut.mutate({
              id: editing.id,
              body: {
                name: form.name.trim(),
                description: form.description.trim(),
                prompt_text: form.prompt_text,
                is_shared: form.is_shared,
              },
            })
          }
          saving={updateMut.isPending}
          error={error}
        />
      )}
      {confirmDelete && (
        <ConfirmDelete
          prompt={confirmDelete}
          pending={deleteMut.isPending}
          onConfirm={() => deleteMut.mutate(confirmDelete.id)}
          onClose={() => setConfirmDelete(null)}
        />
      )}
    </div>
  );
}
