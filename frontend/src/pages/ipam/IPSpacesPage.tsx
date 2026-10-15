import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ipamApi, type IPSpace } from "@/lib/api";
import { zebraBodyCls } from "@/lib/utils";
import { Trash2 } from "lucide-react";

export function IPSpacesPage() {
  const qc = useQueryClient();
  const { data: spaces, isLoading } = useQuery({
    queryKey: ["spaces"],
    queryFn: ipamApi.listSpaces,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => ipamApi.deleteSpace(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["spaces"] }),
  });

  if (isLoading) return <p className="text-muted-foreground">Loading…</p>;

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold tracking-tight">IP Spaces</h1>
      {spaces?.length === 0 && (
        <p className="text-sm text-muted-foreground">No IP spaces yet.</p>
      )}
      <div className="rounded-lg border">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b bg-muted/50">
              <th className="px-4 py-3 text-left font-medium">Name</th>
              <th className="px-4 py-3 text-left font-medium">Description</th>
              <th className="px-4 py-3 text-left font-medium">Default</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {spaces?.map((space: IPSpace) => (
              <tr
                key={space.id}
                className="border-b last:border-0 hover:bg-muted/30"
              >
                <td className="px-4 py-3 font-medium">{space.name}</td>
                <td className="px-4 py-3 text-muted-foreground">
                  {space.description}
                </td>
                <td className="px-4 py-3">{space.is_default ? "Yes" : "—"}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => deleteMutation.mutate(space.id)}
                    disabled={deleteMutation.isPending}
                    className="rounded p-1 text-muted-foreground hover:text-destructive"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
