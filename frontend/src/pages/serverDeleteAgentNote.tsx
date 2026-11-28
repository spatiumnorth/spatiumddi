/** Shared note for the Delete DNS Server / Delete DHCP Server dialogs (#4292).
 * Deleting a server drops its row only; a running agent gets a 404 on its next
 * call and registers again with its pre-shared key, so the row comes back. */
export const SERVER_DELETE_AGENT_SENTENCE =
  "If its agent is still running, the agent registers the server again on its next heartbeat (about 30 s), and the server waits for approval first where agent approval is required. To remove it for good, stop or uninstall the agent (or take the role off the appliance) first.";

export const SERVER_DELETE_RECIPE_URL =
  "https://www.spatiumddi.com/TROUBLESHOOTING.html#recovering-from-an-accidentally-deleted-dns-or-dhcp-server";

export function ServerDeleteAgentNote() {
  return (
    <span className="mt-2 block">
      {SERVER_DELETE_AGENT_SENTENCE}{" "}
      <a
        href={SERVER_DELETE_RECIPE_URL}
        target="_blank"
        rel="noreferrer"
        className="underline"
      >
        Recovering from an accidentally deleted server
      </a>
      .
    </span>
  );
}
