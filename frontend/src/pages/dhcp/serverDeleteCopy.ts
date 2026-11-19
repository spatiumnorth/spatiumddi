/** Scopes belong to the server group, not to a server, so nothing is
 * unassigned by a server delete (#2609). */
export function deleteServerDescription(name: string) {
  return `Remove server "${name}"? The group's scopes stay with the group; if this is its last server, nothing serves them until another server joins.`;
}
