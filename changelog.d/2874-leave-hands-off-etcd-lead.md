### Fixed

- **Demoting both members of a three-node cluster no longer leaves the
  seed's control plane down when a member leads etcd (#2874).** A
  demoted member removed its own etcd member even while it was the
  leader, which leaves the cluster with no leader until an election
  timeout. The other member's removal waited through that election,
  and when that member won it, its removal committed at once with
  itself as the leader. The seed was left the only voter, still
  without a leader: its controller-manager lost its lease, k3s exited,
  and k3s came back counting the removed member as a voter, so the
  seed never elected itself again. Its API server stayed down for the
  rest of the walk, and both rows read `evicting` with no way on. A
  leaving member whose etcd leads now hands the lead to the seed
  (etcd's MoveLeader) before it removes itself, and a member that
  cannot hand it off refuses the leave with k3s left running, as for
  a removal etcd refused.
