### Fixed

- **A packet capture stored on another node's disk now says which node
  holds it (#2866).** On a multi-node appliance a capture's `.pcap`
  lands on the `pcaps` hostPath of the node whose api pod took the
  upload (or whose worker ran a server-side capture), so a download
  served by any other node's api answered 404 "capture artifact no
  longer on disk (pruned or volume drift)", which read as a lost file.
  The capture row now records the holding node
  (`packet_capture.artifact_node`, set from the pod's `NODE_NAME` when
  the artifact is stored), and a download that misses the file on a
  different node answers 502 naming that node and where to retry. The
  404 stays for a miss on the holding node itself, for a pod with no
  node name (Compose), and for captures from before this change, which
  have no recorded node. The Packet Capture page shows the holding node
  and now shows download errors; `artifact_node` is also on the capture
  API response and the `find_packet_captures` tool. Serving a capture
  from any node is not part of this change.

### Migrations

- `a2866c5e7d41` — #2866, adds the nullable
  `packet_capture.artifact_node` column. No backfill.
