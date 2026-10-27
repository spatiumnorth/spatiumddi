### Fixed

- **A packet capture's file no longer leaks on a multi-node appliance
  (#2868).** A capture's `.pcap` sits on the `pcaps` hostPath of one
  node, but delete, bulk delete and the retention prune unlink only on
  the node of the pod that served them, so a file held elsewhere stayed
  forever once its row was gone. Every api and worker pod now sweeps
  its own pcaps directory every six hours and deletes capture files
  that no capture row names: the worker for the captures it writes,
  the api for the ones appliances upload. A file is touched only when
  it is a plain `<id>.pcap` (or `.pcap.partial`) older than an hour,
  and a database error deletes nothing. The sweep runs on every
  deployment shape, since a plain multi-replica Helm install keeps a
  directory per pod with the same leak. Files leaked before this
  change are cleaned up too.
