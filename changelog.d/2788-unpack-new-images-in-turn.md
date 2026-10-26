### Fixed

- **A Rolling Upgrade no longer has every node unpack its new images at
  the same moment (#2788).** k3s's import leaves the slot's images
  packed, and containerd unpacks each one when the kubelet starts its
  first container from it. A rolling run moves the shared image tags
  on every node in one step once its last node is done (#1710), so
  every node unpacked 1-2 GB at once, on the `/var` that etcd writes
  its WAL to. On a shared disk that held etcd's fdatasync for seconds,
  a kube-scheduler lease ran out and k3s exited, and a node whose DNS
  and DHCP pods were mid-swap served neither for about two minutes.
  Each node now unpacks the new release of the images it runs right
  after its reboot, in its own turn: `spatiumddi-image-unpack.service`
  runs `spatium-k3s-images unpack` on every boot once k3s's start-up
  import is over, one image at a time, paced at the 32 MiB/s the
  upgrade's other writes on `/var` keep to (#2090). It keeps k3s's
  image labels, so the kubelet's image GC still leaves the rollback
  slot's images alone, and stops while `/var` has less than 10% free.
  It is best effort: whatever it leaves, the kubelet unpacks as
  before. The new slot carries it, so an upgrade from an earlier
  release gets it too.
