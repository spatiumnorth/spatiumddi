### Fixed

- **An archive past the size cap is refused before it is read.**
  Downloading an archive by name from a backup destination, and
  restoring from one, read the whole archive into memory and only then
  checked it against the 2 GiB cap, so an oversized object could
  exhaust the api's memory first. Both routes now check the size the
  destination's listing declares before the download starts, and every
  destination driver's `download` takes a `max_bytes` limit:
  `local_volume` refuses from a stat without opening the file; S3,
  Azure, SCP and WebDAV refuse from the size the destination reports
  when it reports one; and every driver (including FTP, SMB, GCS and
  NFS) stops reading as the running total passes the cap. The routes
  answer 413, and a restore drill reports the archive as an error that
  names the cap. The latest-archive download, the by-name download,
  restore-from-destination and the drill all pass the cap.
- **Pre-restore safety dumps no longer accumulate.** Each one carries
  the install's `SECRET_KEY` under the documented constant passphrase.
  The api now keeps the newest three in `/var/lib/spatiumddi/backups`
  and deletes older ones each time it writes a new one. Before, they
  were pruned only when a `local_volume` target pointed at that
  directory. Only `pre-restore-*.zip` files are touched.
- **An `https_put` receiver's error body is passed through the URL
  scrubber** before it is stored as the run error, as the transport
  error already was, so a receiver that echoes the request URL cannot
  put a query-string credential into `last_run_error` or the audit log.
