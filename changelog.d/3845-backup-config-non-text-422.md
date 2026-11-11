### Fixed

- A backup destination setting that is not text (an FTP mode, an HTTPS PUT auth mode, an S3 object lock mode, an SCP host key check) now answers 422 naming the field on Add and Edit, instead of a 500.
