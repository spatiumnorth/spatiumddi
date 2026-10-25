### Fixed

- **An InfluxDB target with an empty Measurement prefix no longer looks like it uses the default (#2751).**
  An empty prefix is stored and pushed as no prefix, but the Edit dialog's
  grey placeholder read "spatiumddi_". The placeholder now says unprefixed
  names, and an empty field carries a note saying so.
