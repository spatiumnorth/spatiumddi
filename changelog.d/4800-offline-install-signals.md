### Fixed

- Offline installs now say what is wrong: the Fleet APT chip reads "APT: sources unreachable" when the last `apt-get update` is over three days old or never succeeded; a failed MAC vendor refresh is a failed task, retried once a day instead of hourly, with "last refresh failed at …" on the settings card; a failed TLD Registry refresh closes the confirm dialog and shows its error; and the release check waits for the settings row on a fresh install instead of sitting out the 24 h tick.
