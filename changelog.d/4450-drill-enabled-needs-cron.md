### Fixed

- A restore-drill schedule can no longer be saved enabled with no cron: blanking the cron of an enabled drill is refused with a 422 (the check now judges the stored state after the edit), and the Drill schedule dialog blocks Save with the reason ([#4450](https://github.com/spatiumnorth/spatiumddi/issues/4450)).
