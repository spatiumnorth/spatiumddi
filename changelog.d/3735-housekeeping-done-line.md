### Fixed

- The supervisor's `housekeeping_done` log line is written for every heartbeat housekeeping job that outlived its wait, and before a shutdown drain returns. It used to be decided by comparing the job's own run time with the wait, so a job that ended just after the heartbeat stopped waiting could go unlogged, and the line could be written after the drain had already returned. ([#3735](https://github.com/spatiumnorth/spatiumddi/issues/3735))
