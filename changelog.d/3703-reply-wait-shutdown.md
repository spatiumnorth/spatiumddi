### Fixed

- The kubeapi proxy and the appliance command channels (nettool, storage) stop waiting for a supervisor's reply as soon as the api begins shutting down, and answer with their usual timeout, instead of holding the pod for up to 15 or 30 seconds. The shared queues from #3703 and #3706 had turned that wait into a loop the shutdown guard did not cover.
