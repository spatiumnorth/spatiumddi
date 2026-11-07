### Fixed

- On a control plane with more than one api replica, network tools, Wake-on-LAN and storage (RAID / multipath) actions sent to a member appliance no longer time out when its supervisor polls a different replica, and a scheduled Wake-on-LAN fire from the worker through an appliance now reaches it. The command queues and replies were held in one process's memory; they now go through Redis, and each command is handed out at most once. (#3706)
