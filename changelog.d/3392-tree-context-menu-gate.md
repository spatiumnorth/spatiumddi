### Fixed

- IPAM: the tree's right-click menus (space, block, subnet) disable their New, Edit and Delete items for a user without the matching permission, an orphan address's right-click Restore and Delete Forever (and its inline purge button, for a user who may write but not delete) are disabled the same way, and tree rows can no longer be dragged to another block by a user who may not write them; the rows themselves stay selectable. A disabled right-click item now shows its reason on hover. (#3392)
