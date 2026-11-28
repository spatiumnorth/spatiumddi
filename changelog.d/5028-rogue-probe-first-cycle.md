### Fixed

- The DHCP agent's rogue-DHCP probe now waits until its packet capture is running before it sends the DISCOVER. Before, the first probe after every agent start could miss a second DHCP server that answers at once, and reported it one probe interval (300 s by default) late. (#5028)
