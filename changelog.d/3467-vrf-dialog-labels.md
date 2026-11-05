### Fixed

- **The New VRF and Edit VRF dialogs' labels name their fields
  (#3467).** Each label was drawn beside its field without being tied
  to it, so a screen reader announced Name, Description, the route
  distinguisher and the route targets as unlabelled fields, a search
  by label found nothing, and a click on a label did not focus its
  field. The dialogs now use the labelled field the DHCP and IPAM
  dialogs use.
