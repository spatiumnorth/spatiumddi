### Security

- Audited the eleven open CodeQL ReDoS findings (the BIND query / response / RPZ log parser, DNS record target extraction, the support-bundle PEM scrubber and a CI lint script). Each pattern measured linear on hostile input up to 180 KB, so none was reachable as a slowdown and no matching behaviour changed. Timing regression tests now pin that property.
