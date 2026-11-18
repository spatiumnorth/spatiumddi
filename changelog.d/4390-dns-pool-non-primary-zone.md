### Fixed

- A DNS pool no longer writes records into a zone that has stopped being a primary zone: Edit Zone refuses to turn a zone that a pool targets into a secondary, stub or forward zone (naming the pool), and a pool's health-check, enable and member updates render nothing into such a zone and withdraw any rows already there ([#4390](https://github.com/spatiumnorth/spatiumddi/issues/4390)).
