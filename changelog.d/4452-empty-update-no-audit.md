### Fixed

- Saving a Role, Group or User edit with nothing changed no longer writes an empty "updated" audit row: the Role and Group dialogs send nothing on an untouched Save, and the update handlers skip the audit row when no field changed ([#4452](https://github.com/spatiumnorth/spatiumddi/issues/4452)).
