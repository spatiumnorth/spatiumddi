### Fixed

- **AI Providers: Edit can now remove a stored API key, and says "stored" only when a key is** — the field opened empty yet said "clear to remove", and saving it cleared sent nothing, so the key stayed. A "Remove the stored key" checkbox now sends the removal; a blank field keeps the key. (#2622)
