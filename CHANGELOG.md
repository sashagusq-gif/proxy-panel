# Changelog

## 1.0.1 - 2026-04-23

- Preserve MTProto secrets on restore, so existing `tg://proxy` links remain valid after backup recovery.
- Fix 3proxy credentials rendering for passwords with special characters (including `$`), preventing proxy startup failures.
- Improve installer safety:
  - installer runs in HTTP mode for panel UI and does not manage TLS termination;
  - explicit host port availability checks before starting Docker stack with clear error messages.
