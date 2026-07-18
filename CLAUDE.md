# Project Guidance

Follow [AGENTS.md](AGENTS.md) for repository-wide contributor rules. The supported product is the .NET 10 WinForms solution under `src/`; `PCSwapTool.ps1` is retained only as the legacy implementation.

The core invariants are:

- Keep repository data under `<DEST>\<HOST>_<DATE>\PC_SWAP_INFO`.
- Preserve schema `1.0` read compatibility and unknown JSON properties.
- Write manifest and resume state atomically.
- Keep credentials out of process command lines and logs.
- Treat only Robocopy exit codes below 8 as success and retain its transcript.
- Cache the executable and state before reboot; bind user resume to the selected account.
- Never apply source IP settings or printer drivers without verifiable destination identity.

Build, test, headless examples, and the two-machine validation procedure are documented in [DEVELOPMENT.md](DEVELOPMENT.md) and [TESTING.md](TESTING.md).
