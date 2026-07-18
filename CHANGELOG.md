# Changelog

## 1.0.4 - 2026-07-17

- Make resume-task cleanup idempotent without logging a false PowerShell failure when the system task has already removed itself.
- Surface genuine scheduled-task cleanup failures instead of silently leaving stale resume tasks behind.

## 1.0.3 - 2026-07-17

- Make the user logon resume wait for the startup resume handoff, preventing fast or automatic logon from racing the system task and leaving restore incomplete.

## 1.0.2 - 2026-07-17

- Apply the captured wallpaper to the active target-user desktop instead of only copying the theme cache file.
- Deliver captured browser password CSVs to the target user's Documents folder and add sensitive-file cleanup guidance.
- Warn in the restore log and final technician guidance when the gathered user profile contains no files.

## 1.0.1 - 2026-07-16

- Stage UNC-hosted migration repositories under `%ProgramData%` before registering reboot-resume tasks, so startup and user phases do not depend on network-share authentication.
- Avoid applying Windows ACLs to Samba paths and remove partially registered tasks when setup fails.
- Mirror phase state back to the source share on a best-effort basis while keeping the local staged copy authoritative.

## 1.0.0 - 2026-07-15

- Rewrote the tool as a native .NET 10 WinForms application distributed as a self-contained, single-file Windows executable.
- Added atomic manifest/state persistence, structured logging, machine-readable command results, and cached reboot-resume execution.
- Corrected Robocopy success handling and excluded non-portable live Windows profile databases and caches.
- Replaced command-line password handling with native Windows account and domain APIs.
- Added explicit adapter safety, source-DPAPI warnings, mapped-drive restore, safe shared-printer restore, and final technician guidance.
- Added xUnit coverage, Windows CI publishing, release packaging, and two-VM source-to-destination validation.
