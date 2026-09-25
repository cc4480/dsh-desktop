# v0.1.7-rc.1 — unofficial Windows x64 build

First public build of the DeepSeek Harness desktop application for Windows, packaged as a
single unsigned installer.

> Unofficial build. Not affiliated with, endorsed by, or supported by DeepSeek. The
> application is DeepSeek's MIT-licensed DeepSeek Harness; this page distributes a binary
> built from upstream commit `46a7f68b0922371ce7144b668b90e377d8e799f4`.

## Download

`deepseek-harness-0.1.7-rc.1-win-x64-unsigned.exe` — 299.1 MB

```
SHA-256  8a5bb7920d9434e9bf5a28460aa397399b746a0f863f4dc5c91bb9f9a696fc72
```

## Install

1. Run the installer. It installs per-user into
   `%LOCALAPPDATA%\Programs\DeepSeek Harness` — no administrator rights required.
2. SmartScreen warns about an unknown publisher because the build is unsigned: **More info**
   → **Run anyway**.
3. Open the app from the **DeepSeek Harness** shortcut.

The `.exe` attached to this release is a setup program. Running it again reinstalls the same
version instead of opening the app — use the shortcut to launch it. Sessions, settings,
credentials, and installed plugins live in `%USERPROFILE%\.dsh` and survive reinstalling.

## Requirements

- Windows x64.
- Your own DeepSeek API key or DeepSeek account. The app asks for it on first run.
- About 1.5 GB of disk space once installed.

## Notes and limitations

- No auto-update is configured, and the baked update-policy origin is the reserved
  non-resolving domain `updates.dsh-local.invalid`, so the app contacts no DeepSeek update
  service.
- Office → PDF conversion fails in this build
  (`LibreOffice conversion failed: Unknown LibreOfficeKit exception`). DOCX, XLSX, and PPTX
  authoring and editing are unaffected.
- Unsigned, so SmartScreen and enterprise code-integrity policies may block it.
- The packaging record flags the checkout as dirty at build time, so the binary may include
  changes beyond the recorded commit.

## What works

- The full desktop application: sessions, workspaces, subagents, background jobs, skills,
  MCP servers, the plugin manager, and the Web UI served locally.
- Bundled Node.js, pnpm, and Python runtimes, so no system toolchain is needed.
- Office skills with bundled Python libraries.
