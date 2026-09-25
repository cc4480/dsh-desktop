# DSH Desktop — unofficial Windows build

An unofficial, unsigned Windows x64 installer build of **DeepSeek Harness**, an all-plugin
Cordis agent harness with an Electron desktop shell and a bundled runtime (Node.js, pnpm,
Python with Office libraries, and LibreOffice-based document conversion).

> **Not affiliated with, endorsed by, or supported by DeepSeek.** The name "DeepSeek", the
> DeepSeek logo, and the DeepSeek Harness application belong to DeepSeek. This repository
> redistributes a binary built from the MIT-licensed source published at
> [deepseek-ai/deepseek-harness](https://github.com/deepseek-ai/deepseek-harness). Bug reports
> about this build belong here, not with DeepSeek.

## Download

Take the installer from the [Releases](../../releases) page:

| File | Size | SHA-256 |
|---|---|---|
| `deepseek-harness-0.1.7-rc.1-win-x64-unsigned.exe` | 299.1 MB | `8a5bb7920d9434e9bf5a28460aa397399b746a0f863f4dc5c91bb9f9a696fc72` |

Verify the download before running it:

```powershell
Get-FileHash .\deepseek-harness-0.1.7-rc.1-win-x64-unsigned.exe -Algorithm SHA256
```

## Install

1. Run the installer. It installs per-user, with no administrator rights, into
   `%LOCALAPPDATA%\Programs\DeepSeek Harness`, and creates Start menu and Desktop shortcuts.
2. Windows SmartScreen warns that the publisher is unknown, because the build is unsigned.
   Choose **More info** → **Run anyway**.
3. Open the app from the **DeepSeek Harness** shortcut (Desktop or Start menu).

**Do not run the installer again to open the app.** The `.exe` on the Releases page is a
setup program, not a launcher: running it again performs a full reinstall of the same
version. Use the **DeepSeek Harness** shortcut, or launch
`%LOCALAPPDATA%\Programs\DeepSeek Harness\DeepSeek Harness.exe` directly. A second launch
while the app is already running hands off to the running copy.

## First run

The app asks for a DeepSeek API key (or a DeepSeek account sign-in) before it opens the
workspace. Without one, no model request can run.

Sessions, settings, plugins, and credentials live under `%USERPROFILE%\.dsh`, outside the
installation directory, so reinstalling or upgrading keeps them.

## What is in the build

- The Electron desktop shell and the complete dsh Web application, bundled in
  `resources/app.asar`.
- Bundled runtimes, so no system Node.js, pnpm, or Python is required: Node.js, pnpm, and a
  Python distribution carrying numpy, pandas, python-docx, python-pptx, openpyxl, Pillow,
  lxml, and XlsxWriter.
- Bundled LibreOffice engine and the `office-docx`, `office-pptx`, and `office-xlsx` skills,
  registered by default.

## Build provenance

| Field | Value |
|---|---|
| Desktop version | `0.1.7-rc.1` |
| Upstream commit | `46a7f68b0922371ce7144b668b90e377d8e799f4` |
| Target | `win-x64`, unsigned |
| Installer built | 2026-09-24 22:57 local |
| Checkout state | the packaging record flags the source checkout as **dirty**, so the binary may contain changes that are not in the commit above |

Auto-update is **not** configured for this build: there is no `app-update.yml`, and the
update-policy origin baked into the application manifest is
`https://updates.dsh-local.invalid` — a reserved `.invalid` domain that never resolves. The
application therefore contacts no DeepSeek update service; it talks only to the model API
endpoint your own credentials select.

## Known issues

- **Office → PDF conversion fails.** The packaged-runtime smoke test fails with
  `OfficeToPdfError: LibreOffice conversion failed: Unknown LibreOfficeKit exception`.
  Creating and editing DOCX, XLSX, and PPTX still works; only the PDF conversion path is
  affected.
- **Unsigned.** SmartScreen warns on first run, and enterprise code-integrity policies can
  block the executable outright.
- **No auto-update.** Newer builds must be installed manually.
- The installer artifact is named `-unsigned` on purpose so it cannot be mistaken for a
  signed DeepSeek release.

## Build it yourself

Requires Windows x64, Node.js `^22.19 || >=24`, and the pnpm version pinned by the
repository (`11.7.0`).

```sh
git clone https://github.com/deepseek-ai/deepseek-harness.git
cd deepseek-harness
git checkout 46a7f68b0922371ce7144b668b90e377d8e799f4
pnpm install
```

Create `apps/desktop/.env.windows` (git-ignored) with the release settings the packaging
entry point validates before it builds:

```ini
DSH_DESKTOP_APP_ID=com.deepseek.harness
DSH_DESKTOP_AUTO_UPDATE_ENV=production
DSH_DESKTOP_MANDATORY_UPDATE_PROD_ORIGIN=https://updates.dsh-local.invalid
```

The policy origin must be a bare HTTPS origin. The value above is a reserved non-resolving
domain, which keeps the build from calling any update service. Then:

```sh
pnpm --dir apps/desktop run package:win:x64:unsigned
```

Artifacts land in `apps/desktop/.desktop-build/targets/win-x64/unsigned-artifacts/`. Note
that the packaging run reports failure when the packaged-runtime smoke test fails, but the
installer is still produced.

## Uninstall

Use **Uninstall DeepSeek Harness** in the Start menu, or Apps & Features. Application data
under `%USERPROFILE%\.dsh` is left in place.

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 DeepSeek.
