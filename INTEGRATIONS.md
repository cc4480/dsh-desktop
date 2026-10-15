# Adding tools to a DSH Desktop install

This repository ships a **binary installer only** — `README.md`, `RELEASE-NOTES.md`,
`LICENSE`, `SHA256SUMS.txt`. It contains no application source and no build pipeline. The
build is performed against upstream `deepseek-ai/deepseek-harness`; see "Build it yourself"
in [README.md](README.md).

That distinction matters for anyone asking *"how do I add tools to this build?"*, because the
answer differs depending on whether they mean an **existing install** or a **future build**.

---

## The two extension mechanisms

DSH Desktop carries two separate things, and they are not interchangeable.

| | **Skills** | **Plugins** |
|---|---|---|
| Lives in | `resources\runtime\office-skills\<name>\SKILL.md` | `%USERPROFILE%\.dsh\profiles\<profile>\` |
| Shipped how | Baked into the build | Installed into a profile's `node_modules` |
| Registered by | Presence in the runtime directory ("registered by default") | An entry in `cordis.patch.yml` |
| Examples | `office-docx`, `office-pptx`, `office-xlsx` | `@deepseek-ai/dsh-base`, `@deepseek-ai/dsh-web-app` |
| Survives reinstall | Yes (part of the install) | Yes (`.dsh` is outside the install directory) |

A **skill** is instructions and assets the model loads on demand. A **plugin** is a Cordis
module that runs code in the host — hooks, tool providers, UI panels. Adding a skill does not
give you a hook; adding a plugin does not give you a `SKILL.md`.

---

## Adding a plugin to an existing install

1. Build the plugin into a **self-contained** package. Any install step that fetches from the
   npm registry will fail if the package (or its workspace siblings) are `private: true`.
   A tarball with `bundledDependencies` avoids that entirely.
2. Install it into the active profile's `node_modules`:

   ```powershell
   $profile = "$env:USERPROFILE\.dsh\profiles\desktop"
   cd $profile
   npm install <path-to>\<your-plugin>.tgz
   ```

3. Append the plugin's loader entry to the profile's `cordis.patch.yml`. That file is a
   top-level YAML **array** of patch entries, applied after every bundle layer, so `insert`
   blocks append cleanly. Do not edit `cordis.yml` — it is the profile root and is documented
   as "an empty entry list".

4. Put any secrets in the **environment**, never in the patch file. The patch format supports
   `!!js` expressions, so a token can be referenced as
   `!!js "'Bearer ' + (process.env.YOUR_TOKEN || '')"`.

5. **Close and reopen DSH Desktop.** The profile is composed at startup. There is no runtime
   reload for profile changes, and no refresh that will pick them up.

## Adding a plugin to a future build

Because this repository has no build pipeline, "bake it into the installer" means changing the
build stage in the upstream checkout:

```sh
git clone https://github.com/deepseek-ai/deepseek-harness.git
cd deepseek-harness
git checkout 46a7f68b0922371ce7144b668b90e377d8e799f4
pnpm install
pnpm --dir apps/desktop run package:win:x64:unsigned
```

To ship a plugin by default, seed the profile that a new install creates — the analogue of how
the office skills are registered by default. **Do not** drop a Cordis plugin into
`office-skills/`; that directory is the skills mechanism and will not load a plugin module.

Note the packaging run records the checkout state, and the current build's record flags the
source checkout as **dirty**. If you start patching the build, keep that record accurate — it is
the only thing telling a user whether the binary matches the commit it claims.

---

## Worked example: `@secscan/redteam-harness-plugin`

A real integration, and a useful case study because it hit the registry problem.

- **Plugin:** `secscan-redteam` — an authorization gate as a `tools/pre-execute` hook, plus an
  engagement-protocol system-prompt section.
- **Companion:** `mcp-secscan` — the harness-native `@deepseek-ai/dsh-mcp-client` pointed at
  `https://secscan.us/api/mcp`, exposing tools as `mcp__secscan__*`.
- **Problem:** `npm pack` produced a tarball that could not be installed. The compiled plugin
  imported two sibling workspace packages, both `private: true`, so install failed with
  `404 Not Found - GET .../@secscan%2Fredteam-auth-gate`.
- **Fix:** bundle the siblings. They had zero runtime dependencies of their own, so inlining
  `dist/` + `package.json` each was sufficient — no transitive tree.
- **Result:** a ~30 KB tarball that installs with no registry access.

Full details, including the install steps and the honest status of the plugin, live in the
plugin's own `README.md` in the `secscan-redteam` repository.

---

## Points worth remembering

- **`.dsh` is outside the install directory.** Plugins, sessions, settings and credentials
  survive reinstalling and upgrading. Reinstalling is not a clean slate; uninstalling does not
  remove `.dsh` either.
- **The installer is a setup program, not a launcher.** Running it again reinstalls the same
  version rather than opening the app. Use the shortcut.
- **The build is unsigned**, so SmartScreen warns on first run and enterprise code-integrity
  policy may block it outright — regardless of what plugins are baked in.
