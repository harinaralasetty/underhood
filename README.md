# Underhood

Look under the hood of any app. Offline, deterministic, evidence for every claim.

**See what an app declares and touches in seconds, without running it.**

[![MIT licence](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Go version](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](go.mod) [![CI](https://github.com/harinaralasetty/underhood/actions/workflows/ci.yml/badge.svg)](https://github.com/harinaralasetty/underhood/actions/workflows/ci.yml)

[Quick start](#quick-start) · [How it works](#how-it-works) · [What you can analyse](#what-you-can-analyse) · [Sample report](#sample-report) · [FAQ](#faq) · [Documentation](#documentation)

## Install

With Go 1.22+ once the repository is published:

```sh
go install github.com/harinaralasetty/underhood/cmd/underhood@latest
```

Build from source:

```sh
git clone https://github.com/harinaralasetty/underhood.git
cd underhood
CGO_ENABLED=0 go build -o underhood ./cmd/underhood
./underhood --help
```

No external modules or Apple command-line tools are required. The inspector builds for macOS, Linux and Windows; a macOS app bundle must be available locally to inspect it. Preserve the bundle layout when copying between hosts.

## Quick start

```sh
underhood /System/Applications/Calculator.app
underhood ./launcher.exe --format both --output launcher-report
underhood ./portable-app --format json
underhood /System/Applications/Notes.app --format json --output notes.json
underhood /System/Applications/Calculator.app --format both --output calculator --full
```

Markdown goes to stdout by default. `--format both` writes `<base>.md` and `<base>.json`. Output parents must exist. Existing regular files outside target and system directories are replaced atomically using a temporary file in the same directory; all saved reports use mode `0600`, including replacements. Directories, symlinks and other non-regular outputs are refused. Replacing a hard link leaves its original file untouched. Both destinations are checked before `--format both` writes; if the second write fails, the first is removed only when newly created by this run. A replaced first report remains in place.

Use `--no-binary-strings` to omit endpoint scanning, or `--max-binary-mb 100` to change the per-binary bound (default 300 MiB). Flags may follow the target. Exit codes: **0** report produced, including documented skips; **1** usage/output error; **2** invalid or unsupported target.

Windows files can be inspected from macOS or Linux, and the tool also builds for Windows. No Windows runtime is needed. See [Windows inspection](docs/windows.md).

## How it works

**Detect target → inventory → parse → analysers → evidence-backed report.**

Underhood parses bundle plists, Mach-O slices and embedded code-signature metadata in-process. It reports permissions, entitlements, registrations, launch declarations, automation metadata and endpoint strings, with source-file and locator evidence. No subprocesses, target execution or network access occur.

The user-supplied target path is resolved through symlinks before detection; macOS reports show the resolved root and Windows reports retain the cleaned command-line path. Traversal inside the target avoids symlinks and bounds nesting, file counts, metadata and binary scanning. One analyser's failure becomes a skip note while the others continue. Reports sort and merge evidence deterministically; `scannedAt` varies. Host launch entries affect macOS-host results and are unavailable on other hosts.

Default Markdown shows readable titles and inline path/locator evidence, a nested-bundle table, and at most eight grouped summary items. Repeated informational families are capped at ten entries, informational endpoint rows at fifty, and skip notes at twenty. Sensitive and notable findings remain visible, so large automation surfaces can exceed compact size targets. `--full` lists every evidence entry and description; JSON always retains all findings and retained evidence.

## What you can analyse

| Target | What you get | Status |
| --- | --- | --- |
| macOS `.app` | Identity, signing metadata, entitlements, privacy declarations, URL/document registrations, launch items, automation, endpoint strings | Available |
| Windows PE `.exe` / `.dll` | Identity, embedded manifests/version info, hardening, Authenticode metadata, imports and strings | Available |
| Windows portable/installed app folders | PE inventory and up to 20 embedded binaries | Available |
| Windows `.msix` / `.appx`, bundles and unpacked MSIX | Package manifests, capabilities and signatures | Planned next |
| Linux, iOS `.ipa`, Android `.apk` | Target-specific static inspection | Roadmap |

## Sample report

```markdown
# Underhood: Calculator

## Summary

- Requests 2 sandbox temporary exceptions: files.absolute-path.read-only, mach-lookup.global-name
- Requests access to user-selected files
- Allows outgoing network connections
- App Sandbox enabled

## identity

**App Sandbox presence** · I/D · `bundle.sandbox`
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.app-sandbox = true
```

Excerpt above omits other summary and finding lines. Full generated reports: [Calculator Markdown](examples/calculator.md) · [Calculator JSON](examples/calculator.json). These describe the inspected system-app version, not every version of Calculator. A declared capability or string is not observed runtime behavior.

Windows launcher excerpt ([Markdown](examples/windows-launcher.md) · [JSON](examples/windows-launcher.json)):

```markdown
# Underhood: Simple Launcher
- Control Flow Guard not declared
- Debugger detection APIs
- Not signed
- Dynamic loading APIs
- Runs with the invoking user's privileges
- Does not request elevated UI access
```

This x64 console launcher declares `asInvoker` and imports KERNEL32/SHLWAPI. Imports are heuristics common in legitimate tools and in malware; presence does not establish use.

## FAQ

**Does it run the app?** No. It reads files and never executes the target or bundled binaries.

**Does it send anything anywhere?** No. Runtime analysis is entirely offline, with no telemetry, network access or API calls.

**Is a signature verified?** No. Underhood parses flags, identifiers, entitlements and certificate names. It does not verify cryptographic integrity, trust, Gatekeeper or notarization.

**How is this different from a decompiler?** It identifies declarations and byte strings with evidence. It does not reconstruct implementation logic or decompile code.

**Why Go?** The standard library provides portable binary/XML/JSON parsing and a small CLI implementation with no external dependencies or host inspection tools.

## Where this fits: complements REA

[REA](https://github.com/morluto/rea) connects AI agents to reverse-engineering tools and returns evidence and limitations. Underhood provides a fast offline first look; its evidence-backed JSON can tell you or an agent where to dig during deeper reverse engineering.

## Documentation

- [Windows inspection](docs/windows.md) · [B1 verification](docs/windows-verification.md)
- [Architecture and limits](docs/architecture.md)
- [JSON schema v2](docs/schema.md)
- [Finding catalogue](docs/findings.md)
- [Adding a target](docs/adding-a-target.md)
- [Verification results and known deviations](docs/verification.md)
- [Suggested repository topics](docs/github-topics.md)

## Disclaimer

Static findings are not a verdict of safety. Apps may behave differently from their declarations. See [DISCLAIMER.md](DISCLAIMER.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build, test, fuzz and extension instructions, and [SECURITY.md](SECURITY.md) for private vulnerability reporting. Production code must remain dependency-free and subprocess-free.

## License

[MIT](LICENSE).
