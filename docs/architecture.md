# Architecture

The CLI detects a registered target, inventories safe entries, parses metadata and binaries, runs isolated analysers, then normalizes an evidence-backed report. No subprocess, target execution, network request or external module is involved.

| Package | Responsibility |
| --- | --- |
| `cmd/underhood` | Process entry and exit status |
| `internal/cli` | Interspersed flags, output protection |
| `internal/target` | Registry, context and result boundary |
| `internal/model` | Portable schema and caps |
| `internal/inventory` | Lstat checks, bounded walk, safe file reads |
| `internal/plist` | XML and binary property lists |
| `internal/macho` | Thin/fat headers, load commands, signature blobs, CMS certificates |
| `internal/scan` | Streaming ASCII and UTF-16LE URL extraction |
| `internal/analyzers/macos` | Eight independent macOS analysers |
| `internal/report` | Merging, stable ordering, summary, Markdown and JSON |
| `internal/testutil` | Generated portable fixtures |

The shared packages do not import macOS-specific code. `cli` explicitly imports the available target package to register it. New targets can reuse inventory, scanning, model and rendering.

Caps: 20,000 inventory entries, four nested bundle levels, 64 ordinary directory levels, 16 MiB per metadata read, 300 MiB per binary string scan by default. Plists have 64 nesting levels and 200,000 decoded nodes, plus a 64 MiB cumulative decoded-byte budget to bound shared-reference expansion. Fat binaries have at most 128 slices; CMS at most 128 certificates. Intent metadata has 20,000 visited entries. Endpoint extraction retains 10,000 distinct URLs per binary, 200 hosts per report and 20 evidence entries per host. Runs longer than 16 KiB are dropped. Every reached cap is disclosed.

The scanner maintains bounded runs across chunks and both UTF-16 byte alignments; incomplete runs at the scan boundary are discarded. URLs are strings, never fetched. The denylist excludes common placeholders and XML namespaces.

Mach-O parsing prevalidates load commands and passes only supported dylib commands to `debug/macho`; symbol, relocation and section tables are never read merely to obtain linked-library names. Weak, re-exported, lazy and upward dylib commands are parsed directly. SuperBlob and CodeDirectory integers are big-endian. CMS BER lengths are normalized before ASN.1 certificate-set parsing; `crypto/x509` extracts certificate names. Issuer/subject links determine leaf-to-root order without a trust evaluation. Each fat slice contributes separate evidence. DER-only entitlements are reported as unavailable, not interpreted as an empty entitlement set.

The four flag masks follow [XNU cs_blobs.h](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h): ad-hoc `0x2`, library validation `0x2000`, hardened runtime `0x10000`, linker-signed `0x20000`.

The host launch-job scan runs only on macOS. Its results depend on the host's installed launch plists; other hosts report it unavailable. Determinism assumes unchanged inputs, host launch entries and options, and excludes `scannedAt`.

Default Markdown uses reversible P/L path and locator references to reduce repeated long names, one evidence entry per finding, and a compact endpoint table. `--full` and JSON retain every evidence entry. Very large App Intents surfaces can still produce large reports because findings are never silently dropped for presentation.

Output uses exclusive creation: existing files, symlinks and hard links are refused. This deliberately stricter policy avoids truncating linked target files. The runtime writes only explicitly requested output paths. A failure writing the second `both` output can leave the first output intact; errors identify the failure.
