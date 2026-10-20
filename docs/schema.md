# JSON schema v2

All fields shown below are present. Lists are arrays, including when empty. JSON object keys and report lists have deterministic order; only `scannedAt` varies for identical inputs and host context.

```json
{
  "schemaVersion": 2,
  "tool": {"name": "underhood", "version": "0.1.0-dev"},
  "scannedAt": "2026-01-01T00:00:00Z",
  "target": {"kind": "macos-app", "path": "./Fixture.app", "name": "Fixture", "id": "org.test.fixture", "version": "1.0", "build": "1"},
  "summary": [{"text": "No notable declarations found in the scanned files.", "findingIDs": []}],
  "findings": [{"id": "bundle.architectures", "category": "identity", "title": "Architectures", "detail": "arm64", "severity": "info", "confidence": "found-in-binary", "evidence": [{"file": "Contents/MacOS/Fixture", "locator": "Mach-O arm64 slice at byte 0/CPU", "value": "arm64"}]}],
  "skipped": [],
  "limits": ["Signatures are parsed, not cryptographically verified."]
}
```

This illustrative example abbreviates the mandatory limits list; see the generated [Calculator JSON](../examples/calculator.json) for a complete report.

| Object | Fields and types |
| --- | --- |
| Report | `schemaVersion`: integer 2; `tool`: Tool; `scannedAt`: UTC RFC3339 string; `target`: Target; `summary`: SummaryItem[]; `findings`: Finding[]; `skipped`: SkipNote[]; `limits`: string[] |
| Tool | `name`, `version`: strings |
| Target | `kind`, `path`, `name`, `id`, `version`, `build`: strings |
| SummaryItem | `text`: string; `findingIDs`: string[] |
| Finding | `id`, `category`, `title`, `detail`: strings; `severity`: enum; `confidence`: enum; `evidence`: nonempty Evidence[] |
| Evidence | `file`, `locator`, `value`: strings; value at most 200 Unicode characters |
| SkipNote | `analyzer`, `file`, `reason`: strings; `count`: positive integer |

Severity: `info`, `notable`, `sensitive`. Confidence: `declared`, `found-in-binary`, `heuristic`. Categories: `identity`, `signing`, `entitlements`, `permissions`, `registrations`, `launchItems`, `automation`, `network`, `windows-manifest`, `capabilities`, `imports`, `hardening`, `sections`.

Finding IDs merge distinct evidence. If slices disagree, the merged finding retains the highest sensitivity and all slice evidence. Missing evidence drops the claim and creates a report skip note. Repeated skip reasons collapse with a count. Summary items group related declarations and cite every contributing ID, with at most eight items ranked by sensitivity and stable key after selecting category variety. Identity and ordinary informational signing findings are excluded. When no eligible declarations exist, the single fallback item has an empty `findingIDs` array. Markdown summaries contain readable text only; JSON retains all contributing IDs.

Evidence paths are bundle-relative; external host launch paths can use `../` or `~`. The target root in values becomes `.`, and the current home prefix becomes `~`. The target path itself remains useful as a path, with its home prefix redacted. Paths and declarations may still contain application-supplied identifying information; review reports before sharing.

Available target kinds: `macos-app`, `windows-pe`, `windows-folder`, `windows-msix`. Windows target names use VERSIONINFO ProductName, falling back to filename; ID uses OriginalFilename; version uses ProductVersion (FileVersion fallback); build is empty. Windows paths retain the cleaned command-line spelling with home redaction. Folder binary IDs use `@<relative-path>`. Signing expiry metadata is evaluated at scan time, so that finding may change when a certificate expires.


MSIX targets (including bundles) use manifest Identity Name as `id`, Identity Version as `version`, and Properties DisplayName as `name` (Identity Name, then filename fallback). `build` remains empty. Unpacked manifest folders retain kind `windows-folder` and use the same identity rules. Manifest findings use `windows.msix.*`; nested package findings append `@<package-path>`, and embedded PE findings append `@<package-path>/<entry-path>`. Existing `net.host.<host>` endpoint IDs remain report-wide, with source paths in evidence, so host/evidence caps and grouping remain compatible with B1. Categories and schema version 2 are unchanged. Capabilities may now be declared manifest facts as well as binary-string evidence. Summary text groups restricted capabilities and repeated embedded PE declarations, while `findingIDs` retains their IDs.

## Diff JSON schema v1

`underhood diff OLD NEW --format json` emits a separate document with `type: "diff"` and `schemaVersion: 1`. Ordinary inspection reports remain schema v2, with unchanged finding IDs and field meanings. Every field below is present; lists are arrays even when empty. JSON keys are sorted. Only the top-level `scannedAt` varies for identical inputs, host context, options and time-dependent certificate metadata.

| Object | Fields and types |
| --- | --- |
| DiffReport | `schemaVersion`: integer 1; `type`: string `diff`; `tool`: Tool; `scannedAt`: UTC RFC3339 string; `old`, `new`: Snapshot; `warnings`: string[]; `summary`: SummaryItem[]; `changes`: Change[] |
| Snapshot | `target`: Target; `skipped`: SkipNote[]; `limits`: string[]; types and semantics as in ordinary reports above |
| Change | `id`, `category`: strings; `status`: `added`, `removed` or `changed`; `severity`: severity enum; `old`, `new`: Finding or null |

`added` has `old: null` and a non-null `new`; `removed` has a non-null `old` and `new: null`; `changed` retains both complete normalized findings. Each non-null finding contains every retained evidence item, including its original file, locator and bounded value. Change severity is the highest sensitivity of either side, so a removed or downgraded sensitive declaration remains visible. Category comes from NEW when present, otherwise OLD. Changes sort by the normal category order, then sensitivity descending, then ID; unrecognized categories sort lexically before known categories.

Summary counts refer to changed finding IDs, not unique user-facing capabilities: related analyzer findings can describe the same declaration. The summary's sorted `findingIDs` cites every change; an unchanged comparison has an empty list. Sensitive additions count findings in `entitlements`, `permissions` and `capabilities`; new hosts count added `net.host.*` IDs, not URLs or observed connections.

Matching uses exact finding IDs. Equality compares category, title, detail, severity, confidence and the set of `(file, normalized locator, value)` evidence tuples. Endpoint-host and Windows persistence-string locators are ignored because they record physical string positions/encoding. Mach-O slice byte positions are removed while architecture and declaration-key associations are preserved. Other locators remain semantic. Evidence ordering and duplicate normalized tuples do not affect equality; complete original locators remain in output for reported changes. For a standalone Windows PE, the evidence file is treated as the root for equality, so renaming the input file alone produces no change. Target paths, target display names, report summaries and scan timestamps do not become synthetic findings. Bundle/package identity and version changes are reported through existing evidence-backed identity findings. Renames of stable IDs appear as removal plus addition; array-index IDs retain their existing positional semantics.

Warnings report differing target kinds or IDs and the presence of skipped analyses on either side. Null means a finding was not retained on that side, not proven absent. Each snapshot preserves all skips and limits even when there are no changes. URL evidence is bounded by the ordinary scan caps and 200-character evidence limit: changes beyond retained/truncated data cannot be recovered. See [comparison limitations](diff.md).
