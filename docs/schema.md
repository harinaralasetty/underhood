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

Severity: `info`, `notable`, `sensitive`. Confidence: `declared`, `found-in-binary`, `heuristic`. Categories: `identity`, `signing`, `entitlements`, `permissions`, `registrations`, `launchItems`, `automation`, `network`.

Finding IDs merge distinct evidence. If slices disagree, the merged finding retains the highest sensitivity and all slice evidence. Missing evidence drops the claim and creates a report skip note. Repeated skip reasons collapse with a count. Summary items group related declarations and cite every contributing ID, with at most eight items ranked by sensitivity and stable key after selecting category variety. Identity and ordinary informational signing findings are excluded. When no eligible declarations exist, the single fallback item has an empty `findingIDs` array. Markdown cites at most two IDs per item; JSON retains them all.

Evidence paths are bundle-relative; external host launch paths can use `../` or `~`. The target root in values becomes `.`, and the current home prefix becomes `~`. The target path itself remains useful as a path, with its home prefix redacted. Paths and declarations may still contain application-supplied identifying information; review reports before sharing.
