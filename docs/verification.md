# Verification

This is a local verification record, not a claim that hosted CI ran. Toolchain: `go version go1.27.2 darwin/arm64`; module language version: `go 1.22`.

Environment used unless a command explicitly overrides it:

```sh
export GOCACHE="$PWD/.gocache" GOFLAGS=-buildvcs=false GOPROXY=off CGO_ENABLED=0
```

## Original verification (superseded by A2 below)

- Build, vet, unit/fixture tests, race tests and six cross-builds passed. Both native fuzz targets ran for 20 seconds and passed. No production subprocess import or module requirement was found.
- All five requested apps exited 0 in under 10 seconds. Notes produces 247,209 bytes of default Markdown, exceeding the size target; every finding is retained. The large Electron examples are about 59 KiB and 43 KiB.
- At original verification, existing output files were refused. A2 below supersedes this policy with atomic replacement.
- At original verification, compact Markdown used reversible P/L references. A2 below replaces these with inline evidence. Full descriptions and all evidence remain in `--full` and JSON.
- Go reports validly decoded XML entitlement declarations where the Swift oracle rejects an `invalid entitlements` diagnostic. These are parsed declarations, never claims of signature validity. Every entitlement-derived extra ID was matched to that exact oracle skip reason for its target.
- UTF-16LE adds a host and changes selection at the 200-host cap in two apps. External home launch-plist paths use `~`, intentionally changing their path-derived IDs from the Swift version's unredacted relative paths.
- When slices disagree, merged findings retain the highest severity and all per-slice evidence. Additional defensive bounds cover decoded plist expansion, metadata recursion, fat slices, certificates and intent entries; reached bounds are reported.

## Unverified boundaries

- Hosted GitHub Actions has not run; publishing and repository settings are left to the repository owner.
- Linux and Windows binaries were cross-built, not executed. Go 1.22 itself was not installed or run; compatibility was checked using the module's language version on the available Go toolchain.
- `codesign -dvv` reported `Authority=(unavailable)` for all four CMS-signed app roots. Thus it could not independently confirm certificate names. In-process CMS parsing found leaf-to-root names, and a synthetic certificate-chain test verified ordering.
- Team IDs and all observed flags agreed with `codesign`. The real apps exercised zero flags, hardened runtime and ad-hoc signing; library-validation and linker-signed bits were checked against XNU headers and synthetic fixtures, not a real app with those bits set.
- Notarization/Gatekeeper and cryptographic signature verification are intentionally absent. The oracle produced no stapled-ticket findings because its stapler calls were unavailable in this environment.
- Inspect stable input trees. Concurrent adversarial filesystem mutation is outside the portable Lstat/open identity-check guarantee. UTF-16LE URL scanning recognizes printable ASCII code units; internationalized raw Unicode URL strings are not fully covered.

## Smoke and Swift parity

The throwaway driver `.scratch/parity.py` invoked these commands for each requested app (all outputs were confined to `.scratch`):

```sh
GOCACHE="$PWD/.gocache" GOFLAGS=-buildvcs=false GOPROXY=off CGO_ENABLED=0 go build -o .scratch/underhood ./cmd/underhood
.scratch/underhood "<app>" --format both --output ".scratch/<name>"
../app-xray/.build/release/appxray "<app>" --format json --output ".scratch/<name>.swift.json"
/usr/bin/codesign -dvv "<app>"
```

Inputs were `/System/Applications/Calculator.app`, `/System/Applications/Notes.app`, `/Applications/Claude.app`, `/Applications/Wispr Flow.app`, and `/Applications/Caffeinate UI.app`. These tools inspected metadata; no target app was executed. The Swift sibling was not modified.

Real final driver output:

```text
calculator: exit=0 time=0.467s md=15880 bytes stderr=
  Swift exit=0 time=0.266s 
  differences: {'swiftOnly': 0, 'goOnly': 18, 'severity': 0}
notes: exit=0 time=0.279s md=247209 bytes stderr=
  Swift exit=0 time=0.642s 
  differences: {'swiftOnly': 0, 'goOnly': 221, 'severity': 0}
claude: exit=0 time=3.757s md=60391 bytes stderr=
  Swift exit=0 time=4.219s 
  differences: {'swiftOnly': 1, 'goOnly': 87, 'severity': 0}
wispr-flow: exit=0 time=1.782s md=43539 bytes stderr=
  Swift exit=0 time=2.906s 
  differences: {'swiftOnly': 1, 'goOnly': 28, 'severity': 0}
caffeinate-ui: exit=0 time=0.019s md=3550 bytes stderr=
  Swift exit=0 time=0.064s 
  differences: {'swiftOnly': 1, 'goOnly': 1, 'severity': 0}
```

| App | Swift-only IDs | Go-only IDs | Severity mismatches | Explanation |
| --- | ---: | ---: | ---: | --- |
| Calculator | 0 | 18 | 0 | Readable XML entitlements rejected by oracle |
| Notes | 0 | 221 | 0 | Readable XML entitlements rejected by oracle |
| Claude | 1 | 87 | 0 | 86 entitlement-derived extras; UTF-16 host displaces one capped ASCII host |
| Wispr Flow | 1 | 28 | 0 | 27 entitlement-derived extras; UTF-16 host displaces one capped ASCII host |
| Caffeinate UI | 1 | 1 | 0 | Same host launch job; home-prefix redaction changes path-derived ID |

Claude's Swift-only network ID is `net.host.host`; Wispr Flow's is `net.host.i.pki.goog`. Both Go reports instead include `net.host.bugzilla.mozilla.org`, supported by UTF-16LE evidence. The 200-host selection is deterministic but naturally changes with the additional encoding. All other extra IDs are entitlement findings, `bundle.sandbox`, or network-entitlement findings for targets where the oracle recorded `invalid entitlements`. The Caffeinate launch-plist ID is intentionally omitted here because it contains a personal identifier; the reviewed local parity artifact redacts it.

Per-ID sets with a reason attached to every difference are retained in the ignored `.scratch/parity-reviewed.json`. No unexplained ID or severity differences remain. These comparisons do not assert byte-for-byte report equality: schema, locators, summary, skips, authority values and presentation intentionally differ.

Automated signing and example consistency check:

```text
calculator: team and flags agree; severity mismatches=0; all 18 ID differences classified; codesign authorities unavailable
notes: team and flags agree; severity mismatches=0; all 221 ID differences classified; codesign authorities unavailable
claude: team and flags agree; severity mismatches=0; all 88 ID differences classified; codesign authorities unavailable
wispr-flow: team and flags agree; severity mismatches=0; all 29 ID differences classified; codesign authorities unavailable
caffeinate-ui: team and flags agree; severity mismatches=0; all 2 ID differences classified; codesign authorities unavailable
Calculator example matches final binary output except scannedAt
```

The [XNU flag definitions](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h) confirm `0x2`, `0x2000`, `0x10000`, and `0x20000`.

## Exact check commands and captured output

`grep` exit 1 below means no matches, as intended. Commands with no output completed successfully unless otherwise stated. Cached test results are shown as reported by Go; these packages also ran uncached during earlier verification passes.

```text
$ gofmt -l .
exit=0; elapsed=0.039s
(no output)
```

```text
$ go vet ./...
exit=0; elapsed=0.438s
(no output)
```

```text
$ go build ./...
exit=0; elapsed=0.705s
(no output)
```

```text
$ go test ./...
exit=0; elapsed=0.867s
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/cli	0.500s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
```

```text
$ go test -race ./...
exit=0; elapsed=2.342s
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/cli	1.459s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
```

```text
$ CGO_ENABLED=1 go test -race ./...
exit=0; elapsed=1.795s
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/cli	1.456s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
```

```text
$ GOOS=linux GOARCH=amd64 go build -o .scratch/underhood-linux-amd64 ./cmd/underhood
exit=0; elapsed=0.715s
(no output)
```

```text
$ GOOS=linux GOARCH=arm64 go build -o .scratch/underhood-linux-arm64 ./cmd/underhood
exit=0; elapsed=0.704s
(no output)
```

```text
$ GOOS=windows GOARCH=amd64 go build -o .scratch/underhood-windows-amd64.exe ./cmd/underhood
exit=0; elapsed=0.696s
(no output)
```

```text
$ GOOS=windows GOARCH=arm64 go build -o .scratch/underhood-windows-arm64.exe ./cmd/underhood
exit=0; elapsed=0.656s
(no output)
```

```text
$ GOOS=darwin GOARCH=amd64 go build -o .scratch/underhood-darwin-amd64 ./cmd/underhood
exit=0; elapsed=0.761s
(no output)
```

```text
$ GOOS=darwin GOARCH=arm64 go build -o .scratch/underhood-darwin-arm64 ./cmd/underhood
exit=0; elapsed=0.228s
(no output)
```

```text
$ grep -R os/exec --include=*.go cmd internal
exit=1; elapsed=0.006s
(no output)
```

```text
$ grep -n require go.mod
exit=1; elapsed=0.004s
(no output)
```

```text
$ go test ./internal/plist -run '^$' -fuzz '^FuzzDecode$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/204 completed
fuzz: elapsed: 0s, gathering baseline coverage: 204/204 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 273063 (90993/sec), new interesting: 6 (total: 210)
fuzz: elapsed: 6s, execs: 440781 (55916/sec), new interesting: 12 (total: 216)
fuzz: elapsed: 9s, execs: 654235 (71132/sec), new interesting: 12 (total: 216)
fuzz: elapsed: 12s, execs: 654235 (0/sec), new interesting: 12 (total: 216)
fuzz: elapsed: 15s, execs: 858133 (67966/sec), new interesting: 15 (total: 219)
fuzz: elapsed: 18s, execs: 928838 (23570/sec), new interesting: 18 (total: 222)
fuzz: elapsed: 21s, execs: 979703 (16958/sec), new interesting: 22 (total: 226)
fuzz: elapsed: 21s, execs: 979703 (0/sec), new interesting: 22 (total: 226)
PASS
ok  	github.com/harinaralasetty/underhood/internal/plist	21.406s
```

```text
$ go test ./internal/macho -run '^$' -fuzz '^FuzzSuperBlob$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/55 completed
fuzz: elapsed: 0s, gathering baseline coverage: 55/55 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 199815 (66275/sec), new interesting: 3 (total: 58)
fuzz: elapsed: 6s, execs: 383020 (61353/sec), new interesting: 6 (total: 61)
fuzz: elapsed: 9s, execs: 567656 (61553/sec), new interesting: 9 (total: 64)
fuzz: elapsed: 12s, execs: 844950 (92420/sec), new interesting: 14 (total: 69)
fuzz: elapsed: 15s, execs: 1125166 (93406/sec), new interesting: 19 (total: 74)
fuzz: elapsed: 18s, execs: 1317762 (63859/sec), new interesting: 23 (total: 78)
fuzz: elapsed: 21s, execs: 1413165 (37154/sec), new interesting: 24 (total: 79)
PASS
ok  	github.com/harinaralasetty/underhood/internal/macho	21.013s
```

## Examples and hygiene

```sh
.scratch/underhood /System/Applications/Calculator.app --format both --output examples/calculator
```

Exit 0. Generated Markdown: 15,880 bytes; JSON: 54,518 bytes. JSON was compared to a final-binary scan after removing only `scannedAt` and matched. The README excerpt is copied directly from the generated Markdown. Home-path and email checks passed. Required platform, SDK and public certificate names remain as technical evidence; personal/employer details were not added to shareable files.

The CI matrix is configured for Ubuntu, macOS and Windows, with major-version-pinned checkout/setup-go actions. It still needs to run after push. No git initialization, commits, remote setup or repository-topic changes were performed.

## File tree

Ignored build caches and scratch verification outputs are omitted.

```text
.github/ISSUE_TEMPLATE/bug_report.yml
.github/ISSUE_TEMPLATE/feature_request.yml
.github/pull_request_template.md
.github/workflows/ci.yml
.gitignore
AGENTS.md
CHANGELOG.md
CONTRIBUTING.md
DISCLAIMER.md
LICENSE
README.md
SECURITY.md
cmd/underhood/main.go
docs/adding-a-target.md
docs/architecture.md
docs/findings.md
docs/github-topics.md
docs/schema.md
docs/verification.md
examples/calculator.json
examples/calculator.md
go.mod
internal/analyzers/macos/automation.go
internal/analyzers/macos/bundle_info.go
internal/analyzers/macos/code_signing.go
internal/analyzers/macos/context.go
internal/analyzers/macos/entitlements.go
internal/analyzers/macos/launch_items.go
internal/analyzers/macos/macos_test.go
internal/analyzers/macos/network.go
internal/analyzers/macos/permissions.go
internal/analyzers/macos/url_schemes.go
internal/cli/cli.go
internal/cli/cli_test.go
internal/inventory/inventory.go
internal/inventory/inventory_test.go
internal/macho/ber.go
internal/macho/ber_test.go
internal/macho/cms_test.go
internal/macho/macho.go
internal/macho/macho_test.go
internal/macho/signature.go
internal/model/model.go
internal/plist/plist.go
internal/plist/plist_test.go
internal/report/compact.go
internal/report/report.go
internal/report/report_test.go
internal/scan/strings.go
internal/scan/strings_test.go
internal/target/target.go
internal/testutil/fixtures.go
testdata/README.md
```

## A2 — report quality and CLI fixes

Verified locally on 2026-10-14 with the environment above. No git-writing commands, target execution, or network access were used. The pre-change Calculator JSON was captured with the supplied committed `/tmp/underhood` binary before editing. Scratch artifacts and temporary profiling instrumentation are not part of the changes.

| Gate | Result |
| --- | --- |
| G1 formatting | PASS, exit 0 |
| G2 vet | PASS, exit 0, no output |
| G3 tests and race | PASS, all packages, exit 0 with CGO_ENABLED=0 |
| G4 subprocesses/dependencies | PASS, no production import matches, require count 0; grep returns 1 for no matches |
| G5 cross-builds | PASS, all six OS/architecture combinations, exit 0 |
| G6 Safari symlink | Resolved Cryptex path and complete scan exit 0. Literal head pipeline exits 0 but producer emits broken pipe when head closes early; this is not a clean producer exit. |
| G7 compact output | PARTIAL: Calculator below 25 KB, Notes above 60 KB. Both overwrite runs exit 0; no reference labels; eight summary items with at most two IDs each. |
| G8 JSON stability | PASS, jq deletion of only scannedAt and summary produces identical Calculator JSON |
| G9 negative gates | PASS, both targeted tests fail with the fix removed and pass after restoration using scratch patch files |
| G10 hygiene | PASS, no home-path, owner-email or checked private organization identifiers outside excluded working artifacts |

Final native-binary measurements (seconds include process startup and output writing, and vary with cache state):

| App | Compact bytes | Run 1 | Run 2 / overwrite | Exit |
| --- | ---: | ---: | ---: | ---: |
| Calculator | 21,595 | 0.451 s | 0.033 s | 0 / 0 |
| Notes | 337,882 | 0.205 s | 0.141 s | 0 / 0 |
| Safari | 101,937 | 0.152 s | 0.144 s | 0 / 0 |

Safari resolves to `/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app` with no added informational/skip note. Existing home-prefix redaction remains in place for home-local reports.

**Interpretation of conflicting compact requirements:** the existing analyzers classify App Intent entries and endpoint hosts as notable. The instruction that sensitive/notable findings must never be dropped or capped takes precedence over the family/host display caps and byte targets. Caps therefore apply only to informational findings. Notes has 737 notable automation findings, all preserved; its 60 KB target is not met. No finding severities or IDs were changed. Summary intent counts describe identifiers/fields or titles rather than claiming that every metadata field is a distinct intent. Unknown raw entitlements do not enter the summary; they remain in findings. The fallback summary has an empty ID array.

Output replacements use mode 0600, including when overwriting another mode. Temporary files are exclusively created in the destination directory and removed after errors. `both` preflights both paths; failure of the second write removes a newly created first report, but retains a replaced pre-existing report. The two output replacements are not transactional. Concurrent adversarial directory mutation remains outside the pre-existing portable safety guarantee.

Only the old overwrite expectations in `TestCLIAndOutputProtection` were changed: regular files and hard-link destinations now succeed, with an explicit assertion that the target inode's contents are unchanged. Existing unsafe-target assertions remain. Added regression tests cover target symlinks (including dangling/non-app links), output refusal, mode, overwrite, preflight, second-write failure, rename-failure cleanup, summary ranking/grouping/empty output, compact inline evidence, nested bundles, family/host/skip caps, and preservation of sensitive and notable entries. Failure injection is local to helper calls, with no global hooks.

Additional checks: full Calculator Markdown is identical to the committed binary outside the summary and timestamp. The checked-in Calculator example JSON changes only its summary; its Markdown was regenerated from that same example. The README excerpt uses relative evidence paths. Notes and Docker JSON were also compared before/after the string-scan optimization and match outside summary/timestamp.

Cross-built Windows/Linux binaries were not executed; Go 1.22 itself and hosted CI were not run. No commits were created. The outstanding compact-size conflict requires a future decision to permit grouping or capping notable automation entries if a hard 60 KB limit is required.

### Known performance

Docker's temporary phase-timed run before the optimization:

```text
exit=0 total=14.505s
inventory: 33.786ms (147 files, 71 binaries)
metadata: 950.041µs
Mach-O parsing: 28.310583ms
signing target setup: 20.917µs
BundleInfo: 126.209µs
CodeSigning: 226.334µs
Entitlements: 167.917µs
Permissions: 15.709µs
URLSchemes: 2.958µs
LaunchItems: 5.121542ms
Automation: 8.875µs
Network: 13.916669375s
```

Inventory already reads only four bytes for file-type detection and retains distinct file paths. Network string scanning dominated this run (13.917 of 14.505 seconds). The sole performance change adds a byte-substring prefilter: a run with no `://` cannot match any supported URL regex, so regex matching is skipped. ASCII/UTF-16LE extraction, limits, offsets, sorting and evidence are unchanged. Temporary phase-timing code was restored exactly and is absent from production sources.

Observed after-change results:

```text
calculator: exit=0, seconds=0.4594, JSON stable=True
notes: exit=0, seconds=0.2219, JSON stable=True
docker: exit=0, seconds=9.9305, JSON stable=True
```

The observed Docker reduction is about 32%, from 14.505 to 9.931 seconds. These are single local measurements, not a controlled benchmark; filesystem cache and startup costs can vary. No further scanner redesign was attempted.

### A2 command outputs

```text
G1: $ test -z "$(gofmt -l .)"
exit=0; elapsed=0.104s
(no output)

G2: $ go vet ./...
exit=0; elapsed=0.448s
(no output)

G3: $ go test ./... && go test -race ./...
exit=0; elapsed=3.454s
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	0.536s
ok  	github.com/harinaralasetty/underhood/internal/cli	0.547s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	0.513s
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	1.470s
ok  	github.com/harinaralasetty/underhood/internal/cli	1.527s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	1.416s
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]

G4: $ grep -rn "os/exec" --include='*.go' . | grep -v _test.go; grep -c '^require' go.mod
exit=1; elapsed=0.126s
0

G5: $ GOOS=darwin GOARCH=arm64 go build -o /dev/null ./cmd/underhood
exit=0; elapsed=0.204s
(no output)

G5: $ GOOS=darwin GOARCH=amd64 go build -o /dev/null ./cmd/underhood
exit=0; elapsed=0.758s
(no output)

G5: $ GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/underhood
exit=0; elapsed=0.673s
(no output)

G5: $ GOOS=linux GOARCH=arm64 go build -o /dev/null ./cmd/underhood
exit=0; elapsed=0.647s
(no output)

G5: $ GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/underhood
exit=0; elapsed=0.670s
(no output)

G5: $ GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/underhood
exit=0; elapsed=0.661s
(no output)

G6: $ go run ./cmd/underhood /Applications/Safari.app | head -30
exit=0; elapsed=0.809s
# Underhood: Safari

**ID:** com.apple.Safari
**Version / build:** 27.0 / 22625.1.29.11.27
**Path:** /System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app
**Tool version:** 0.1.0-dev
**Scanned at:** 2026-10-14T15:45:40.500869Z

## Summary

- Allows DYLD environment variables [ent.com.apple.security.cs.allow-dyld-environment-variables@Contents/MacOS/SafariForWebKitDevelopment]
- Disables library validation [ent.com.apple.security.cs.disable-library-validation@Contents/MacOS/SafariForWebKitDevelopment]
- Requests a sandbox exception; exception targets/values follow [ent.com.apple.security.temporary-exception.apple-events]
- Declares AppleScript support [automation.NSAppleScriptEnabled]
- Ships 3 launch helpers [launch.embedded@Contents/XPCServices/com.apple.Safari.BrowserDataImportingService.xpc, launch.embedded@Contents/XPCServices/com.apple.Safari.ContentBlockerLoader.xpc; +1 more]
- Allows outgoing network connections (5 distinct bundles/places) [net.entitlement.com.apple.security.network.client, net.entitlement.com.apple.security.network.client@Contents/Extensions/SafariLinkExtension.appex; +3 more]
- Declares 2 privacy permissions: Location, Speech Recognition [privacy.NSLocationUsageDescription, privacy.NSSpeechRecognitionUsageDescription]
- Registers 6 URL schemes: file, http, https, … [url.scheme.file, url.scheme.http; +4 more]

I = info, N = notable, S = sensitive; D = declared, B = found-in-binary, H = heuristic. Use --full or JSON for every evidence entry.

## identity

**CFBundleDisplayName** · I/D · `bundle.CFBundleDisplayName`
Contents/Info.plist · CFBundleDisplayName = Safari

**CFBundleIdentifier** · I/D · `bundle.CFBundleIdentifier`
Contents/Info.plist · CFBundleIdentifier = com.apple.Safari

**CFBundleName** · I/D · `bundle.CFBundleName`
signal: broken pipe

build: $ go build -o .scratch/underhood ./cmd/underhood
exit=0; elapsed=0.182s
(no output)

G7 calculator run 1: $ .scratch/underhood /System/Applications/Calculator.app --output .scratch/calculator.md
exit=0; elapsed=0.451s
(no output)

G7 calculator run 2: $ .scratch/underhood /System/Applications/Calculator.app --output .scratch/calculator.md
exit=0; elapsed=0.033s
(no output)

G7 notes run 1: $ .scratch/underhood /System/Applications/Notes.app --output .scratch/notes.md
exit=0; elapsed=0.205s
(no output)

G7 notes run 2: $ .scratch/underhood /System/Applications/Notes.app --output .scratch/notes.md
exit=0; elapsed=0.141s
(no output)

G7 safari run 1: $ .scratch/underhood /Applications/Safari.app --output .scratch/safari.md
exit=0; elapsed=0.152s
(no output)

G7 safari run 2: $ .scratch/underhood /Applications/Safari.app --output .scratch/safari.md
exit=0; elapsed=0.144s
(no output)

sizes: $ wc -c .scratch/calculator.md .scratch/notes.md .scratch/safari.md
exit=0; elapsed=0.004s
   21595 .scratch/calculator.md
  337882 .scratch/notes.md
  101937 .scratch/safari.md
  461414 total

labels: $ grep -En '\bP[0-9]+/L[0-9]+\b' .scratch/calculator.md .scratch/notes.md .scratch/safari.md
exit=1; elapsed=0.006s
(no output)

calculator: 8 summary lines; at most two IDs per line=True
notes: 8 summary lines; at most two IDs per line=True
safari: 8 summary lines; at most two IDs per line=True
G8: $ jq 'del(.scannedAt, .summary)' .scratch/calculator-before.json > .scratch/before-stable.json && jq 'del(.scannedAt, .summary)' .scratch/calculator-after.json > .scratch/after-stable.json && cmp .scratch/before-stable.json .scratch/after-stable.json
exit=0; elapsed=0.017s
(no output)

G10: searched the working tree for the local home prefix, owner email prefix, and private organization identifiers; excluded .git, .gocache and .scratch
exit=1; elapsed=0.040s
(no output)
```

The final current-binary Calculator JSON was regenerated and the jq/cmp comparison repeated successfully after the command batch. The full-Markdown and checked-in example checks returned:

```text
Full Markdown identical outside summary/scannedAt: True
Example JSON changed only summary: True
```

Negative gate output (each change applied and reversed with a patch in `.scratch`, without git):

```text
symlink: reverted exit=1
--- FAIL: TestSymlinkTarget (0.00s)
    cli_test.go:95: 2 underhood: unrecognized or invalid target; supported kinds: macos-app (symlink not traversed: /private/tmp/TestSymlinkTarget2135248758/002/Link.app)

FAIL
FAIL	github.com/harinaralasetty/underhood/internal/cli	0.409s
FAIL

symlink: restored exit=0
ok  	github.com/harinaralasetty/underhood/internal/cli	0.461s

overwrite: reverted exit=1
--- FAIL: TestOverwriteOutput (0.00s)
    cli_test.go:140: 1 underhood: refusing existing output path

FAIL
FAIL	github.com/harinaralasetty/underhood/internal/cli	0.423s
FAIL

overwrite: restored exit=0
ok  	github.com/harinaralasetty/underhood/internal/cli	0.146s
```

## Report-format review adjustments

After the A2 run, the following were adjusted and re-verified (gofmt, vet, `go test`, `-race`, six cross-builds, JSON identical outside `summary`/`scannedAt`):

- Markdown summary lines show readable text only (full ID trail stays in JSON `summary[].findingIds`); App Intent entries merge into one item, sandbox temporary exceptions merge into one item, identical summary texts are merged.
- Compact Markdown caps repeated families: informational findings and bulk App Intent entries at 10 per family; non-sensitive entitlements at 3 per key with an "also declared in N more places" line. Sensitive findings are never capped or dropped. `--full` and JSON keep everything.
- Resulting compact sizes: Calculator 18,198 bytes; Notes 98,021 bytes (the earlier 60 KB target is not met because sensitive entitlements are intentionally uncapped); Safari 97,343 bytes. This supersedes the interpretation note above.
