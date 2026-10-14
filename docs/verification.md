# Verification

This is a local verification record, not a claim that hosted CI ran. Toolchain: `go version go1.27.2 darwin/arm64`; module language version: `go 1.22`.

Environment used unless a command explicitly overrides it:

```sh
export GOCACHE="$PWD/.gocache" GOFLAGS=-buildvcs=false GOPROXY=off CGO_ENABLED=0
```

## Result and known deviations

- Build, vet, unit/fixture tests, race tests and six cross-builds passed. Both native fuzz targets ran for 20 seconds and passed. No production subprocess import or module requirement was found.
- All five requested apps exited 0 in under 10 seconds. Notes produces 247,209 bytes of default Markdown, exceeding the size target; every finding is retained. The large Electron examples are about 59 KiB and 43 KiB.
- Output creation is deliberately stricter than requested: all existing files are refused, including unrelated regular files. This prevents hard-link overwrites and avoids truncation races. Choose a new output path.
- Compact Markdown uses reversible P/L references and one evidence entry per finding. Full descriptions and all evidence remain in `--full` and JSON. This keeps repetitive Electron reports near the requested size without silently dropping findings.
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
