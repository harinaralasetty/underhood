# Diff verification

This records local checks for `underhood diff OLD NEW`, using `go version go1.27.2 darwin/arm64` and module language version Go 1.22. No target code was executed. Windows and Linux artifacts were cross-built, not executed; the Go 1.22 toolchain itself was not installed or run. No commit or push was made.

Environment (except explicit per-command overrides):

```sh
export GOCACHE="$PWD/.gocache" GOFLAGS=-buildvcs=false GOPROXY=off CGO_ENABLED=0
```

## Automated checks

Unit coverage includes added/removed/changed/unchanged findings, category and sensitivity ordering, input-order determinism, changed declaration fields, string and slice relocation, preserved architecture/value bindings, mismatches, one-sided caps, complete evidence and writer errors. Generated macOS version pairs assert the exact set of differences and no extras, including reversed and identical comparisons. CLI tests also exercise Windows PE, renamed identical PEs, folders, MSIX capabilities/version changes, malformed metadata, actual one-sided binary caps, and output protection against both targets and their aliases.

Final captured check output follows. Empty output between a command and `exit=0` is intentional; formatting produced no filenames. Cached results are shown as reported by Go; the changed packages also ran uncached during implementation and race verification.

```text
$ gofmt -l cmd internal
exit=0

$ go vet ./...
exit=0

$ go build ./...
exit=0

$ go test ./...
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	(cached)
ok  	github.com/harinaralasetty/underhood/internal/cli	(cached)
ok  	github.com/harinaralasetty/underhood/internal/diff	(cached)
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
exit=0

$ CGO_ENABLED=1 go test -race ./...
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	(cached)
ok  	github.com/harinaralasetty/underhood/internal/cli	2.610s
ok  	github.com/harinaralasetty/underhood/internal/diff	1.543s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
exit=0

$ GOOS=windows GOARCH=arm64 go build -o .scratch/underhood-windows-arm64.exe ./cmd/underhood
exit=0

$ GOOS=linux go build -o .scratch/underhood-linux ./cmd/underhood
exit=0

$ go build -o .scratch/underhood ./cmd/underhood
exit=0
```

The existing bounded parser fuzz targets were also exercised with two workers. Trimmed actual output:

```text
$ go test ./internal/plist -run '^$' -fuzz '^FuzzDecode$' -fuzztime=20s -parallel=2
PASS
ok  	github.com/harinaralasetty/underhood/internal/plist	21.407s
$ go test ./internal/macho -run '^$' -fuzz '^FuzzSuperBlob$' -fuzztime=20s -parallel=2
PASS
ok  	github.com/harinaralasetty/underhood/internal/macho	21.390s
```

`go list -m all` printed only `github.com/harinaralasetty/underhood`. A production-source check found no `os/exec` imports. `git diff --check` passed. These are local results, not a claim that hosted CI ran.

## Real-app comparison

One installed Calculator copy was found in standard application locations. The real `/System/Applications/Calculator.app` (version 12.0, build 225) was compared with a modified byte-copy under ignored `.scratch/`. The reproduction steps and exact report excerpts are in [Compare two versions](diff.md#real-calculator-demonstration). Only the copied Info.plist version string and synthetic camera declaration were changed; no real app contents or full host report are included in the source changes.

The current binary ran this command, then repeated it with a second output base:

```sh
.scratch/underhood diff /System/Applications/Calculator.app .scratch/Calculator-copy.app --format both --output .scratch/calculator-diff
```

Assertions checked the exact changes, empty skips, deterministic JSON and Markdown after removing `scannedAt`, and that every new README/comparison-doc output excerpt occurs in the actual report. Actual assertion output:

```text
changed: bundle.CFBundleShortVersionString
added: privacy.NSCameraUsageDescription
Real-app smoke: exact expected changes; no skipped analyses.
Real-app determinism: JSON and Markdown identical after removing scannedAt.
README and comparison-doc excerpts match actual report output.
```
