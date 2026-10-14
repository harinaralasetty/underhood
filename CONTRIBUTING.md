# Contributing

Use Go 1.22 or newer. Keep changes focused, deterministic, offline and read-only. No third-party modules, subprocesses, target execution, telemetry, or runtime network calls. Apple-tool parity checks belong only in `*_parity_test.go` with `//go:build darwin && parity`.

```sh
export GOCACHE="$PWD/.gocache" GOFLAGS=-buildvcs=false GOPROXY=off CGO_ENABLED=0
gofmt -w cmd internal
go vet ./...
go build ./...
go test ./...
go test -race ./...
go test ./internal/plist -run '^$' -fuzz '^FuzzDecode$' -fuzztime=20s
go test ./internal/macho -run '^$' -fuzz '^FuzzSuperBlob$' -fuzztime=20s
GOOS=windows GOARCH=arm64 go build -o .scratch/underhood.exe ./cmd/underhood
```

Create `.scratch` before the last command. Some Go versions/platforms require `CGO_ENABLED=1` for race instrumentation; use that override if requested by the toolchain. Shipped binaries and cross-builds do not need CGO. Fuzzing may need fewer workers (`-parallel=2`) in constrained environments.

To add a finding, use a stable ID, category, severity and confidence; attach a source file, locator and bounded value. Add a programmatic fixture assertion and update [the finding catalogue](docs/findings.md). Never infer a permission grant, real traffic, execution or trust from static declarations. Preserve unrelated finding semantics.

To add a target, follow [adding a target](docs/adding-a-target.md). Shared core packages must not depend on target-specific parsers. Add malformed input, symlink, cap and determinism coverage. Inspect generated reports for personal data before including examples.

Open a focused pull request describing the behavior change and actual verification results. Do not publish private app contents in issues.
