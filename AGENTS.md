# Coding guide

Underhood is a read-only, offline static inspector. Keep Go 1.22 compatibility and use only the standard library. Never execute target code, import `os/exec` in production, access the network at runtime, or write into targets/system directories.

- `cmd/underhood`: thin entry point; `internal/cli`: arguments and safe output.
- `internal/model`, `target`, `inventory`, `scan`, `report`: portable shared core.
- `internal/plist`, `macho`, `analyzers/macos`: parsers and macOS target.
- `internal/testutil`: portable synthetic fixtures. Preserve finding IDs and evidence semantics.

Use bounded parsers, sorted output, explicit skip notes, and tests for malformed input. Do not introduce unrelated features or dependencies. Keep docs and schema consistent with changes.

```sh
export GOCACHE="$PWD/.gocache" GOFLAGS=-buildvcs=false GOPROXY=off CGO_ENABLED=0
gofmt -w cmd internal
go vet ./...
go build ./...
go test ./...
go test -race ./...
```

See CONTRIBUTING.md for fuzzing and target registration. Do not commit `.scratch`, caches, personal paths, or host-specific reports other than reviewed system-app examples.
