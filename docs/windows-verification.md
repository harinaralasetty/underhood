# Windows B1 verification

Verified on 2026-10-14 with `go version go1.27.2 darwin/arm64`. No git write commands, commits or configuration changes were made. Baselines were saved using `/tmp/underhood2` before source edits. The Go module still specifies Go 1.22 and has no dependencies; an actual Go 1.22 toolchain was not available/tested.

## Environment and gates

```sh
export GOCACHE="$PWD/.gocache" GOFLAGS=-buildvcs=false GOPROXY=off CGO_ENABLED=0
```

Actual final gate output (silent success is shown as exit 0):

```text
$ gofmt -l .
.scratch/pe-dump.go
exit=0; elapsed=0.133s
$ go vet ./...
exit=0; elapsed=0.493s
$ go build ./...
exit=0; elapsed=0.585s
$ go test ./...
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	(cached)
ok  	github.com/harinaralasetty/underhood/internal/cli	0.563s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
exit=0; elapsed=0.908s
$ go test -race ./...
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	1.672s
ok  	github.com/harinaralasetty/underhood/internal/cli	1.680s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
exit=0; elapsed=2.772s
$ CGO_ENABLED=1 go test -race ./...
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	1.728s
ok  	github.com/harinaralasetty/underhood/internal/cli	1.745s
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
exit=0; elapsed=2.132s
$ GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o .scratch/underhood-linux-amd64 ./cmd/underhood
exit=0; elapsed=0.703s
$ GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o .scratch/underhood-windows-amd64 ./cmd/underhood
exit=0; elapsed=0.792s
$ GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o .scratch/underhood-windows-arm64 ./cmd/underhood
exit=0; elapsed=1.677s
$ GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o .scratch/underhood-darwin-arm64 ./cmd/underhood
exit=0; elapsed=0.740s
$ GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o .scratch/underhood.exe ./cmd/underhood
exit=0; elapsed=0.451s
$ go build -o .scratch/underhood-b1 ./cmd/underhood
exit=0; elapsed=0.412s
```

The first final formatting check listed only the ignored independent dump helper, `.scratch/pe-dump.go`. After `gofmt -w .scratch/pe-dump.go`, `gofmt -l .` was rerun and produced **no output** (exit 0). Production sources were already formatted.

The requested race run worked with CGO disabled on this toolchain. An additional CGO-enabled race run also passed. Cross-built binaries were inspected but not executed on Windows/Linux.

## Fuzzing and robustness

Each command used the environment above. Actual final outputs reported by the executing agents:

```text
$ go test ./internal/analyzers/windows -run '^$' -fuzz '^FuzzResourceWalker$' -fuzztime=20s
1,373,471 executions
PASS
ok github.com/harinaralasetty/underhood/internal/analyzers/windows 21.479s

$ go test ./internal/analyzers/windows -run '^$' -fuzz '^FuzzPEManifest$' -fuzztime=20s
1,026,646 executions
PASS
ok github.com/harinaralasetty/underhood/internal/analyzers/windows 21.519s

$ go test ./internal/analyzers/windows -run '^$' -fuzz '^FuzzPKCS7$' -fuzztime=20s -parallel=2
fuzz: elapsed: 21s, execs: 999601 (0/sec), new interesting: 7 (total: 37)
PASS
ok github.com/harinaralasetty/underhood/internal/analyzers/windows 21.498s
```

Manifest fuzzing found a copied `strings.Builder` panic. The parser now holds frame pointers, and the failing input is retained as a regression corpus. Synthetic tests cover PE32/PE32+, CLR, imports, embedded resources/version strings, generated self-signed PKCS#7, multiple certificate entries, truncation/corruption, malformed XML, symlink/depth/candidate/analysis caps, CLI exits, report wording, and mixed manifest privilege declarations. Independent review found and prompted fixes for misleading mixed-privilege summaries and filesystem-order-dependent candidate caps.

## Real files and macOS parity

The distlib t64, w64 and w64-arm launchers were copied from the locally installed pip vendor directory into `.scratch` before analysis. All reports below came from copies. The tool's Windows image was cross-compiled with the command above.

```text
$ .scratch/underhood-b1 .scratch/t64.exe --format both --output .scratch/t64-report
exit=0; elapsed=0.608s; 
Name: Simple Launcher
windows.identity.machine: Machine | x64
windows.identity.subsystem: Subsystem | console
windows.imports.debugger: Debugger detection APIs | KERNEL32.dll:IsDebuggerPresent
windows.imports.dynamic: Dynamic loading APIs | KERNEL32.dll:GetProcAddress
windows.imports.libraries: Imported libraries | KERNEL32.dll, SHLWAPI.dll
windows.pe.unsigned: Unsigned | absent
windows.manifest.requestedExecutionLevel: Requested execution level | asInvoker
skipped: []
$ .scratch/underhood-b1 .scratch/w64.exe --format both --output .scratch/w64-report
exit=0; elapsed=0.017s; 
Name: Simple Launcher
windows.identity.machine: Machine | x64
windows.identity.subsystem: Subsystem | GUI
windows.imports.debugger: Debugger detection APIs | KERNEL32.dll:IsDebuggerPresent
windows.imports.dynamic: Dynamic loading APIs | KERNEL32.dll:GetProcAddress
windows.imports.libraries: Imported libraries | KERNEL32.dll, SHLWAPI.dll, USER32.dll
windows.pe.unsigned: Unsigned | absent
windows.manifest.requestedExecutionLevel: Requested execution level | asInvoker
skipped: []
$ .scratch/underhood-b1 .scratch/w64-arm.exe --format both --output .scratch/w64-arm-report
exit=0; elapsed=0.017s; 
Name: Simple Launcher
windows.identity.machine: Machine | ARM64
windows.identity.subsystem: Subsystem | GUI
windows.imports.dynamic: Dynamic loading APIs | KERNEL32.dll:GetProcAddress
windows.imports.libraries: Imported libraries | KERNEL32.dll, SHLWAPI.dll, USER32.dll
windows.pe.unsigned: Unsigned | absent
windows.manifest.requestedExecutionLevel: Requested execution level | asInvoker
skipped: []
$ .scratch/underhood-b1 .scratch/underhood.exe --format both --output .scratch/underhood-report
exit=0; elapsed=0.102s; 
Name: underhood.exe
windows.identity.machine: Machine | x64
windows.identity.subsystem: Subsystem | console
windows.imports.dynamic: Dynamic loading APIs | kernel32.dll:GetProcAddress
windows.imports.libraries: Imported libraries | kernel32.dll
windows.imports.process: Process and memory manipulation APIs | kernel32.dll:SetThreadContext
windows.pe.unsigned: Unsigned | absent
skipped: []
calculator: full JSON including summary identical except scannedAt; Markdown identical except Scanned at; 70 findings
notes: full JSON including summary identical except scannedAt; Markdown identical except Scanned at; 1057 findings
safari: full JSON including summary identical except scannedAt; Markdown identical except Scanned at; 392 findings
claude: finding ID sets identical (495 findings)
wispr: finding ID sets identical (412 findings)
caffeinate: finding ID sets identical (13 findings)
$ file .scratch/{t64,w64,w64-arm,underhood}.exe
.scratch/t64.exe:       PE32+ executable (console) x86-64, for MS Windows
.scratch/w64.exe:       PE32+ executable (GUI) x86-64, for MS Windows
.scratch/w64-arm.exe:   PE32+ executable (GUI) Aarch64, for MS Windows
.scratch/underhood.exe: PE32+ executable (console) x86-64, for MS Windows

```

Required baseline commands, all successful before edits:

```sh
/tmp/underhood2 /System/Applications/Calculator.app --format both --output .scratch/base-calculator
/tmp/underhood2 /System/Applications/Notes.app --format both --output .scratch/base-notes
/tmp/underhood2 /Applications/Safari.app --format both --output .scratch/base-safari
```

Final reports used the same arguments with `.scratch/underhood-b1` and `new-` output names. Python compared complete JSON objects after removing only `scannedAt` (including summaries), and Markdown after removing only `**Scanned at:**` lines. Additional literal jq/cmp verification passed with no output:

```sh
for name in calculator notes safari; do
  jq 'del(.scannedAt)' ".scratch/base-$name.json" > ".scratch/base-$name.normalized.json"
  jq 'del(.scannedAt)' ".scratch/new-$name.json" > ".scratch/new-$name.normalized.json"
  cmp ".scratch/base-$name.normalized.json" ".scratch/new-$name.normalized.json" || exit 1
done
```

Optional app baseline IDs were obtained using the unchanged baseline binary during final verification; required Calculator/Notes/Safari baselines were saved before edits.

Independent `debug/pe` dump:

```text
.scratch/t64.exe machine=0x8664 subsystem=3 security(offset=0,size=0) imports=map[KERNEL32.dll:true SHLWAPI.dll:true]
.scratch/w64.exe machine=0x8664 subsystem=2 security(offset=0,size=0) imports=map[KERNEL32.dll:true SHLWAPI.dll:true USER32.dll:true]
.scratch/w64-arm.exe machine=0xaa64 subsystem=2 security(offset=0,size=0) imports=map[KERNEL32.dll:true SHLWAPI.dll:true USER32.dll:true]
.scratch/underhood.exe machine=0x8664 subsystem=3 security(offset=0,size=0) imports=map[kernel32.dll:true]
```

Raw manifest reads found `requestedExecutionLevel level="asInvoker" uiAccess="false"` in t64/w64 and the equivalent single-quoted declaration in w64-arm. No disagreement with the report was found. `file` calls x64 “x86-64” and ARM64 “Aarch64”; subsystem numbers 2/3 mean GUI/console. Import clusters are interpretations of the independently matched names, not evidence of use.

## Examples and hygiene

```sh
.scratch/underhood-b1 .scratch/t64.exe --format both --output examples/windows-launcher
```

Exit 0. Both generated files retain the relative `.scratch/t64.exe` path. A content check found no `/Users/`, `/home/` or current home-directory strings. The sample contains only public launcher metadata. Production-source inspection found zero `os/exec` imports outside parity-test exclusions, and zero `require` lines in go.mod. `git diff --check` returned exit 0. Scratch files and caches remain ignored; no binary or host-app report was added to the reviewable changes.

## Scope decisions and limitations

- B1 only: no MSIX/APPX/bundle parsing, zip handling or related fixtures. Root AppxManifest.xml yields the required skip and stops that folder. README marks these Planned next.
- Delay-load imports produce an explicit skip; the optional packing heuristic was omitted.
- Imports use a bounded manual reader rather than debug/pe's import convenience methods, avoiding section-wide allocations on untrusted input. debug/pe remains the header parser.
- EFI subsystem images are excluded even if DLL flags are set. Detection reads 158 header bytes; filename extensions alone never establish a PE.
- Folder selection sorts each complete bounded directory before the 200-candidate cap. A directory exceeding its remaining inventory budget is skipped entirely to preserve deterministic selection. Largest EXEs are prioritised among retained candidates.
- Windows path spelling is retained from the command line, cleaned/redacted. macOS path behavior and output are unchanged.
- Endpoint IDs reuse `net.host.<host>` and merge folder evidence under the shared 200-host/20-evidence budget; other nested PE IDs use `@relative/path`.
- Signatures are parsed only. No trust, revocation, digest/signature validation or timestamp validity claims. Real smoke files were unsigned; signed parsing was verified with synthetic certificates, not a real vendor-signed executable.
- Parser bounds: 96 sections, 65,536 COFF symbols, 16 MiB metadata; 4 MiB resource directory/payload and 16 MiB aggregate resource payloads, 4,096 resource entries; 64 XML levels/50,000 tokens/512 findings; 256 import descriptors/8,192 imports/512-byte names; 64 WIN_CERTIFICATE/certificate entries and 32 signers. Reached caps produce skips.
- No Windows/Linux runtime execution or actual Go 1.22 toolchain test. Cross-builds passed. No additional unverified B1 deliverables remain.
- Planning-with-files was not available in the provided plugin/skill catalog; compact ongoing context was kept in ignored `.scratch/B1-ledger.md`.

## Changed and new files

- `docs/windows.md`
- `examples/windows-launcher.json`
- `examples/windows-launcher.md`
- `internal/analyzers/windows/imports.go`
- `internal/analyzers/windows/manifest.go`
- `internal/analyzers/windows/pe.go`
- `internal/analyzers/windows/pe_test.go`
- `internal/analyzers/windows/resources.go`
- `internal/analyzers/windows/resources_test.go`
- `internal/analyzers/windows/signature.go`
- `internal/analyzers/windows/signature_test.go`
- `internal/analyzers/windows/strings.go`
- `internal/analyzers/windows/target.go`
- `internal/analyzers/windows/target_test.go`
- `internal/analyzers/windows/testdata/fuzz/FuzzPEManifest/528106e4c252d34a`
- `internal/cli/windows_test.go`
- `internal/report/windows.go`
- `internal/report/windows_test.go`
- `internal/testutil/pe.go`
- `internal/testutil/pe_resources.go`
- `internal/testutil/signature.go`
- `CHANGELOG.md`
- `README.md`
- `docs/adding-a-target.md`
- `docs/architecture.md`
- `docs/findings.md`
- `docs/schema.md`
- `internal/cli/cli.go`
- `internal/model/model.go`
- `internal/report/compact.go`
- `internal/report/report.go`
- `internal/report/summary.go`
- `internal/target/target.go`
- `docs/windows-verification.md` (this report)
