# B2 MSIX verification record
Verified 2026-10-14 using `go version go1.27.2 darwin/arm64`. Scope: MSIX/APPX packages, bundles and unpacked manifest folders on the existing B1 PE implementation. No git write commands were used.
## Outcome
All final formatting, vet, build, unit, race and cross-build gates returned exit 0. Seven native fuzz targets completed their requested 20-second runs without a failure. Calculator, Notes and Safari JSON (including summary) matched baselines after deleting only `scannedAt`; Markdown matched except its scan-time line. The B1 relative-path `t64.exe` JSON also matched. Optional macOS app finding-ID sets matched.
The synthetic package produced 47 findings and zero skips. The generated [Markdown](../examples/windows-msix.md) and [JSON](../examples/windows-msix.json) use a relative target path and synthetic identities.
## Environment and exact gate commands
```sh
export GOCACHE="$PWD/.gocache" GOFLAGS=-buildvcs=false GOPROXY=off CGO_ENABLED=0
```
Outputs below are captured, not expected output. Empty output is labelled explicitly. The additional `CGO_ENABLED=1 go test -race ./...` run also passed; the required CGO-disabled race run passed on this toolchain.

```text
$ gofmt -l .
(no output)
exit 0; elapsed 0.17s
```

```text
$ go vet ./...
(no output)
exit 0; elapsed 0.37s
```

```text
$ go build ./...
(no output)
exit 0; elapsed 0.96s
```

```text
$ go test ./...
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	0.618s
ok  	github.com/harinaralasetty/underhood/internal/cli	(cached)
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
exit 0; elapsed 2.16s
```

```text
$ go test -race ./...
?   	github.com/harinaralasetty/underhood/cmd/underhood	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/analyzers/macos	(cached)
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	2.181s
ok  	github.com/harinaralasetty/underhood/internal/cli	(cached)
ok  	github.com/harinaralasetty/underhood/internal/inventory	(cached)
ok  	github.com/harinaralasetty/underhood/internal/macho	(cached)
?   	github.com/harinaralasetty/underhood/internal/model	[no test files]
ok  	github.com/harinaralasetty/underhood/internal/plist	(cached)
ok  	github.com/harinaralasetty/underhood/internal/report	(cached)
ok  	github.com/harinaralasetty/underhood/internal/scan	(cached)
?   	github.com/harinaralasetty/underhood/internal/target	[no test files]
?   	github.com/harinaralasetty/underhood/internal/testutil	[no test files]
exit 0; elapsed 4.19s
```

```text
$ GOOS=linux GOARCH=amd64 go build -o .scratch/b2-linux-amd64 ./cmd/underhood
(no output)
exit 0; elapsed 2.68s
```

```text
$ GOOS=windows GOARCH=amd64 go build -o .scratch/b2-windows-amd64 ./cmd/underhood
(no output)
exit 0; elapsed 1.16s
```

```text
$ GOOS=windows GOARCH=arm64 go build -o .scratch/b2-windows-arm64 ./cmd/underhood
(no output)
exit 0; elapsed 1.09s
```

```text
$ GOOS=darwin GOARCH=arm64 go build -o .scratch/b2-darwin-arm64 ./cmd/underhood
(no output)
exit 0; elapsed 0.4s
```

## Timed native fuzzing
The ZIP fuzz run executed only six cases in its 20-second window, so it is limited evidence rather than broad fuzz coverage. Deterministic ZIP tests separately exercise truncation, forged sizes/counts, ZIP64, CRC corruption, unsafe names, duplicate names, symlinks, nested-bundle rejection, four-package selection and 20-PE caps. Manifest tests cover malformed/truncated XML, namespaces, capabilities, every requested extension family, finding caps and mixed service accounts.

```text
$ go test ./internal/analyzers/windows -run '^$' -fuzz '^FuzzResourceWalker$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/49 completed
fuzz: elapsed: 0s, gathering baseline coverage: 49/49 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 58526 (19496/sec), new interesting: 0 (total: 49)
fuzz: elapsed: 6s, execs: 118652 (20055/sec), new interesting: 0 (total: 49)
fuzz: elapsed: 9s, execs: 174659 (18638/sec), new interesting: 0 (total: 49)
fuzz: elapsed: 12s, execs: 229178 (18202/sec), new interesting: 0 (total: 49)
fuzz: elapsed: 15s, execs: 281716 (17512/sec), new interesting: 0 (total: 49)
fuzz: elapsed: 18s, execs: 337463 (18570/sec), new interesting: 0 (total: 49)
fuzz: elapsed: 20s, execs: 380212 (20772/sec), new interesting: 1 (total: 50)
PASS
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	20.582s
exit 0; elapsed 23.91s
```

```text
$ go test ./internal/analyzers/windows -run '^$' -fuzz '^FuzzPKCS7$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/37 completed
fuzz: elapsed: 0s, gathering baseline coverage: 37/37 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 3099 (1033/sec), new interesting: 0 (total: 37)
fuzz: elapsed: 6s, execs: 3099 (0/sec), new interesting: 0 (total: 37)
fuzz: elapsed: 9s, execs: 3099 (0/sec), new interesting: 0 (total: 37)
fuzz: elapsed: 12s, execs: 302166 (103396/sec), new interesting: 2 (total: 39)
fuzz: elapsed: 15s, execs: 302166 (0/sec), new interesting: 2 (total: 39)
fuzz: elapsed: 18s, execs: 302166 (0/sec), new interesting: 2 (total: 39)
fuzz: elapsed: 21s, execs: 302166 (0/sec), new interesting: 2 (total: 39)
fuzz: elapsed: 21s, execs: 302166 (0/sec), new interesting: 2 (total: 39)
PASS
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	21.484s
exit 0; elapsed 22.84s
```

```text
$ go test ./internal/analyzers/windows -run '^$' -fuzz '^FuzzPEManifest$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/161 completed
fuzz: elapsed: 0s, gathering baseline coverage: 161/161 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 53375 (17791/sec), new interesting: 12 (total: 173)
fuzz: elapsed: 6s, execs: 109898 (18835/sec), new interesting: 32 (total: 193)
fuzz: elapsed: 9s, execs: 148851 (12987/sec), new interesting: 42 (total: 203)
fuzz: elapsed: 12s, execs: 151545 (898/sec), new interesting: 43 (total: 204)
fuzz: elapsed: 15s, execs: 217738 (22057/sec), new interesting: 52 (total: 213)
fuzz: elapsed: 18s, execs: 218697 (320/sec), new interesting: 53 (total: 214)
fuzz: elapsed: 21s, execs: 218697 (0/sec), new interesting: 53 (total: 214)
fuzz: elapsed: 21s, execs: 218697 (0/sec), new interesting: 53 (total: 214)
PASS
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	21.389s
exit 0; elapsed 22.95s
```

```text
$ go test ./internal/analyzers/windows -run '^$' -fuzz '^FuzzAppxManifest$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/3 completed
fuzz: elapsed: 0s, gathering baseline coverage: 3/3 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 446 (149/sec), new interesting: 3 (total: 6)
fuzz: elapsed: 6s, execs: 50666 (16739/sec), new interesting: 4 (total: 7)
fuzz: elapsed: 9s, execs: 50666 (0/sec), new interesting: 4 (total: 7)
fuzz: elapsed: 12s, execs: 50666 (0/sec), new interesting: 4 (total: 7)
fuzz: elapsed: 15s, execs: 50666 (0/sec), new interesting: 4 (total: 7)
fuzz: elapsed: 18s, execs: 149970 (33098/sec), new interesting: 9 (total: 12)
fuzz: elapsed: 21s, execs: 149970 (0/sec), new interesting: 9 (total: 12)
fuzz: elapsed: 21s, execs: 149970 (0/sec), new interesting: 9 (total: 12)
PASS
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	21.576s
exit 0; elapsed 27.5s
```

```text
$ go test ./internal/analyzers/windows -run '^$' -fuzz '^FuzzMSIXZip$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/3 completed
fuzz: elapsed: 0s, gathering baseline coverage: 3/3 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 6 (2/sec), new interesting: 0 (total: 3)
fuzz: elapsed: 6s, execs: 6 (0/sec), new interesting: 0 (total: 3)
fuzz: elapsed: 9s, execs: 6 (0/sec), new interesting: 0 (total: 3)
fuzz: elapsed: 12s, execs: 6 (0/sec), new interesting: 0 (total: 3)
fuzz: elapsed: 15s, execs: 6 (0/sec), new interesting: 0 (total: 3)
fuzz: elapsed: 18s, execs: 6 (0/sec), new interesting: 0 (total: 3)
fuzz: elapsed: 21s, execs: 6 (0/sec), new interesting: 0 (total: 3)
fuzz: elapsed: 21s, execs: 6 (0/sec), new interesting: 0 (total: 3)
PASS
ok  	github.com/harinaralasetty/underhood/internal/analyzers/windows	21.151s
exit 0; elapsed 22.14s
```

```text
$ go test ./internal/plist -run '^$' -fuzz '^FuzzDecode$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/226 completed
fuzz: elapsed: 0s, gathering baseline coverage: 226/226 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 49437 (16473/sec), new interesting: 3 (total: 229)
fuzz: elapsed: 6s, execs: 76467 (9012/sec), new interesting: 4 (total: 230)
fuzz: elapsed: 9s, execs: 269512 (64351/sec), new interesting: 6 (total: 232)
fuzz: elapsed: 12s, execs: 475692 (68712/sec), new interesting: 8 (total: 234)
fuzz: elapsed: 15s, execs: 546114 (23477/sec), new interesting: 15 (total: 241)
fuzz: elapsed: 18s, execs: 593089 (15658/sec), new interesting: 17 (total: 243)
fuzz: elapsed: 20s, execs: 810363 (106319/sec), new interesting: 20 (total: 246)
PASS
ok  	github.com/harinaralasetty/underhood/internal/plist	20.931s
exit 0; elapsed 22.48s
```

```text
$ go test ./internal/macho -run '^$' -fuzz '^FuzzSuperBlob$' -fuzztime=20s -parallel=2
fuzz: elapsed: 0s, gathering baseline coverage: 0/79 completed
fuzz: elapsed: 0s, gathering baseline coverage: 79/79 completed, now fuzzing with 2 workers
fuzz: elapsed: 3s, execs: 189414 (63109/sec), new interesting: 3 (total: 82)
fuzz: elapsed: 6s, execs: 239685 (16763/sec), new interesting: 4 (total: 83)
fuzz: elapsed: 9s, execs: 335058 (31783/sec), new interesting: 6 (total: 85)
fuzz: elapsed: 12s, execs: 473427 (46123/sec), new interesting: 8 (total: 87)
fuzz: elapsed: 15s, execs: 568651 (31741/sec), new interesting: 10 (total: 89)
fuzz: elapsed: 18s, execs: 660802 (30716/sec), new interesting: 12 (total: 91)
fuzz: elapsed: 20s, execs: 660802 (0/sec), new interesting: 12 (total: 91)
PASS
ok  	github.com/harinaralasetty/underhood/internal/macho	21.009s
exit 0; elapsed 22.18s
```

## Baselines, parity and smoke results
Before code edits, `/tmp/underhood2` generated `.scratch/base-{Calculator,Notes,Safari}.{json,md}` using `--format json` and `--format md`. `/tmp/underhood3 t64.exe --format json`, invoked with `.scratch` as working directory, reproduced `.scratch/base-t64.json` after removing `scannedAt`.
Exact JSON normalization and comparison commands:

```text
$ jq -S 'del(.scannedAt)' .scratch/base-Calculator.json > .scratch/b2-normalized-base-Calculator.json
(normalized JSON written)
exit 0
```

```text
$ jq -S 'del(.scannedAt)' .scratch/b2-Calculator.json > .scratch/b2-normalized-new-Calculator.json
(normalized JSON written)
exit 0
```

```text
$ diff -u .scratch/b2-normalized-base-Calculator.json .scratch/b2-normalized-new-Calculator.json
(no output)
exit 0
```

```text
$ jq -S 'del(.scannedAt)' .scratch/base-Notes.json > .scratch/b2-normalized-base-Notes.json
(normalized JSON written)
exit 0
```

```text
$ jq -S 'del(.scannedAt)' .scratch/b2-Notes.json > .scratch/b2-normalized-new-Notes.json
(normalized JSON written)
exit 0
```

```text
$ diff -u .scratch/b2-normalized-base-Notes.json .scratch/b2-normalized-new-Notes.json
(no output)
exit 0
```

```text
$ jq -S 'del(.scannedAt)' .scratch/base-Safari.json > .scratch/b2-normalized-base-Safari.json
(normalized JSON written)
exit 0
```

```text
$ jq -S 'del(.scannedAt)' .scratch/b2-Safari.json > .scratch/b2-normalized-new-Safari.json
(normalized JSON written)
exit 0
```

```text
$ diff -u .scratch/b2-normalized-base-Safari.json .scratch/b2-normalized-new-Safari.json
(no output)
exit 0
```

```text
$ jq -S 'del(.scannedAt)' .scratch/base-t64.json > .scratch/b2-normalized-base-t64.json
(normalized JSON written)
exit 0
```

```text
$ jq -S 'del(.scannedAt)' .scratch/b2-t64.exe.json > .scratch/b2-normalized-new-t64.json
(normalized JSON written)
exit 0
```

```text
$ diff -u .scratch/b2-normalized-base-t64.json .scratch/b2-normalized-new-t64.json
(no output)
exit 0
```

Markdown comparison removed only lines containing `Scanned at` from each saved baseline/new output and compared the remaining byte lines. Optional app ID sets were compared with fresh `/tmp/underhood3` results. The verification driver was `python3 .scratch/verify-b2.py`; its output follows.
```text
Calculator: JSON including summary identical minus scannedAt; Markdown identical except Scanned at line — PASS
Notes: JSON including summary identical minus scannedAt; Markdown identical except Scanned at line — PASS
Safari: JSON including summary identical minus scannedAt; Markdown identical except Scanned at line — PASS
claude: 495 finding IDs identical to /tmp/underhood3 — PASS
wispr: 412 finding IDs identical to /tmp/underhood3 — PASS
caffeinate: 13 finding IDs identical to /tmp/underhood3 — PASS
B1 t64.exe: JSON including summary identical minus scannedAt — PASS
t64.exe: exit 0; 0.014s; x64; console; execution=asInvoker; unsigned=True; imports=KERNEL32.dll, SHLWAPI.dll
  clusters: debugger, dynamic
  independent file: t64.exe: PE32+ executable (console) x86-64, for MS Windows
w64.exe: exit 0; 0.012s; x64; GUI; execution=asInvoker; unsigned=True; imports=KERNEL32.dll, SHLWAPI.dll, USER32.dll
  clusters: debugger, dynamic
  independent file: w64.exe: PE32+ executable (GUI) x86-64, for MS Windows
w64-arm.exe: exit 0; 0.017s; ARM64; GUI; execution=asInvoker; unsigned=True; imports=KERNEL32.dll, SHLWAPI.dll, USER32.dll
  clusters: dynamic
  independent file: w64-arm.exe: PE32+ executable (GUI) Aarch64, for MS Windows
b2-windows-amd64: exit 0; 0.152s; x64; console; execution=none; unsigned=True; imports=kernel32.dll
  clusters: dynamic, process
  independent file: b2-windows-amd64: PE32+ executable (console) x86-64, for MS Windows
Synthetic MSIX: exit 0; 47 findings; 0 skips; summary:
  Declares a full-trust process
  Declares a LocalSystem service
  Declares 2 restricted capabilities: broadFileSystemAccess, runFullTrust
  Control Flow Guard not declared
  Network APIs
  Declares 4 capabilities: Synthetic.Custom, documentsLibrary, internetClient, microphone
  Declares content URI rule
  Embedded executable not signed
Windows examples: no home/absolute personal paths — PASS
Production os/exec imports: none — PASS
go.mod require declarations: none — PASS
```
The independent `file` readings agree on architectures and GUI/console subsystems. They do not independently establish import clusters, execution-level declarations or signature state. The tool cross-build has no embedded application manifest; unlike the distlib launchers, there is therefore no `asInvoker` finding.
Smoke commands (all executed from `.scratch`, with the new host binary at `./underhood-b2`):
```sh
./underhood-b2 t64.exe --format json
./underhood-b2 w64.exe --format json
./underhood-b2 w64-arm.exe --format json
./underhood-b2 b2-windows-amd64 --format json
file t64.exe
file w64.exe
file w64-arm.exe
file b2-windows-amd64
```
Example generation used the existing synthetic PKCS#7 certificate helper; signature bytes intentionally do not establish cryptographic validity:
```sh
go build -o .scratch/underhood-b2 ./cmd/underhood
UNDERHOOD_MSIX_FIXTURE="$PWD/.scratch/synthetic.msix" go test ./internal/analyzers/windows -run '^TestWriteMSIXExample$' -count=1
# From .scratch, capture stdout into the corresponding examples file:
./underhood-b2 synthetic.msix --format md
./underhood-b2 synthetic.msix --format json
```
Generator output: `ok github.com/harinaralasetty/underhood/internal/analyzers/windows 0.169s`, exit 0. Example CLI invocations returned exit 0. A content check rejected home prefixes, `/Users/`, and `/private/` in Windows examples; inspection confirmed synthetic package names, certificate names, protocol names, ports and service names. The existing B1 launcher examples were preserved.
Production-source checks found no `"os/exec"` imports, and `go.mod` has no `require` declarations. `rg -n 'os/exec' cmd internal -g '*.go'` and `rg '^require' go.mod` both returned no matches (exit 1). `git diff --check` returned exit 0 with no diff errors.
## Decisions, deviations and unverified items
- ZIP detection uses a bounded central-directory scan instead of a few-KiB probe: entry names may appear anywhere in the directory. It accepts ZIP64 and the standard `AppxMetadata/AppxBundleManifest.xml` location in addition to the brief’s root location. Central directories must end at their end-record boundary; split archives and extra/unrecognized directory records are rejected.
- Added a 512 MiB aggregate expanded-read budget, counting nested ZIP bytes and selected contents. The 20-PE cap applies across the entire bundle report; the four application-package cap applies to unique selected names. Metadata reads remain capped at 16 MiB, below the 256 MiB entry ceiling.
- Existing `net.host.<host>` findings remain report-wide with entry paths in evidence, rather than gaining per-entry ID suffixes. This preserves B1 host grouping and shared host/evidence caps. Other embedded PE findings retain the existing `@path` namespacing.
- Publisher comparison is textual, not Windows distinguished-name canonicalization; equivalent names encoded or ordered differently can produce a mismatch. It is explicitly labelled as a textual comparison.
- Unpacked manifest folders inspect declared application executables only and do not assess the package signature. Filesystem case sensitivity applies to declared disk paths. Unknown/custom capabilities are informational, including unknown restricted names.
- No real MSIX package was available, as stated in the brief. Package behavior is verified with generated fixtures; cross-built Windows/Linux executables were not run on those operating systems. Go 1.22 compatibility is retained in the module/language/API choices, but the installed compiler was Go 1.27.2, not Go 1.22. Longer fuzz campaigns and broader real-package compatibility remain unverified.
- The first targeted test run failed only on the B1 assertion requiring deferred MSIX analysis. That test now verifies the malformed-manifest skip; all final test runs passed. No implementation work remains blocked.
## Changed and new files
- `CHANGELOG.md` (updated).
- `README.md` (updated).
- `docs/adding-a-target.md` (updated).
- `docs/architecture.md` (updated).
- `docs/findings.md` (updated).
- `docs/schema.md` (updated).
- `docs/windows.md` (updated).
- `internal/analyzers/windows/target.go` (updated).
- `internal/analyzers/windows/target_test.go` (updated).
- `internal/cli/cli.go` (updated).
- `internal/cli/windows_test.go` (updated).
- `internal/report/compact.go` (updated).
- `internal/report/summary.go` (updated).
- `internal/report/windows.go` (updated).
- `internal/report/windows_test.go` (updated).
- `examples/windows-msix.json` (new).
- `examples/windows-msix.md` (new).
- `internal/analyzers/windows/capabilities.go` (new).
- `internal/analyzers/windows/msix.go` (new).
- `internal/analyzers/windows/msix_manifest.go` (new).
- `internal/analyzers/windows/msix_signature.go` (new).
- `internal/analyzers/windows/msix_test.go` (new).
- `internal/testutil/msix.go` (new).
- `docs/windows-msix-verification.md` (new; this record).
