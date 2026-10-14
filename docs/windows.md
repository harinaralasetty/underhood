# Windows static inspection

Windows PE files, portable/installed app folders, MSIX/APPX packages, bundles and unpacked MSIX folders are available on macOS, Linux and Windows. All inspection is static and host-independent.

```sh
underhood ./launcher.exe --format both --output launcher-report
underhood ./portable-app --full
```

Detection reads DOS/PE header content, not filename extensions. Windows subsystem images and DLLs are accepted; EFI images are excluded. The analyser reads PE32/PE32+ headers, section declarations, embedded VERSIONINFO and application manifest resources, import tables, Authenticode certificate tables, and bounded ASCII/UTF-16LE URL and persistence strings. CLR directory presence identifies managed assemblies without decompiling metadata. It does not infer installers or self-extraction from binary content.

Folder discovery considers files at the root and one directory level below, without following internal symlinks. It inventories at most 200 PE files within 20,000 directory entries, analyses at most 20 (largest `.exe` files first, then other PEs, path tie-breaks), and names the remainder in skip notes. Inventory counts can be incomplete when caps are reached. Candidate paths are discovered in sorted directory order before the 200-PE cap. A directory exceeding the remaining entry budget is skipped entirely, avoiding filesystem-order-dependent selections. `unins000.exe` and `uninstall.exe` are reported by name only.

Authenticode/MSIX signatures are parsed but not cryptographically verified; trust, revocation and timestamp validity are not assessed. Certificate subjects, serial numbers, validity dates, issuer/subject chains, signer selection, digest OIDs and timestamp attribute presence describe unverified metadata. Expiry is informational and evaluated against scan time; a valid timestamp can keep a signature acceptable. A parse failure is distinguished from no certificate table.

Import clusters are heuristics common in legitimate tools and in malware; presence does not establish use. Dynamic resolution can hide APIs from the import table. Delay-load imports are explicitly skipped when present. No packing inference is made. Persistence strings are string presence, not proof of use. The same URL denylist and bounded scanner used by macOS apply, including both UTF-16 byte alignments.

No registry, running services, scheduled tasks, live processes or host configuration are inspected. No signature/hash verification, revocation calls, external `.manifest` reads, MSI/NSIS/Inno/ClickOnce unpacking, deobfuscation, malware verdicts or numeric risk scores are provided. Target files are never executed or modified; no network calls or subprocesses occur. A Windows live-host scan is a separate roadmap item, outside this read-only artifact inspector.

Sources: [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [application manifests](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests), and [Authenticode overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode).

## MSIX, APPX and bundles

ZIP content identifies `windows-msix`, regardless of filename extension: a root `AppxManifest.xml`, root `AppxBundleManifest.xml`, or standard `AppxMetadata/AppxBundleManifest.xml`. Detection inspects the central directory, not compressed payloads. Unlike the small PE header probe, ZIP detection requires up to 65,557 bytes for the end-record search and up to 16 MiB of directory metadata (read again by `archive/zip`). ZIP64 offsets are accepted; multi-disk archives are not. Directory counts and lengths are checked before allocating the ZIP file list. At most 20,000 entries are accepted per archive.

Manifest parsing matches XML local names across namespace prefixes. It reports identity, display properties, dependencies, applications, capability declarations, extension attributes/typed children and content URI rules. Resource references such as `ms-resource:` are retained without resolution. XML is limited to 16 MiB, 10,000 elements, 64 nesting levels, 128 attributes per element, 64 KiB text per element and 2,048 findings. Invalid or over-limit XML produces a skip note with no partial manifest claims. Unknown capabilities and extensions remain raw informational declarations; no permission grant or actual activation is inferred.

`AppxSignature.p7x` is parsed as `PKCX` followed by PKCS#7 SignedData, reusing the PE parser. Signer subjects, validity, digest and timestamp declarations are reported without verification. Publisher comparison is textual: equivalent distinguished names with different ordering or encoding can differ. A missing signature, an ambiguous duplicate signature, and a present but unparsable signature are distinguished. A manifest failure does not stop independent signature or executable inspection.

Declared application executables are inspected first in sorted path order, then other `.exe` entries. A report analyses at most 20 PEs, including all selected bundle applications. Each executable is read into memory and passed to the existing ReaderAt PE analyser; nothing is extracted. Compressed and expanded entry reads are capped at 256 MiB (metadata/signatures at 16 MiB), with a 512 MiB cumulative expanded-read budget per report. The aggregate budget includes nested ZIP bytes and their selected contents. Cap hits and missing declared executables are explicit skips. Counts and executable names describe the package layout. Unsafe paths, symlink/non-regular entries, and case-insensitive duplicate names are skipped. Windows backslashes in manifest executable paths are normalized; archive entries use ZIP forward slashes.

Bundles list every declared application/resource package, including architecture and resource ID. At most four unique application packages are inspected in sorted filename order. Resource packages are listed only. Nesting is limited to one bundle-to-package level; a bundle within a bundle is skipped.

An unpacked folder with a root `AppxManifest.xml` runs the same manifest analysis and reads only its declared application executables, using safe disk opens without following internal symlinks. It does not run portable-folder discovery or assess a package signature. Manifest executable casing must match the filesystem on case-sensitive hosts.

Generated examples: [synthetic MSIX Markdown](../examples/windows-msix.md), [JSON](../examples/windows-msix.json). To regenerate without `go run`, set `UNDERHOOD_MSIX_FIXTURE` to a scratch destination and run `go test ./internal/analyzers/windows -run '^TestWriteMSIXExample$' -count=1`, then inspect that package with the CLI from its directory.
