# Windows static inspection

Windows PE files and portable/installed app folders are available on macOS, Linux and Windows. MSIX/APPX packages, bundles and unpacked MSIX manifests are **Planned next**. A folder with root `AppxManifest.xml` produces a deferred-analysis skip and no PE analysis.

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
