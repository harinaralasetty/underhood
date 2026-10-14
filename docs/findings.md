# Finding catalogue

Suffix `@<relative-path>` identifies a nested bundle or standalone binary; the main app normally has no suffix. `<key>` and array indices retain their raw declaration names. Categories, titles and severity rules follow the reference implementation; tool-command locators are replaced by parsed source locations.

| ID pattern | Category | Severity | Confidence |
| --- | --- | --- | --- |
| `bundle.<Info-key>` | identity | info | declared |
| `bundle.architectures` | identity | info | found-in-binary |
| `bundle.sandbox` | identity | info when enabled, sensitive otherwise | declared |
| `sign.unsigned` | signing | notable | declared |
| `sign.adhoc` | signing | notable | declared |
| `sign.flags`, `sign.team`, `sign.authorities` | signing | info | declared |
| `ent.<key>` / `ent.apple-events` | entitlements | mapped below; disabled declarations info | declared |
| `ent.no-sandbox` | entitlements | sensitive | declared |
| `privacy.NS*UsageDescription` | permissions | notable | declared |
| `url.scheme.<scheme>`, `url.applinks:<domain>` | registrations | notable | declared |
| `registration.<key>.<index>` | registrations | info | declared |
| `launch.plist@<path>` | launchItems | notable | declared |
| `launch.embedded@<path>` | launchItems | notable | heuristic |
| `launch.SMPrivilegedExecutables`, `launch.SMAuthorizedClients` | launchItems | sensitive | declared |
| `automation.<Info-key>`, `automation.sdef@<path>`, `automation.sdef.<kind>.<name>@<path>` | automation | notable | declared |
| `automation.intentdefinition@<path>`, `automation.appintents@<path>` | automation | notable | declared |
| `automation.action@<path>:<locator>`, `automation.title@<path>:<locator>`, `automation.intent@<path>:<locator>` | automation | notable | declared |
| `net.ats.<key>` | network | sensitive for enabled NSAllowsArbitraryLoads*, otherwise info | declared |
| `net.ats.domain.<domain>` | network | notable | declared |
| `net.self-updater.<key>` | network | notable | declared |
| `net.entitlement.<key>` | network | notable when enabled, otherwise info | declared |
| `net.sdk.<name>` | network | notable | heuristic |
| `net.host.<host>` | network | notable | found-in-binary |

Sensitive entitlement mappings: library-validation disabled, DYLD environment variables allowed, debugger task access, and temporary sandbox exceptions. Network, device access, personal information, automation, executable memory/JIT, associated domains, shared containers/keychains and file access map to notable. App Sandbox and unmapped entitlements are info. False/zero declarations are info. The exact plain-English table is in `internal/analyzers/macos/entitlements.go`.

No `sign.stapled-ticket` finding is emitted: Gatekeeper and notarization are not assessed. Unknown/malformed signing data does not imply absent entitlements. DER-only entitlements are not decoded. Certificate common names describe parsed, unverified metadata. SDK matches and endpoint strings never establish actual use or traffic.

## Windows PE findings

All Windows IDs may carry `@<relative-path>` when analysing a folder or future package entry. Raw header/resource declarations use `declared`; import capability interpretations use `heuristic`; URL and persistence strings use `found-in-binary`.

| ID pattern | Category | Severity / meaning |
| --- | --- | --- |
| `windows.identity.*` | identity | info: machine, EXE/DLL, timestamp, subsystem, versions/image size, CLR presence |
| `windows.version.<key>`, `windows.version.fixed`, `windows.version.fixedInfo` | identity | info: selected StringFileInfo keys and fixed file info |
| `windows.folder.inventory` | identity | info: PE/.dll counts and uninstaller names |
| `windows.manifest.requestedExecutionLevel` | windows-manifest | requireAdministrator sensitive; highestAvailable notable; asInvoker info |
| `windows.manifest.uiAccess`, `windows.manifest.autoElevate` | windows-manifest | true sensitive, other values info |
| `windows.manifest.longPathAware`, `.dpiAware`, `.dpiAwareness`, `.supportedOS`, `.dependentAssembly`, `.disableWindowFiltering` | windows-manifest | info: embedded XML values |
| `windows.hardening.*` | hardening | absent ASLR/NX/CFG notable; remaining flags info; no enforcement inference |
| `windows.section.<index>` | sections | executable+writable notable; other sections info |
| `windows.pe.unsigned` | signing | notable: no Authenticode certificate table |
| `windows.pe.signature`, `windows.pe.signature-unparsable` | signing | parsed metadata or explicit parse failure; no trust/hash verification |
| `windows.imports.libraries` | imports | info, declared: static DLL names |
| `windows.imports.<cluster>` | imports | heuristic, table below |
| `net.host.<host>` | network | notable: URL string; not verified traffic |
| `windows.persistence.<index>` | capabilities | notable: string present, not proof of use |

The authoritative import table is `internal/analyzers/windows/imports.go`. Each cluster retains at most ten matched DLL/symbol evidence entries and reports truncation. Matching ignores case; `*` denotes API suffix variants.

| Cluster | DLL or symbol matches | Severity |
| --- | --- | --- |
| network | ws2_32, wsock32, wininet, winhttp, urlmon, httpapi, dnsapi | notable |
| crypto | bcrypt, ncrypt, crypt32 | info |
| process | OpenProcess, WriteProcessMemory, VirtualAllocEx, CreateRemoteThread, NtUnmapViewOfSection, QueueUserAPC, SetThreadContext | notable |
| input | SetWindowsHookEx*, GetAsyncKeyState, RegisterRawInputDevices | notable |
| services | CreateService*, StartServiceCtrlDispatcher* | notable |
| privilege | AdjustTokenPrivileges, LookupPrivilegeValue* | notable |
| clipboard | GetClipboardData | notable |
| debugger | IsDebuggerPresent, CheckRemoteDebuggerPresent | notable |
| dynamic | LoadLibrary*, GetProcAddress | info; imports under-report dynamically resolved APIs |

These APIs are common in legitimate tools and in malware; presence does not establish use. The cluster names summarize API families, not actual runtime behavior. No tiny-import/packing heuristic is emitted.

Persistence matches (case-insensitive ASCII/UTF-16LE): `\CurrentVersion\Run`, `\CurrentVersion\RunOnce`, `\Services\`, `\Winlogon\`, `Image File Execution Options`, `schtasks`, `\Startup\`. These do not establish a registry write or scheduled task.

Sources: [PE format, imports, resources and flags](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), [manifest declarations](https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests), [process functions](https://learn.microsoft.com/en-us/windows/win32/procthread/process-and-thread-functions), [Winsock](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-start-page-2), [service functions](https://learn.microsoft.com/en-us/windows/win32/services/service-functions), [dynamic linking](https://learn.microsoft.com/en-us/windows/win32/dlls/run-time-dynamic-linking).
