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
