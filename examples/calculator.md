# Underhood: Calculator

**ID:** com.apple.calculator  
**Version / build:** 12.0 / 225  
**Path:** /System/Applications/Calculator.app  
**Tool version:** 0.1.0-dev  
**Scanned at:** 2026-10-14T15:51:02.827072Z

## Summary

- Requests 2 sandbox temporary exceptions: files.absolute-path.read-only, mach-lookup.global-name
- Declares App Intents / Shortcuts actions (30 metadata entries)
- Requests access to user-selected files
- Allows outgoing network connections
- 3 distinct hosts found as strings in binaries; strings are not proof of traffic
- App Sandbox enabled

I = info, N = notable, S = sensitive; D = declared, B = found-in-binary, H = heuristic. Use --full or JSON for every evidence entry.

## identity

**CFBundleDisplayName** · I/D · `bundle.CFBundleDisplayName`  
Contents/Info.plist · CFBundleDisplayName = Calculator

**CFBundleIdentifier** · I/D · `bundle.CFBundleIdentifier`  
Contents/Info.plist · CFBundleIdentifier = com.apple.calculator

**CFBundleName** · I/D · `bundle.CFBundleName`  
Contents/Info.plist · CFBundleName = Calculator

**CFBundleShortVersionString** · I/D · `bundle.CFBundleShortVersionString`  
Contents/Info.plist · CFBundleShortVersionString = 12.0

**CFBundleVersion** · I/D · `bundle.CFBundleVersion`  
Contents/Info.plist · CFBundleVersion = 225

**LSMinimumSystemVersion** · I/D · `bundle.LSMinimumSystemVersion`  
Contents/Info.plist · LSMinimumSystemVersion = 27.0

**Architectures** · I/B · `bundle.architectures`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/CPU = arm64e

**App Sandbox presence** · I/D · `bundle.sandbox`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.app-sandbox = true

### Nested bundles

| Path | Bundle ID | Version | Build | Sandbox |
| --- | --- | --- | --- | --- |
| Contents/PlugIns/CalculatorWidget.appex | com.apple.calculator.CalculatorWidget | 11.0 | 224 | true |

## signing

**Signing authority chain** · I/D · `sign.authorities`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/CMS/certificate[0] = macOS Software Signing

**Signing authority chain** · I/D · `sign.authorities@Contents/PlugIns/CalculatorWidget.appex`  
Contents/PlugIns/CalculatorWidget.appex/Contents/MacOS/CalculatorWidget · Mach-O arm64e slice at byte 16384/CMS/certificate[0] = macOS Software Signing

**Code signature flags** · I/D · `sign.flags`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/CodeDirectory slot 0x0/flags = flags=0x0()

**Code signature flags** · I/D · `sign.flags@Contents/PlugIns/CalculatorWidget.appex`  
Contents/PlugIns/CalculatorWidget.appex/Contents/MacOS/CalculatorWidget · Mach-O arm64e slice at byte 16384/CodeDirectory slot 0x0/flags = flags=0x0()

**Signing team** · I/D · `sign.team`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/CodeDirectory slot 0x0/teamID = not set

**Signing team** · I/D · `sign.team@Contents/PlugIns/CalculatorWidget.appex`  
Contents/PlugIns/CalculatorWidget.appex/Contents/MacOS/CalculatorWidget · Mach-O arm64e slice at byte 16384/CodeDirectory slot 0x0/teamID = not set


## entitlements

**com.apple.private.coreservices.canmaplsdatabase** · I/D · `ent.com.apple.private.coreservices.canmaplsdatabase`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.private.coreservices.canmaplsdatabase = true

**com.apple.private.hid.client.event-dispatch.internal** · I/D · `ent.com.apple.private.hid.client.event-dispatch.internal`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.private.hid.client.event-dispatch.internal = true

**com.apple.runningboard.terminateprocess** · I/D · `ent.com.apple.runningboard.terminateprocess`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.runningboard.terminateprocess = true

**com.apple.security.app-sandbox** · I/D · `ent.com.apple.security.app-sandbox`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.app-sandbox = true
App Sandbox entitlement

**com.apple.security.app-sandbox** · I/D · `ent.com.apple.security.app-sandbox@Contents/PlugIns/CalculatorWidget.appex`  
Contents/PlugIns/CalculatorWidget.appex/Contents/MacOS/CalculatorWidget · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.app-sandbox = true
App Sandbox entitlement

**com.apple.security.exception.shared-preference.read-only** · I/D · `ent.com.apple.security.exception.shared-preference.read-only`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.exception.shared-preference.read-only = ["com.apple.calculator"]

**com.apple.security.exception.shared-preference.read-write** · I/D · `ent.com.apple.security.exception.shared-preference.read-write`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.exception.shared-preference.read-write = ["com.apple.internal.testplatform"]

**com.apple.security.files.user-selected.read-write** · N/D · `ent.com.apple.security.files.user-selected.read-write`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.files.user-selected.read-write = true
Requests access to user-selected files

**com.apple.security.network.client** · N/D · `ent.com.apple.security.network.client`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.network.client = true
Allows outgoing network connections

**com.apple.security.print** · I/D · `ent.com.apple.security.print`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.print = true

**com.apple.security.temporary-exception.files.absolute-path.read-only** · S/D · `ent.com.apple.security.temporary-exception.files.absolute-path.read-only`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.temporary-exception.files.absolute-path.read-only = ["/Library/Managed Preferences/"]
Requests a sandbox exception; exception targets/values follow

**com.apple.security.temporary-exception.mach-lookup.global-name** · S/D · `ent.com.apple.security.temporary-exception.mach-lookup.global-name`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.temporary-exception.mach-lookup.global-name = ["com.apple.managedconfiguration.profiled","com.apple.ManagedSettingsAgent","com.apple.internal.xctestinternalangel.sessions"]
Requests a sandbox exception; exception targets/values follow

**file-read-data** · I/D · `ent.file-read-data`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/file-read-data = true

**file-write-data** · I/D · `ent.file-write-data`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/file-write-data = true

**user-preference-read** · I/D · `ent.user-preference-read`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/user-preference-read = true

**user-preference-write** · I/D · `ent.user-preference-write`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/user-preference-write = true


## permissions

none found

## registrations

none found

## launchItems

none found

## automation

**App Intent identifier** · N/D · `automation.action@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions/dictionary key = LaunchCalculatorOpenIntent

**App Intent identifier** · N/D · `automation.action@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent`  
Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions/dictionary key = LaunchCalculatorOpenIntent

**App Intents metadata** · N/D · `automation.appintents@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · metadata file = extract.actionsdata

**App Intents metadata** · N/D · `automation.appintents@Contents/Resources/Metadata.appintents/extract.actionsdata`  
Contents/Resources/Metadata.appintents/extract.actionsdata · metadata file = extract.actionsdata

**App Intent identifier/title field** · N/D · `automation.intent@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.identifier`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.identifier = LaunchCalculatorOpenIntent

**App Intent identifier/title field** · N/D · `automation.intent@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].name`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.parameters[0].name = target

**App Intent identifier/title field** · N/D · `automation.intent@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].valueType.linkEnumeration.wrapper.identifier`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.parameters[0].valueType.linkEnumeration.wrapper.identifier = CalculatorAppView

**App Intent identifier/title field** · N/D · `automation.intent@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].identifier`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].identifier = app

**App Intent identifier/title field** · N/D · `automation.intent@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.identifier`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.identifier = CalculatorAppView

**App Intent identifier/title field** · N/D · `automation.intent@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].cases[0].identifier`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.enums[0].cases[0].identifier = app

**App Intent identifier/title field** · N/D · `automation.intent@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].identifier`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.enums[0].identifier = CalculatorAppView

**App Intent identifier/title field** · N/D · `automation.intent@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.generator.name`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.generator.name = xcode-tools

**App Intent identifier/title field** · N/D · `automation.intent@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.identifier`  
Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.identifier = LaunchCalculatorOpenIntent

**App Intent identifier/title field** · N/D · `automation.intent@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].name`  
Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.parameters[0].name = target

**App Intent title** · N/D · `automation.title@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.descriptionMetadata.categoryName.title`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.descriptionMetadata.categoryName.title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].title`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.parameters[0].title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.title`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].displayRepresentation.title`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].displayRepresentation.title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].cases[0].displayRepresentation.title`  
Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata · $.enums[0].cases[0].displayRepresentation.title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.descriptionMetadata.categoryName.title`  
Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.descriptionMetadata.categoryName.title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].title`  
Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.parameters[0].title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.title`  
Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].displayRepresentation.title`  
Contents/Resources/Metadata.appintents/extract.actionsdata · $.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].displayRepresentation.title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**App Intent title** · N/D · `automation.title@Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].cases[0].displayRepresentation.title`  
Contents/Resources/Metadata.appintents/extract.actionsdata · $.enums[0].cases[0].displayRepresentation.title = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

automation.intent: … and 6 more (use --full or JSON)


## network

**Allows outgoing network connections** · N/D · `net.entitlement.com.apple.security.network.client`  
Contents/MacOS/Calculator · Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.network.client = true

URL string present in a binary, not verified traffic. Counts reflect retained distinct URL evidence (caps may apply). Finding ID = net.host.<host>.

| Host | #URLs | Example |
| --- | ---: | --- |
| crl.apple.com | 2 | http://crl.apple.com/root.crl0 |
| ocsp.apple.com | 2 | http://ocsp.apple.com/ocsp03-applerootca0 |
| www.apple.com | 1 | https://www.apple.com/appleca/0 |

## Skipped analyses and bounded scans

None.

## Limits of this scan

- App Intents and AppleScript detection is best-effort; none found does not mean none exist.
- Apps may behave differently from what they declare.
- Gatekeeper and notarization status are not assessed.
- Runtime permission grants (TCC) are not visible.
- Runtime-built URLs and server-driven behaviour are invisible.
- SDK names are heuristic evidence of inclusion, not proof of use. Findings are not a verdict of safety.
- Signatures are parsed, not cryptographically verified. Certificate names are unverified declarations.
- Static analysis only; the target app and its bundled binaries are never executed.
- Strings in a binary are not proof of network traffic; endpoints are not verified traffic.
- Symlinks are not traversed; nested bundles are limited to depth 4, inventory to 20,000 entries, and metadata to 16 MiB per file. Reached caps are reported.
