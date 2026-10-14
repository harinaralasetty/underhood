# Underhood: Calculator

**ID:** com.apple.calculator  
**Version / build:** 12.0 / 225  
**Path:** /System/Applications/Calculator.app  
**Tool version:** 0.1.0-dev  
**Scanned at:** 2026-10-14T15:25:50.703546Z

## Summary

- com.apple.security.temporary-exception.files.absolute-path.read-only [ent.com.apple.security.temporary-exception.files.absolute-path.read-only]
- App Intent identifier (2 findings) [automation.action@P7, automation.action@P22]
- Allows outgoing network connections [net.entitlement.com.apple.security.network.client]
- CFBundleDisplayName (2 findings) [bundle.CFBundleDisplayName, bundle.CFBundleDisplayName@P3]
- Signing authority chain (2 findings) [sign.authorities, sign.authorities@P3]
- com.apple.security.temporary-exception.mach-lookup.global-name [ent.com.apple.security.temporary-exception.mach-lookup.global-name]
- App Intents metadata (2 findings) [automation.appintents@P6, automation.appintents@P21]
- App Intent identifier/title field (16 findings) [automation.intent@P9, automation.intent@P10, automation.intent@P12, automation.intent@P15, automation.intent@P16, automation.intent@P18, automation.intent@P19, automation.intent@P20, automation.intent@P24, automation.intent@P25, automation.intent@P27, automation.intent@P30, automation.intent@P31, automation.intent@P33, automation.intent@P34, automation.intent@P35]

Compact view: each block starts with its finding ID. P/L references expand to exact paths/locators below; @P expands the ID suffix. One evidence entry per finding; --full or JSON includes all entries and full descriptions. I = info, N = notable, S = sensitive; D = declared, B = found-in-binary, H = heuristic.

## identity

**bundle.CFBundleDisplayName** [I/D]  
P1/L15 = Calculator

**bundle.CFBundleDisplayName@P3** [I/D]  
P4/L15 = CalculatorWidget

**bundle.CFBundleIdentifier** [I/D]  
P1/L16 = com.apple.calculator

**bundle.CFBundleIdentifier@P3** [I/D]  
P4/L16 = com.apple.calculator.CalculatorWidget

**bundle.CFBundleName** [I/D]  
P1/L17 = Calculator

**bundle.CFBundleName@P3** [I/D]  
P4/L17 = CalculatorWidget

**bundle.CFBundleShortVersionString** [I/D]  
P1/L18 = 12.0

**bundle.CFBundleShortVersionString@P3** [I/D]  
P4/L18 = 11.0

**bundle.CFBundleVersion** [I/D]  
P1/L19 = 225

**bundle.CFBundleVersion@P3** [I/D]  
P4/L19 = 224

**bundle.LSMinimumSystemVersion** [I/D]  
P1/L20 = 27.0

**bundle.LSMinimumSystemVersion@P3** [I/D]  
P4/L20 = 27.0

**bundle.architectures** [I/B] (+1 evidence)  
P2/L22 = arm64e

**bundle.sandbox** [I/D] (+1 evidence)  
P2/L28 = true


## signing

**sign.authorities** [I/D] (+5 evidence)  
P2/L21 = macOS Software Signing

**sign.authorities@P3** [I/D] (+5 evidence)  
P5/L21 = macOS Software Signing

**sign.flags** [I/D] (+3 evidence)  
P2/L23 = flags=0x0()

**sign.flags@P3** [I/D] (+3 evidence)  
P5/L23 = flags=0x0()

**sign.team** [I/D] (+1 evidence)  
P2/L24 = not set

**sign.team@P3** [I/D] (+1 evidence)  
P5/L24 = not set


## entitlements

**ent.com.apple.private.coreservices.canmaplsdatabase** [I/D] (+1 evidence)  
P2/L25 = true

**ent.com.apple.private.hid.client.event-dispatch.internal** [I/D] (+1 evidence)  
P2/L26 = true

**ent.com.apple.runningboard.terminateprocess** [I/D] (+1 evidence)  
P2/L27 = true

**ent.com.apple.security.app-sandbox** [I/D] (+1 evidence)  
P2/L28 = true
App Sandbox entitlement

**ent.com.apple.security.app-sandbox@P3** [I/D] (+1 evidence)  
P5/L28 = true
App Sandbox entitlement

**ent.com.apple.security.exception.shared-preference.read-only** [I/D] (+1 evidence)  
P2/L29 = ["com.apple.calculator"]

**ent.com.apple.security.exception.shared-preference.read-write** [I/D] (+1 evidence)  
P2/L30 = ["com.apple.internal.testplatform"]

**ent.com.apple.security.files.user-selected.read-write** [N/D] (+1 evidence)  
P2/L31 = true
Requests access to user-selected files

**ent.com.apple.security.network.client** [N/D] (+1 evidence)  
P2/L32 = true
Allows outgoing network connections

**ent.com.apple.security.print** [I/D] (+1 evidence)  
P2/L33 = true

**ent.com.apple.security.temporary-exception.files.absolute-path.read-only** [S/D] (+1 evidence)  
P2/L34 = ["/Library/Managed Preferences/"]
Requests a sandbox exception; exception targets/values follow

**ent.com.apple.security.temporary-exception.mach-lookup.global-name** [S/D] (+1 evidence)  
P2/L35 = ["com.apple.managedconfiguration.profiled","com.apple.ManagedSettingsAgent","com.apple.internal.xctestinternalangel.sessions"]
Requests a sandbox exception; exception targets/values follow

**ent.file-read-data** [I/D] (+1 evidence)  
P2/L36 = true

**ent.file-write-data** [I/D] (+1 evidence)  
P2/L37 = true

**ent.user-preference-read** [I/D] (+1 evidence)  
P2/L38 = true

**ent.user-preference-write** [I/D] (+1 evidence)  
P2/L39 = true


## permissions

none found

## registrations

none found

## launchItems

none found

## automation

**automation.action@P7** [N/D]  
P6/L10 = LaunchCalculatorOpenIntent

**automation.action@P22** [N/D]  
P21/L10 = LaunchCalculatorOpenIntent

**automation.appintents@P6** [N/D]  
P6/L40 = extract.actionsdata

**automation.appintents@P21** [N/D]  
P21/L40 = extract.actionsdata

**automation.intent@P9** [N/D]  
P6/L2 = LaunchCalculatorOpenIntent

**automation.intent@P10** [N/D]  
P6/L3 = target

**automation.intent@P12** [N/D]  
P6/L5 = CalculatorAppView

**automation.intent@P15** [N/D]  
P6/L8 = app

**automation.intent@P16** [N/D]  
P6/L9 = CalculatorAppView

**automation.intent@P18** [N/D]  
P6/L12 = app

**automation.intent@P19** [N/D]  
P6/L13 = CalculatorAppView

**automation.intent@P20** [N/D]  
P6/L14 = xcode-tools

**automation.intent@P24** [N/D]  
P21/L2 = LaunchCalculatorOpenIntent

**automation.intent@P25** [N/D]  
P21/L3 = target

**automation.intent@P27** [N/D]  
P21/L5 = CalculatorAppView

**automation.intent@P30** [N/D]  
P21/L8 = app

**automation.intent@P31** [N/D]  
P21/L9 = CalculatorAppView

**automation.intent@P33** [N/D]  
P21/L12 = app

**automation.intent@P34** [N/D]  
P21/L13 = CalculatorAppView

**automation.intent@P35** [N/D]  
P21/L14 = xcode-tools

**automation.title@P8** [N/D]  
P6/L1 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P11** [N/D]  
P6/L4 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P13** [N/D]  
P6/L6 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P14** [N/D]  
P6/L7 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P17** [N/D]  
P6/L11 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P23** [N/D]  
P21/L1 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P26** [N/D]  
P21/L4 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P28** [N/D]  
P21/L6 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P29** [N/D]  
P21/L7 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}

**automation.title@P32** [N/D]  
P21/L11 = {"alternatives":[],"key":"Calculator","table":"WidgetLocalizable"}


## network

**net.entitlement.com.apple.security.network.client** [N/D] (+1 evidence)  
P2/L32 = true

URL string present in a binary, not verified traffic. Counts reflect retained distinct URL evidence (caps may apply). Finding ID = net.host.<host>.

| Host | #URLs | Example |
| --- | ---: | --- |
| crl.apple.com | 2 | http://crl.apple.com/root.crl0 |
| ocsp.apple.com | 2 | http://ocsp.apple.com/ocsp03-applerootca0 |
| www.apple.com | 1 | https://www.apple.com/appleca/0 |

## Evidence reference key

- P1: Contents/Info.plist
- P2: Contents/MacOS/Calculator
- P3: Contents/PlugIns/CalculatorWidget.appex
- P4: Contents/PlugIns/CalculatorWidget.appex/Contents/Info.plist
- P5: Contents/PlugIns/CalculatorWidget.appex/Contents/MacOS/CalculatorWidget
- P6: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata
- P7: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent
- P8: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.descriptionMetadata.categoryName.title
- P9: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.identifier
- P10: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].name
- P11: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].title
- P12: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].valueType.linkEnumeration.wrapper.identifier
- P13: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.title
- P14: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].displayRepresentation.title
- P15: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].identifier
- P16: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.identifier
- P17: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].cases[0].displayRepresentation.title
- P18: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].cases[0].identifier
- P19: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].identifier
- P20: Contents/PlugIns/CalculatorWidget.appex/Contents/Resources/Metadata.appintents/extract.actionsdata:$.generator.name
- P21: Contents/Resources/Metadata.appintents/extract.actionsdata
- P22: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent
- P23: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.descriptionMetadata.categoryName.title
- P24: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.identifier
- P25: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].name
- P26: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].title
- P27: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.parameters[0].valueType.linkEnumeration.wrapper.identifier
- P28: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.title
- P29: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].displayRepresentation.title
- P30: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].identifier
- P31: Contents/Resources/Metadata.appintents/extract.actionsdata:$.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.identifier
- P32: Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].cases[0].displayRepresentation.title
- P33: Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].cases[0].identifier
- P34: Contents/Resources/Metadata.appintents/extract.actionsdata:$.enums[0].identifier
- P35: Contents/Resources/Metadata.appintents/extract.actionsdata:$.generator.name
- L1: $.actions.LaunchCalculatorOpenIntent.descriptionMetadata.categoryName.title
- L2: $.actions.LaunchCalculatorOpenIntent.identifier
- L3: $.actions.LaunchCalculatorOpenIntent.parameters[0].name
- L4: $.actions.LaunchCalculatorOpenIntent.parameters[0].title
- L5: $.actions.LaunchCalculatorOpenIntent.parameters[0].valueType.linkEnumeration.wrapper.identifier
- L6: $.actions.LaunchCalculatorOpenIntent.title
- L7: $.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].displayRepresentation.title
- L8: $.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.cases[0].identifier
- L9: $.actions.LaunchCalculatorOpenIntent.typeSpecificMetadata[1].enumMetadata.wrapper.identifier
- L10: $.actions/dictionary key
- L11: $.enums[0].cases[0].displayRepresentation.title
- L12: $.enums[0].cases[0].identifier
- L13: $.enums[0].identifier
- L14: $.generator.name
- L15: CFBundleDisplayName
- L16: CFBundleIdentifier
- L17: CFBundleName
- L18: CFBundleShortVersionString
- L19: CFBundleVersion
- L20: LSMinimumSystemVersion
- L21: Mach-O arm64e slice at byte 16384/CMS/certificate[0]
- L22: Mach-O arm64e slice at byte 16384/CPU
- L23: Mach-O arm64e slice at byte 16384/CodeDirectory slot 0x0/flags
- L24: Mach-O arm64e slice at byte 16384/CodeDirectory slot 0x0/teamID
- L25: Mach-O arm64e slice at byte 16384/entitlements/com.apple.private.coreservices.canmaplsdatabase
- L26: Mach-O arm64e slice at byte 16384/entitlements/com.apple.private.hid.client.event-dispatch.internal
- L27: Mach-O arm64e slice at byte 16384/entitlements/com.apple.runningboard.terminateprocess
- L28: Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.app-sandbox
- L29: Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.exception.shared-preference.read-only
- L30: Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.exception.shared-preference.read-write
- L31: Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.files.user-selected.read-write
- L32: Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.network.client
- L33: Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.print
- L34: Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.temporary-exception.files.absolute-path.read-only
- L35: Mach-O arm64e slice at byte 16384/entitlements/com.apple.security.temporary-exception.mach-lookup.global-name
- L36: Mach-O arm64e slice at byte 16384/entitlements/file-read-data
- L37: Mach-O arm64e slice at byte 16384/entitlements/file-write-data
- L38: Mach-O arm64e slice at byte 16384/entitlements/user-preference-read
- L39: Mach-O arm64e slice at byte 16384/entitlements/user-preference-write
- L40: metadata file

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
