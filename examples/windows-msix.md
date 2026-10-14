# Underhood: Synthetic Windows App

**ID:** Underhood.Synthetic  
**Version / build:** 1.2.3.0  
**Path:** synthetic.msix  
**Tool version:** 0.1.0-dev  
**Scanned at:** 2026-10-14T16:19:04.846981Z

## Summary

- Declares a full-trust process
- Declares a LocalSystem service
- Declares 2 restricted capabilities: broadFileSystemAccess, runFullTrust
- Control Flow Guard not declared
- Network APIs
- Declares 4 capabilities: Synthetic.Custom, documentsLibrary, internetClient, microphone
- Declares content URI rule
- Embedded executable not signed

I = info, N = notable, S = sensitive; D = declared, B = found-in-binary, H = heuristic. Use --full or JSON for every evidence entry.

## identity

**Package contents** · I/D · `windows.msix.contents`  
. · zip entries = 4 entries; 1 executable files
Counts describe safe, unambiguous entries; executable names do not establish execution.

**Package dependency** · I/D · `windows.msix.dependency.PackageDependency`  
AppxManifest.xml · Dependencies/PackageDependency = MinVersion=1.0.0.0; Name=Synthetic.Framework
Declared dependency; installation is not checked.

**Package dependency** · I/D · `windows.msix.dependency.TargetDeviceFamily`  
AppxManifest.xml · Dependencies/TargetDeviceFamily = MaxVersionTested=10.0.26100.0; MinVersion=10.0.19041.0; Name=Windows.Desktop
Declared dependency; installation is not checked.

**Package identity** · I/D · `windows.msix.identity`  
AppxManifest.xml · Identity = Name=Underhood.Synthetic; ProcessorArchitecture=x64; Publisher=CN=Synthetic signer,O=Underhood test; Version=1.2.3.0
Manifest identity declaration.

**DisplayName** · I/D · `windows.msix.property.DisplayName`  
AppxManifest.xml · Properties/DisplayName = Synthetic Windows App
Manifest property; resource references are not resolved.

**PublisherDisplayName** · I/D · `windows.msix.property.PublisherDisplayName`  
AppxManifest.xml · Properties/PublisherDisplayName = Underhood test
Manifest property; resource references are not resolved.


## signing

**Package signature present** · I/D · `windows.msix.signature`  
AppxSignature.p7x · signer[0].subject = CN=Synthetic signer,O=Underhood test
Authenticode/MSIX signatures are parsed but not cryptographically verified; trust, revocation and timestamp validity are not assessed.

**Unsigned** · N/D · `windows.pe.unsigned@bin/app.exe`  
bin/app.exe · Security directory = absent
No Authenticode certificate table is declared. Authenticode/MSIX signatures are parsed but not cryptographically verified; trust, revocation and timestamp validity are not assessed.


## network

**Declares content URI rule** · N/D · `windows.msix.uri-rule`  
AppxManifest.xml · /Package/Applications/Application/ApplicationContentUriRules/Rule = Match=https://synthetic.example.org/*; Type=include
A manifest URL rule, not observed network traffic.


## Windows application manifest

**Requested execution level** · I/D · `windows.manifest.requestedExecutionLevel@bin/app.exe`  
bin/app.exe · .rsrc/RT_MANIFEST/1/1033/requestedExecutionLevel = asInvoker

**Application declaration** · I/D · `windows.msix.application`  
AppxManifest.xml · /Package/Applications/Application = EntryPoint=windows.fullTrustApplication; Executable=bin\\app.exe; Id=App; RuntimeBehavior=packagedClassicApp; TrustLevel=mediumIL
Declared executable, entry point, runtime behavior and trust level.

**Registers command aliases** · I/D · `windows.msix.extension.windows.appExecutionAlias`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/AppExecutionAlias/ExecutionAlias = Alias=synthetic.exe
Raw extension declaration; activation is not observed.

**Declares an app service** · I/D · `windows.msix.extension.windows.appService`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/AppService = Name=SyntheticAppService
Raw extension declaration; activation is not observed.

**Registers web URI hosts** · I/D · `windows.msix.extension.windows.appUriHandler`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/AppUriHandler/Host = Name=synthetic.example.org
Raw extension declaration; activation is not observed.

**Declares background tasks** · I/D · `windows.msix.extension.windows.backgroundTasks`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/BackgroundTasks/Task = Type=timer
Raw extension declaration; activation is not observed.

**Registers a COM server** · I/D · `windows.msix.extension.windows.comServer`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/ComServer/ExeServer = Executable=bin\\app.exe
Raw extension declaration; activation is not observed.

**Registers file types** · I/D · `windows.msix.extension.windows.fileTypeAssociation`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/FileTypeAssociation = Name=synthetic
Raw extension declaration; activation is not observed.

**Declares firewall rules** · N/D · `windows.msix.extension.windows.firewallRules`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/FirewallRules/Rule = Direction=in; IPProtocol=TCP; LocalPortMax=4242; LocalPortMin=4242
Declared directions, protocols and ports; effective firewall configuration is not inspected.

**Declares a full-trust process** · S/D · `windows.msix.extension.windows.fullTrustProcess`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/FullTrustProcess = Executable=bin\\app.exe
Declares a process outside the app sandbox with the user's privileges.

**Registers a URL protocol** · I/D · `windows.msix.extension.windows.protocol`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/Protocol = Name=synthetic
Raw extension declaration; activation is not observed.

**Declares a LocalSystem service** · S/D · `windows.msix.extension.windows.service`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/Service = Name=SyntheticService; StartAccount=localSystem; StartupType=auto
The declared service runs as LocalSystem; installation and execution are not assessed.

**Registers a share target** · I/D · `windows.msix.extension.windows.shareTarget`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/ShareTarget/DataFormat = Text
Raw extension declaration; activation is not observed.

**Declares a startup task** · N/D · `windows.msix.extension.windows.startupTask`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/StartupTask = DisplayName=Synthetic startup; Enabled=true; TaskId=SyntheticTask
Declares a task that can run at sign-in; Enabled is the manifest setting, not current user state.

**Declares extension: windows.syntheticUnknown** · I/D · `windows.msix.extension.windows.syntheticUnknown`  
AppxManifest.xml · /Package/Applications/Application/Extensions/Extension/Unknown = Name=raw
Raw extension declaration; activation is not observed.


## Capabilities

**Declares capability: Synthetic.Custom** · I/D · `windows.msix.capability.Synthetic.Custom`  
AppxManifest.xml · Capabilities/CustomCapability/@Name = Synthetic.Custom
Unmapped capability (raw declaration). Declaration does not establish permission grant or use.

**Declares capability: documentsLibrary** · N/D · `windows.msix.capability.documentsLibrary`  
AppxManifest.xml · Capabilities/Capability/@Name = documentsLibrary
Requests access to the documents library. Declaration does not establish permission grant or use.

**Declares capability: internetClient** · N/D · `windows.msix.capability.internetClient`  
AppxManifest.xml · Capabilities/Capability/@Name = internetClient
Requests outbound internet access. Declaration does not establish permission grant or use.

**Declares capability: microphone** · N/D · `windows.msix.capability.microphone`  
AppxManifest.xml · Capabilities/DeviceCapability/@Name = microphone
Requests microphone access. Declaration does not establish permission grant or use.

**Declares capability: broadFileSystemAccess** · S/D · `windows.msix.restricted.broadFileSystemAccess`  
AppxManifest.xml · Capabilities/Capability/@Name = broadFileSystemAccess
Requests broad access to files available to the user. Declaration does not establish permission grant or use.

**Declares capability: runFullTrust** · S/D · `windows.msix.restricted.runFullTrust`  
AppxManifest.xml · Capabilities/Capability/@Name = runFullTrust
Runs outside the app sandbox with the user's full privileges. Declaration does not establish permission grant or use.


## Imported libraries and symbols

**Imported libraries** · I/D · `windows.imports.libraries@bin/app.exe`  
bin/app.exe · ImportDirectory = winhttp.dll
Static import declarations; dynamically loaded libraries may be absent.

**Network APIs** · N/H · `windows.imports.network@bin/app.exe`  
bin/app.exe · ImportDirectory = winhttp.dll
These APIs are common in legitimate tools and in malware; presence does not establish use.


## PE hardening declarations

**AppContainer** · I/D · `windows.hardening.appContainer@bin/app.exe`  
bin/app.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**ASLR** · I/D · `windows.hardening.aslr@bin/app.exe`  
bin/app.exe · OptionalHeader.DllCharacteristics = true
Header declaration only; runtime enforcement is not assessed.

**Control Flow Guard not declared** · N/D · `windows.hardening.cfg@bin/app.exe`  
bin/app.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**Force integrity** · I/D · `windows.hardening.forceIntegrity@bin/app.exe`  
bin/app.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**High-entropy VA** · I/D · `windows.hardening.highEntropyVA@bin/app.exe`  
bin/app.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**No SEH** · I/D · `windows.hardening.noSEH@bin/app.exe`  
bin/app.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**NX compatibility** · I/D · `windows.hardening.nx@bin/app.exe`  
bin/app.exe · OptionalHeader.DllCharacteristics = true
Header declaration only; runtime enforcement is not assessed.

**Terminal-server aware** · I/D · `windows.hardening.terminalServerAware@bin/app.exe`  
bin/app.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.


## PE sections

**Section .idata** · I/D · `windows.section.0@bin/app.exe`  
bin/app.exe · Sections[0] = .idata; raw 16384; virtual 16384; flags 0x40000040
Section flags and sizes are static declarations.

**Section .rsrc** · I/D · `windows.section.1@bin/app.exe`  
bin/app.exe · Sections[1] = .rsrc; raw 512; virtual 176; flags 0x40000040
Section flags and sizes are static declarations.


## Skipped analyses and bounded scans

None.

## Limits of this scan

- Authenticode/MSIX signatures are parsed but not cryptographically verified; trust, revocation and timestamp validity are not assessed.
- Findings are not a verdict of safety; applications may behave differently from declarations.
- Imports are heuristics common in legitimate tools and in malware; presence does not establish use.
- No registry, services or scheduled tasks are inspected; external manifests and installer contents are not read.
- PE folders inspect at most 20 of 200 detected PE files, at depth two, with at most 20,000 inventory entries; symlinks inside targets are not traversed.
- Runtime-built URLs and server-driven behaviour are invisible.
- Static analysis only; target binaries are never executed.
- Strings in a binary are not proof of network traffic; endpoints are not verified traffic.
