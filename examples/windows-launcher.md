# Underhood: Simple Launcher

**ID:** t64.exe  
**Version / build:** 1.1.0.14  
**Path:** t64.exe  
**Tool version:** 0.1.0-dev  
**Scanned at:** 2026-10-14T16:05:03.789419Z

## Summary

- Control Flow Guard not declared
- Debugger detection APIs
- Not signed
- Dynamic loading APIs
- Runs with the invoking user's privileges
- Does not request elevated UI access

I = info, N = notable, S = sensitive; D = declared, B = found-in-binary, H = heuristic. Use --full or JSON for every evidence entry.

## identity

**Machine** · I/D · `windows.identity.machine`  
t64.exe · COFF.Machine = x64

**Subsystem** · I/D · `windows.identity.subsystem`  
t64.exe · OptionalHeader.Subsystem = console

**Linker timestamp** · I/D · `windows.identity.timestamp`  
t64.exe · COFF.TimeDateStamp = 1659768065 (2022-08-06T06:41:05Z)
The COFF timestamp can be forged or zeroed for reproducible builds.

**Image type** · I/D · `windows.identity.type`  
t64.exe · COFF.Characteristics = EXE

**Image versions** · I/D · `windows.identity.versions`  
t64.exe · OptionalHeader = linker 10.0; OS 5.2; subsystem 5.2; image size 135168
Declared linker, OS and subsystem versions.

**CompanyName** · I/D · `windows.version.CompanyName`  
t64.exe · .rsrc/RT_VERSION/102/0/CompanyName = Simple Launcher User

**FileDescription** · I/D · `windows.version.FileDescription`  
t64.exe · .rsrc/RT_VERSION/102/0/FileDescription = Simple Launcher Executable

**FileVersion** · I/D · `windows.version.FileVersion`  
t64.exe · .rsrc/RT_VERSION/102/0/FileVersion = 1.1.0.14

**InternalName** · I/D · `windows.version.InternalName`  
t64.exe · .rsrc/RT_VERSION/102/0/InternalName = t64.exe

**LegalCopyright** · I/D · `windows.version.LegalCopyright`  
t64.exe · .rsrc/RT_VERSION/102/0/LegalCopyright = Copyright (C) Simple Launcher User

**OriginalFilename** · I/D · `windows.version.OriginalFilename`  
t64.exe · .rsrc/RT_VERSION/102/0/OriginalFilename = t64.exe

**ProductName** · I/D · `windows.version.ProductName`  
t64.exe · .rsrc/RT_VERSION/102/0/ProductName = Simple Launcher

**ProductVersion** · I/D · `windows.version.ProductVersion`  
t64.exe · .rsrc/RT_VERSION/102/0/ProductVersion = 1.1.0.14

**Fixed file version** · I/D · `windows.version.fixed`  
t64.exe · .rsrc/RT_VERSION/102/0/FixedFileVersion = 1.1.0.14

**Fixed version metadata** · I/D · `windows.version.fixedInfo`  
t64.exe · .rsrc/RT_VERSION/102/0/VS_FIXEDFILEINFO = Product version 1.1.0.14; flags mask 0x3f; flags 0x0; OS 0x40004; type 0x1; subtype 0x0; date 0x000000000


## signing

**Unsigned** · N/D · `windows.pe.unsigned`  
t64.exe · Security directory = absent
No Authenticode certificate table is declared. Authenticode/MSIX signatures are parsed but not cryptographically verified; trust, revocation and timestamp validity are not assessed.


## network

none found

## Windows application manifest

**Requested execution level** · I/D · `windows.manifest.requestedExecutionLevel`  
t64.exe · .rsrc/RT_MANIFEST/1/1033/requestedExecutionLevel = asInvoker

**UI access** · I/D · `windows.manifest.uiAccess`  
t64.exe · .rsrc/RT_MANIFEST/1/1033/uiAccess = false


## Inferred capabilities

none found

## Imported libraries and symbols

**Debugger detection APIs** · N/H · `windows.imports.debugger`  
t64.exe · ImportDirectory = KERNEL32.dll:IsDebuggerPresent
These APIs are common in legitimate tools and in malware; presence does not establish use.

**Dynamic loading APIs** · I/H · `windows.imports.dynamic`  
t64.exe · ImportDirectory = KERNEL32.dll:GetProcAddress
These APIs are common in legitimate tools and in malware; presence does not establish use. Dynamic resolution means static imports under-report available APIs.

**Imported libraries** · I/D · `windows.imports.libraries`  
t64.exe · ImportDirectory = KERNEL32.dll, SHLWAPI.dll
Static import declarations; dynamically loaded libraries may be absent.


## PE hardening declarations

**AppContainer** · I/D · `windows.hardening.appContainer`  
t64.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**ASLR** · I/D · `windows.hardening.aslr`  
t64.exe · OptionalHeader.DllCharacteristics = true
Header declaration only; runtime enforcement is not assessed.

**Control Flow Guard not declared** · N/D · `windows.hardening.cfg`  
t64.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**Force integrity** · I/D · `windows.hardening.forceIntegrity`  
t64.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**High-entropy VA** · I/D · `windows.hardening.highEntropyVA`  
t64.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**No SEH** · I/D · `windows.hardening.noSEH`  
t64.exe · OptionalHeader.DllCharacteristics = false
Header declaration only; runtime enforcement is not assessed.

**NX compatibility** · I/D · `windows.hardening.nx`  
t64.exe · OptionalHeader.DllCharacteristics = true
Header declaration only; runtime enforcement is not assessed.

**Terminal-server aware** · I/D · `windows.hardening.terminalServerAware`  
t64.exe · OptionalHeader.DllCharacteristics = true
Header declaration only; runtime enforcement is not assessed.


## PE sections

**Section .text** · I/D · `windows.section.0`  
t64.exe · Sections[0] = .text; raw 61440; virtual 60961; flags 0x60000020
Section flags and sizes are static declarations.

**Section .rdata** · I/D · `windows.section.1`  
t64.exe · Sections[1] = .rdata; raw 14848; virtual 14404; flags 0x40000040
Section flags and sizes are static declarations.

**Section .data** · I/D · `windows.section.2`  
t64.exe · Sections[2] = .data; raw 5120; virtual 16708; flags 0xc0000040
Section flags and sizes are static declarations.

**Section .pdata** · I/D · `windows.section.3`  
t64.exe · Sections[3] = .pdata; raw 3072; virtual 2880; flags 0x40000040
Section flags and sizes are static declarations.

**Section .rsrc** · I/D · `windows.section.4`  
t64.exe · Sections[4] = .rsrc; raw 21504; virtual 21492; flags 0x40000040
Section flags and sizes are static declarations.

**Section .reloc** · I/D · `windows.section.5`  
t64.exe · Sections[5] = .reloc; raw 1024; virtual 852; flags 0x42000040
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
