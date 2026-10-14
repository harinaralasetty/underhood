package testutil

import (
	"archive/zip"
	"bytes"
	"sort"
)

// Zip builds a deterministic in-memory archive, also allowing deliberately unsafe
// names in negative fixtures. No entry is extracted or executed.
func Zip(entries map[string][]byte) []byte {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w, e := z.Create(k)
		if e != nil {
			panic(e)
		}
		if _, e = w.Write(entries[k]); e != nil {
			panic(e)
		}
	}
	if e := z.Close(); e != nil {
		panic(e)
	}
	return b.Bytes()
}

// AppxManifest exercises prefixed declarations using synthetic identities only.
const AppxManifest = `<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10" xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10">
<Identity Name="Underhood.Synthetic" Publisher="CN=Synthetic signer,O=Underhood test" Version="1.2.3.0" ProcessorArchitecture="x64"/>
<Properties><DisplayName>Synthetic Windows App</DisplayName><PublisherDisplayName>Underhood test</PublisherDisplayName></Properties>
<Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0"/><PackageDependency Name="Synthetic.Framework" MinVersion="1.0.0.0"/></Dependencies>
<Capabilities><Capability Name="internetClient"/><uap:Capability Name="documentsLibrary"/><DeviceCapability Name="microphone"/><rescap:Capability Name="runFullTrust"/><rescap:Capability Name="broadFileSystemAccess"/><uap:CustomCapability Name="Synthetic.Custom"/></Capabilities>
<Applications><Application Id="App" Executable="bin\app.exe" EntryPoint="windows.fullTrustApplication" uap10:RuntimeBehavior="packagedClassicApp" uap10:TrustLevel="mediumIL">
<Extensions>
<uap:Extension Category="windows.protocol"><uap:Protocol Name="synthetic"/></uap:Extension>
<uap:Extension Category="windows.fileTypeAssociation"><uap:FileTypeAssociation Name="synthetic"><uap:SupportedFileTypes><uap:FileType>.synthetic</uap:FileType></uap:SupportedFileTypes></uap:FileTypeAssociation></uap:Extension>
<desktop:Extension Category="windows.startupTask"><desktop:StartupTask TaskId="SyntheticTask" Enabled="true" DisplayName="Synthetic startup"/></desktop:Extension>
<uap:Extension Category="windows.appExecutionAlias"><uap:AppExecutionAlias><uap:ExecutionAlias Alias="synthetic.exe"/></uap:AppExecutionAlias></uap:Extension>
<desktop:Extension Category="windows.service"><desktop:Service Name="SyntheticService" StartupType="auto" StartAccount="localSystem"/></desktop:Extension>
<desktop:Extension Category="windows.firewallRules"><desktop:FirewallRules Executable="bin\app.exe"><desktop:Rule Direction="in" IPProtocol="TCP" LocalPortMin="4242" LocalPortMax="4242"/></desktop:FirewallRules></desktop:Extension>
<uap:Extension Category="windows.appUriHandler"><uap:AppUriHandler><uap:Host Name="synthetic.example.org"/></uap:AppUriHandler></uap:Extension>
<Extension Category="windows.backgroundTasks"><BackgroundTasks><Task Type="timer"/></BackgroundTasks></Extension>
<Extension Category="windows.comServer"><ComServer><ExeServer Executable="bin\app.exe"/></ComServer></Extension>
<Extension Category="windows.shareTarget"><ShareTarget><DataFormat>Text</DataFormat></ShareTarget></Extension>
<Extension Category="windows.appService"><AppService Name="SyntheticAppService"/></Extension>
<desktop:Extension Category="windows.fullTrustProcess"><desktop:FullTrustProcess Executable="bin\app.exe"/></desktop:Extension>
<Extension Category="windows.syntheticUnknown"><Unknown Name="raw"/></Extension>
</Extensions><uap:ApplicationContentUriRules><uap:Rule Match="https://synthetic.example.org/*" Type="include"/></uap:ApplicationContentUriRules>
</Application></Applications></Package>`

func MSIX(signature []byte) []byte {
	entries := map[string][]byte{"AppxManifest.xml": []byte(AppxManifest), "bin/app.exe": PE(PEOptions{Imports: map[string][]string{"winhttp.dll": {"WinHttpOpen"}}, Manifest: `<assembly><trustInfo><requestedExecutionLevel level="asInvoker"/></trustInfo></assembly>`}), "Assets/logo.txt": []byte("synthetic placeholder")}
	if signature != nil {
		entries["AppxSignature.p7x"] = append([]byte("PKCX"), signature...)
	}
	return Zip(entries)
}
func MSIXBundle(app []byte) []byte {
	return Zip(map[string][]byte{"AppxMetadata/AppxBundleManifest.xml": []byte(`<Bundle><Identity Name="Underhood.Bundle" Publisher="CN=Synthetic" Version="1.0.0.0"/><Packages><Package FileName="app.msix" Type="application" Architecture="x64"/><Package FileName="resources.msix" Type="resource" Architecture="neutral" ResourceId="en-US"/></Packages></Bundle>`), "app.msix": app, "resources.msix": []byte("resource listed only")})
}
