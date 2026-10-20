package testutil

import (
	"bytes"
	"path/filepath"
	"testing"
)

// AppVersions builds two synthetic versions with planted changes across the
// existing macOS analyzer families. Neither fixture contains executable code.
func AppVersions(t testing.TB) (string, string) {
	t.Helper()
	base := TempDir(t)
	roots := []string{filepath.Join(base, "old", "Fixture.app"), filepath.Join(base, "new", "Fixture.app")}
	for i, root := range roots {
		info := Info()
		ent := map[string]any{"com.apple.security.app-sandbox": true, "com.apple.security.network.client": true}
		flags := uint32(0x10000)
		urls := "https://api.fixture.test/v1\x00https://retired.fixture.test/a\x00"
		if i == 1 {
			info["CFBundleShortVersionString"], info["CFBundleVersion"] = "2.0", "2"
			delete(info, "NSCameraUsageDescription")
			info["NSMicrophoneUsageDescription"] = "Fixture microphone declaration"
			info["CFBundleURLTypes"] = []any{map[string]any{"CFBundleURLSchemes": []any{"fixture-new"}}}
			info["NSAppleScriptEnabled"] = false
			ent["com.apple.security.get-task-allow"] = true
			ent["com.apple.security.network.client"] = false
			flags = 0
			urls = "https://api.fixture.test/v2\x00https://added.fixture.test/a\x00"
			Write(t, filepath.Join(root, "Contents", "Frameworks", "Helper.framework", "Resources", "Info.plist"), XML(map[string]any{"CFBundleIdentifier": "org.test.helper", "CFBundleName": "Helper", "CFBundleVersion": "1"}))
			Write(t, filepath.Join(root, "Contents", "Resources", "Metadata.appintents", "extract.actionsdata"), []byte(`{"actions":{"inspect": {"title":"Inspect fixture"}}}`))
		}
		Write(t, filepath.Join(root, "Contents", "Info.plist"), XML(info))
		exe := MachO(flags, ent)
		if i == 1 {
			exe = bytes.ReplaceAll(exe, []byte("TEAMTEST"), []byte("TEAMNEXT"))
		}
		exe = append(exe, 0)
		exe = append(exe, []byte(urls)...)
		Write(t, filepath.Join(root, "Contents", "MacOS", "Fixture"), exe)
		Write(t, filepath.Join(root, "Contents", "Library", "LaunchAgents", "job.plist"), XML(map[string]any{"Label": "org.test.fixture.job", "RunAtLoad": i == 1}))
	}
	return roots[0], roots[1]
}
