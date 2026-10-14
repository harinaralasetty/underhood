package macos

import (
	"github.com/harinaralasetty/underhood/internal/macho"
	"github.com/harinaralasetty/underhood/internal/model"
	"strings"
)

type meaning struct {
	text     string
	severity model.Severity
}

var meanings = map[string]meaning{
	"com.apple.security.app-sandbox":                         {"App Sandbox entitlement", model.Info},
	"com.apple.security.network.client":                      {"Allows outgoing network connections", model.Notable},
	"com.apple.security.network.server":                      {"Allows incoming network connections", model.Notable},
	"com.apple.security.device.camera":                       {"Requests camera access", model.Notable},
	"com.apple.security.device.audio-input":                  {"Requests microphone access", model.Notable},
	"com.apple.security.device.usb":                          {"Requests USB device access", model.Notable},
	"com.apple.security.device.bluetooth":                    {"Requests Bluetooth device access", model.Notable},
	"com.apple.security.personal-information.addressbook":    {"Requests contacts access", model.Notable},
	"com.apple.security.personal-information.calendars":      {"Requests calendar access", model.Notable},
	"com.apple.security.personal-information.location":       {"Requests location access", model.Notable},
	"com.apple.security.personal-information.photos-library": {"Requests photo library access", model.Notable},
	"com.apple.security.automation.apple-events":             {"Allows requesting Apple Events automation of other apps", model.Notable},
	"com.apple.security.cs.disable-library-validation":       {"Disables library validation", model.Sensitive},
	"com.apple.security.cs.allow-unsigned-executable-memory": {"Allows unsigned executable memory", model.Notable},
	"com.apple.security.cs.allow-jit":                        {"Allows just-in-time executable memory", model.Notable},
	"com.apple.security.cs.allow-dyld-environment-variables": {"Allows DYLD environment variables", model.Sensitive},
	"com.apple.security.get-task-allow":                      {"Allows debugger task access", model.Sensitive},
	"get-task-allow":                                         {"Allows debugger task access", model.Sensitive},
	"com.apple.developer.associated-domains":                 {"Declares associated web domains", model.Notable},
	"com.apple.security.application-groups":                  {"Declares shared app-group containers", model.Notable},
	"keychain-access-groups":                                 {"Declares shared keychain access groups", model.Notable},
	"com.apple.security.scripting-targets":                   {"Declares permitted scripting targets", model.Notable},
}

func entitlementMeaning(k string) meaning {
	if m, ok := meanings[k]; ok {
		return m
	}
	for _, m := range []struct {
		prefix, text string
		severity     model.Severity
	}{
		{"com.apple.security.temporary-exception.", "Requests a sandbox exception; exception targets/values follow", model.Sensitive},
		{"com.apple.security.files.user-selected", "Requests access to user-selected files", model.Notable},
		{"com.apple.security.files.downloads", "Requests access to the Downloads folder", model.Notable},
		{"com.apple.security.files.bookmarks", "Allows persistent security-scoped file bookmarks", model.Notable},
		{"com.apple.security.personal-information.", "Requests personal-information access", model.Notable},
	} {
		if strings.HasPrefix(k, m.prefix) {
			return meaning{m.text, m.severity}
		}
	}
	return meaning{"Unmapped entitlement (raw declaration)", model.Info}
}
func entitlements(c *context) error {
	eachEnt(c, func(t signingTarget, s macho.Slice, ent map[string]any) {
		for _, k := range keys(ent) {
			v := ent[k]
			m := entitlementMeaning(k)
			short := k
			if k == "com.apple.security.automation.apple-events" {
				short = "apple-events"
			}
			disabled := false
			switch v.(type) {
			case bool, int64, uint64, float64:
				disabled = !model.Enabled(v)
			}
			prefix := ""
			if disabled {
				prefix = "Disabled declaration: "
				m.severity = model.Info
			}
			c.add("ent."+short+c.suffix(t.path), "entitlements", k, prefix+m.text+": "+model.Text(v), m.severity, model.Declared, c.ev(t.binary, sliceLocator(s)+"/entitlements/"+k, v))
		}
		if !model.Enabled(ent["com.apple.security.app-sandbox"]) {
			v, ok := ent["com.apple.security.app-sandbox"]
			if !ok {
				v = "<absent from successfully read entitlements>"
			}
			c.add("ent.no-sandbox"+c.suffix(t.path), "entitlements", "App Sandbox not enabled", "The inspected signature does not enable the App Sandbox entitlement.", model.Sensitive, model.Declared, c.ev(t.binary, sliceLocator(s)+"/entitlements/com.apple.security.app-sandbox", v))
		}
	})
	return nil
}
