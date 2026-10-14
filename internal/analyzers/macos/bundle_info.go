package macos

import (
	"github.com/harinaralasetty/underhood/internal/macho"
	"github.com/harinaralasetty/underhood/internal/model"
	"sort"
	"strings"
)

func bundleInfo(c *context) error {
	for _, r := range c.records {
		for _, k := range []string{"CFBundleIdentifier", "CFBundleName", "CFBundleDisplayName", "CFBundleShortVersionString", "CFBundleVersion", "LSMinimumSystemVersion", "LSUIElement", "LSBackgroundOnly"} {
			if v, ok := r.info[k]; ok {
				detail := model.Text(v)
				if k == "LSUIElement" {
					detail = "Declares agent/menu-bar presentation flag: " + detail
				}
				if k == "LSBackgroundOnly" {
					detail = "Declares background-only flag: " + detail
				}
				c.add("bundle."+k+c.suffix(r.path), "identity", k, detail, model.Info, model.Declared, c.ev(r.infoPath, k, v))
			}
		}
	}
	eachEnt(c, func(t signingTarget, s macho.Slice, ent map[string]any) {
		if t.path != c.root {
			return
		}
		v, ok := ent["com.apple.security.app-sandbox"]
		if !ok {
			v = "<absent from successfully read entitlements>"
		}
		severity := model.Sensitive
		detail := "The main signature does not enable the App Sandbox entitlement."
		if model.Enabled(ent["com.apple.security.app-sandbox"]) {
			severity = model.Info
			detail = "The main signature enables the App Sandbox entitlement."
		}
		c.add("bundle.sandbox", "identity", "App Sandbox presence", detail, severity, model.Declared, c.ev(t.binary, sliceLocator(s)+"/entitlements/com.apple.security.app-sandbox", v))
	})
	for _, t := range c.signing {
		if t.path == c.root {
			archs := []string{}
			ev := []model.Evidence{}
			for _, s := range t.slices {
				if s.Architecture != "" {
					archs = append(archs, s.Architecture)
					ev = append(ev, c.ev(t.binary, sliceLocator(s)+"/CPU", s.Architecture))
				}
			}
			sort.Strings(archs)
			c.add("bundle.architectures", "identity", "Architectures", strings.Join(archs, ", "), model.Info, model.Binary, ev...)
			return nil
		}
	}
	c.note("BundleInfo", c.root, "main Mach-O executable not found in inventory")
	return nil
}
