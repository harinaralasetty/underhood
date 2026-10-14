package macos

import (
	"fmt"
	"github.com/harinaralasetty/underhood/internal/macho"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/scan"
	"path/filepath"
	"strings"
)

var sdks = []string{"Sparkle", "Firebase", "Crashlytics", "Sentry", "Bugsnag", "Mixpanel", "Amplitude", "Segment", "PostHog", "TelemetryDeck", "AppCenter", "Datadog"}

func network(c *context) error {
	for _, r := range c.records {
		ats := dict(r.info["NSAppTransportSecurity"])
		for _, k := range keys(ats) {
			v := ats[k]
			if k == "NSExceptionDomains" && dict(v) != nil {
				for _, domain := range keys(dict(v)) {
					value := dict(v)[domain]
					c.add("net.ats.domain."+domain+c.suffix(r.path), "network", "App Transport Security exception domain", domain+": "+model.Text(value), model.Notable, model.Declared, c.ev(r.infoPath, "NSAppTransportSecurity.NSExceptionDomains."+domain, value))
				}
			} else {
				severity := model.Info
				if strings.HasPrefix(k, "NSAllowsArbitraryLoads") && model.Enabled(v) {
					severity = model.Sensitive
				}
				c.add("net.ats."+k+c.suffix(r.path), "network", "App Transport Security: "+k, model.Text(v), severity, model.Declared, c.ev(r.infoPath, "NSAppTransportSecurity."+k, v))
			}
		}
		for _, k := range []string{"SUFeedURL", "SUPublicEDKey"} {
			if v, ok := r.info[k]; ok {
				c.add("net.self-updater."+k+c.suffix(r.path), "network", "Self-updater declaration (Sparkle)", k+": "+model.Text(v), model.Notable, model.Declared, c.ev(r.infoPath, k, v))
			}
		}
	}
	eachEnt(c, func(t signingTarget, s macho.Slice, ent map[string]any) {
		for _, k := range []string{"com.apple.security.network.client", "com.apple.security.network.server"} {
			if v, ok := ent[k]; ok {
				severity := model.Info
				if model.Enabled(v) {
					severity = model.Notable
				}
				c.add("net.entitlement."+k+c.suffix(t.path), "network", entitlementMeaning(k).text, "Entitlement value: "+model.Text(v), severity, model.Declared, c.ev(t.binary, sliceLocator(s)+"/entitlements/"+k, v))
			}
		}
	})
	detect := func(value, file, locator string) {
		for _, sdk := range sdks {
			if strings.Contains(strings.ToLower(value), strings.ToLower(sdk)) {
				c.add("net.sdk."+strings.ToLower(sdk), "network", "Possible embedded SDK: "+sdk, "Framework/bundle or linked-library name matches "+sdk+"; inclusion and use are not verified.", model.Notable, model.Heuristic, c.ev(file, locator, value))
			}
		}
	}
	for _, b := range c.inv.Bundles {
		if b != c.root {
			detect(filepath.Base(b), b, "bundle name")
		}
	}
	hosts := map[string][]model.Evidence{}
	evidenceCaps := map[string]bool{}
	hostCap := false
	for _, b := range c.inv.Binaries {
		for _, s := range c.parsed[b] {
			for _, lib := range s.Libraries {
				detect(lib, b, sliceLocator(s)+"/linked dylib")
			}
		}
		if !c.options.BinaryStrings {
			continue
		}
		result, e := scan.File(b, c.options.MaxBinaryMB<<20)
		if e != nil {
			c.note("Network", b, e.Error())
			continue
		}
		if result.Capped {
			c.note("Network", b, fmt.Sprintf("binary-scan cap of %d MiB reached", c.options.MaxBinaryMB))
		}
		if result.LongRun {
			c.note("Network", b, "ASCII/UTF-16LE runs longer than 16 KiB skipped")
		}
		if result.EndpointCap {
			c.note("Network", b, "10,000 endpoint-per-binary cap reached")
		}
		for _, ep := range result.Endpoints {
			if _, ok := hosts[ep.Host]; !ok && len(hosts) >= model.MaxHosts {
				hostCap = true
				continue
			}
			if len(hosts[ep.Host]) < model.MaxHostEvidence {
				hosts[ep.Host] = append(hosts[ep.Host], c.ev(b, fmt.Sprintf("%s URL at byte %d", ep.Encoding, ep.Offset), ep.URL))
			} else if !evidenceCaps[ep.Host] {
				evidenceCaps[ep.Host] = true
				c.note("Network", b, "20-evidence-per-host cap reached for "+ep.Host)
			}
		}
	}
	for _, host := range keysOfEvidence(hosts) {
		c.add("net.host."+host, "network", "Endpoint string host: "+host, "URL string present in a binary, not verified traffic; not proof of use.", model.Notable, model.Binary, hosts[host]...)
	}
	if hostCap {
		c.note("Network", c.root, "200-host cap reached")
	}
	if !c.options.BinaryStrings {
		c.result.Limits = append(c.result.Limits, "Binary string scan disabled by --no-binary-strings.")
	}
	return nil
}
func keysOfEvidence(m map[string][]model.Evidence) []string {
	d := map[string]any{}
	for k := range m {
		d[k] = nil
	}
	return keys(d)
}
