package macos

import (
	"fmt"
	"github.com/harinaralasetty/underhood/internal/macho"
	"github.com/harinaralasetty/underhood/internal/model"
	"strings"
)

func codeSigning(c *context) error {
	for _, t := range c.signing {
		if t.binary == "" {
			c.add("sign.unsigned"+c.suffix(t.path), "signing", "Unsigned", "No embedded Mach-O signature found in this resource bundle.", model.Notable, model.Declared, c.ev(t.path, "bundle inventory", "no Mach-O executable"))
			continue
		}
		for _, s := range t.slices {
			if s.Error != "" {
				continue
			}
			suffix, loc := c.suffix(t.path), sliceLocator(s)
			sig := s.Signature
			if sig == nil {
				c.add("sign.unsigned"+suffix, "signing", "Unsigned", "No embedded code signature found.", model.Notable, model.Declared, c.ev(t.binary, loc+"/LC_CODE_SIGNATURE", "absent"))
				continue
			}
			if len(sig.Authorities) > 0 {
				ev := []model.Evidence{}
				for i, a := range sig.Authorities {
					ev = append(ev, c.ev(t.binary, fmt.Sprintf("%s/CMS/certificate[%d]", loc, i), a))
				}
				c.add("sign.authorities"+suffix, "signing", "Signing authority chain", strings.Join(sig.Authorities, " → ")+". Parsed, not cryptographically verified.", model.Info, model.Declared, ev...)
			}
			for _, cd := range sig.Directories {
				key, title, sev := "flags", "Code signature flags", model.Info
				if cd.Flags&macho.Adhoc != 0 {
					key, title, sev = "adhoc", "Ad-hoc signature", model.Notable
				}
				detail := macho.FlagText(cd.Flags)
				if cd.Flags&macho.HardenedRuntime != 0 {
					detail = "Hardened runtime flag is present. " + detail
				}
				cdloc := fmt.Sprintf("%s/CodeDirectory slot 0x%x", loc, cd.Slot)
				c.add("sign."+key+suffix, "signing", title, detail+". Parsed, not cryptographically verified.", sev, model.Declared, c.ev(t.binary, cdloc+"/flags", macho.FlagText(cd.Flags)), c.ev(t.binary, cdloc+"/identifier", cd.Identifier))
				team := cd.TeamID
				if team == "" {
					team = "not set"
				}
				c.add("sign.team"+suffix, "signing", "Signing team", "TeamIdentifier="+team, model.Info, model.Declared, c.ev(t.binary, cdloc+"/teamID", team))
			}
			if !sig.HasXML && !sig.HasDER {
				c.result.Limits = append(c.result.Limits, "No entitlement blob in "+c.rel(t.binary)+" ("+s.Architecture+"); no entitlements declared in this slice.")
			}
		}
	}
	return nil
}
