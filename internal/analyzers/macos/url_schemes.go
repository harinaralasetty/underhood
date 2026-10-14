package macos

import (
	"fmt"
	"github.com/harinaralasetty/underhood/internal/macho"
	"github.com/harinaralasetty/underhood/internal/model"
	"strings"
)

func urlSchemes(c *context) error {
	for _, r := range c.records {
		for i, t := range array(r.info["CFBundleURLTypes"]) {
			for _, v := range array(dict(t)["CFBundleURLSchemes"]) {
				scheme := str(v)
				if scheme == "" {
					continue
				}
				c.add("url.scheme."+scheme+c.suffix(r.path), "registrations", "URL scheme: "+scheme, "Registers the "+scheme+": URL scheme.", model.Notable, model.Declared, c.ev(r.infoPath, fmt.Sprintf("CFBundleURLTypes[%d].CFBundleURLSchemes", i), scheme))
			}
		}
		for _, k := range []string{"CFBundleDocumentTypes", "UTImportedTypeDeclarations", "UTExportedTypeDeclarations", "NSServices"} {
			for i, v := range array(r.info[k]) {
				c.add(fmt.Sprintf("registration.%s.%d%s", k, i, c.suffix(r.path)), "registrations", k, model.Text(v), model.Info, model.Declared, c.ev(r.infoPath, fmt.Sprintf("%s[%d]", k, i), v))
			}
		}
	}
	eachEnt(c, func(t signingTarget, s macho.Slice, ent map[string]any) {
		for _, v := range array(ent["com.apple.developer.associated-domains"]) {
			domain := str(v)
			if strings.HasPrefix(domain, "applinks:") {
				c.add("url."+domain+c.suffix(t.path), "registrations", "Universal link domain", domain, model.Notable, model.Declared, c.ev(t.binary, sliceLocator(s)+"/entitlements/com.apple.developer.associated-domains", domain))
			}
		}
	})
	return nil
}
