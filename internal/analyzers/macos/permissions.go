package macos

import (
	"github.com/harinaralasetty/underhood/internal/model"
	"strings"
)

func permissions(c *context) error {
	for _, r := range c.records {
		for _, k := range keys(r.info) {
			if strings.HasPrefix(k, "NS") && strings.Contains(k, "UsageDescription") {
				v := r.info[k]
				c.add("privacy."+k+c.suffix(r.path), "permissions", k, "Developer-declared purpose: "+model.Text(v), model.Notable, model.Declared, c.ev(r.infoPath, k, v))
			}
		}
	}
	return nil
}
