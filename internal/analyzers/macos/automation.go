package macos

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/harinaralasetty/underhood/internal/inventory"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/plist"
	"io"
	"path/filepath"
	"strings"
)

func automation(c *context) error {
	for _, r := range c.records {
		for _, k := range []string{"NSAppleScriptEnabled", "OSAScriptingDefinition", "INIntentsSupported", "NSUserActivityTypes"} {
			if v, ok := r.info[k]; ok {
				c.add("automation."+k+c.suffix(r.path), "automation", k, "Automation declaration: "+model.Text(v), model.Notable, model.Declared, c.ev(r.infoPath, k, v))
			}
		}
	}
	for _, f := range c.inv.Files {
		ext := strings.ToLower(filepath.Ext(f))
		isActions := filepath.Base(f) == "extract.actionsdata" && filepath.Base(filepath.Dir(f)) == "Metadata.appintents"
		if ext != ".sdef" && ext != ".intentdefinition" && !isActions {
			continue
		}
		b, e := inventory.ReadMetadata(f)
		if e != nil {
			c.note("Automation", f, e.Error())
			continue
		}
		if ext == ".sdef" {
			if bytes.Contains(b, []byte("<!ENTITY")) {
				c.note("Automation", f, "scripting definition entity declarations are not expanded")
				continue
			}
			d := xml.NewDecoder(bytes.NewReader(b))
			type entry struct{ kind, name string }
			var entries []entry
			for {
				t, err := d.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					e = err
					break
				}
				if s, ok := t.(xml.StartElement); ok && (s.Name.Local == "suite" || s.Name.Local == "class" || s.Name.Local == "command") {
					for _, a := range s.Attr {
						if a.Name.Local == "name" {
							entries = append(entries, entry{s.Name.Local, a.Value})
						}
					}
				}
				if len(entries) > 20000 {
					e = fmt.Errorf("scripting definition entry cap of 20,000 reached")
					break
				}
			}
			if e != nil {
				c.note("Automation", f, e.Error())
				continue
			}
			c.add("automation.sdef@"+c.rel(f), "automation", "AppleScript scripting definition", "Scripting definition found; suites/classes/commands are listed by name only.", model.Notable, model.Declared, c.ev(f, "file extension", ".sdef"))
			for _, v := range entries {
				c.add("automation.sdef."+v.kind+"."+v.name+"@"+c.rel(f), "automation", "AppleScript "+v.kind, v.name, model.Notable, model.Declared, c.ev(f, "//"+v.kind+"/@name", v.name))
			}
			continue
		}
		var v any
		if ext == ".intentdefinition" {
			v, e = plist.Decode(b)
		} else {
			e = json.Unmarshal(b, &v)
		}
		if e != nil {
			c.note("Automation", f, e.Error())
			continue
		}
		if ext == ".intentdefinition" {
			c.add("automation.intentdefinition@"+c.rel(f), "automation", "Intent definition", "Intent definition metadata found.", model.Notable, model.Declared, c.ev(f, "file extension", ext))
		} else {
			c.add("automation.appintents@"+c.rel(f), "automation", "App Intents metadata", "App Intents metadata found; parsing identifiers and titles is best-effort.", model.Notable, model.Declared, c.ev(f, "metadata file", filepath.Base(f)))
		}
		remaining := 20000
		collect(c, v, "$", f, ext == ".intentdefinition", 0, &remaining)
	}
	return nil
}
func collect(c *context, v any, path, file string, definition bool, depth int, remaining *int) {
	if depth >= 64 {
		c.note("Automation", file, "intent metadata depth cap of 64 reached")
		return
	}
	if *remaining <= 0 {
		return
	}
	*remaining--
	if *remaining == 0 {
		c.note("Automation", file, "intent metadata entry cap of 20,000 reached")
		return
	}
	switch x := v.(type) {
	case map[string]any:
		for _, k := range keys(x) {
			value := x[k]
			loc := path + "." + k
			if k == "actions" {
				for _, id := range keys(dict(value)) {
					c.add("automation.action@"+c.rel(file)+":"+loc+"."+id, "automation", "App Intent identifier", id, model.Notable, model.Declared, c.ev(file, loc+"/dictionary key", id))
				}
			}
			if k == "title" {
				title := dict(value)
				text, hasTitle := title["value"].(string)
				if !hasTitle {
					text, hasTitle = title["key"].(string)
				}
				if hasTitle {
					c.add("automation.title@"+c.rel(file)+":"+loc, "automation", "App Intent title", text, model.Notable, model.Declared, c.ev(file, loc, value))
				}
			}
			switch k {
			case "identifier", "title", "name", "INIntentName", "INIntentTitle", "intentIdentifier":
				if text, ok := value.(string); ok {
					title := "App Intent identifier/title field"
					if definition {
						title = "Intent definition field"
					}
					c.add("automation.intent@"+c.rel(file)+":"+loc, "automation", title, k+": "+text, model.Notable, model.Declared, c.ev(file, loc, text))
				}
			}
			collect(c, value, loc, file, definition, depth+1, remaining)
		}
	case []any:
		for i, v := range x {
			collect(c, v, fmt.Sprintf("%s[%d]", path, i), file, definition, depth+1, remaining)
		}
	}
}
