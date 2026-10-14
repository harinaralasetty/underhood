package windows

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/harinaralasetty/underhood/internal/model"
)

func (s *packageScan) signature(f *zip.File, label, publisher, manifestFile string) {
	file := scoped(label, "AppxSignature.p7x")
	add := func(id, title, detail, value string, sev model.Severity) model.Finding {
		v := peFinding("windows.msix."+id, "signing", title, detail, sev, model.Declared, label, "PKCX / SignedData", value)
		v.Evidence[0].File = file
		return v
	}
	if f == nil {
		s.result.Findings = append(s.result.Findings, add("unsigned", "Unsigned package", SignatureNotice, "AppxSignature.p7x absent or ambiguous", model.Notable))
		return
	}
	b, e := s.read(f, label, model.MaxMetadata)
	var info PKCS7Info
	if e == nil {
		if len(b) < 4 || !bytes.Equal(b[:4], []byte("PKCX")) {
			e = fmt.Errorf("missing PKCX signature prefix")
		} else {
			info, e = ParsePKCS7(b[4:])
		}
	}
	if e != nil {
		s.result.Findings = append(s.result.Findings, add("signature-unparsable", "Package signature present but unparsable", SignatureNotice, e.Error(), model.Notable))
		s.note(file, e.Error())
		return
	}
	finding := add("signature", "Package signature present", SignatureNotice, "PKCS#7 SignedData", model.Info)
	ev := func(k, v string) {
		finding.Evidence = append(finding.Evidence, model.Evidence{File: file, Locator: k, Value: v})
	}
	ev("digest algorithms", strings.Join(info.DigestOIDs, ", "))
	if len(info.TimestampOIDs) > 0 {
		ev("timestamp attributes", strings.Join(info.TimestampOIDs, ", ")+" (presence only)")
	}
	if len(info.Signers) == 0 {
		ev("signer", "no matching issuer/serial certificate found")
	}
	for i, c := range info.Signers {
		ev(fmt.Sprintf("signer[%d].subject", i), c.Subject.String())
		ev(fmt.Sprintf("signer[%d].validity", i), c.NotBefore.UTC().Format(time.RFC3339)+" to "+c.NotAfter.UTC().Format(time.RFC3339))
		if time.Now().After(c.NotAfter) {
			ev(fmt.Sprintf("signer[%d].expiry", i), "Signing certificate is expired now; a valid timestamp can keep a signature acceptable.")
		}
		// Compare textual distinguished names conservatively; this is not a Windows
		// canonical DN comparison and never establishes trust or signature validity.
		if publisher != "" && publisher != c.Subject.String() {
			mismatch := add("publisher-mismatch", "Publisher in manifest differs from signing certificate subject", "Textual distinguished-name comparison only; equivalent encodings or ordering may differ. "+SignatureNotice, c.Subject.String(), model.Notable)
			mismatch.Evidence = append(mismatch.Evidence, model.Evidence{File: manifestFile, Locator: "Identity/@Publisher", Value: publisher})
			s.result.Findings = append(s.result.Findings, mismatch)
		}
	}
	s.result.Findings = append(s.result.Findings, finding)
}
