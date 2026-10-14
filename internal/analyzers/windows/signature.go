package windows

import (
	"bytes"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/harinaralasetty/underhood/internal/model"
)

// SignatureNotice describes the limits shared by PE and future package reports.
const SignatureNotice = "Authenticode/MSIX signatures are parsed but not cryptographically verified; trust, revocation and timestamp validity are not assessed."

// PKCS7Info contains declarations only. Chains are ordered by issuer/subject,
// without verifying signatures or establishing certificate trust.
type PKCS7Info struct {
	Certificates  []*x509.Certificate
	Signers       []*x509.Certificate
	Chains        [][]*x509.Certificate
	DigestOIDs    []string
	TimestampOIDs []string
}

func asnChildren(b []byte, limit int) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(b) > 0 {
		if len(out) >= limit {
			return nil, fmt.Errorf("ASN.1 element limit exceeded")
		}
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		if len(rest) >= len(b) {
			return nil, fmt.Errorf("invalid ASN.1 length")
		}
		out = append(out, v)
		b = rest
	}
	return out, nil
}
func rawOID(v asn1.RawValue) (string, error) {
	var oid asn1.ObjectIdentifier
	rest, e := asn1.Unmarshal(v.FullBytes, &oid)
	if e != nil || len(rest) > 0 {
		return "", fmt.Errorf("invalid object identifier")
	}
	return oid.String(), nil
}
func algorithmOID(v asn1.RawValue) (string, error) {
	c, e := asnChildren(v.Bytes, 4)
	if e != nil || v.Tag != 16 || len(c) == 0 {
		return "", fmt.Errorf("invalid algorithm identifier")
	}
	return rawOID(c[0])
}

// ParsePKCS7 reads bounded DER SignedData, reusable for an MSIX PKCX payload.
// It deliberately does not validate hashes, signatures, trust, or timestamps.
func ParsePKCS7(der []byte) (PKCS7Info, error) {
	var result PKCS7Info
	if len(der) == 0 || len(der) > model.MaxMetadata {
		return result, fmt.Errorf("PKCS#7 size outside bounds")
	}
	outer, e := asnChildren(der, 1)
	if e != nil || len(outer) != 1 || outer[0].Tag != 16 {
		return result, fmt.Errorf("invalid PKCS#7 ContentInfo")
	}
	content, e := asnChildren(outer[0].Bytes, 2)
	if e != nil || len(content) != 2 {
		return result, fmt.Errorf("invalid PKCS#7 ContentInfo fields")
	}
	oid, e := rawOID(content[0])
	if e != nil || oid != "1.2.840.113549.1.7.2" || content[1].Class != 2 || content[1].Tag != 0 {
		return result, fmt.Errorf("PKCS#7 content is not SignedData")
	}
	wrapped, e := asnChildren(content[1].Bytes, 1)
	if e != nil || len(wrapped) != 1 || wrapped[0].Tag != 16 {
		return result, fmt.Errorf("invalid SignedData wrapper")
	}
	fields, e := asnChildren(wrapped[0].Bytes, 8)
	if e != nil || len(fields) < 4 || fields[0].Tag != 2 || fields[1].Tag != 17 || fields[2].Tag != 16 {
		return result, fmt.Errorf("invalid SignedData fields")
	}
	algs, e := asnChildren(fields[1].Bytes, 32)
	if e != nil {
		return result, e
	}
	for _, a := range algs {
		s, e := algorithmOID(a)
		if e != nil {
			return result, e
		}
		result.DigestOIDs = append(result.DigestOIDs, s)
	}
	idx := 3
	if fields[idx].Class == 2 && fields[idx].Tag == 0 {
		certs, e := asnChildren(fields[idx].Bytes, 64)
		if e != nil {
			return result, e
		}
		for _, v := range certs {
			if v.Class != 0 || v.Tag != 16 {
				continue
			}
			c, e := x509.ParseCertificate(v.FullBytes)
			if e != nil {
				return result, fmt.Errorf("invalid signing certificate: %w", e)
			}
			result.Certificates = append(result.Certificates, c)
		}
		idx++
	}
	if idx < len(fields) && fields[idx].Class == 2 && fields[idx].Tag == 1 {
		idx++
	}
	if idx != len(fields)-1 || fields[idx].Tag != 17 {
		return result, fmt.Errorf("missing signer information")
	}
	signers, e := asnChildren(fields[idx].Bytes, 32)
	if e != nil {
		return result, e
	}
	for _, si := range signers {
		s, e := asnChildren(si.Bytes, 8)
		if e != nil || si.Tag != 16 || len(s) < 5 || s[0].Tag != 2 || s[1].Tag != 16 {
			return result, fmt.Errorf("invalid SignerInfo")
		}
		if _, e := algorithmOID(s[2]); e != nil {
			return result, e
		}
		signatureIndex := 3
		if s[signatureIndex].Class == 2 && s[signatureIndex].Tag == 0 {
			signatureIndex++
		}
		if signatureIndex+1 >= len(s) {
			return result, fmt.Errorf("truncated signer signature")
		}
		if _, e := algorithmOID(s[signatureIndex]); e != nil {
			return result, e
		}
		if s[signatureIndex+1].Class != 0 || s[signatureIndex+1].Tag != 4 {
			return result, fmt.Errorf("invalid signer signature bytes")
		}
		issuer, e := asnChildren(s[1].Bytes, 2)
		if e != nil || len(issuer) != 2 {
			return result, fmt.Errorf("invalid signer issuer/serial")
		}
		var serial *big.Int
		if _, e = asn1.Unmarshal(issuer[1].FullBytes, &serial); e != nil || serial == nil {
			return result, fmt.Errorf("invalid signer serial")
		}
		for _, c := range result.Certificates {
			if serial.Cmp(c.SerialNumber) == 0 && bytes.Equal(issuer[0].FullBytes, c.RawIssuer) {
				result.Signers = append(result.Signers, c)
				result.Chains = append(result.Chains, certificateChain(c, result.Certificates))
				break
			}
		}
		for _, v := range s[3:] {
			if v.Class != 2 || v.Tag != 1 {
				continue
			}
			attrs, e := asnChildren(v.Bytes, 64)
			if e != nil {
				return result, e
			}
			for _, a := range attrs {
				parts, e := asnChildren(a.Bytes, 2)
				if e != nil || len(parts) != 2 || a.Tag != 16 {
					return result, fmt.Errorf("invalid unsigned attribute")
				}
				oid, e := rawOID(parts[0])
				if e != nil {
					return result, e
				}
				if oid == "1.2.840.113549.1.9.6" || oid == "1.2.840.113549.1.9.16.2.14" {
					result.TimestampOIDs = append(result.TimestampOIDs, oid)
				}
			}
		}
	}
	return result, nil
}
func certificateChain(leaf *x509.Certificate, all []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	seen := map[*x509.Certificate]bool{leaf: true}
	for len(chain) <= len(all) {
		current := chain[len(chain)-1]
		if bytes.Equal(current.RawIssuer, current.RawSubject) {
			break
		}
		var next *x509.Certificate
		for _, c := range all {
			if !seen[c] && bytes.Equal(current.RawIssuer, c.RawSubject) {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
		seen[next] = true
	}
	return chain
}

func analyzeSignatures(r io.ReaderAt, size int64, p *pe.File, label string) ([]model.Finding, []model.SkipNote) {
	d := peDirectory(p, 4)
	if d.VirtualAddress == 0 && d.Size == 0 {
		return []model.Finding{peFinding("windows.pe.unsigned", "signing", "Unsigned", "No Authenticode certificate table is declared. "+SignatureNotice, model.Notable, model.Declared, label, "Security directory", "absent")}, nil
	}
	var findings []model.Finding
	var skips []model.SkipNote
	bad := func(reason string) {
		findings = append(findings, peFinding("windows.pe.signature-unparsable", "signing", "Signature present but unparsable", SignatureNotice, model.Notable, model.Declared, label, "Security directory", reason))
		skips = append(skips, peNote(label, "Authenticode: "+reason))
	}
	offset, n := int64(d.VirtualAddress), int64(d.Size)
	if offset == 0 || n < 8 || n > model.MaxMetadata || offset > size || n > size-offset {
		bad("certificate table outside file or size bounds")
		return findings, skips
	}
	b := make([]byte, int(n))
	if _, e := r.ReadAt(b, offset); e != nil {
		bad("cannot read certificate table")
		return findings, skips
	}
	for pos, count := int64(0), 0; pos < n; count++ {
		if count >= 64 {
			bad("certificate entry limit exceeded")
			break
		}
		if n-pos < 8 {
			bad("truncated WIN_CERTIFICATE")
			break
		}
		length := int64(binary.LittleEndian.Uint32(b[pos:]))
		if length < 8 || length > n-pos {
			bad("invalid WIN_CERTIFICATE length")
			break
		}
		rev, typ := binary.LittleEndian.Uint16(b[pos+4:]), binary.LittleEndian.Uint16(b[pos+6:])
		if rev != 0x200 || typ != 2 {
			bad(fmt.Sprintf("unsupported WIN_CERTIFICATE revision %#x/type %#x", rev, typ))
		} else {
			info, e := ParsePKCS7(b[pos+8 : pos+length])
			if e != nil {
				bad(e.Error())
			} else {
				f := peFinding("windows.pe.signature", "signing", "Authenticode signature present", SignatureNotice, model.Info, model.Declared, label, fmt.Sprintf("WIN_CERTIFICATE[%d]", count), "PKCS#7 SignedData")
				add := func(k, v string) {
					f.Evidence = append(f.Evidence, model.Evidence{File: f.Evidence[0].File, Locator: fmt.Sprintf("WIN_CERTIFICATE[%d].%s", count, k), Value: v})
				}
				add("digest algorithms", strings.Join(info.DigestOIDs, ", "))
				if len(info.TimestampOIDs) > 0 {
					add("timestamp attributes", strings.Join(info.TimestampOIDs, ", ")+" (presence only; validity not assessed)")
				}
				if len(info.Signers) == 0 {
					add("signer", "no matching issuer/serial certificate found")
				}
				for i, chain := range info.Chains {
					for j, c := range chain {
						add(fmt.Sprintf("signer[%d].chain[%d]", i, j), fmt.Sprintf("CN=%s; O=%s; serial=%s; NotBefore=%s; NotAfter=%s", c.Subject.CommonName, strings.Join(c.Subject.Organization, ", "), c.SerialNumber.String(), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339)))
					}
					if time.Now().After(chain[0].NotAfter) {
						add(fmt.Sprintf("signer[%d].expiry", i), "Signing certificate is expired now; a valid timestamp can keep a signature acceptable.")
					} else {
						add(fmt.Sprintf("signer[%d].expiry", i), "Signing certificate is not expired now; trust and timestamp validity are not assessed.")
					}
				}
				findings = append(findings, f)
			}
		}
		aligned := (length + 7) &^ 7
		if aligned > n-pos {
			if length != n-pos {
				bad("truncated certificate alignment padding")
			}
			break
		}
		pos += aligned
	}
	// Multiple WIN_CERTIFICATE entries contribute to the same stable finding.
	merged := make([]model.Finding, 0, len(findings))
	indexes := make(map[string]int)
	for _, f := range findings {
		if i, ok := indexes[f.ID]; ok {
			merged[i].Evidence = append(merged[i].Evidence, f.Evidence...)
		} else {
			indexes[f.ID] = len(merged)
			merged = append(merged, f)
		}
	}
	return merged, skips
}
