package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

func derValue(tag int, contents ...[]byte) []byte {
	var b []byte
	for _, c := range contents {
		b = append(b, c...)
	}
	v, _ := asn1.Marshal(asn1.RawValue{Tag: tag, IsCompound: tag == 16 || tag == 17, Bytes: b})
	return v
}
func derContext(tag int, b []byte) []byte {
	v, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: tag, IsCompound: true, Bytes: b})
	return v
}
func derOID(s asn1.ObjectIdentifier) []byte { v, _ := asn1.Marshal(s); return v }

// PKCS7 builds synthetic SignedData with an expired self-signed certificate.
// Signature bytes are intentionally not valid: the inspector must never verify them.
func PKCS7() ([]byte, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "Synthetic signer", Organization: []string{"Underhood test"}}, NotBefore: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)}
	cert, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	parsed, e := x509.ParseCertificate(cert)
	if e != nil {
		return nil, e
	}
	version, _ := asn1.Marshal(1)
	serial, _ := asn1.Marshal(big.NewInt(17))
	digest := derValue(16, derOID(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}))
	sigAlg := derValue(16, derOID(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}))
	timestamp := derValue(16, derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}), derValue(17, derValue(16)))
	signer := derValue(16, version, derValue(16, parsed.RawIssuer, serial), digest, sigAlg, derValue(4, []byte{1, 2, 3}), derContext(1, append(timestamp, derValue(16, derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}), derValue(17, derValue(16)))...)))
	sd := derValue(16, version, derValue(17, digest), derValue(16, derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})), derContext(0, cert), derValue(17, signer))
	return derValue(16, derOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), derContext(0, sd)), nil
}
