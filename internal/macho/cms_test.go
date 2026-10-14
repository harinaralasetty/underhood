package macho

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestCMSCertificateOrder(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture Root"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(2000000000, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fixture Leaf"}, NotBefore: root.NotBefore, NotAfter: root.NotAfter}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	marshal := func(v any) []byte {
		b, e := asn1.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	certs := marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: append(rootDER, leafDER...)})
	body := append(marshal(1), marshal(asn1.RawValue{Tag: 17, IsCompound: true})...)
	body = append(body, marshal(asn1.RawValue{Tag: 16, IsCompound: true})...)
	body = append(body, certs...)
	signed := marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: body})
	explicit := marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signed})
	oid := marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})
	cms := marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: append(oid, explicit...)})
	names, e := authorities(cms)
	if e != nil || !reflect.DeepEqual(names, []string{"Fixture Leaf", "Fixture Root"}) {
		t.Fatal(names, e)
	}
}
