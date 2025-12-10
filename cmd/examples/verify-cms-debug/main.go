package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	signedmessage "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message"
	signerinfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/signer-info"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	signaturealgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/signature-algorithm"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/chunks"
)

type sigVariant struct {
	name string
	data []byte
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func readFileOrFatal(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	return data
}

func curveFromCert(cert *certificate.Container, algoPub string) (*gost3410.Curve, error) {
	// Try parameters first.
	params := cert.TBSCertificate.PublicKeyInfo.Algorithm.Parameters
	if len(params.FullBytes) > 0 {
		var (
			paramSetOID asn1.ObjectIdentifier
			oidsList    []asn1.ObjectIdentifier
		)
		if _, err := asn1.Unmarshal(params.FullBytes, &oidsList); err == nil && len(oidsList) > 0 {
			paramSetOID = oidsList[0]
		} else {
			_, _ = asn1.Unmarshal(params.FullBytes, &paramSetOID)
		}
		switch paramSetOID.String() {
		case "1.2.643.2.2.36.0": // CryptoPro XchA
			return gost3410.CurveIdGostR34102001CryptoProXchAParamSet(), nil
		}
	}

	switch algoPub {
	case "GostR34102012512":
		return gost3410.CurveIdtc26gost34102012512paramSetA(), nil
	case "GostR34102012256":
		return gost3410.CurveIdtc26gost34102012256paramSetA(), nil
	default:
		return gost3410.CurveIdGostR34102001CryptoProAParamSet(), nil
	}
}

func main() {
	if len(os.Args) != 4 {
		fatalf("usage: %s <content file> <signature base64 DER> <cert PEM>", os.Args[0])
	}

	content := readFileOrFatal(os.Args[1])
	sigB64 := readFileOrFatal(os.Args[2])
	certPath := os.Args[3]

	sigDER, err := base64.StdEncoding.DecodeString(string(bytes.ReplaceAll(sigB64, []byte("\n"), nil)))
	if err != nil {
		fatalf("decode base64 signature: %v", err)
	}

	msg, err := signedmessage.DecodeDER(sigDER)
	if err != nil {
		fatalf("parse CMS: %v", err)
	}
	cms, ok := msg.(*signedmessage.Container)
	if !ok || len(cms.SignedData.SignerInfos) == 0 {
		fatalf("unexpected CMS structure")
	}
	signer := cms.SignedData.SignerInfos[0]

	certs, err := certificate.DecodePEMFile(certPath)
	if err != nil {
		fatalf("read cert: %v", err)
	}
	if len(certs) == 0 {
		fatalf("no certs in pem")
	}
	signerCert := certs[0]

	attrBytes, err := signerinfo.EncodeAttributeSliceToDER(signer.AuthenticatedAttributes)
	if err != nil {
		fatalf("encode attrs: %v", err)
	}

	digestOidID, err := oids.GetID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		fatalf("digest oid: %v", err)
	}
	digestHash, err := hash.Get(digestOidID)
	if err != nil {
		fatalf("digest hash: %v", err)
	}

	h := digestHash.New()
	h.Write(attrBytes)
	digestBE := h.Sum(nil)
	digestLE := chunks.ReverseFullBytes(append([]byte{}, digestBE...))

	sigRaw := signer.EncryptedDigest
	ps := len(sigRaw) / 2
	s := sigRaw[:ps]
	r := sigRaw[ps:]

	sigs := []sigVariant{
		{name: "raw (asn1 order)", data: sigRaw},
		{name: "s||r", data: append(append([]byte{}, s...), r...)},
		{name: "r||s", data: append(append([]byte{}, r...), s...)},
		{name: "raw reversed", data: chunks.ReverseFullBytes(append([]byte{}, sigRaw...))},
	}

	curve, err := curveFromCert(signerCert, signer.DigestEncryptionAlgorithm.Algorithm.String())
	if err != nil {
		fatalf("curve: %v", err)
	}

	var v asn1.RawValue
	if _, err := asn1.Unmarshal(signerCert.TBSCertificate.PublicKeyInfo.PublicKey.Bytes, &v); err != nil {
		fatalf("parse pubkey: %v", err)
	}

	pk, err := gost3410.NewPublicKey(curve, v.Bytes)
	if err != nil {
		fatalf("build pubkey: %v", err)
	}

	fmt.Printf("digestBE: %x\n", digestBE)
	fmt.Printf("digestLE: %x\n", digestLE)

	try := func(name string, digest []byte, sig []byte) {
		ok, err := pk.VerifyDigest(digest, sig)
		fmt.Printf("%s / len(sig)=%d -> ok=%v err=%v\n", name, len(sig), ok, err)
	}

	for _, sv := range sigs {
		try(sv.name+" with digestBE", digestBE, sv.data)
		try(sv.name+" with digestLE", digestLE, sv.data)
	}

	// Also try via CheckSignature with forced hash = digestHash
	sigOidID, err := oids.GetID(signer.DigestEncryptionAlgorithm.Algorithm)
	if err == nil {
		if sa, err := signaturealgorithm.Get(sigOidID); err == nil {
			sa.Hash = digestHash
			if err := signerCert.CheckSignature(sa, attrBytes, sigRaw); err != nil {
				fmt.Printf("CheckSignature (attr digest, raw sig): err=%v\n", err)
			} else {
				fmt.Println("CheckSignature (attr digest, raw sig): ok")
			}
		}
	}

	// Verify content digest match
	hc := digestHash.New()
	hc.Write(content)
	contentDigest := hc.Sum(nil)
	fmt.Printf("contentDigest: %x (len=%d)\n", contentDigest, len(contentDigest))
}
