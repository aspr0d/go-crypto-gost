package main

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message"
	signerinfo "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/signed-message/signed-data/signer-info"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	signaturealgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/signature-algorithm"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/hash"
)

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 4 {
		fatalf("usage: %s <content file> <signature base64 DER> <cert PEM>", os.Args[0])
	}

	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		fatalf("read content: %v", err)
	}
	sigB64, err := os.ReadFile(os.Args[2])
	if err != nil {
		fatalf("read signature: %v", err)
	}
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

	certs, err := certificate.DecodePEMFile(os.Args[3])
	if err != nil {
		fatalf("read cert: %v", err)
	}
	if len(certs) == 0 {
		fatalf("no certs in pem")
	}
	signerCert := certs[0] // при необходимости можно подобрать по serial/issuer

	// 1) вычисляем digest контента
	digestOidID, err := oids.GetID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		fatalf("digest oid: %v", err)
	}
	digestHash, err := hash.Get(digestOidID)
	if err != nil {
		fatalf("digest hash: %v", err)
	}
	h := digestHash.New()
	h.Write(content)
	contentDigest := h.Sum(nil)

	// 2) достаём messageDigest из атрибутов
	oidMD, _ := oids.Get(oids.AttributeMessageDigest)
	var signedMsgDigest []byte
	for _, attr := range signer.AuthenticatedAttributes {
		if attr.Type.Equal(oidMD) {
			if _, err := asn1.Unmarshal(attr.Value.Bytes, &signedMsgDigest); err != nil {
				fatalf("parse messageDigest attr: %v", err)
			}
		}
	}
	if signedMsgDigest == nil || !bytes.Equal(signedMsgDigest, contentDigest) {
		fatalf("messageDigest mismatch")
	}

	// 3) проверяем подпись атрибутов
	attrBytes, err := signerinfo.EncodeAttributeSliceToDER(signer.AuthenticatedAttributes)
	if err != nil {
		fatalf("encode attrs: %v", err)
	}
	sigOidID, err := oids.GetID(signer.DigestEncryptionAlgorithm.Algorithm)
	if err != nil {
		fatalf("sig oid: %v", err)
	}
	sigAlg, err := signaturealgorithm.Get(sigOidID)
	if err != nil {
		fatalf("sig alg: %v", err)
	}
	if sigAlg.Hash == hash.UnknownHashFunction {
		sigAlg.Hash = digestHash
	}
	if err := signerCert.CheckSignature(sigAlg, attrBytes, signer.EncryptedDigest); err != nil {
		fatalf("signature verify failed: %v", err)
	}

	fmt.Println("OK: CMS signature is valid")
}

