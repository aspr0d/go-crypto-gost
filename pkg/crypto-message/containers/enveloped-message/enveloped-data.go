package envelopedmessage

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"

	"github.com/aspr0d/go-crypto-gost/pkg/crypto-message/containers"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// represents CMS EnvelopedData structure (RFC 5652)
type EnvelopedDataContainer struct {
	Version              int             `asn1:"default:0"`
	OriginatorInfo       *OriginatorInfo `asn1:"optional,tag:0"`
	RecipientInfos       []RecipientInfo `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
	UnprotectedAttrs     []pkix.AttributeTypeAndValue `asn1:"optional,tag:1"`
}

// is optional and contains certificates/keys for originator
type OriginatorInfo struct {
	Certificates []asn1.RawValue `asn1:"optional,tag:0"`
	CRLs         []asn1.RawValue `asn1:"optional,tag:1"`
}

// represents key transport information for a recipient
type RecipientInfo struct {
	Version                int `asn1:"default:0"`
	IssuerAndSerialNumber  IssuerAndSerialNumber
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// identifies a certificate
// Note: Issuer is stored as RawValue to preserve original ASN.1 encoding
// (string type tags like IA5String, NumericString must match the certifiscate exactly)
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

func DecodeEnvelopedDataDER(data containers.DER) (*EnvelopedDataContainer, error) {
	ed := &EnvelopedDataContainer{}

	_, err := asn1.Unmarshal(data, ed)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return ed, nil
}
