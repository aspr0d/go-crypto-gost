// Package enveloped реализует функциональность для работы с CMS EnvelopedData.
package enveloped

import (
	"encoding/asn1"
	"math/big"
)

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit"`
}

type EnvelopedData struct {
	Version              int
	RecipientInfos       []RecipientInfo `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
}

type RecipientInfo struct {
	KeyTransRecipientInfo KeyTransRecipientInfo `asn1:"optional"`
}

type KeyTransRecipientInfo struct {
	Version                int `asn1:"default:0"`
	RID                    RecipientIdentifier
	KeyEncryptionAlgorithm AlgorithmIdentifier
	EncryptedKey           []byte
}

type RecipientIdentifier struct {
	IssuerAndSerialNumber IssuerAndSerialNumber `asn1:"optional"`
}

type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type KeyTransportParameters struct {
	EncryptionParamSet asn1.ObjectIdentifier
	EphemeralPublicKey asn1.RawValue
	UKM                []byte
}
