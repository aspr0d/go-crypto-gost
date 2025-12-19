package envelopedmessage

import (
	"encoding/asn1"

	"github.com/aspr0d/go-crypto-gost/pkg/crypto-message/containers"
	"github.com/aspr0d/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// represents CMS ContentInfo with EnvelopedData
type Container struct {
	ContentType   asn1.ObjectIdentifier
	Content       asn1.RawContent `asn1:"tag:0,explicit"`
	EnvelopedData *EnvelopedDataContainer
}

// decodes CMS EnvelopedMessage from DER format
func DecodeDER(data containers.DER) (*Container, error) {
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}

	_, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		return nil, ge.Pin(err)
	}

	oidEnvelopedData, err := oids.Get(oids.EnvelopedData)
	if err != nil {
		return nil, ge.Pin(err)
	}

	if !contentInfo.ContentType.Equal(oidEnvelopedData) {
		return nil, ge.New("not an EnvelopedData content type")
	}

	// extract EnvelopedData
	ed, err := DecodeEnvelopedDataDER(contentInfo.Content.Bytes)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return &Container{
		ContentType:   oidEnvelopedData,
		Content:       contentInfo.Content.Bytes,
		EnvelopedData: ed,
	}, nil
}

// CMS EnvelopedMessage to DER format
func (em *Container) EncodeToDER() (containers.DER, error) {
	edDER, err := em.EnvelopedData.EncodeToDER()
	if err != nil {
		return nil, ge.Pin(err)
	}

	oidEnvelopedData, err := oids.Get(oids.EnvelopedData)
	if err != nil {
		return nil, ge.Pin(err)
	}

	contentInfo := struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}{
		ContentType: oidEnvelopedData,
		Content: asn1.RawValue{
			Class:      2, // context-specific
			Tag:        0,
			IsCompound: true,
			Bytes:      edDER,
		},
	}

	data, err := asn1.Marshal(contentInfo)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return containers.DER(data), nil
}
