package envelopedmessage

import (
	"encoding/asn1"

	"github.com/apr0d/go-crypto-gost/pkg/crypto-message/containers"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// encodes EnvelopedData to DER format
func (ed *EnvelopedDataContainer) EncodeToDER() (containers.DER, error) {
	data, err := asn1.Marshal(*ed)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return containers.DER(data), nil
}
