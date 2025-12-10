package certificate

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"

	publickeyalgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/public-key-algorithm"
	signaturealgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/signature-algorithm"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/chunks"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

func IsCertificatesEqual(a, b *Container) bool {
	isIssuerEqual := bytes.Equal(
		a.TBSCertificate.Issuer.FullBytes,
		b.TBSCertificate.Issuer.FullBytes,
	)

	isPublicKeyEqual := bytes.Equal(
		a.TBSCertificate.PublicKeyInfo.PublicKey.Bytes,
		b.TBSCertificate.PublicKeyInfo.PublicKey.Bytes,
	)

	return isIssuerEqual && isPublicKeyEqual
}

// RSA public key PKCS#1 representation
type PKCS1PublicKey struct {
	N *big.Int
	E int
}

func checkSignatureGostR34102001(signature, digest, pubKey []byte, curve *gost3410.Curve) error {
	pk, err := gost3410.NewPublicKey(curve, pubKey)
	if err != nil {
		return ge.Pin(err)
	}

	// Digest уже в правильном порядке для VerifyDigest.
	ok, err := pk.VerifyDigest(digest, signature[:])
	if err != nil {
		return ge.Pin(err)
	}

	if !ok {
		return ge.Pin(&VerifyDigestError{})
	}

	return nil
}

func checkSignatureGostR34102012512(signature, digest, pubKey []byte, curve *gost3410.Curve) error {
	pk, err := gost3410.NewPublicKey(curve, pubKey)
	if err != nil {
		return ge.Pin(err)
	}

	// Digest уже в правильном порядке для VerifyDigest.
	ok, err := pk.VerifyDigest(digest, signature[:])
	if err != nil {
		return ge.Pin(err)
	}

	if !ok {
		return ge.Pin(&VerifyDigestError{})
	}

	return nil
}

type gostCurveInfo struct {
	curve         *gost3410.Curve
	reverseDigest bool
}

func selectGostCurve(
	algo publickeyalgorithm.PublicKeyAlgorithm,
	params asn1.RawValue,
) (*gostCurveInfo, error) {
	info := &gostCurveInfo{}

	if len(params.FullBytes) > 0 {
		var (
			paramSetOID asn1.ObjectIdentifier
			oids        []asn1.ObjectIdentifier
		)

		// Parameters for GOST public keys обычно идут как SEQUENCE OF OID:
		//   paramSetOID (кривая), digestOID (опционально).
		if _, err := asn1.Unmarshal(params.FullBytes, &oids); err == nil && len(oids) > 0 {
			paramSetOID = oids[0]
		} else {
			// fallback: single OID
			_, _ = asn1.Unmarshal(params.FullBytes, &paramSetOID)
		}

		switch paramSetOID.String() {
		case "1.2.643.2.2.36.0": // CryptoPro XchA
			info.curve = gost3410.CurveIdGostR34102001CryptoProXchAParamSet()
			info.reverseDigest = true
			return info, nil
		}
	}

	switch algo {
	case publickeyalgorithm.GostR34102012512:
		info.curve = gost3410.CurveIdtc26gost34102012512paramSetA()
	case publickeyalgorithm.GostR34102012256:
		info.curve = gost3410.CurveIdtc26gost34102012256paramSetA()
	case publickeyalgorithm.GostR34102001:
		info.curve = gost3410.CurveIdGostR34102001CryptoProAParamSet()
	default:
		return nil, ge.Pin(&algorithm.UnsupportedAlgorithmError{})
	}

	return info, nil
}

// checkSignatureRSA - see. https://golang.org/src/crypto/x509/x509.go?s=27969:28036#L800
func checkSignatureRSA(algo *signaturealgorithm.SignatureAlgorithm, signature, digest, pubKey []byte) error {
	p := new(PKCS1PublicKey)

	rest, err := asn1.Unmarshal(pubKey, p)
	if err != nil {
		return ge.Pin(err)
	}

	if len(rest) != 0 {
		return ge.Pin(&containers.TrailingDataError{})
	}

	pub := &rsa.PublicKey{
		E: p.E,
		N: p.N,
	}

	return rsa.VerifyPKCS1v15(pub, algo.Hash.CryptoHash(), digest, signature)
}

// checkSignature - verifies signature over provided public key and digest/signature algorithm pair
// ToDo create and store PublicKey in certificate during parse state
// ToDo concern algorithm parameters for GOST cryptography . adjust PublicKey ParamSet according to them
func checkSignature(
	algo *signaturealgorithm.SignatureAlgorithm,
	signedSource,
	signature,
	pubKey []byte,
	algoParams asn1.RawValue,
) error {
	if algo == nil || !algo.Hash.IsActual() || !algo.PublicKeyAlgorithm.IsActual() {
		return ge.Pin(&algorithm.UnsupportedAlgorithmError{})
	}

	h := algo.Hash.New()
	h.Write(signedSource)
	digest := h.Sum(nil)

	var err error

	switch algo.PublicKeyAlgorithm {
	case publickeyalgorithm.GostR34102001, publickeyalgorithm.GostR34102012256:
		curveInfo, curveErr := selectGostCurve(algo.PublicKeyAlgorithm, algoParams)
		if curveErr != nil {
			return ge.Pin(curveErr)
		}
		if ok := verifyGostWithVariants(signature, digest, pubKey, curveInfo.curve); !ok {
			return ge.Pin(&VerifyDigestError{})
		}

	case publickeyalgorithm.GostR34102012512:
		curveInfo, curveErr := selectGostCurve(algo.PublicKeyAlgorithm, algoParams)
		if curveErr != nil {
			return ge.Pin(curveErr)
		}
		if ok := verifyGostWithVariants(signature, digest, pubKey, curveInfo.curve); !ok {
			return ge.Pin(&VerifyDigestError{})
		}

	case publickeyalgorithm.RSA:
		err = checkSignatureRSA(algo, signature, digest, pubKey)
		if err != nil {
			return ge.Pin(err)
		}

	default:
		return ge.Pin(&algorithm.UnsupportedAlgorithmError{})
	}

	return nil
}

// verifyGostWithVariants tries known signature/digest orderings observed in GOST/openssl.
// digestBE is the hash result; we try both BE and LE digest and signature permutations.
func verifyGostWithVariants(signature, digestBE, pubKey []byte, curve *gost3410.Curve) bool {
	pk, err := gost3410.NewPublicKey(curve, pubKey)
	if err != nil {
		return false
	}

	// digests
	dLE := chunks.ReverseFullBytes(append([]byte{}, digestBE...))

	// signatures variants
	raw := append([]byte{}, signature...)
	ps := len(signature) / 2
	s := append([]byte{}, signature[:ps]...)
	r := append([]byte{}, signature[ps:]...)
	sr := append(append([]byte{}, s...), r...)
	rs := append(append([]byte{}, r...), s...)
	rawRev := chunks.ReverseFullBytes(append([]byte{}, signature...))

	variants := []struct {
		digest []byte
		sig    []byte
	}{
		{dLE, raw}, // works for CryptoPro XchA (observed)
		{dLE, sr},
		{dLE, rs},
		{dLE, rawRev},
		{digestBE, raw},
		{digestBE, sr},
		{digestBE, rs},
		{digestBE, rawRev},
	}

	for _, v := range variants {
		ok, err := pk.VerifyDigest(v.digest, v.sig)
		if err == nil && ok {
			return true
		}
	}

	return false
}

// VerifyPartialChain checks that a given cert is issued by the first parent in the list,
// then continue down the path. It doesn't require the last parent to be a root CA,
// or to be trusted in any truststore. It simply verifies that the chain provided, albeit
// partial, makes sense.
func VerifyPartialChain(cert *Container, parents []*Container) error {
	//var x x509.Certificate
	if len(parents) == 0 {
		return ge.New("pkcs7: zero parents provided to verify the signature of certificate") // %q , cert.Subject.CommonName)
	}

	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		return ge.Pin(err)
	}

	if len(parents) == 1 {
		// there is no more parent to check, return
		return nil
	}

	return VerifyPartialChain(parents[0], parents[1:])
}
