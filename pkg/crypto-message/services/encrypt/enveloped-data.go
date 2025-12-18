package encrypt

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	envelopedmessage "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/enveloped-message"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	publickeyalgorithm "github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/algorithm/public-key-algorithm"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/curves"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost28147"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

// encrypts plaintext using CMS EnvelopedData with GOST algorithms
// it uses GOST 28147-89 for content encryption and VKO (GOST R 34.10-2012) for key wrapping!
func EncryptCMS(ctx context.Context, plaintext []byte, recipientCert *certificate.Container) ([]byte, error) {
	slog.InfoContext(ctx, "starting CMS encryption",
		slog.Int("plaintextLen", len(plaintext)),
	)

	// 1. extract public key from certificate
	pubKey, err := recipientCert.TBSCertificate.PublicKeyInfo.GetPublicKey()
	if err != nil {
		return nil, ge.Pin(err)
	}

	algo, err := recipientCert.TBSCertificate.PublicKeyInfo.GetAlgorithm()
	if err != nil {
		return nil, ge.Pin(err)
	}

	if algo != publickeyalgorithm.GostR34102012256 {
		return nil, ge.New("certificate must use GOST R 34.10-2012 with 256-bit modulus")
	}

	slog.DebugContext(ctx, "extracted public key from certificate",
		slog.String("algorithm", string(algo)),
	)

	// 2. generate random session key for GOST 28147-89 (32 bytes)
	sessionKey := make([]byte, gost28147.KeySize)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, ge.Pin(err)
	}

	slog.DebugContext(ctx, "generated session key", slog.Int("keyLen", len(sessionKey)))

	// 3. generate random UKM - 8 bytes (as OpenSSL key transport)
	ukmBytes := make([]byte, gost28147.BlockSize)
	if hexEnv := os.Getenv("GOST_UKM_HEX"); hexEnv != "" {
		b, err := hex.DecodeString(hexEnv)
		if err != nil {
			return nil, ge.Pin(err)
		}
		if len(b) != gost28147.BlockSize {
			return nil, ge.New(fmt.Sprintf("invalid GOST_UKM_HEX length: got %d bytes, need %d (16 hex chars)", len(b), gost28147.BlockSize))
		}
		copy(ukmBytes, b)
		slog.InfoContext(ctx, "using fixed UKM from env", slog.String("ukmBytesHex", hex.EncodeToString(ukmBytes)))
	} else {
		if _, err := rand.Read(ukmBytes); err != nil {
			return nil, ge.Pin(err)
		}
		slog.InfoContext(ctx, "generated random UKM", slog.String("ukmBytesHex", hex.EncodeToString(ukmBytes)))
	}

	// UKM must be interpreted as little-endian per VKO/GOST specs
	// NewUKM reverses bytes and converts to big.Int, matching OpenSSL's BN_lebin2bn
	ukm := gost3410.NewUKM(ukmBytes)
	slog.InfoContext(ctx, "UKM generated",
		slog.String("ukmBytesHex", hex.EncodeToString(ukmBytes)),
		slog.String("ukmBigInt", ukm.Text(16)),
	)

	// 4. пenerate random IV for content encryption (8 bytes for GOST 28147-89)
	iv := make([]byte, gost28147.BlockSize)
	if hexEnv := os.Getenv("GOST_IV_HEX"); hexEnv != "" {
		b, err := hex.DecodeString(hexEnv)
		if err != nil || len(b) != gost28147.BlockSize {
			return nil, ge.New("invalid GOST_IV_HEX (need 16 hex chars)")
		}
		copy(iv, b)
	} else {
		if _, err := rand.Read(iv); err != nil {
			return nil, ge.Pin(err)
		}
	}

	slog.DebugContext(ctx, "generated IV", slog.Int("ivLen", len(iv)))

	// 5. Encrypt content with GOST 28147-89 in CFB mode (TC26 param Z)
	contentSbox := &gost28147.SboxIdtc26gost28147paramZ
	cipher := gost28147.NewCipher(sessionKey, contentSbox)

	cfbEncrypter := cipher.NewCFBEncrypter(iv)
	ciphertext := make([]byte, len(plaintext))
	cfbEncrypter.XORKeyStream(ciphertext, plaintext)

	slog.InfoContext(ctx, "CFB encryption",
		slog.String("sessionKeyHex", hex.EncodeToString(sessionKey)),
		slog.String("ivHex", hex.EncodeToString(iv)),
		slog.String("plaintextHex", hex.EncodeToString(plaintext)),
		slog.String("ciphertextHex", hex.EncodeToString(ciphertext)),
	)

	// 6. Key transport (ephemeral VKO + CryptoPro KeyWrap)
	algoParams, err := recipientCert.TBSCertificate.PublicKeyInfo.GetAlgorithmParams()
	if err != nil {
		return nil, ge.Pin(err)
	}

	// Get curve OID ID
	curveOIDID, err := oids.GetID(algoParams.CurveOID)
	if err != nil {
		return nil, ge.Pin(err)
	}

	curve, err := curves.Get(curveOIDID)
	if err != nil {
		return nil, ge.Pin(err)
	}

	ephemPriv, err := generateTempPrivateKey(ctx, curve)
	if err != nil {
		return nil, ge.Pin(err)
	}

	// derive KEK using VKO GOST R 34.10-2012 with GOST R 34.11-2012 (256-bit hash)
	// this matches OpenSSL VKO_compute_key with NID_id_GostR3411_2012_256
	kek, err := ephemPriv.KEK2012256(pubKey, ukm)
	if err != nil {
		return nil, ge.Pin(err)
	}

	ephemPub, err := ephemPriv.PublicKey()
	if err != nil {
		return nil, ge.Pin(err)
	}

	slog.DebugContext(ctx, "derived KEK using VKO",
		slog.Int("kekLen", len(kek)),
		slog.String("kekHex", hex.EncodeToString(kek)),
		slog.String("ephemPubHex", hex.EncodeToString(ephemPub.Raw())),
	)

	// KeyWrap: Use TC26 Z sbox (same as content encryption) for key wrap operations
	// OpenSSL engine-gost uses the cipher OID from GOST_KEY_AGREEMENT_INFO.cipher!
	wrapSbox := contentSbox
	wrappedKey, err := keyWrapCryptoPro(kek[:gost28147.KeySize], sessionKey, ukmBytes, wrapSbox)
	if err != nil {
		return nil, ge.Pin(err)
	}

	slog.InfoContext(ctx, "key wrapping",
		slog.Int("wrappedKeyLen", len(wrappedKey)),
		slog.String("kekHex", hex.EncodeToString(kek[:gost28147.KeySize])),
		slog.String("sessionKeyHex", hex.EncodeToString(sessionKey)),
		slog.String("ukmBytesHex", hex.EncodeToString(ukmBytes)),
		slog.String("wrappedKeyHex", hex.EncodeToString(wrappedKey)),
	)

	// extract components from wrapped key: 8 bytes UKM + 32 bytes encrypted key + 4 bytes MAC
	// note: wrappedKey already contains UKM at the beginning but we also need it separately
	encryptedKey := wrappedKey[8:40] // 32 bytes encrypted session key
	imit := wrappedKey[40:44]        // 4 bytes MAC

	slog.DebugContext(ctx, "extracted key components",
		slog.Int("encryptedKeyLen", len(encryptedKey)),
		slog.String("encryptedKeyHex", hex.EncodeToString(encryptedKey)),
		slog.Int("imitLen", len(imit)),
		slog.String("imitHex", hex.EncodeToString(imit)),
	)

	// build CMS EnvelopedData structure
	ed, err := buildEnvelopedData(ctx, recipientCert, ephemPriv, ukmBytes, encryptedKey, imit, iv, ciphertext, contentSbox)
	if err != nil {
		return nil, ge.Pin(err)
	}

	// 8. encode to CMS ContentInfo
	em := &envelopedmessage.Container{
		EnvelopedData: ed,
	}

	der, err := em.EncodeToDER()
	if err != nil {
		return nil, ge.Pin(err)
	}

	slog.InfoContext(ctx, "CMS encryption completed",
		slog.Int("derLen", len(der)),
	)

	return der, nil
}

// buildEnvelopedData constructs the CMS EnvelopedData structure
func buildEnvelopedData(
	ctx context.Context,
	recipientCert *certificate.Container,
	ephemPriv *gost3410.PrivateKey,
	ukmBytes []byte,
	encryptedKey []byte,
	imit []byte,
	iv []byte,
	ciphertext []byte,
	sbox *gost28147.Sbox,
) (*envelopedmessage.EnvelopedDataContainer, error) {

	oidData, err := oids.Get(oids.Data)
	if err != nil {
		return nil, ge.Pin(err)
	}

	oidGost28147, err := oids.Get(oids.Gost28147)
	if err != nil {
		return nil, ge.Pin(err)
	}

	// TC26 GOST 28147-89 parameter set Z OID:
	oidTc26Gost28147ParamZ := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 5, 1, 1}

	// build content encryption algorithm identifier (SEQ {IV, paramSet})
	contentEncAlg := pkix.AlgorithmIdentifier{
		Algorithm: oidGost28147,
		Parameters: asn1.RawValue{
			FullBytes: func() []byte {
				params := struct {
					IV       []byte
					ParamSet asn1.ObjectIdentifier
				}{IV: iv, ParamSet: oidTc26Gost28147ParamZ}
				data, _ := asn1.Marshal(params)
				return data
			}(),
		},
	}

	// key encryption algorithm identifier (GOST R 34.10-2012 key transport params)
	oidGostR34102012 := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}
	oidCryptoProXchA := asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}
	oidGostR34112012256 := asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 2, 2}
	keyEncAlgParamsDER, _ := asn1.Marshal(struct {
		PublicKeyParamSet asn1.ObjectIdentifier
		DigestParamSet    asn1.ObjectIdentifier
	}{PublicKeyParamSet: oidCryptoProXchA, DigestParamSet: oidGostR34112012256})
	keyEncAlg := pkix.AlgorithmIdentifier{
		Algorithm:  oidGostR34102012,
		Parameters: asn1.RawValue{FullBytes: keyEncAlgParamsDER},
	}

	ephemPub, err := ephemPriv.PublicKey()
	if err != nil {
		return nil, ge.Pin(err)
	}

	keyTransportDER, err := buildKeyTransport(ephemPub, encryptedKey, imit, ukmBytes, oidTc26Gost28147ParamZ, oidGostR34112012256, oidCryptoProXchA)
	if err != nil {
		return nil, ge.Pin(err)
	}

	// use raw Issuer bytes directly to preserve original ASN.1 string type tags
	// (IA5String, NumericString, etc.) - server matches by exact Issuer+SerialNumber!
	recipientInfo := envelopedmessage.RecipientInfo{
		Version: 0,
		IssuerAndSerialNumber: envelopedmessage.IssuerAndSerialNumber{
			Issuer:       recipientCert.TBSCertificate.Issuer,
			SerialNumber: recipientCert.TBSCertificate.SerialNumber,
		},
		KeyEncryptionAlgorithm: keyEncAlg,
		EncryptedKey:           keyTransportDER,
	}

	encryptedContentInfo := envelopedmessage.EncryptedContentInfo{
		ContentType:                oidData,
		ContentEncryptionAlgorithm: contentEncAlg,
		EncryptedContent:           ciphertext,
	}

	ed := &envelopedmessage.EnvelopedDataContainer{
		Version:              0,
		RecipientInfos:       []envelopedmessage.RecipientInfo{recipientInfo},
		EncryptedContentInfo: encryptedContentInfo,
	}

	slog.DebugContext(ctx, "built EnvelopedData structure",
		slog.Int("recipientInfos", len(ed.RecipientInfos)),
	)

	return ed, nil
}

// generateTempPrivateKey generates a temporary private key for VKO
// can be overridden with GOST_EPHEMERAL_KEY_HEX env var (64 hex chars = 32 bytes)
func generateTempPrivateKey(ctx context.Context, curve *gost3410.Curve) (*gost3410.PrivateKey, error) {
	var privateRaw []byte

	if ephemKeyHex := os.Getenv("GOST_EPHEMERAL_KEY_HEX"); ephemKeyHex != "" {
		var err error
		privateRaw, err = hex.DecodeString(ephemKeyHex)
		if err != nil {
			return nil, ge.Pin(err)
		}
		if len(privateRaw) != 32 {
			return nil, ge.New("GOST_EPHEMERAL_KEY_HEX must be 64 hex chars (32 bytes)")
		}
		slog.DebugContext(ctx, "using fixed ephemeral key from GOST_EPHEMERAL_KEY_HEX")
	} else {
		privateRaw = make([]byte, 32) // 256-bit key
		if _, err := rand.Read(privateRaw); err != nil {
			return nil, ge.Pin(err)
		}
		slog.DebugContext(ctx, "generated random temporary private key for VKO")
	}

	privKey, err := gost3410.NewPrivateKey(curve, privateRaw)
	if err != nil {
		return nil, ge.Pin(err)
	}

	return privKey, nil
}

// implements RFC 4357 section 6.5 key diversification algorithm.
// diversifies key using random UserKey Material.
func keyDiversifyCryptoPro(inputKey []byte, ukm []byte, sbox *gost28147.Sbox, outputKey []byte) {
	if len(inputKey) != gost28147.KeySize || len(ukm) != gost28147.BlockSize || len(outputKey) != gost28147.KeySize {
		panic("invalid key or ukm size")
	}

	copy(outputKey, inputKey)

	for i := 0; i < 8; i++ {
		var s1, s2 uint32
		var S [8]byte

		// ccmpute IV S from key based on ukm[i] bits
		for j, mask := 0, uint8(1); j < 8; j, mask = j+1, mask<<1 {
			k := uint32(outputKey[4*j]) | uint32(outputKey[4*j+1])<<8 |
				uint32(outputKey[4*j+2])<<16 | uint32(outputKey[4*j+3])<<24

			if mask&ukm[i] != 0 {
				s1 += k
			} else {
				s2 += k
			}
		}

		S[0] = byte(s1 & 0xff)
		S[1] = byte((s1 >> 8) & 0xff)
		S[2] = byte((s1 >> 16) & 0xff)
		S[3] = byte((s1 >> 24) & 0xff)
		S[4] = byte(s2 & 0xff)
		S[5] = byte((s2 >> 8) & 0xff)
		S[6] = byte((s2 >> 16) & 0xff)
		S[7] = byte((s2 >> 24) & 0xff)

		// re-key the cipher with current outputKey
		ctx := gost28147.NewCipher(outputKey, sbox)
		// encrypt outputKey with S as IV in CFB mode (4 blocks = 32 bytes)
		curIV := make([]byte, gost28147.BlockSize)
		copy(curIV, S[:])
		for block := 0; block < 4; block++ {
			gamma := make([]byte, gost28147.BlockSize)
			ctx.Encrypt(gamma, curIV)
			for j := 0; j < gost28147.BlockSize; j++ {
				offset := block*gost28147.BlockSize + j
				outputKey[offset] ^= gamma[j]
				curIV[j] = outputKey[offset]
			}
		}
	}
}

// macBlock performs one step of MAC calculation (like mac_block in OpenSSL)
// uses SeqMAC (16 rounds) instead of regular encryption (32 rounds)
// this uses the new MacBlock method from gost28147 package
func macBlock(ctx *gost28147.Cipher, buffer []byte, block []byte) {
	ctx.MacBlock(buffer, block)
}

// macIV computes MAC with non-zero IV (used in CryptoPro key transport)
// implements the same algoritm as gost_mac_iv in OpenSSL engine
// macLen is in bits (32 = 4 bytes)
func macIV(ctx *gost28147.Cipher, macLen int, iv []byte, data []byte, mac []byte) {
	if len(iv) != gost28147.BlockSize {
		panic("invalid IV size")
	}

	buffer := make([]byte, gost28147.BlockSize)
	copy(buffer, iv)

	// full blocks
	i := 0
	for i+gost28147.BlockSize <= len(data) {
		macBlock(ctx, buffer, data[i:i+gost28147.BlockSize])
		i += gost28147.BlockSize
	}

	// remaining bytes
	if i < len(data) {
		buf2 := make([]byte, gost28147.BlockSize)
		copy(buf2, data[i:])
		macBlock(ctx, buffer, buf2)
		i += gost28147.BlockSize
	}

	// if only one block was processed add padding block
	if i == gost28147.BlockSize {
		buf2 := make([]byte, gost28147.BlockSize)
		macBlock(ctx, buffer, buf2)
	}

	// extract MAC (macLen bits = macLen/8 bytes)
	macBytes := macLen / 8
	if macBytes > len(buffer) {
		macBytes = len(buffer)
	}
	copy(mac, buffer[:macBytes])
}

// keyWrapCryptoPro performs CryptoPro KeyWrap according to RFC 4357 section 6.3:
// 1. diversify KEK using UKM
// 2. encrypt session key using ECB mode (4 blocks = 32 bytes)
// 3. compute MAC over plsain session key with IV=UKM
// return 44 bytes: 8 bytes UKM + 32 bytes encrypted key + 4 bytes MAC!
func keyWrapCryptoPro(kek []byte, sessionKey []byte, ukm []byte, sbox *gost28147.Sbox) (wrappedKey []byte, err error) {
	if len(kek) != gost28147.KeySize || len(sessionKey) != gost28147.KeySize || len(ukm) != gost28147.BlockSize {
		return nil, ge.New("invalid key or ukm size")
	}

	kekUkm := make([]byte, gost28147.KeySize)
	keyDiversifyCryptoPro(kek, ukm, sbox, kekUkm)

	// create cipher with diversified key
	ctx := gost28147.NewCipher(kekUkm, sbox)

	// allocate wrapped key: 8 bytes UKM + 32 bytes encrypted key + 4 bytes MAC
	wrappedKey = make([]byte, 8+32+4)
	copy(wrappedKey, ukm)

	// encrypt session key using ECB mode (4 blocks)
	ecb := ctx.NewECBEncrypter()
	ecb.CryptBlocks(wrappedKey[8:40], sessionKey)

	// compute MAC over plain session key with IV=UKM (32 bits = 4 bytes)
	mac := make([]byte, 4)
	macIV(ctx, 32, ukm, sessionKey, mac)
	copy(wrappedKey[40:44], mac)

	return wrappedKey, nil
}

func buildKeyTransport(ephemPub *gost3410.PublicKey, encKey []byte, imit []byte, ukm []byte, encParamSet, digestOID, pubParamSet asn1.ObjectIdentifier) ([]byte, error) {
	//  algorithm identifier for ephemeral public key
	paramsDER, _ := asn1.Marshal(struct {
		PublicKeyParamSet asn1.ObjectIdentifier
		DigestParamSet    asn1.ObjectIdentifier
	}{PublicKeyParamSet: pubParamSet, DigestParamSet: digestOID})

	alg := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 1, 1}, // GOST R 34.10-2012
		Parameters: asn1.RawValue{FullBytes: paramsDER},
	}

	pubRaw := ephemPub.Raw()
	pubOctetString, _ := asn1.Marshal(pubRaw)
	pubBits := asn1.BitString{Bytes: pubOctetString, BitLength: len(pubOctetString) * 8}

	// (matches X509_PUBKEY encoding)
	type subjectPublicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	ephemPubKeyInfo := subjectPublicKeyInfo{
		Algorithm: alg,
		PublicKey: pubBits,
	}

	type gostKeyInfo struct {
		EncryptedKey []byte // 32 bytes
		Imit         []byte // 4 bytes MAC
	}

	keyInfo := gostKeyInfo{
		EncryptedKey: encKey,
		Imit:         imit,
	}

	type gostKeyAgreementInfo struct {
		Cipher   asn1.ObjectIdentifier
		EphemKey subjectPublicKeyInfo `asn1:"optional,tag:0"`
		EphIV    []byte
	}

	keyAgreementInfo := gostKeyAgreementInfo{
		Cipher:   encParamSet, // (TC26 GOST 28147-89 param Z)
		EphemKey: ephemPubKeyInfo,
		EphIV:    ukm,
	}

	// Note: KeyAgreementInfo is IMPLICIT tagged [0] and optional in OpenSSL
	type gostKeyTransport struct {
		KeyInfo          gostKeyInfo
		KeyAgreementInfo gostKeyAgreementInfo `asn1:"tag:0"`
	}

	gkt := gostKeyTransport{
		KeyInfo:          keyInfo,
		KeyAgreementInfo: keyAgreementInfo,
	}

	return asn1.Marshal(gkt)
}
