// Package enveloped реализует функциональность для работы с CMS EnvelopedData.
package enveloped

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/oids/curves"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost28147"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3410"
	"github.com/nobuenhombre/go-crypto-gost/pkg/gost3413"
)

var (
	oidData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}

	oidGost28147_89 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 21}

	oidKeyTransportGost2001 = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 28, 1}

	oidKeyTransportGost2012_256 = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 1, 6, 1}

	oidGost28147_89_CryptoPro_ParamSet = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 31, 1}
)

// еncrypt создает CMS EnvelopedData, шифруя данные для получателя с использованием его сертификата
// Функция реализует схему как описано в RFC 4490
func Encrypt(recipientCert *certificate.Container, data []byte) ([]byte, error) {
	recipientPublicKey, err := recipientCert.TBSCertificate.PublicKeyInfo.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения публичного ключа из сертификата: %w", err)
	}
	if recipientPublicKey == nil {
		return nil, errors.New("сертификат получателя не содержит публичный ключ ГОСТ")
	}

	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return nil, fmt.Errorf("ошибка генерации сессионного ключа: %w", err)
	}

	// шифруем данные с помощью ГОСТ 28147-89 в режиме CBC
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("ошибка генерации вектора инициализации: %w", err)
	}

	paddedData := gost3413.Pad2(data, gost28147.BlockSize)

	gostCipher := gost28147.NewCipher(sessionKey, &gost28147.SboxIdGost2814789CryptoProAParamSet)

	encryptedData := make([]byte, len(paddedData))
	cipher.NewCBCEncrypter(gostCipher, iv).CryptBlocks(encryptedData, paddedData)

	paramBytes, err := asn1.Marshal(iv)
	if err != nil {
		return nil, fmt.Errorf("ошибка маршалинга IV: %w", err)
	}
	encryptedContentInfo := EncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: AlgorithmIdentifier{
			Algorithm:  oidGost28147_89,
			Parameters: asn1.RawValue{FullBytes: paramBytes},
		},
		EncryptedContent: asn1.RawValue{Class: 2, Tag: 0, Bytes: encryptedData},
	}

	// генерируем эфемерную пару ключей
	ephemeralKey, err := gost3410.GenPrivateKey(recipientPublicKey.C, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации эфемерного ключа: %w", err)
	}

	// UKM здесь - это часть алгоритма согласования ключа, а не тот, что пойдет в структуру
	// для VKO_GOSTR3410_2012_256 он должен быть равен 1
	ukmInternal := big.NewInt(1)
	sharedKey, err := ephemeralKey.KEK2012256(recipientPublicKey, ukmInternal)
	if err != nil {
		return nil, fmt.Errorf("ошибка вычисления общего ключа (VKO): %w", err)
	}

	// "заворачиваем" сессионный ключ с помощью общего ключа в режиме ECB.
	kek := gost28147.NewCipher(sharedKey, &gost28147.SboxIdGost2814789CryptoProAParamSet)

	wrappedKey := make([]byte, len(sessionKey))
	kek.Encrypt(wrappedKey, sessionKey)

	// параметры для алгоритма транспортировки ключа (RFC 4490).
	ukm := make([]byte, 8)
	if _, err := rand.Read(ukm); err != nil {
		return nil, fmt.Errorf("ошибка генерации UKM: %w", err)
	}

	ephemeralPubKey, err := ephemeralKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("ошибка получения эфемерного публичного ключа: %w", err)
	}

	ephemeralPublicKeyBytes, err := marshalGostPublicKey(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка маршалинга эфемерного публичного ключа: %w", err)
	}

	keyTransParams := KeyTransportParameters{
		EncryptionParamSet: oidGost28147_89_CryptoPro_ParamSet,
		EphemeralPublicKey: asn1.RawValue{FullBytes: ephemeralPublicKeyBytes},
		UKM:                ukm,
	}
	keyTransParamsBytes, err := asn1.Marshal(keyTransParams)
	if err != nil {
		return nil, fmt.Errorf("ошибка маршалинга параметров транспортировки ключа: %w", err)
	}

	recipientInfo := RecipientInfo{
		KeyTransRecipientInfo: KeyTransRecipientInfo{
			Version: 0,
			RID: RecipientIdentifier{
				IssuerAndSerialNumber: IssuerAndSerialNumber{
					Issuer:       recipientCert.TBSCertificate.Issuer,
					SerialNumber: recipientCert.TBSCertificate.SerialNumber,
				},
			},
			KeyEncryptionAlgorithm: AlgorithmIdentifier{
				Algorithm:  oidKeyTransportGost2012_256, // используем OID для 2012-256
				Parameters: asn1.RawValue{FullBytes: keyTransParamsBytes},
			},
			EncryptedKey: wrappedKey,
		},
	}

	envelopedData := EnvelopedData{
		Version:              0,
		RecipientInfos:       []RecipientInfo{recipientInfo},
		EncryptedContentInfo: encryptedContentInfo,
	}
	envelopedDataBytes, err := asn1.Marshal(envelopedData)
	if err != nil {
		return nil, fmt.Errorf("ошибка маршалинга EnvelopedData: %w", err)
	}

	// оборачиваем EnvelopedData в ContentInfo и возвращаем результат.
	contentInfo := ContentInfo{
		ContentType: oidEnvelopedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: envelopedDataBytes},
	}

	return asn1.Marshal(contentInfo)
}

// subjectPublicKeyInfo - это локальная копия структуры pkix.PublicKeyInfo.
//  нужна для ручного маршалинга, так как стандартные средства не поддерживают ключи ГОСТ.
type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// marshalGostPublicKey вручную собираем и сериализует структуру для публичного ключа ГОСТу
// так как стандартная библиотека crypto/x509 не умеет работать с ключами ГОСТ.
func marshalGostPublicKey(pub *gost3410.PublicKey) ([]byte, error) {
	curveID, err := curves.GetIDByCurve(pub.C)
	if err != nil {
		return nil, fmt.Errorf("не удалось найти OID для кривой '%s': %w", pub.C.Name, err)
	}
	curveOID, err := oids.Get(curveID)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить ASN.1 OID для кривой '%s': %w", curveID, err)
	}
	paramBytes, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, fmt.Errorf("ошибка маршалинга параметров кривой: %w", err)
	}

	var keyAlgoID oids.ID
	switch pub.C.PointSize() {
	case 32:
		keyAlgoID = oids.Tc26Gost34102012256
	case 64:
		keyAlgoID = oids.Tc26Gost34102012512
	default:
		return nil, fmt.Errorf("неподдерживаемый размер ключа: %d", pub.C.PointSize()*8)
	}
	keyAlgoOID, err := oids.Get(keyAlgoID)
	if err != nil {
		return nil, fmt.Errorf("не удалось получить ASN.1 OID для алгоритма ключа '%s': %w", keyAlgoID, err)
	}

	algo := pkix.AlgorithmIdentifier{
		Algorithm:  keyAlgoOID,
		Parameters: asn1.RawValue{FullBytes: paramBytes},
	}

	publicKeyBytes := pub.Raw()

	pkixPublicKey := subjectPublicKeyInfo{
		Algorithm: algo,
		PublicKey: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: len(publicKeyBytes) * 8,
		},
	}

	return asn1.Marshal(pkixPublicKey)
}
