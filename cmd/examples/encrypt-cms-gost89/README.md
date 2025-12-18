# CMS Encrypt GOST89 Example

Данный пример использования для CMS GOST 28147-89 атомный аналог использования openssl с модулем libengine-gost-openssl для шифрование с VKO (ГОСТ Р 34.10-2012) для обертывания ключей

## Usage

```bash
# Эксплуатация
echo -n "2202205000012424" | go run ./cmd/examples/encrypt-cms-gost89/main.go -cert test.crt

# В режиме откладки
echo -n "2202205000012424" | go run ./cmd/examples/encrypt-cms-gost89/main.go -cert test.crt -v
```

## Проверка с помощью OpenSSL

### 1. Сравните структуру с выводом openssl

```bash
# Генерация на openssl
echo -n "2202205000012424" | \
  openssl cms -encrypt \
    -engine gost -gost89 \
    -recip test.crt \
    -outform DER > /tmp/openssl_cms.der

# Генерация на Go
echo -n "2202205000012424" | \
  go run cmd/examples/encrypt-cms-gost89/main.go \
    -cert test.crt | \
  base64 -d > /tmp/go_cms.der

### 2. Просмотр CMS structure

```bash
# Parse CMS structure
openssl asn1parse -inform DER -in /tmp/go_cms.der -i -dump

# - Content encryption algorithm: GOST 28147-89 (OID 1.2.643.2.2.21)
# - Parameter set: TC26 (OID 1.2.643.7.1.2.5.1.1)
# - Key encryption algorithm: GOST R 34.10-2012 (OID 1.2.643.7.1.1.1.1)
# - Parameter set: CryptoPro XchA (OID 1.2.643.2.2.36.0)
# - UKM (User Keying Material): 16 bytes
# - IV: 8 bytes
```

### Common issues

1. **Формат сертификата**: сертификат должен быть в формате PEM и использовать ГОСТ Р 34.10-2012 с 256-битным модулем
2. **Наборы параметров**: убедитесь, что сертификат использует совместимые наборы параметров (CryptoPro XchA для согласования ключей)

### Распространенные проблемы

1. **Формат сертификата**: Сертификат должен быть в формате PEM и использовать GOST R 34.10-2012 с 256-битным модулем
2. **Наборы параметров**: убедитесь, что сертификат использует совместимые наборы параметров (CryptoPro XchA для согласования ключей)
3. **Случайное генерирование**: убедитесь, что crypto/rand доступен и работает

### Сравнение с openssl

Реализация Go должна создавать функционально эквивалентные структуры CMS, но:
- **UKM является случайным**: каждое шифрование использует разные UKM, поэтому обернутые ключи будут отличаться
- **IV является случайным**: каждое шифрование использует разные IV, поэтому шифротекст будет отличаться
- **Структура должна совпадать**: OID, идентификаторы алгоритмов и общая структура должны быть идентичными

## Детали реализации

### Используемые алгоритмы

1. **Шифрование содержимого**: GOST 28147-89 в режиме CFB
   - Набор параметров: TC26 (SboxIdtc26gost28147paramZ)
   - IV: 8 байт (случайный)
   - Ключ: 32 байта (случайный сеансовый ключ)

2. **Оболочка ключа**: GOST 28147-89 в режиме ECB.
   - Набор параметров: CryptoPro A (SboxIdGost2814789CryptoProAParamSet).
   - KEK: получен с помощью VKO GOST R 34.10-2012 (256 бит).

3. **Согласование ключей**: VKO GOST R 34.10-2012
   - Набор параметров: CryptoPro XchA
   - UKM: 16 байт (случайный)
   - Хеш: GOST R 34.11-2012 (256-битный)


### CMS структура

```
ContentInfo
  ContentType: EnvelopedData (1.2.840.113549.1.7.3)
  Content: EnvelopedData
    Version: 0
    RecipientInfos: SET OF RecipientInfo
      RecipientInfo
        Version: 0
        IssuerAndSerialNumber
        KeyEncryptionAlgorithm: GOST R 34.10-2012
        EncryptedKey: wrapped session key
    EncryptedContentInfo
      ContentType: Data (1.2.840.113549.1.7.1)
      ContentEncryptionAlgorithm: GOST 28147-89
      EncryptedContent: encrypted plaintext
```

## Notes

- Результат представляет собой DER с кодировкой base64, совместимый с конвейерами openssl.
- Все случайные значения (UKM, IV, сеансовый ключ) генерируются с помощью crypto/rand.