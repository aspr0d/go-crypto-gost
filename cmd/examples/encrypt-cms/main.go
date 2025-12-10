// Данное приложение демонстрирует использование пакета enveloped для шифрования
// файла в формате CMS EnvelopedData для получателя с заданным сертификатом.
package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/enveloped"
)

func main() {

	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Использование: %s <путь к сертификату получателя> <путь к файлу для шифрования>\n", os.Args[0])
		os.Exit(1)
	}
	certPath := os.Args[1]
	filePath := os.Args[2]

	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка чтения файла сертификата: %v\n", err)
		os.Exit(1)
	}

	certs, err := certificate.DecodePEM(certPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка парсинга PEM сертификата: %v\n", err)
		os.Exit(1)
	}
	if len(certs) == 0 {
		fmt.Fprintln(os.Stderr, "В PEM файле не найдено сертификатов")
		os.Exit(1)
	}
	recipientCert := certs[0]

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка чтения файла с данными: %v\n", err)
		os.Exit(1)
	}

	encryptedData, err := enveloped.Encrypt(recipientCert, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка шифрования: %v\n", err)
		os.Exit(1)
	}

	encoded := base64.StdEncoding.EncodeToString(encryptedData)
	fmt.Println(encoded)
}
