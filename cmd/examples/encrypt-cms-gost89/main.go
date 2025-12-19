package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/containers/certificate"
	"github.com/nobuenhombre/go-crypto-gost/pkg/crypto-message/services/encrypt"
	"github.com/nobuenhombre/suikat/pkg/fico"
	"github.com/nobuenhombre/suikat/pkg/ge"
)

var (
	certPath = flag.String("cert", "", "path to recipient certificate (GOST 34.10-2012, PEM format)")
	message  = flag.String("msg", "", "plaintext to encrypt (optional, otherwise read from stdin)")
	verbose  = flag.Bool("v", false, "verbose logging")
)

func main() {
	flag.Parse()

	// logging
	logLevel := slog.LevelError
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	ctx := context.Background()

	if *certPath == "" {
		logger.Error("cert path is required (-cert)")
		os.Exit(1)
	}

	// read certificate
	certFile := fico.TxtFile(*certPath)
	certPEM, err := certFile.ReadBytes()
	if err != nil {
		logger.Error("read certificate", "err", err)
		os.Exit(1)
	}

	certs, err := certificate.DecodePEM(certPEM)
	if err != nil {
		logger.Error("decode certificate", "err", err)
		os.Exit(1)
	}

	if len(certs) == 0 {
		logger.Error("no certificate found in file")
		os.Exit(1)
	}

	recipientCert := certs[0]
	logger.Info("loaded recipient certificate",
		"serialNumber", recipientCert.TBSCertificate.SerialNumber.String(),
	)

	// read plaintext
	plaintext, err := resolvePlaintext(*message)
	if err != nil {
		logger.Error("read plaintext", "err", err)
		os.Exit(1)
	}

	logger.Info("encrypting plaintext",
		"plaintextLen", len(plaintext),
	)

	// encrypt
	der, err := encrypt.EncryptCMS(ctx, plaintext, recipientCert)
	if err != nil {
		logger.Error("encrypt", "err", err)
		os.Exit(1)
	}

	// output base64-encoded DER (compatible with openssl pipeline)
	fmt.Println(base64.StdEncoding.EncodeToString(der))
}

func resolvePlaintext(msg string) ([]byte, error) {
	if msg != "" {
		return []byte(msg), nil
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, ge.Pin(err)
	}

	// drop trailing newline to match echo -n behavior
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}

	return data, nil
}
