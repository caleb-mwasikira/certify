package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/caleb-mwasikira/certify/encrypt"
	"github.com/caleb-mwasikira/certify/utils/file_paths"
)

var (
	ErrInvalidCertType error = errors.New("invalid certificate type")
)

func defaultCertTemplate(isCA bool) x509.Certificate {
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour * 365 * 10) // 10 years

	maxNumber := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, maxNumber)
	if err != nil {
		log.Fatalf("error generating certificate serial number; %v\n", err)
	}

	defaultSubjectName := pkix.Name{
		Country:            []string{"US"},
		Locality:           []string{"Florida"},
		Province:           []string{"Miami"},
		Organization:       []string{"Araknet"},
		OrganizationalUnit: []string{"Araknet"},
		CommonName:         "localhost",
	}

	certTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               defaultSubjectName,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("0.0.0.0"),
		},
		DNSNames: []string{"localhost", "localhost.local"},
	}

	if isCA {
		certTemplate.IsCA = true
		certTemplate.KeyUsage = certTemplate.KeyUsage | x509.KeyUsageCertSign
	}

	return certTemplate
}

func signCertWithCA(clientCert *x509.Certificate, clientPublicKey *rsa.PublicKey) (pem.Block, error) {
	signedCert := pem.Block{
		Type: "CERTIFICATE",
	}

	caCert, err := loadCertFromFile(file_paths.CACertFile)
	if err != nil {
		return signedCert, err
	}
	caPrivateKey, err := encrypt.LoadPrivateKeyFromFile(file_paths.CAPrivateKeyFile, enterKeyPassphrase)
	if err != nil {
		return signedCert, err
	}

	fmt.Println("signing certificate")
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		clientCert,
		caCert,
		clientPublicKey,
		caPrivateKey,
	)
	if err != nil {
		return signedCert, err
	}

	signedCert.Bytes = certBytes
	return signedCert, nil
}

func saveCertToFile(certPem pem.Block, fpath string) error {
	// save cert as a PEM encoded file
	if !filepath.IsAbs(fpath) {
		fpath = filepath.Join(file_paths.CertDir, filepath.Base(fpath))
	}
	fmt.Printf("saving certificate to file '%v'\n", fpath)

	file, err := os.Create(fpath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &certPem)
	return err
}

func loadCertFromFile(fpath string) (*x509.Certificate, error) {
	if !filepath.IsAbs(fpath) {
		fpath = filepath.Join(file_paths.CertDir, filepath.Base(fpath))
	}
	fmt.Printf("loading certificate from file '%v'\n", fpath)

	fileData, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	certPem, _ := pem.Decode(fileData)
	if certPem == nil || certPem.Type != "CERTIFICATE" {
		return nil, ErrInvalidCertType
	}

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, ErrInvalidCertType
	}
	return cert, nil
}

func newSelfSignedCert(priv_key rsa.PrivateKey, isCA bool) (pem.Block, error) {
	certPem := pem.Block{
		Type: "CERTIFICATE",
	}

	defaultCertTemplate := defaultCertTemplate(isCA)
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&defaultCertTemplate,
		&defaultCertTemplate,
		&priv_key.PublicKey,
		&priv_key,
	)
	if err != nil {
		return pem.Block{}, err
	}

	certPem.Bytes = certBytes
	return certPem, nil
}
