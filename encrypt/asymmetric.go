package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"

	"github.com/caleb-mwasikira/certify/fpaths"
)

var (
	keySize int = 4096
)

type ErrInvalidKey struct {
	msg string
}

func (err ErrInvalidKey) Error() string {
	if len(err.msg) != 0 {
		return err.msg
	}
	return "invalid private or public key"
}

// generates asymmetric keys - public and private keys
func GenerateKeyPair() (*rsa.PrivateKey, rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatalf("[!] error generating private key; %v\n", err)
	}

	return privateKey, privateKey.PublicKey
}

func SavePrivateKeyToFile(key *rsa.PrivateKey, fpath string, encryptFn func() string) error {
	var pemBlock pem.Block
	keyBytes := x509.MarshalPKCS1PrivateKey(key)

	if encryptFn != nil {
		// encrypt private key bytes
		passphrase := encryptFn()
		keyBytes, err := Encrypt(keyBytes, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("[!] error encrypting private key; %v", err)
		}

		pemBlock = pem.Block{
			Type:  "ENCRYPTED RSA PRIVATE KEY",
			Bytes: keyBytes,
		}
	} else {
		fmt.Println("[!] security warning !!!saving unencrypted private keys is not recommended!!!")
		pemBlock = pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		}
	}

	if !filepath.IsAbs(fpath) {
		fpath = filepath.Join(fpaths.PrivateKeysDir, filepath.Base(fpath))
	}
	fmt.Printf("[*] saving private key to file '%v'\n", fpath)
	file, err := os.Create(fpath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pemBlock)
	return err
}

func LoadPrivateKeyFromFile(fpath string, decryptFn func() string) (*rsa.PrivateKey, error) {
	if !filepath.IsAbs(fpath) {
		fpath = filepath.Join(fpaths.PrivateKeysDir, filepath.Base(fpath))
	}

	fmt.Printf("[*] loading private key from file '%v'\n", fpath)
	fileData, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	validPemTypes := []string{"RSA PRIVATE KEY", "ENCRYPTED RSA PRIVATE KEY"}
	pemBlock, _ := pem.Decode(fileData)
	if pemBlock == nil || !slices.Contains(validPemTypes, pemBlock.Type) {
		return nil, ErrInvalidKey{
			msg: "key found was not a valid private key",
		}
	}

	if pemBlock.Type == "ENCRYPTED RSA PRIVATE KEY" {
		passphrase := decryptFn()

		// decrypt pem bytes
		ciphertext := pemBlock.Bytes
		keyBytes, err := Decrypt(ciphertext, []byte(passphrase))
		if err != nil {
			return nil, ErrInvalidKey{
				msg: fmt.Sprintf("[!] error decrypting encrypted key: %v", err),
			}
		}
		pemBlock.Bytes = keyBytes
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func SavePublicKeyToFile(key rsa.PublicKey, fpath string) error {
	keyBytes := x509.MarshalPKCS1PublicKey(&key)
	pemBlock := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: keyBytes,
	}

	if !filepath.IsAbs(fpath) {
		fpath = filepath.Join(fpaths.PublicKeysDir, filepath.Base(fpath))
	}
	fmt.Printf("[*] saving public key to file '%v'\n", fpath)
	file, err := os.Create(fpath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pemBlock)
	return err
}

func LoadPublicKeyFromFile(fpath string) (*rsa.PublicKey, error) {
	if !filepath.IsAbs(fpath) {
		fpath = filepath.Join(fpaths.PublicKeysDir, filepath.Base(fpath))
	}

	fmt.Printf("[*] loading public key from file '%v'\n", fpath)
	fileData, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	pemBlock, _ := pem.Decode(fileData)
	if pemBlock == nil || pemBlock.Type != "RSA PUBLIC KEY" {
		return nil, ErrInvalidKey{
			msg: "key found was not a valid public key",
		}
	}

	publicKey, err := x509.ParsePKCS1PublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, ErrInvalidKey{
			msg: "key found was not a valid public key",
		}
	}
	return publicKey, nil
}
