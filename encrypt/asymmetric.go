package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
)

var (
	key_size int = 4096

	ErrInvalidKeyType error = errors.New("invalid key type: the file you are trying to load/save may not be a private/public key")
)

// generates asymmetric keys - public and private keys
func GenerateKeyPair() (*rsa.PrivateKey, rsa.PublicKey) {
	private_key, err := rsa.GenerateKey(rand.Reader, key_size)
	if err != nil {
		log.Fatalf("error generating private key; %v\n", err)
	}

	return private_key, private_key.PublicKey
}

func SavePrivateKeyToFile(key *rsa.PrivateKey, fpath string, encrypt_fn func() string) error {
	var pem_block pem.Block
	key_bytes := x509.MarshalPKCS1PrivateKey(key)

	if encrypt_fn != nil {
		// encrypt private key bytes
		passphrase := encrypt_fn()
		key_bytes, err := Encrypt(key_bytes, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("error encrypting private key; %v", err)
		}

		pem_block = pem.Block{
			Type:  "ENCRYPTED RSA PRIVATE KEY",
			Bytes: key_bytes,
		}
	} else {
		fmt.Println("security warning: saving unencrypted private key!")
		pem_block = pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: key_bytes,
		}
	}

	fmt.Printf("saving private key to file '%v'\n", fpath)
	file, err := os.Create(fpath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pem_block)
	return err
}

func LoadPrivateKeyFromFile(fpath string, decrypt_fn func() string) (*rsa.PrivateKey, error) {
	fmt.Printf("loading private key from file '%v'...\n", fpath)

	file_data, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	valid_pem_types := []string{"RSA PRIVATE KEY", "ENCRYPTED RSA PRIVATE KEY"}
	pem_block, _ := pem.Decode(file_data)
	if pem_block == nil || !slices.Contains(valid_pem_types, pem_block.Type) {
		return nil, ErrInvalidKeyType
	}

	if pem_block.Type == "ENCRYPTED RSA PRIVATE KEY" {
		passphrase := decrypt_fn()

		// decrypt pem bytes
		ciphertext := pem_block.Bytes
		key_bytes, err := Decrypt(ciphertext, []byte(passphrase))
		if err != nil {
			return nil, ErrInvalidKeyType
		}
		pem_block.Bytes = key_bytes
	}

	private_key, err := x509.ParsePKCS1PrivateKey(pem_block.Bytes)
	if err != nil {
		return nil, err
	}
	return private_key, nil
}

func SavePublicKeyToFile(key rsa.PublicKey, fpath string) error {
	if len(strings.TrimSpace(fpath)) == 0 {
		fmt.Println("public key not saved to file; no file path provided")
		return nil
	}

	key_bytes := x509.MarshalPKCS1PublicKey(&key)
	pem_block := pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: key_bytes,
	}
	fmt.Printf("saving public key to file '%v'...\n", fpath)
	file, err := os.Create(fpath)
	if err != nil {
		return err
	}
	defer file.Close()

	err = pem.Encode(file, &pem_block)
	return err
}

func LoadPublicKeyFromFile(fpath string) (*rsa.PublicKey, error) {
	fmt.Printf("loading public key from file '%v'...\n", fpath)

	file_data, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	pem_block, _ := pem.Decode(file_data)
	if pem_block == nil || pem_block.Type != "RSA PUBLIC KEY" {
		return nil, ErrInvalidKeyType
	}

	public_key, err := x509.ParsePKCS1PublicKey(pem_block.Bytes)
	if err != nil {
		return nil, ErrInvalidKeyType
	}
	return public_key, nil
}
