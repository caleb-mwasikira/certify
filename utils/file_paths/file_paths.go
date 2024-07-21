package file_paths

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
)

var (
	ProjectPath                     string
	rootDir, CertDir, SignedCertDir string
	PrivateKeysDir, PublicKeysDir   string
	LogDir                          string
	CACertFile, CAPrivateKeyFile    string

	ErrEmptyDir error = errors.New("empty directory")
)

func init() {
	_, _file, _, _ := runtime.Caller(0)
	ProjectPath = filepath.Join(filepath.Dir(_file), "../../")

	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("error accessing user's home dir: %v", err)
	}

	rootDir = filepath.Join(homeDir, ".araknet")
	CertDir = filepath.Join(rootDir, "certs/")
	PrivateKeysDir = filepath.Join(rootDir, "priv_keys/")
	PublicKeysDir = filepath.Join(rootDir, "pub_keys/")
	LogDir = filepath.Join(rootDir, "logs/")
	SignedCertDir = filepath.Join(rootDir, "signed_certs/")

	CACertFile = filepath.Join(CertDir, "ca.crt")
	CAPrivateKeyFile = filepath.Join(PrivateKeysDir, "ca.key")

	// ensure directories exists
	dirs := []string{CertDir, PrivateKeysDir, PublicKeysDir, LogDir, SignedCertDir}
	for _, dir := range dirs {
		fmt.Printf("creating directory %v\n", dir)
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			log.Fatalf("error creating directory - %v", err)
		}
	}
}
