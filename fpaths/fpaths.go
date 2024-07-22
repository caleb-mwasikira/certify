package fpaths

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	ProjectPath                     string
	RootDir, CertDir, SignedCertDir string
	PrivateKeysDir, PublicKeysDir   string
	CaCertFile, CaPrivateKeyFile    string

	ErrEmptyDir error = errors.New("empty directory")
)

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("[!] error accessing user's home dir: %v", err)
	}

	RootDir = filepath.Join(homeDir, ".certify")
	CertDir = filepath.Join(RootDir, "certs/")
	PrivateKeysDir = filepath.Join(RootDir, "priv_keys/")
	PublicKeysDir = filepath.Join(RootDir, "pub_keys/")
	SignedCertDir = filepath.Join(RootDir, "signed_certs/")

	CaCertFile = filepath.Join(CertDir, "ca.crt")
	CaPrivateKeyFile = filepath.Join(PrivateKeysDir, "ca.key")

	// ensure directories exists
	dirs := []string{CertDir, PrivateKeysDir, PublicKeysDir, SignedCertDir}
	for _, dir := range dirs {
		fmt.Printf("[*] creating directory '%v'\n", dir)
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			log.Fatalf("[!] error creating directory: %v", err)
		}
	}
}

func ListFilesInDir(dirpath string) ([]fs.DirEntry, error) {
	entries, err := os.ReadDir(dirpath)
	if err != nil {
		return []fs.DirEntry{}, err
	}

	files := []fs.DirEntry{}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			files = append(files, entry)
		}
	}
	return files, nil
}

func printListing(entry string, depth int) {
	indent := strings.Repeat("|   ", depth)
	fmt.Printf("%s|-- %s\n", indent, filepath.Base(entry))
}

func PrintDirectory(path string, depth int) {
	entries, err := os.ReadDir(path)
	if err != nil {
		log.Fatalf("[!] error reading '%v': %v", path, err)
	}

	printListing(path, depth)
	for _, entry := range entries {
		if entry.IsDir() {
			PrintDirectory(filepath.Join(path, entry.Name()), depth+1)
			continue
		}

		fileInfo, err := entry.Info()
		if err != nil {
			log.Fatalf("[!] error reading file info: %v", err)
		}

		if (fileInfo.Mode() & os.ModeSymlink) == os.ModeSymlink {
			full_path, err := os.Readlink(filepath.Join(path, entry.Name()))
			if err != nil {
				log.Fatalf("[!] error reading link: %v", err)
			}

			printListing(entry.Name()+" -> "+full_path, depth+1)
			continue
		}

		printListing(entry.Name(), depth+1)
	}
}
