package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/caleb-mwasikira/certify/encrypt"
	"github.com/caleb-mwasikira/certify/utils"
	"github.com/caleb-mwasikira/certify/utils/file_paths"

	"github.com/charmbracelet/huh"
)

func enterKeyPassphrase() string {
	var passphrase string
	const MIN_PASSWORD_LENGTH int = 8

	fmt.Println("encrypted key detected")
	err := huh.NewInput().
		Title("Enter password: ").
		EchoMode(huh.EchoModePassword).
		Value(&passphrase).
		Validate(func(s string) error {
			if len(s) >= MIN_PASSWORD_LENGTH {
				return nil
			}

			return fmt.Errorf("password too short. Min length of %v characters required", MIN_PASSWORD_LENGTH)
		}).
		Run()
	if err != nil {
		log.Fatalf("input err: %v\n", err)
	}
	return passphrase
}

func selectFileFromDir(prompt string, dirpath string) (string, error) {
	var selectedFpath string
	files, err := utils.ListFilesInDir(dirpath)
	if err != nil {
		return "", err
	}

	if len(files) == 0 {
		fmt.Println(prompt)
		fmt.Println("searching files in storage")
		return "", fmt.Errorf("no files found in storage directory")
	}

	options := []huh.Option[string]{}
	for _, file := range files {
		options = append(options, huh.NewOption(file.Name(), file.Name()))
	}

	err = huh.NewSelect[string]().
		Title(prompt).
		Options(options...).
		Value(&selectedFpath).
		Run()
	if err != nil {
		return "", err
	}
	return selectedFpath, nil
}

func generateKeys() {
	var (
		privateKeyFname, publicKeyFname string
		encryptPrivateKey               bool = false
		encryptFn                       func() string
	)

	fmt.Println("generating key pair")
	privateKey, publicKey := encrypt.GenerateKeyPair()
	fmt.Println("private and public keys generated")
	fmt.Println("where do you want to save your files?")

	err := huh.NewInput().
		Title("private key: ").
		Value(&privateKeyFname).
		Validate(func(s string) error {
			if len(s) == 0 {
				return fmt.Errorf("private key filename cannot be empty")
			}
			return nil
		}).
		Run()
	if err != nil {
		log.Fatalf("input error: %v\n", err)
	}

	err = huh.NewInput().
		Title("public key (optional): ").
		Value(&publicKeyFname).
		Run()
	if err != nil {
		log.Fatalf("input error: %v\n", err)
	}

	err = huh.NewConfirm().
		Title("encrypt private key? ").
		Affirmative("Yes").
		Negative("No").
		Value(&encryptPrivateKey).
		Run()
	if err != nil {
		log.Fatalf("input error: %v\n", err)
	}

	if encryptPrivateKey {
		encryptFn = enterKeyPassphrase
	}
	err = encrypt.SavePrivateKeyToFile(privateKey, privateKeyFname, encryptFn)
	if err != nil {
		log.Fatalf("error saving private key to file; %v\n", err)
	}
	err = encrypt.SavePublicKeyToFile(publicKey, publicKeyFname)
	if err != nil {
		log.Fatalf("error saving public key to file; %v", err)
	}
}

func createNewCertificate() {
	var (
		certFpath, privateKeyFpath string
		isCA                       bool
	)

	fmt.Println("creating new self-signed certificate")
	fmt.Println("a self-signed certificate requires a private key to sign it")
	privateKeyFpath, err := selectFileFromDir(
		"select key to sign certificate:",
		file_paths.PrivateKeysDir,
	)
	if err != nil {
		log.Fatalf("input error: %v", err)
	}

	// load private key
	privateKey, err := encrypt.LoadPrivateKeyFromFile(privateKeyFpath, enterKeyPassphrase)
	if err != nil {
		log.Fatalf("error loading private key; %v", err)
	}

	err = huh.NewConfirm().
		Title("does certificate belong to CA?").
		Affirmative("Yes").
		Negative("No").
		Value(&isCA).
		Run()
	if err != nil {
		log.Fatalf("input error: %v", err)
	}

	signedCert, err := newSelfSignedCert(*privateKey, isCA)
	if err != nil {
		log.Fatalf("error creating new self-signed certificate; %v", err)
	}

	if isCA {
		certFpath = file_paths.CACertFile
	} else {
		// enter cert filepath
		err = huh.NewInput().
			Title("enter certificate name: ").
			Value(&certFpath).
			Validate(func(val string) error {
				if len(val) == 0 {
					return fmt.Errorf("certificate name cannot be empty")
				}
				return nil
			}).
			Run()
		if err != nil {
			log.Fatalf("input error: %v", err)
		}
	}

	err = saveCertToFile(signedCert, certFpath)
	if err != nil {
		log.Fatalf("error saving certificate to file; %v", err)
	}
}

func signClientCertificate() {
	var (
		clientCertFpath      string
		clientPublicKeyFpath string
	)

	// load client certificate
	clientCertFpath, err := selectFileFromDir(
		"enter certificate file to be signed:",
		file_paths.CertDir,
	)
	if err != nil {
		log.Fatalf("input error: %v", err)
	}

	clientCert, err := loadCertFromFile(clientCertFpath)
	if err != nil {
		log.Fatalf("error loading client cert from file; %v", err)
	}

	// load client's public key file
	clientPublicKeyFpath, err = selectFileFromDir(
		"enter client's public key filepath:",
		file_paths.PublicKeysDir,
	)
	if err != nil {
		log.Fatalf("input error: %v", err)
	}

	clientPublicKey, err := encrypt.LoadPublicKeyFromFile(clientPublicKeyFpath)
	if err != nil {
		log.Fatalf("error loading client's public key; %v", err)
	}

	// sign client cert
	signedCert, err := signCertWithCA(clientCert, clientPublicKey)
	if err != nil {
		log.Fatalf("error signing cert with CA; %v", err)
	}

	// save signed cert as a file in signed cert dir
	clientCertFname := filepath.Base(clientCertFpath)
	clientCertFpath = filepath.Join(file_paths.SignedCertDir, clientCertFname)
	err = saveCertToFile(signedCert, clientCertFpath)
	if err != nil {
		log.Fatalf("error saving cert to file; %v", err)
	}
}

func main() {
	welcomeMsg := `
     _________welcome to certify
    / ======= \
   / __________\	generate certificates
  | ___________ |		become your own certificate authority
  | | _certify| |			sign your own certificates
  | |         | |		or sign for others as a certificate authority
  | |_________| |_______________________________
  \=____________/   art by: brian macdonald   	)
  / """"""""""" \                       	/
 / ::::::::::::: \                  	=D-'
(_________________)

	`
	fmt.Println(welcomeMsg)

	var userAction int
	err := huh.NewSelect[int]().
		Title("What would you like to do?").
		Options(
			huh.NewOption("Generate Public and Private Keys", 0),
			huh.NewOption("Create New Certificate", 1),
			huh.NewOption("Sign existing certificate", 2),
		).
		Value(&userAction).
		Run()
	if err != nil {
		log.Fatalf("input error: %v\n", err)
	}

	switch userAction {
	case 0:
		generateKeys()
	case 1:
		createNewCertificate()
	case 2:
		signClientCertificate()
	default:
		log.Fatal("unknown user action")
	}
}
