package main

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/caleb-mwasikira/certify/encrypt"
	"github.com/caleb-mwasikira/certify/fpaths"

	"github.com/charmbracelet/huh"
)

func enterKeyPassphrase() string {
	fmt.Println("encrypted key detected")

	var passphrase string
	const MIN_PASSWORD_LENGTH int = 8
	err := huh.NewInput().
		Title("enter password: ").
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
		log.Fatalf("[!] input err: %v", err)
	}
	return passphrase
}

func selectFileFromDir(prompt string, path string) (string, error) {
	fmt.Println("[*] searching files in storage")
	files, err := fpaths.ListFilesInDir(path)
	if err != nil {
		return "", err
	}

	if len(files) == 0 {
		fmt.Println(prompt)
		return "", fmt.Errorf("no files found in storage directory")
	}

	options := []huh.Option[string]{}
	for _, file := range files {
		options = append(options, huh.NewOption(file.Name(), file.Name()))
	}

	var selectedFpath string
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
	fmt.Println("[*] generating key pair")
	privateKey, publicKey := encrypt.GenerateKeyPair()
	fmt.Println("[.] private and public keys generated")
	fmt.Println("[?] where do you want to save your files?")

	var privateKeyFname string
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
		log.Fatalf("[!] input error: %v", err)
	}

	var publicKeyFname string
	err = huh.NewInput().
		Title("public key (optional): ").
		Value(&publicKeyFname).
		Run()
	if err != nil {
		log.Fatalf("[!] input error: %v", err)
	}

	var encryptKey bool
	err = huh.NewConfirm().
		Title("encrypt private key? ").
		Affirmative("Yes").
		Negative("No").
		Value(&encryptKey).
		Run()
	if err != nil {
		log.Fatalf("[!] input error: %v", err)
	}

	var encryptFn func() string
	if encryptKey {
		encryptFn = enterKeyPassphrase
	}
	err = encrypt.SavePrivateKeyToFile(privateKey, privateKeyFname, encryptFn)
	if err != nil {
		log.Fatalf("[!] error saving private key: %v", err)
	}
	err = encrypt.SavePublicKeyToFile(publicKey, publicKeyFname)
	if err != nil {
		log.Fatalf("[!] error saving public key: %v", err)
	}
}

func createNewCertificate() {
	fmt.Println("[*] creating new self-signed certificate")
	fmt.Println("[.] a self-signed certificate requires a private key to sign it")
	privateKeyFpath, err := selectFileFromDir(
		"select private key to sign:",
		fpaths.PrivateKeysDir,
	)
	if err != nil {
		log.Fatalf("[!] input error: %v", err)
	}

	// load private key
	privateKey, err := encrypt.LoadPrivateKeyFromFile(privateKeyFpath, enterKeyPassphrase)
	if err != nil {
		log.Fatalf("[!] error loading private key: %v", err)
	}

	var isCA bool
	err = huh.NewConfirm().
		Title("does certificate belong to CA?").
		Affirmative("Yes").
		Negative("No").
		Value(&isCA).
		Run()
	if err != nil {
		log.Fatalf("[!] input error: %v", err)
	}

	signedCert, err := newSelfSignedCert(*privateKey, isCA)
	if err != nil {
		log.Fatalf("[!] error creating new self-signed certificate: %v", err)
	}

	var certFpath string
	if isCA {
		certFpath = fpaths.CaCertFile
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
			log.Fatalf("[!] input error: %v", err)
		}
	}

	err = saveCertToFile(signedCert, certFpath)
	if err != nil {
		log.Fatalf("[!] error saving certificate: %v", err)
	}

	var signWithCA bool
	err = huh.NewConfirm().
		Title("sign certificate with CA?").
		Affirmative("Yes").
		Negative("No").
		Value(&signWithCA).
		Run()
	if err != nil {
		log.Fatalf("[!] input error: %v", err)
	}

	if !signWithCA {
		return
	}

	signClientCertificate()
}

func signClientCertificate() {
	// load client certificate
	clientCertFpath, err := selectFileFromDir(
		"enter certificate file to be signed:",
		fpaths.CertDir,
	)
	if err != nil {
		log.Fatalf("[!] input error: %v", err)
	}

	clientCert, err := loadCertFromFile(clientCertFpath)
	if err != nil {
		log.Fatalf("[!] error loading client cert: %v", err)
	}

	// load client's public key file
	clientPublicKeyFpath, err := selectFileFromDir(
		"enter client's public key filepath:",
		fpaths.PublicKeysDir,
	)
	if err != nil {
		log.Fatalf("[!] input error: %v", err)
	}

	clientPublicKey, err := encrypt.LoadPublicKeyFromFile(clientPublicKeyFpath)
	if err != nil {
		log.Fatalf("[!] error loading client's public key: %v", err)
	}

	// sign client cert
	signedCert, err := signCertWithCA(clientCert, clientPublicKey)
	if err != nil {
		log.Fatalf("[!] error signing cert with CA: %v", err)
	}

	// save signed cert as a file in signed cert dir
	clientCertFname := filepath.Base(clientCertFpath)
	clientCertFpath = filepath.Join(fpaths.SignedCertDir, clientCertFname)
	err = saveCertToFile(signedCert, clientCertFpath)
	if err != nil {
		log.Fatalf("[!] error saving cert: %v", err)
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
			huh.NewOption("generate key pair", 0),
			huh.NewOption("new certificate", 1),
			huh.NewOption("sign existing certificate", 2),
			huh.NewOption("view storage", 3),
		).
		Value(&userAction).
		Run()
	if err != nil {
		log.Fatalf("[!] input error: %v", err)
	}

	switch userAction {
	case 0:
		generateKeys()
	case 1:
		createNewCertificate()
	case 2:
		signClientCertificate()
	case 3:
		fmt.Printf("[*] listing cert storage dir %v\n\n", fpaths.RootDir)
		fpaths.PrintDirectory(fpaths.RootDir, 0)
	default:
		log.Fatal("[?] unknown user action")
	}
}
