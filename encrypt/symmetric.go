package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	mrand "math/rand"
)

type ErrMissingEncryptionKey struct {
	msg string
}

func (err *ErrMissingEncryptionKey) Error() string {
	if len(err.msg) != 0 {
		return err.msg
	}

	return "no passphrase provided for message encryption or decryption"
}

// padByteArray pads the input byte array to the specified length with the given pad byte.
func padByteArray(input []byte, length int) []byte {
	if len(input) >= length {
		return input[:length] // If the input is already long enough, truncate it.
	}

	paddedArray := make([]byte, length)
	copy(paddedArray, input)

	// seed a random number generator with a constant value
	// so we always get the same numbers on multiple runs of the program
	random := mrand.NewSource(42)

	for i := len(input); i < length; i++ {
		randomNumber := random.Int63()
		paddedArray[i] = byte(randomNumber)
	}

	return paddedArray
}

func Encrypt(message, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, &ErrMissingEncryptionKey{}
	}

	// always pad key to 32bytes to select AES-256
	key = padByteArray(key, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// create byte slice to hold the encrypted message
	ciphertext := make([]byte, aes.BlockSize+len(message))

	// generate iv nonce which is stored at the beginning of the byte slice
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	// use the AES block cipher in CFB to encrypt the message
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], message)
	return ciphertext, nil
}

func Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, &ErrMissingEncryptionKey{}
	}

	// always pad key to 32bytes to select AES-256
	key = padByteArray(key, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// separate the iv nonce from encrypted message bytes
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// decrypt the message using the CFB block mode
	cfb := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
