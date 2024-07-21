package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	mrand "math/rand"
)

type ErrMissingEncryptionKey struct {
	message string
}

func (e *ErrMissingEncryptionKey) Error() string {
	if len(e.message) == 0 {
		e.message = "no passphrase provided for message encryption or decryption"
	}

	return e.message
}

// padByteArray pads the input byte array to the specified length with the given pad byte.
func padByteArray(input []byte, length int) []byte {
	if len(input) >= length {
		return input[:length] // If the input is already long enough, truncate it.
	}

	padded_array := make([]byte, length)
	copy(padded_array, input)

	// seed a random number generator with a constant value
	// so we always get the same numbers on multiple runs of the program
	random_num_generator := mrand.NewSource(42)

	for i := len(input); i < length; i++ {
		rand_num := random_num_generator.Int63()
		padded_array[i] = byte(rand_num)
	}

	return padded_array
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
