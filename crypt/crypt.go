package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

// a byteString of length 16 to modify the algorithm to encrypt and decrypt.(must be of length 16)
var bytesString string = "hellohellohello!"
var bytes = decode(bytesString)

// secretkey can be 16, 24, or 32 of size. to implement differnt kinds of aes algorithms
// currently using a 16 byte string
var secretKeyString string = "thisisthesecret!"
var secretKey []byte = decode(secretKeyString)

func encode(b []byte) string {
	return hex.EncodeToString(b)
}

func decode(s string) []byte {
	data, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func Encrypt(text string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return encode(cipherText), nil
}

func Decrypt(text string) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", nil
	}
	cipherText := decode(text)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return encode(plainText), nil
}
