package ecb

import (
	"github.com/emanuelzabka/crypt-aes/modes"
)

// ECB is the Electronic Code Book mode
type ECB struct {
	cipher modes.Cipher
}

// NewMode creates a new mode of operation ECB using the cipher
func NewMode(cipher modes.Cipher) *ECB {
	ecbCipher := new(ECB)
	ecbCipher.cipher = cipher
	return ecbCipher
}

// Encrypt encrypts a block into dest
func (c *ECB) Encrypt(block, dest []byte) {
	c.cipher.Encrypt(block, dest)
}

// Decrypt decrypts a block into dest
func (c *ECB) Decrypt(block, dest []byte) {
	c.cipher.Decrypt(block, dest)
}

// BlockSize returns the block size used
func (c *ECB) BlockSize() int {
	return c.cipher.BlockSize()
}
