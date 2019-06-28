package ecb

import (
	"github.com/emanuelzabka/crypt-aes/aes"
	"testing"
)

func TestEncrypt(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("Error creating cipher")
	}
	ecbCipher := NewMode(cipher)
	block := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	expected := []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}
	dest := make([]byte, len(block))
	ecbCipher.Encrypt(block, dest)
	for i := range expected {
		if expected[i] != dest[i] {
			t.Errorf("Invalid encryption")
			break
		}
	}
}

func TestDecrypt(t *testing.T) {
	key := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("Error creating cipher")
	}
	ecbCipher := NewMode(cipher)
	block := []byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}
	expected := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dest := make([]byte, len(block))
	ecbCipher.Decrypt(block, dest)
	for i := range expected {
		if expected[i] != dest[i] {
			t.Errorf("Invalid encryption")
			break
		}
	}
}
