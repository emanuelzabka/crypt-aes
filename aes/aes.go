package aes

import (
	"encoding/binary"
	"errors"
)

type AESCipher struct {
	keyLength int
	numRounds int
	key []byte
	expandedKeys []byte
};

var sBoxMatrix []byte = []byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var rCon []uint32 = []uint32{
	0x01000000,
	0x02000000,
	0x04000000,
	0x08000000,
	0x10000000,
	0x20000000,
	0x40000000,
	0x80000000,
	0x1b000000,
	0x36000000,
}

func subBytes(state []byte) {
	for i := range state {
		row := state[i] >> 4
		col := state[i] & 0x0f
		state[i] = sBoxMatrix[row*16+col]
	}
}

func shiftRows(src, dst []byte) {
	copy(dst, src)
	for r := 1; r < 4; r++ {
		for c := 0; c < 4; c++ {
			// state[r][c] = state[r][(c+shift(r)) mod 4]
			dst[r+c*4] = src[r+((c + r) & 3)*4]
		}
	}
}

// gfMul return GF(2^8) Galois Field (finite field) multiplication using a modified version of peasant's algorithm
func gfMul(a, b byte) byte {
	var prod byte = 0
	for a != 0 && b != 0 {
		if b & 1 != 0 {
			prod ^= a
		}
		b >>= 1
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1b
		}
	}
	return prod
}

func mixColumns(src, dst []byte) {
	for c := 0; c < 4; c++ {
		// column offset
		cOff := c*4
		dst[0+cOff] = gfMul(0x02, src[0+cOff]) ^ gfMul(0x03, src[1+cOff]) ^ src[2+cOff] ^ src[3+cOff]
		dst[1+cOff] = src[0+cOff] ^ gfMul(0x02, src[1+cOff]) ^ gfMul(0x03, src[2+cOff]) ^ src[3+cOff]
		dst[2+cOff] = src[0+cOff] ^ src[1+cOff] ^ gfMul(0x02, src[2+cOff]) ^ gfMul(0x03, src[3+cOff])
		dst[3+cOff] = gfMul(0x03, src[0+cOff]) ^ src[1+cOff] ^ src[2+cOff] ^ gfMul(0x02, src[3+cOff])
	}
}

func addRoundKey(state []byte, keys []byte, round int) {
	// key row offset
	krOff := round*4
	for c := 0; c < 4; c++ {
		// column offset
		cOff := c*4
		state[0+cOff] ^= keys[krOff+c+0]
		state[1+cOff] ^= keys[krOff+c+1]
		state[2+cOff] ^= keys[krOff+c+2]
		state[3+cOff] ^= keys[krOff+c+3]
	}
}

func subWord(word uint32) uint32 {
	var buffer [4]byte
	var result uint32
	binary.BigEndian.PutUint32(buffer[:], word)
	subBytes(buffer[:])
	result = binary.BigEndian.Uint32(buffer[:])
	return result
}

func rotWord(word uint32) uint32 {
	trail := word >> 24
	return (word << 8) | trail
}

func getNumRounds(keyLength int) int {
	var numRounds int
	switch keyLength {
	case 4:
		numRounds = 10
	case 6:
		numRounds = 12
	case 8:
		numRounds = 14
	}
	return numRounds
}

func keyExpansion(key, expandedKeys []byte, keyLength int) {
	var temp uint32
	var wordKeys [15*4]uint32
	var numRounds int = getNumRounds(keyLength)
	i := 0
	for i < keyLength {
		wordKeys[i] = binary.BigEndian.Uint32(key[4*i:(4*i+4)])
		i++
	}
	i = keyLength
	for i < 4*(numRounds+1) {
		temp = wordKeys[i-1]
		if i % keyLength == 0 {
			temp = subWord(rotWord(temp)) ^ rCon[i/keyLength - 1]
		} else if keyLength > 6 && i % keyLength == 4 {
			temp = subWord(temp)
		}
		wordKeys[i] = wordKeys[i-keyLength] ^ temp
		i++
	}
	for i = 0; i < 4*(numRounds+1); i++ {
		binary.BigEndian.PutUint32(expandedKeys[i*4:(i*4+4)], wordKeys[i])
	}
}

func NewCipher(key []byte) (*AESCipher, error) {
	var err error = nil
	if len(key) != 16 && len(key) != 32 && len(key) != 64 {
		err = errors.New("Invalid key length. Allowed lengths: 128-bit (16 bytes), 192-bit (24 bytes), 256-bit (64 bytes)")
		return nil, err
	}
	cipher := new(AESCipher)
	cipher.key = make([]byte, len(key))
	copy(cipher.key, key)
	cipher.keyLength = len(key) / 4
	cipher.numRounds = getNumRounds(cipher.keyLength)
	cipher.expandedKeys = make([]byte, (cipher.numRounds+1)*cipher.keyLength*4)
	keyExpansion(cipher.key, cipher.expandedKeys, cipher.keyLength)
	return cipher, err
}

func (c *AESCipher) Encrypt(block, dest []byte) {
	var state []byte = make([]byte, 16)
	var tmpState []byte = make([]byte, 16)
	copy(state, block)
	addRoundKey(state, c.expandedKeys, 0)
	for r := 1; r < c.numRounds - 1; r++ {
		subBytes(state)
		copy(tmpState, state)
		shiftRows(tmpState, state)
		copy(tmpState, state)
		mixColumns(tmpState, state)
		addRoundKey(state, c.expandedKeys, r)
	}
	subBytes(state)
	copy(tmpState, state)
	shiftRows(tmpState, state)
	addRoundKey(state, c.expandedKeys, c.numRounds)
	copy(dest, state)
}

