package modes

import (
	"testing"
	"io"
)

type MockCipher struct {
	blockSize int
}

func NewMockCipher(blockSize int) *MockCipher {
	c := new(MockCipher)
	c.blockSize = blockSize
	return c
}

func (c *MockCipher) Encrypt(block, dest []byte) {
	copy(dest, block)
}

func (c *MockCipher) Decrypt(block, dest []byte) {
	copy(dest, block)
}

func (c *MockCipher) BlockSize() int {
	return c.blockSize
}

type MockReader struct {
	data []byte
	pos int
}

func NewMockReader(data []byte) *MockReader {
	r := new(MockReader)
	r.data = data
	return r
}

func (r *MockReader) Read(p []byte) (n int, err error) {
	blockSize := len(p)
	if r.pos + blockSize <= len(r.data) {
		copy(p, r.data[r.pos:r.pos+blockSize])
		r.pos += blockSize
		n = blockSize
	} else if r.pos < len(r.data) {
		n = len(r.data) - r.pos
		copy(p, r.data[r.pos:r.pos+n])
		r.pos += n
		err = io.EOF
	} else {
		err = io.EOF
	}
	return n, err
}

func TestReadSizes(t *testing.T) {
	sizes := []int {
		8, 16, 32, 48, 50,
	}
	expectedReads := [][]int {
		[]int{8, 0},
		[]int{16, 0},
		[]int{16, 16, 0},
		[]int{16, 16, 16, 0},
		[]int{16, 16, 16, 2, 0},
	}
	var data [][]byte = make([][]byte, len(sizes))
	for i := range sizes {
		data[i] = make([]byte, 16*(len(expectedReads[i])-1))
		if sizes[i] % 16 != 0 {
			data[i][15] = byte(16 - sizes[i])
		}
	}
	for i := range sizes {
		c := NewMockCipher(16)
		r := NewMockReader(data[i])
		reader := NewReader(c, r, ENCRYPTION)
		dest := make([]byte, 16)
		for _, expected := range expectedReads[i] {
			var n int
			n, _ = reader.Read(dest)
			if n != expected {
				t.Errorf("Invalid read. Expected %d bytes, got %d bytes", expected, n)
			}
		}
	}
}
