package modes

import (
	"io"
)

type Reader struct {
	size      int
	cipher    Cipher
	reader    io.Reader
	nextBlock []byte
	auxBlock  []byte
	nextN     int
	nextErr   error
	op        int
	opFunc    func(r *Reader, dest []byte) (n int, err error)
}

// NewReader creates a new reader for a block cipher operation (ENCRYPTION or DECRYPTION)
func NewReader(cipher Cipher, reader io.Reader, op int) *Reader {
	r := new(Reader)
	r.cipher = cipher
	r.reader = reader
	r.size = cipher.BlockSize()
	r.auxBlock = make([]byte, r.size)
	r.nextBlock = make([]byte, r.size)
	r.nextN = -1
	r.op = op
	if op == ENCRYPTION {
		r.opFunc = encRead
	} else if op == DECRYPTION {
		r.opFunc = decRead
	} else {
		panic("Invalid operation mode.")
	}
	return r
}

// encRead is the method used to read on encryption mode
func encRead(r *Reader, dest []byte) (n int, err error) {
	// block can be of unfixed size
	n, err = r.reader.Read(r.auxBlock)
	if r.nextN >= 0 {
		return n, err
	}
	if n < r.size {
		pad := r.size - n
		for i := n; i < r.size; i++ {
			r.auxBlock[i] = byte(pad)
		}
	}
	// mark end of data for next calls
	if n == 0 {
		r.nextN = 0
	}
	r.cipher.Encrypt(r.auxBlock, dest)
	n = r.size
	return n, err
}

// decRead is the method used to read on decryption mode
func decRead(r *Reader, dest []byte) (n int, err error) {
	if r.nextN > 0 {
		n, err = r.nextN, r.nextErr
		copy(dest, r.nextBlock)
		r.nextN, r.nextErr = r.reader.Read(r.auxBlock)
		if r.nextErr == io.EOF {
			n, err = r.size-int(dest[r.size-1]), r.nextErr
		} else {
			r.cipher.Decrypt(r.auxBlock, r.nextBlock)
		}
	} else {
		n, err = r.reader.Read(r.auxBlock)
		if n > 0 {
			r.cipher.Decrypt(r.auxBlock, dest)
			r.nextN, r.nextErr = r.reader.Read(r.auxBlock)
			if r.nextErr == io.EOF {
				n, err = r.size-int(dest[r.size-1]), r.nextErr
			} else {
				r.cipher.Decrypt(r.auxBlock, r.nextBlock)
			}
		}
	}
	return n, err
}

// Read reads the next block of data managing the possible paddings and the encryption/decryption depending
// on the operation used in NewCipher
func (r *Reader) Read(dest []byte) (n int, err error) {
	return r.opFunc(r, dest)
}
