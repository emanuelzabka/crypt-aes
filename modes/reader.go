package modes

import (
	"io"
)

type Reader struct {
	size int
	cipher Cipher
	reader io.Reader
	nextBlock []byte
	auxBlock []byte
	nextN int
	nextErr error
	op int
	opFunc func(block, dest []byte)
}

func NewReader(cipher Cipher, reader io.Reader, op int) *Reader {
	r := new(Reader)
	r.cipher = cipher
	r.reader = reader
	r.size = cipher.BlockSize()
	r.auxBlock = make([]byte, r.size)
	r.nextBlock = make([]byte, r.size)
	r.op = op
	if op == ENCRYPTION {
		r.opFunc = cipher.Encrypt
	} else if op == DECRYPTION {
		r.opFunc = cipher.Decrypt
	}
	return r
}

func (r *Reader) Read(dest []byte) (n int, err error) {
	/*
	if r.nextN > 0 || r.nextErr == io.EOF {
		n = r.nextN
		err = r.nextErr
		copy(dest, r.nextBlock)
		if err == io.EOF {
			r.nextN = 0
		}
	} else {
		n, err = r.reader.Read(r.auxBlock)
		r.opFunc(r.auxBlock, dest)
	}
	if err != io.EOF {
		r.nextN, r.nextErr = r.reader.Read(r.auxBlock)
		if r.nextN > 0 {
			r.opFunc(r.auxBlock, r.nextBlock)
		}
	}
	if r.nextN > 0 && r.nextErr == io.EOF {
		r.nextN = r.size - int(r.nextBlock[r.size-1])
	}
	*/
	n, err = r.reader.Read(dest)
	return n, err
}
