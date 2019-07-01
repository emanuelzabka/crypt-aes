package modes

import (
	"io"
	//"errors"
)

type Writer struct {
	cipher Cipher
	writer io.Writer
	size int
	op int
}

func NewWriter(cipher Cipher, writer io.Writer, op int) *Writer {
	w := new(Writer)
	w.cipher = cipher
	w.writer = writer
	w.size = cipher.BlockSize()
	w.op = op
	return w
}

func (w *Writer) Write(block []byte, pad int) (err error) {
	err = nil
	return err
}
