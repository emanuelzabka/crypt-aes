package modes

// Operations
const (
	ENCRYPTION = iota
	DECRYPTION
)

type Cipher interface {
	Encrypt(block, dest []byte)
	Decrypt(block, dest []byte)
	BlockSize() int
}

type CipherMode interface {
	Cipher
}
