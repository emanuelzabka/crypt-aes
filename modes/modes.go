package modes

type Cipher interface {
	Encrypt(block, dest []byte)
	Decrypt(block, dest []byte)
}

type CipherMode interface {
	Encrypt(block, dest []byte)
	Decrypt(block, dest []byte)
}
