package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/emanuelzabka/crypt-aes/aes"
	"github.com/emanuelzabka/crypt-aes/modes"
	"github.com/emanuelzabka/crypt-aes/modes/ecb"
	flags "github.com/jessevdk/go-flags"
	"os"
	"strings"
)

var opts struct {
	Encrypt   bool   `short:"e" long:"encrypt" description:"Perform encryption operation (default)"`
	Decrypt   bool   `short:"d" long:"decrypt" description:"Perform decryption operation"`
	Key       string `short:"k" long:"key" description:"Cipher key"`
	NewKey    bool   `long:"newkey" description:"Generates and outputs a new cipher key"`
	KeyLength int    `short:"l" long:"key-length" description:"Key length for the operation" choice:"128" choice:"192" choice:"256" default:"192"`
	OpMode    string `short:"m" long:"mode" description:"Mode of operation" choice:"ecb" default:"ecb"`
	Input     string `short:"i" long:"input" description:"Input file path or '-' to stdin" default:"-"`
	Output    string `short:"o" long:"output" description:"Output file path or '-' to stdout" default:"-"`
}

var cipherKey []byte
var inputReader *bufio.Reader
var inputFile *os.File
var outputWriter *bufio.Writer
var outputFile *os.File

func askForKey() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "Enter key: ")
	key, _ := reader.ReadString('\n')
	return strings.Trim(key, "\n")
}

func initInputReader() {
	if inputReader != nil {
		return
	}
	if opts.Input != "-" {
		file, err := os.Open(opts.Input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening input file: %s\n", err.Error())
			os.Exit(1)
		}
		inputFile = file
		inputReader = bufio.NewReader(file)
	} else {
		inputReader = bufio.NewReader(os.Stdin)
	}
}

func initOutputWriter() {
	if outputWriter != nil {
		return
	}
	if opts.Output != "-" {
		file, err := os.OpenFile(opts.Output, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %s\n", err.Error())
			os.Exit(1)
		}
		outputFile = file
		outputWriter = bufio.NewWriter(file)
	} else {
		outputWriter = bufio.NewWriter(os.Stdout)
	}
}

func byteToHexString(block []byte) string {
	return hex.EncodeToString(block)
}

func newKey() (result []byte) {
	size := opts.KeyLength / 8
	result = make([]byte, size)
	_, err := rand.Read(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %s\n", err.Error())
		os.Exit(1)
	}
	return result
}

func parseArgs() {
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}
	if opts.Encrypt && opts.Decrypt {
		fmt.Fprintln(os.Stderr, "Encrypt and decrypt options cannot be used at the same call")
		os.Exit(1)
	}
	// Assuming encrypt for default
	if !opts.Encrypt && !opts.Decrypt {
		opts.Encrypt = true
	}
	if opts.Key == "" && opts.Decrypt {
		if opts.Input != "-" {
			opts.Key = askForKey()
		}
		if opts.Key == "" {
			fmt.Fprintln(os.Stderr, "* Cipher key is required for decryption operation")
			os.Exit(1)
		}
	}
	if opts.Input != "-" {
		if _, err := os.Stat(opts.Input); os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "Error: Input file not found")
			os.Exit(1)
		}
	}
	if opts.NewKey || (opts.Encrypt && opts.Key == "") {
		cipherKey = newKey()
		if !opts.NewKey {
			fmt.Fprintf(os.Stderr, "Using key: %s\n", byteToHexString(cipherKey))
		} else {
			fmt.Fprintln(os.Stdout, byteToHexString(cipherKey))
		}
	} else {
		cipherKey, err = hex.DecodeString(opts.Key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "* Error decoding the provided key: %s\n", opts.Key)
			os.Exit(1)
		}
	}
}

func closeFiles() {
	if outputWriter != nil {
		outputWriter.Flush()
	}
	if inputFile != nil {
		inputFile.Close()
	}
	if outputFile != nil {
		outputFile.Close()
	}
}

func process(operation int) {
	var block []byte
	var endBlock []byte
	cipher, err := aes.NewCipher(cipherKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing cipher: %s\n", err.Error())
		os.Exit(1)
	}
	block = make([]byte, cipher.BlockSize())
	ecbCipher := ecb.NewMode(cipher)
	reader := modes.NewReader(ecbCipher, inputReader, operation)
	for true {
		n, err := reader.Read(block)
		if n == 0 {
			break
		}
		if n < cipher.BlockSize() {
			endBlock = make([]byte, n)
			copy(endBlock, block)
			block = endBlock
		}
		_, err = outputWriter.Write(block)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to output: %s\n", err.Error())
			os.Exit(1)
		}
		if opts.Output == "-" {
			outputWriter.Flush()
		}
	}
}

func main() {
	defer closeFiles()
	parseArgs()
	initInputReader()
	initOutputWriter()
	if opts.Encrypt {
		process(modes.ENCRYPTION)
	}
	if opts.Decrypt {
		process(modes.DECRYPTION)
	}
}
