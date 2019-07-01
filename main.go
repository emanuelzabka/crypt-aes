package main

import (
	flags "github.com/jessevdk/go-flags"
	"fmt"
	"os"
)

var opts struct {
	Encrypt bool `short:"e" long:"encrypt" description:"Perform encryption operation"`
	Decrypt bool `short:"d" long:"decrypt" description:"Perform decryption operation"`
	Key bool `short:"k" long:"key" description:"Cipher key"`
	Newkey bool `long:"newkey" description:"Generates and outputs a new cipher key"`
	KeyLength int `short:"l" long:"key-length" description:"Key length for the operation" choice:"128" choice:"192" choice:"256"`
	Output string `short:"o" long:"output" description:"Output path or '-' to stdout" default:"-"`
}

func main() {
	args, err := flags.Parse(&opts)

	if err != nil {
		os.Exit(1)
		//panic(err)
	}
	fmt.Println(args)
}
