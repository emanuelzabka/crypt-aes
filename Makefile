.PHONY: clean build fmt test
SHELL = /bin/sh

build: crypt-aes

crypt-aes: *.go */*.go */*/*.go
	go build -o crypt-aes main.go

test: crypt-aes
	go test -cover ./...

fmt:
	go fmt ./...

clean:
	rm -f crypt-aes
