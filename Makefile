BINARY_NAME := hooky
INSTALL_PATH := /usr/local/bin

.PHONY: build install clean test snapshot release

build:
	go build -ldflags "-X main.version=dev" -o $(BINARY_NAME) .

install: build
	sudo mv $(BINARY_NAME) $(INSTALL_PATH)/

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/
	go clean

test:
	go test -race ./...

snapshot:
	goreleaser release --snapshot --clean

release:
	goreleaser release --clean
