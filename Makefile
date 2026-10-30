GO ?= go
DIST := dist
BINARY := $(DIST)/tesla-gateway

.PHONY: build build-arm64 test clean

# Local developer build (host OS/architecture).
build:
	mkdir -p $(DIST)
	CGO_ENABLED=0 $(GO) build -o $(BINARY) ./cmd/tg

# OpenWrt / UFI003 build: static linux/arm64 binary.
build-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -o $(BINARY) ./cmd/tg

test:
	$(GO) vet ./...
	$(GO) test -race ./...

clean:
	rm -f $(BINARY)
