BIN_DIR ?= bin

.PHONY: build build-server build-client build-client-windows test vet

build: build-server build-client

build-server:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/warden-server ./cmd/warden-server

build-client:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/warden ./cmd/warden

build-client-windows:
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(BIN_DIR)/warden.exe ./cmd/warden

test:
	go test ./...

vet:
	go vet ./...
