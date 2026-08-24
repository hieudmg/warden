BIN_DIR ?= bin

.PHONY: build build-server build-client build-client-windows test test-race vet \
	frontend-install frontend-test frontend-build

build: build-server build-client

# Every target that compiles the server package builds the frontend first:
# the Go binary embeds the generated Vite distribution at compile time.
frontend-install:
	npm --prefix web ci

frontend-test: frontend-install
	npm --prefix web test

frontend-build: frontend-install
	npm --prefix web run build

build-server: frontend-build
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/warden-server ./cmd/warden-server

build-client:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/warden ./cmd/warden

build-client-windows:
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(BIN_DIR)/warden.exe ./cmd/warden

test: frontend-test frontend-build
	go test ./...

test-race: frontend-test frontend-build
	go test -race ./...

vet: frontend-build
	go vet ./...
