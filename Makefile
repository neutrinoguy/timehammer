# Makefile for TimeHammer
# Cross-platform NTP Security Testing Tool

BINARY_NAME=timehammer
VERSION=1.0.0
BUILD_DIR=build
MAIN_PATH=./cmd/timehammer

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w -X main.AppVersion=$(VERSION)"

.PHONY: all build clean test deps run help

all: deps build

## build: Build for current platform
build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(MAIN_PATH)
	@echo "Done! Run ./$(BINARY_NAME)"

## build-all: Build for all platforms
build-all: clean deps
	@echo "Building for all platforms..."
	@mkdir -p $(BUILD_DIR)
	
	@echo "Building Linux (amd64)..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_PATH)
	
	@echo "Building Linux (arm64)..."
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_PATH)
	
	@echo "Building Windows (amd64)..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_PATH)
	
	@echo "Building macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_PATH)
	
	@echo "Building macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_PATH)
	
	@echo "Done! Binaries are in $(BUILD_DIR)/"
	@ls -la $(BUILD_DIR)/

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)
	@echo "Done!"

## test: Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Done!"

## run: Build and run
run: build
	./$(BINARY_NAME)

## run-headless: Build and run in headless mode
run-headless: build
	./$(BINARY_NAME) --headless

## install: Install to GOPATH/bin
install:
	@echo "Installing $(BINARY_NAME)..."
	$(GOCMD) install $(LDFLAGS) $(MAIN_PATH)
	@echo "Done! $(BINARY_NAME) installed to $$(go env GOPATH)/bin"

## lint: Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

## release: Create release archives
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	
	@cd $(BUILD_DIR) && tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64
	@cd $(BUILD_DIR) && tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64
	@cd $(BUILD_DIR) && tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64
	@cd $(BUILD_DIR) && tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64
	@cd $(BUILD_DIR) && zip release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	
	@echo "Release archives created in $(BUILD_DIR)/release/"
	@ls -la $(BUILD_DIR)/release/

## help: Show this help
help:
	@echo "TimeHammer Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
