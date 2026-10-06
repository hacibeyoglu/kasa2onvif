# kasa2onvif Makefile
GO := $(shell command -v go 2>/dev/null || echo $(HOME)/.local/go/bin/go)
TARGET ?= kasa2onvif
VERSION := 1.0.0
LDFLAGS := -s -w

.PHONY: all build test vet clean deploy pi

all: build

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(TARGET) ./cmd/kasa2onvif

pi:
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(TARGET)-linux-arm64 ./cmd/kasa2onvif

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -f $(TARGET) $(TARGET)-linux-arm64

# Override with your Pi's SSH target, e.g.: make deploy SSH_USER=pi SSH_HOST=192.168.1.50
SSH_USER ?= pi
SSH_HOST ?= raspberrypi.local
SSH_TARGET := $(SSH_USER)@$(SSH_HOST)

# Deploy the arm64 binary + local config to the Pi.
# Your local config.yaml (git-ignored) is what gets shipped.
deploy: pi
	scp $(TARGET)-linux-arm64 $(SSH_TARGET):~/kasa2onvif.new
	scp config.yaml $(SSH_TARGET):~/config.yaml.new
	ssh $(SSH_TARGET) 'mv ~/kasa2onvif.new ~/kasa2onvif && chmod +x ~/kasa2onvif'
	@echo "Deployed to $(SSH_TARGET). Install the service with: sudo ./install.sh (on the Pi)"
