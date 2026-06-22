AGENT_NAME := machbox-guest
PKG_ID := dev.machbox.guest
VERSION := 1.0

SIGN_IDENTITY := $(or $(SIGN_IDENTITY),-)

BUILD_DIR := build
PAYLOAD_DIR := $(BUILD_DIR)/payload
PLIST_DST := $(PAYLOAD_DIR)/Library/LaunchDaemons
BIN_DST := $(PAYLOAD_DIR)/usr/local/libexec

SCRIPTS_DIR := pkg-scripts

PKG_OUTPUT := $(BUILD_DIR)/$(AGENT_NAME).pkg

.PHONY: all clean build-agent package uninstall

all: package

build-agent:
	CGO_ENABLED=0 GOOS=darwin go build -ldflags "-s -w" -trimpath -o "$(AGENT_NAME)" main.go

	codesign --force --sign "$(SIGN_IDENTITY)" \
		--options runtime \
		"$(AGENT_NAME)"

package: build-agent
	mkdir -p $(PLIST_DST)
	mkdir -p $(BIN_DST)

	cp ${PKG_ID}.plist $(PLIST_DST)
	mv $(AGENT_NAME) $(BIN_DST)/$(AGENT_NAME)
	chmod 755 $(BIN_DST)/$(AGENT_NAME)

	pkgbuild \
		--root $(PAYLOAD_DIR) \
		--scripts $(SCRIPTS_DIR) \
		--identifier $(PKG_ID) \
		--version $(VERSION) \
		$(PKG_OUTPUT)

clean:
	rm -rf $(BUILD_DIR)

uninstall:
	sudo launchctl bootout system /Library/LaunchDaemons/${PKG_ID}.plist || true
	sudo rm -f /Library/LaunchDaemons/${PKG_ID}.plist
	sudo rm -f /usr/local/libexec/$(AGENT_NAME)
