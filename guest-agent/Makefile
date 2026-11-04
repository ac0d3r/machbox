AGENT_NAME := machbox-guest
LABEL := dev.machbox.guest
APP_NAME := Machbox Setup

SIGN_IDENTITY := $(or $(SIGN_IDENTITY),-)

BUILD_DIR := build
DMG_DIR := $(BUILD_DIR)/dmg
APP_DIR := $(DMG_DIR)/$(APP_NAME).app

.PHONY: all clean build-agent package uninstall

all: package

build-agent:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin go build -ldflags "-s -w" -trimpath -o "$(BUILD_DIR)/$(AGENT_NAME)" .

	codesign --force --sign "$(SIGN_IDENTITY)" \
		--identifier "$(LABEL)" \
		--options runtime \
		"$(BUILD_DIR)/$(AGENT_NAME)"

# Runs from the MachboxGuest volume and is never copied into the guest; its
# install.sh copies the agent in.
package: build-agent
	rm -rf "$(DMG_DIR)"
	mkdir -p "$(APP_DIR)/Contents/MacOS" "$(APP_DIR)/Contents/Resources"

	swiftc -O -parse-as-library -swift-version 5 \
		-target arm64-apple-macos13.0 \
		-o "$(APP_DIR)/Contents/MacOS/$(APP_NAME)" \
		app/MachboxSetup.swift

	cp app/Info.plist "$(APP_DIR)/Contents/"
	cp "$(BUILD_DIR)/$(AGENT_NAME)" $(LABEL).plist app/install.sh "$(APP_DIR)/Contents/Resources/"

	codesign --force --sign "$(SIGN_IDENTITY)" --options runtime "$(APP_DIR)"

clean:
	rm -rf $(BUILD_DIR)

uninstall:
	sudo launchctl bootout system/$(LABEL) || true
	sudo rm -f /Library/LaunchDaemons/$(LABEL).plist
	sudo rm -f /usr/local/libexec/$(AGENT_NAME)
