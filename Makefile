PRODUCT_NAME  := machbox
ENTITLEMENTS  := entitlements.plist
SIGN_IDENTITY := $(or $(SIGN_IDENTITY),-)
BINFILE       := bin/$(PRODUCT_NAME)
VERSION       := $(or $(VERSION),$(shell git describe --tags --always --dirty 2>/dev/null || echo dev))

# Suppress linker warning for duplicate objc libs (Xcode 15+).
export CGO_LDFLAGS := -Wl,-no_warn_duplicate_libraries

# Guest image
VOLUME_NAME   := MachboxGuest
GUEST_PKG     := guestkit/agent/build/machbox-guest.pkg
GUEST_DMG     := guestkit/agent/guest.dmg

# machbox assets
EMBED_DIR     := internal/assets/data

# Report web view
REPORT_WEB_DIR := internal/report/web

.PHONY: all build build-agent prepare-assets clean

all: build

build: prepare-assets
	CGO_ENABLED=1 GOOS=darwin go build -ldflags "-s -w -X main.Version=$(VERSION)" -trimpath -o "$(BINFILE)" main.go

	@test -f ${ENTITLEMENTS} || { echo "error: missing entitlements file: $@" >&2; exit 1; }

	codesign --force --sign "$(SIGN_IDENTITY)" \
		--entitlements "$(ENTITLEMENTS)" \
		--options runtime \
		"$(BINFILE)"

prepare-assets: build-agent build-tools build-report-web
	@mkdir -p $(EMBED_DIR)
	@mv "$(GUEST_DMG)" $(EMBED_DIR)/

	@mv guestkit/statictool/bin/statictool $(EMBED_DIR)/

	@mv guestkit/dynamictool/bin/dynamictool $(EMBED_DIR)/
	@mkdir -p  $(EMBED_DIR)/DTrace
	@cp -r guestkit/dynamictool/DTrace/*.d $(EMBED_DIR)/DTrace

	@shasum -a 256 $(EMBED_DIR)/guest.dmg | awk '{print $$1}' > $(EMBED_DIR)/guest.dmg.sha256

build-agent:
	rm -f $(GUEST_DMG)
	$(MAKE) -C guestkit/agent package VERSION=$(VERSION)
	@if [ ! -f "$(GUEST_DMG)" ]; then \
		hdiutil create \
			-srcfolder "$(GUEST_PKG)" \
			-volname "$(VOLUME_NAME)" \
			-format UDRW \
			-o "$(GUEST_DMG)"; \
	fi

build-tools:
	$(MAKE) -C guestkit/statictool build
	$(MAKE) -C guestkit/dynamictool build

build-report-web:
	cd "$(REPORT_WEB_DIR)" && npm install && npm run build

clean:
	rm -f $(BINFILE)
	rm -f $(GUEST_DMG)
	rm -rf $(EMBED_DIR)
	
	rm -rf "$(REPORT_WEB_DIR)/dist"

	$(MAKE) -C guestkit/agent clean
	$(MAKE) -C guestkit/statictool clean
	$(MAKE) -C guestkit/dynamictool clean
