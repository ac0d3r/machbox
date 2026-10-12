PRODUCT_NAME  := dynamictool
CONFIGURATION := release
ENTITLEMENTS  := entitlements.plist
SIGN_IDENTITY := $(or $(SIGN_IDENTITY),-)
BINFILE       := bin/$(PRODUCT_NAME)

.PHONY: all build lint clean

all: build

lint:
	swiftlint lint --strict --disable-sourcekit

build:
	swift build -c "$(CONFIGURATION)" --product "$(PRODUCT_NAME)" \
		-Xswiftc -gnone
	
	@mkdir -p bin
	@mv .build/$(CONFIGURATION)/$(PRODUCT_NAME) $(BINFILE)

	@test -f $(ENTITLEMENTS) || { echo "error: missing entitlements file: $@" >&2; exit 1; }

	strip "$(BINFILE)"

	codesign --force --sign "$(SIGN_IDENTITY)" \
		--entitlements "$(ENTITLEMENTS)" \
		--options runtime \
		"$(BINFILE)"

clean:
	swift package clean
	rm -rf .build
	rm -rf bin