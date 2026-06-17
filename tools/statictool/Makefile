PRODUCT_NAME  := statictool
SIGN_IDENTITY := $(or $(SIGN_IDENTITY),-)
BINFILE       := bin/$(PRODUCT_NAME)

.PHONY: all build clean

all: build

build:
	CGO_ENABLED=0 GOOS=darwin go build -ldflags "-s -w" -trimpath -o $(BINFILE) cmd/main.go
	
	codesign --force --sign "$(SIGN_IDENTITY)" \
		--options runtime \
		"$(BINFILE)"

clean:
	rm -f $(BINFILE)
