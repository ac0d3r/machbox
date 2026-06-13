
.PHONY: all build

all: build

build:
	CGO_ENABLED=0 GOOS=darwin go build -ldflags "-s -w" -trimpath -o samples/netExecSample netExecSample/main.go