all: build

# Production binaries: no cgo, reproducible.
build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false ./cmd/age-plugin-tpm ./cmd/age-plugin-ykpiv

# The TPM simulator needs cgo and a C compiler.
test:
	CGO_ENABLED=1 go test -race -tags agetpmsim ./...
	CGO_ENABLED=0 go test ./plugin ./ykpiv

check:
	go vet ./...
	GOOS=windows go vet ./...
	test -z "$$(gofmt -l .)"
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

fuzz:
	go test -run '^$$' -fuzz FuzzDecodeIdentity -fuzztime 30s ./plugin
	go test -run '^$$' -fuzz FuzzParseTPMRecipient -fuzztime 30s ./plugin
	go test -run '^$$' -fuzz FuzzUnwrapStanza -fuzztime 30s ./plugin
	go test -run '^$$' -fuzz FuzzUnmarshal -fuzztime 30s ./ykpiv
	go test -run '^$$' -fuzz FuzzUnwrap -fuzztime 30s ./ykpiv

.PHONY: all build test check fuzz
