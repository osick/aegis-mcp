.PHONY: test cover build
test:
	go test ./...
cover:
	go test -cover ./...
build:
	go build -o aegis ./cmd/aegis
