APP=recordscan

.PHONY: fmt build tidy test

fmt:
	gofmt -w ./cmd ./internal

build:
	go build -o ./bin/$(APP) ./cmd/$(APP)

tidy:
	go mod tidy

test:
	go test ./...
