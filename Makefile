VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := cred-mcp

.PHONY: build clean test cross install

build:
	go build -ldflags '$(LDFLAGS)' -o $(BIN) .

test:
	go test ./...

clean:
	rm -f $(BIN) $(BIN)-* *.test *.out

cross:
	GOOS=darwin  GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-darwin-amd64  .
	GOOS=darwin  GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-darwin-arm64  .
	GOOS=linux   GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-linux-amd64   .
	GOOS=linux   GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-linux-arm64   .
	GOOS=windows GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-windows-amd64.exe .

install: build
	cp $(BIN) $(GOPATH)/bin/$(BIN)
