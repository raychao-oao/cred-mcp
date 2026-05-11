VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := cred-mcp

DEV_PLUGIN_DIR   := $(HOME)/.claude/plugins/local/cred-mcp-dev
DEV_PLUGIN_VER   := $(shell cat $(HOME)/.claude/plugins/local/cred-mcp-dev/.claude-plugin/plugin.json 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['version'])" 2>/dev/null || echo "0.0.1-dev")
DEV_CACHE_DIR    := $(HOME)/.claude/plugins/cache/cred-mcp-dev/cred-mcp-dev/$(DEV_PLUGIN_VER)

.PHONY: build clean test cross install install-dev

build:
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(BIN) .

test:
	go test ./...

clean:
	rm -f $(BIN) $(BIN)-* *.test *.out

cross:
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-darwin-amd64  .
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-darwin-arm64  .
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-linux-amd64   .
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-linux-arm64   .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o $(BIN)-windows-amd64.exe .

install: build
	cp $(BIN) $(GOPATH)/bin/$(BIN)

# Build and copy binary into the local Claude Code plugin cache.
# Claude Code reads from the cache dir, not the local plugin dir.
# After running this, restart Claude Code to pick up the new binary.
install-dev: build
	@if [ ! -d "$(DEV_PLUGIN_DIR)" ]; then \
		echo "ERROR: $(DEV_PLUGIN_DIR) does not exist."; \
		echo "Set up the dev plugin first (see CLAUDE.md)."; \
		exit 1; \
	fi
	mkdir -p $(DEV_PLUGIN_DIR)/bin
	cp $(BIN) $(DEV_PLUGIN_DIR)/bin/$(BIN)
	mkdir -p $(DEV_CACHE_DIR)/bin
	cp $(BIN) $(DEV_CACHE_DIR)/bin/$(BIN)
	@echo "Installed $(BIN) to:"
	@echo "  $(DEV_PLUGIN_DIR)/bin/"
	@echo "  $(DEV_CACHE_DIR)/bin/"
	@echo "Restart Claude Code to load the new binary."
