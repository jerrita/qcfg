PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
LDFLAGS   := -s -w

.PHONY: build release fmt lint test

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/qcfg ./cmd/qcfg

release:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" \
			-o dist/qcfg-$$os-$$arch$$ext ./cmd/qcfg || exit 1; \
	done

fmt:
	gofmt -w .

lint:
	go vet ./...

test:
	go test ./...
