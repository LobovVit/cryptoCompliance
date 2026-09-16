GO_SDK ?= /Users/vitaliy/Developer/SDK/Go/current
GO := $(GO_SDK)/bin/go
export GOROOT := $(GO_SDK)
export GOTOOLCHAIN := local
export GOCACHE := /tmp/crypto-compliance-sdk-cache

.PHONY: db-up db-down run check build
db-up:
	docker compose up -d --wait postgres

db-down:
	docker compose down

run:
	$(GO) run .

check:
	$(GO) test -race ./...
	$(GO) vet ./...
	node --check web/app.js

build:
	$(GO) build -o /tmp/cryptocompliance .
