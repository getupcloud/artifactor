# Build, package and deploy the artifactor.

VERSION    ?= 0.4.0
IMAGE_NAME ?= ghcr.io/getupcloud/artifactor
IMAGE      ?= $(IMAGE_NAME):$(VERSION)
REGISTRY   ?=
NAMESPACE  ?= artifactor
KUBECTL    ?= kubectl
BIN_DIR    ?= ~/bin
BIN        ?= bin/artifactor
SOURCES    := go.mod go.sum *.go $(shell find internal -name '*.go' -type f) $(shell find web -type f)

# IS_LATEST controls the :latest image tag in .goreleaser.yaml. It must
# always be present in the environment when goreleaser runs (its templates
# fail on missing env keys), so default it to "false" for local builds;
# `IS_LATEST=true make docker-build` publishes :latest.
export IS_LATEST ?= false


ifneq ($(REGISTRY),)
FULL_IMAGE := $(REGISTRY)/$(IMAGE)
else
FULL_IMAGE := $(IMAGE)
endif

.ONESHELL:
.PHONY: help build test vet fmt run export bump docker-build docker-push deploy undeploy port-forward logs tidy clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

build: $(BIN) ## Compile the binary locally

$(BIN): $(SOURCES)
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $@ .

test: ## Run unit tests
	go test ./... -count=1

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

run: ## Run locally against your kubeconfig (dev mode)
	go run . scan --db-dir ./grype-db

export: ## Run a scan and export the full report (scan.html + sbom/ + grype/) to ./export/
	rm -rf export && go run . scan --db-dir ./grype-db --export export

bump: gitleaks ## Bump VERSION (Makefile) and the image tag (deploy/deployment.yaml)
	@read -p 'Next version: ' -e -i "$(VERSION)" NEXT_VERSION
	if [ "$(VERSION)" == "$$NEXT_VERSION" ]; then
		echo "Error: same version"
		exit 1
	fi
	sed -i -E 's|^(VERSION[[:space:]]*\?=[[:space:]]*).*|\1'"$$NEXT_VERSION"'|' Makefile
	sed -i -E 's|(image:[[:space:]]*$(IMAGE_NAME):)[^ #]+|\1'"$$NEXT_VERSION"'|' deploy/deployment.yaml
	git commit -m "Bump version $$NEXT_VERSION" Makefile deploy/deployment.yaml

release:
	@read -p 'gh workflow run release ? [Y/n]: ' res
	[ "$${res,,}" == y -o "$${res}" == '' ] && gh workflow run release || true

gitleaks: ## Avoid secrets to leak
	gitleaks git && gitleaks dir

install: build
	install -m=0766 $(BIN) $(BIN_DIR)/$(notdir $(BIN))

docker-build: ## Build multi-arch container images locally (snapshot, no push; requires goreleaser + buildx)
	goreleaser release --clean --snapshot

docker-push: ## Build and push multi-arch container images with GoReleaser (requires a git tag + registry login)
	goreleaser release --clean

deploy: ## Apply the Kubernetes manifests (namespace, RBAC, deployment, service)
	$(KUBECTL) apply -f deploy/namespace.yaml
	$(KUBECTL) apply -f deploy/serviceaccount.yaml
	$(KUBECTL) apply -f deploy/clusterrole.yaml
	$(KUBECTL) apply -f deploy/clusterrolebinding.yaml
	$(KUBECTL) apply -f deploy/deployment.yaml
	$(KUBECTL) apply -f deploy/service.yaml

undeploy: ## Remove the Kubernetes resources
	$(KUBECTL) delete -f deploy/ --ignore-not-found

port-forward: ## Forward local port 8080 to the service
	$(KUBECTL) port-forward -n $(NAMESPACE) svc/artifactor 8080:8080

logs: ## Follow the scanner pod logs
	$(KUBECTL) logs -n $(NAMESPACE) -l app=artifactor -f

tidy: ## Tidy the Go module
	go mod tidy

clean: ## Remove local build artifacts
	rm -rf bin
