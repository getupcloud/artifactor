# Build, package and deploy the artifactor.

VERSION    ?= 0.0.6
IMAGE      ?= ghcr.io/getupcloud/artifactor:$(VERSION)
REGISTRY   ?=
NAMESPACE  ?= artifactor
KUBECTL    ?= kubectl

ifneq ($(REGISTRY),)
FULL_IMAGE := $(REGISTRY)/$(IMAGE)
else
FULL_IMAGE := $(IMAGE)
endif

.ONESHELL:
.PHONY: help build test vet fmt run export docker-build docker-push deploy undeploy port-forward logs tidy clean

bump:
	@read -p 'Next version: ' -e -i "$(VERSION)" NEXT_VERSION
	echo $$NEXT_VERSION
	if [ "$(VERSION)" == "$$NEXT_VERSION" ]; then
		echo "Error: same version"
		exit 1
	fi
	sed -i -e "/^VERSION /s|$(VERSION)|$$NEXT_VERSION|" Makefile

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

build: ## Compile the binary locally
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/artifactor .

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
