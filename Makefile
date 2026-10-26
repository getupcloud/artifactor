# Build, package and deploy the cluster-image-scanner.

VERSION    ?= dev
IMAGE      ?= cluster-image-scanner:$(VERSION)
REGISTRY   ?=
NAMESPACE  ?= image-scanner
KUBECTL    ?= kubectl

ifneq ($(REGISTRY),)
FULL_IMAGE := $(REGISTRY)/$(IMAGE)
else
FULL_IMAGE := $(IMAGE)
endif

.PHONY: help build test vet fmt run docker-build docker-push deploy undeploy port-forward logs tidy clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

build: ## Compile the binary locally
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/cluster-image-scanner .

test: ## Run unit tests
	go test ./... -count=1

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

run: ## Run locally against your kubeconfig (dev mode)
	go run . -db-dir ./grype-db

docker-build: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(FULL_IMAGE) .

docker-push: docker-build ## Build and push the container image
	docker push $(FULL_IMAGE)

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
	$(KUBECTL) port-forward -n $(NAMESPACE) svc/cluster-image-scanner 8080:8080

logs: ## Follow the scanner pod logs
	$(KUBECTL) logs -n $(NAMESPACE) -l app=cluster-image-scanner -f

tidy: ## Tidy the Go module
	go mod tidy

clean: ## Remove local build artifacts
	rm -rf bin
