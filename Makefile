ENV         ?= dev
TF_DIR      := infra/envs/$(ENV)
POLICY_ARGS := --policy policies/terraform --data policies/data

.DEFAULT_GOAL := help
.PHONY: help fmt validate lint scan policy-test policy-demo init plan policy-check check

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-14s %s\n", $$1, $$2}'

fmt: ## Format all Terraform code
	terraform fmt -recursive

validate: ## terraform validate every root module and module
	@for d in bootstrap infra/envs/* infra/modules/*; do \
		echo "== $$d"; \
		terraform -chdir=$$d init -backend=false -input=false >/dev/null && terraform -chdir=$$d validate || exit 1; \
	done

lint: ## Run TFLint
	tflint --init --config $(CURDIR)/.tflint.hcl
	tflint --recursive --config $(CURDIR)/.tflint.hcl

scan: ## Run Checkov
	checkov --config-file .checkov.yaml

policy-test: ## Run Rego unit tests
	conftest verify --policy policies --data policies/data --show-builtin-errors

policy-demo: ## Run policies against the sample plans (no AWS needed)
	@echo "== secure-plan.json (expect pass)"
	conftest test policies/fixtures/secure-plan.json $(POLICY_ARGS)
	@echo "== insecure-plan.json (expect failures)"
	-conftest test policies/fixtures/insecure-plan.json $(POLICY_ARGS)

init: ## terraform init using backend.hcl
	terraform -chdir=$(TF_DIR) init -backend-config=backend.hcl

plan: ## Plan and export plan.json
	terraform -chdir=$(TF_DIR) plan -out=tfplan
	terraform -chdir=$(TF_DIR) show -json tfplan > $(TF_DIR)/plan.json

policy-check: ## Evaluate policies against the latest local plan
	conftest test $(TF_DIR)/plan.json $(POLICY_ARGS)

check: fmt validate lint scan policy-test ## Everything CI runs before planning
