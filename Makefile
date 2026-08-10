SHELL := /bin/bash
TF := terraform -chdir=terraform
COMPOSE := docker compose
RG = $(shell $(TF) output -raw resource_group 2>/dev/null)
ACR = $(shell $(TF) output -raw registry_name 2>/dev/null)
REGISTRY = $(shell $(TF) output -raw registry_login_server 2>/dev/null)
IMAGE_TAG ?= latest

.PHONY: help test lint build push deploy migrate seed traffic scan dashboard \
        evidence logs env destroy clean

help:
	@echo "test        run the suite in docker (no host ruby needed)"
	@echo "lint        rubocop, brakeman, bundler-audit, terraform fmt"
	@echo "deploy      registry first, then image, then everything else"
	@echo "migrate     run db:prepare as the migrate job"
	@echo "seed        create the demo secret estate"
	@echo "traffic     trigger the consumer jobs so the audit log fills"
	@echo "scan        start the scan job now instead of waiting for cron"
	@echo "dashboard   print the dashboard URL"
	@echo "evidence    list evidence artifacts in the immutable container"
	@echo "destroy     purge evidence, remove the seed, tear down"

test:
	$(COMPOSE) run --rm test

lint:
	$(COMPOSE) run --rm test bash -lc "\
		bundle exec rubocop --parallel && \
		bundle exec brakeman --quiet --no-pager && \
		bundle exec bundle-audit check --update"
	$(TF) fmt -check -recursive
	$(TF) init -backend=false -input=false >/dev/null && $(TF) validate

# Two applies on purpose. The container app cannot be created until an
# image exists to pull, and the registry cannot exist before terraform
# runs. Targeting the registry first is the smallest thing that breaks
# the cycle without a placeholder image sitting in state.
deploy:
	$(TF) init -input=false
	$(TF) apply -input=false -auto-approve -target=module.compute.azurerm_container_registry.main
	$(MAKE) push
	$(TF) apply -input=false -auto-approve
	$(MAKE) migrate
	@echo
	@echo "dashboard: $$($(TF) output -raw dashboard_url)"
	@echo "next: make seed, then make traffic, wait ~10 minutes, then make scan"

push:
	az acr login --name $(ACR)
	docker build --platform linux/amd64 -t $(REGISTRY)/secops:$(IMAGE_TAG) .
	docker push $(REGISTRY)/secops:$(IMAGE_TAG)

migrate:
	az containerapp job start --name $$($(TF) output -raw migrate_job_name) \
		--resource-group $(RG) --output none
	@echo "migrate job started"

# Operator tasks read the deployment's coordinates from terraform outputs.
env:
	@$(TF) output -raw shell_env

# Seeding runs on the host as the operator, not in the app container. It
# needs the az CLI and the operator's Entra session, and it deliberately
# does not run under the platform identity, which cannot write to any of
# these services.
seed:
	@eval "$$($(TF) output -raw shell_env)" && scripts/seed.sh create

traffic:
	az containerapp job start --name $$($(TF) output -raw consumer_app_job_name) \
		--resource-group $(RG) --output none
	az containerapp job start --name $$($(TF) output -raw consumer_batch_job_name) \
		--resource-group $(RG) --output none
	@echo "consumer jobs started; audit events reach Log Analytics in 5 to 15 minutes"

scan:
	az containerapp job start --name $$($(TF) output -raw scan_job_name) \
		--resource-group $(RG) --output none
	@echo "scan started; the dashboard updates when it finishes"
	@echo "dashboard: $$($(TF) output -raw dashboard_url)"

dashboard:
	@echo $$($(TF) output -raw dashboard_url)

evidence:
	az storage blob list \
		--account-name $$($(TF) output -raw evidence_storage_account) \
		--container-name $$($(TF) output -raw evidence_container) \
		--auth-mode login --output table

logs:
	az containerapp job logs show --name $$($(TF) output -raw scan_job_name) \
		--resource-group $(RG) --follow

destroy:
	@eval "$$($(TF) output -raw shell_env)" && \
		scripts/seed.sh destroy && scripts/purge_evidence.sh
	$(TF) destroy -input=false -auto-approve
	@echo "destroyed. the Key Vault is soft deleted with purge protection on:"
	@echo "  az keyvault list-deleted --query \"[].name\""
	@echo "it expires on its own after the retention window and bills nothing."

clean:
	$(COMPOSE) down -v
	rm -rf tmp/cache tmp/pids
