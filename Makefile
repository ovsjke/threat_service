# Resolve paths relative to this Makefile, including make -f /path/to/Makefile.
ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
COMPOSE = docker compose --project-directory "$(ROOT)" -f "$(ROOT)docker-compose.yml"
.DEFAULT_GOAL := help

.PHONY: help init restart ps config migrate
help: ## Show development commands
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "%-18s %s\n", $$1, $$2}' "$(ROOT)Makefile"

init: env cert ## Prepare local environment and TLS

config: ## Validate Compose including all profiles without printing secrets
	$(COMPOSE) --profile monitoring --profile test --profile e2e config -q

restart: ## Restart running services (use up to apply config changes)
	@set -eu; \
	services=$$($(COMPOSE) --profile monitoring ps --services --status running | awk '$$0 !~ /^(migrations|test_migrations|test_db|e2e_app)$$/'); \
	if [ -n "$$services" ]; then $(COMPOSE) --profile monitoring restart $$services; fi

ps: ## Show all container states
	$(COMPOSE) --profile monitoring --profile test --profile e2e ps -a

migrate: init ## Apply pending main database migrations once
	$(COMPOSE) up -d --wait db
	$(COMPOSE) run --rm migrations


.PHONY: up down test integration e2e logs cert env monitoring-up monitoring-down

up: init ## Build and start the application stack
	$(COMPOSE) up -d --build --wait --wait-timeout 900 nginx
	$(COMPOSE) exec -T nginx nginx -t
	$(COMPOSE) exec -T nginx nginx -s reload
	@echo "Stack ready. Endpoints: see API_URL and host ports in .env (default https://localhost)."
	@echo "Logs: make logs"

down: ## Stop all profiles without removing persistent data
	$(COMPOSE) --profile monitoring --profile test --profile e2e down

logs: ## Follow application and proxy logs
	$(COMPOSE) logs -f nginx app_api scanner clamav

cert: ## Create or renew local TLS certificate
	@set -eu; cd "$(ROOT)"; \
	mkdir -p infra/nginx/certs; \
	if [ ! -s infra/nginx/certs/localhost.crt ] || \
	    [ ! -s infra/nginx/certs/localhost.key ] || \
	    ! openssl x509 -checkend 86400 -noout -in infra/nginx/certs/localhost.crt >/dev/null 2>&1; then \
		echo "Generating local TLS certificate..."; \
		openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
			-keyout infra/nginx/certs/localhost.key \
			-out infra/nginx/certs/localhost.crt \
			-config infra/nginx/openssl.cnf \
			-extensions v3_req; \
		chmod 600 infra/nginx/certs/localhost.key; \
	fi

env: ## Create .env if missing
	@set -eu; cd "$(ROOT)"; \
	if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example"; \
	fi

test: ## Run unit tests in all Go modules
	cd "$(ROOT)" && go test ./contracts/... ./scanner/... ./threat_api/... -count=1

integration: init ## Test repository against a temporary database
	@set -eu; cd "$(ROOT)"; \
	trap '$(COMPOSE) --profile test --profile e2e rm -sf test_migrations test_db >/dev/null 2>&1 || true' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	$(COMPOSE) --profile test up -d --wait test_db; \
	$(COMPOSE) --profile test run --rm test_migrations; \
	test_db_address=$$($(COMPOSE) --profile test port test_db 5432); \
	(cd threat_api && TEST_DB_URL="postgres://test:test@$$test_db_address/threats_test?sslmode=disable" go test -tags=integration -v ./internal/... -count=1)

e2e: init ## Test HTTP API against a temporary database
	@set -eu; cd "$(ROOT)"; \
	trap '$(COMPOSE) --profile test --profile e2e rm -sf e2e_app test_migrations test_db >/dev/null 2>&1 || true' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	$(COMPOSE) --profile test --profile e2e up -d --build --wait e2e_app; \
	e2e_address=$$($(COMPOSE) port e2e_app 8080); \
	n=0; \
	until [ "$$(curl -s -o /dev/null -w '%{http_code}' http://$$e2e_address/info/invalid)" = '400' ]; do \
		n=$$((n + 1)); \
		[ $$n -lt 30 ] || { echo 'E2E application did not become ready'; exit 1; }; \
		sleep 1; \
	done; \
	(cd threat_api && E2E_BASE_URL=http://$$e2e_address go test -tags=e2e -v ./tests/e2e -count=1)
	
monitoring-up: init ## Start the complete monitoring stack and API
	$(COMPOSE) --profile monitoring up -d --build --wait prometheus postgres_exporter grafana app_api

monitoring-down: ## Stop monitoring without removing its data
	$(COMPOSE) stop grafana prometheus postgres_exporter
