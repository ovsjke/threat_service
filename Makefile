ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
COMPOSE = docker compose --project-directory "$(ROOT)" -f "$(ROOT)docker-compose.yml"
.DEFAULT_GOAL := help

.PHONY: help init restart ps config migrate
help: 
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "%-18s %s\n", $$1, $$2}' "$(ROOT)Makefile"

init: env cert

config: 
	$(COMPOSE) --profile monitoring --profile test --profile e2e config -q

restart:
	services=$$($(COMPOSE) --profile monitoring ps --services --status running | awk '$$0 !~ /^(migrations|test_migrations|test_db|e2e_app)$$/'); \
	if [ -n "$$services" ]; then $(COMPOSE) --profile monitoring restart $$services; fi

ps:
	$(COMPOSE) --profile monitoring --profile test --profile e2e ps -a

migrate: init 
	$(COMPOSE) up -d --wait db
	$(COMPOSE) run --rm migrations


.PHONY: up down test integration e2e logs cert env monitoring-up monitoring-down

up: init
	$(COMPOSE) up -d --build --wait --wait-timeout 900 redis nginx
	$(COMPOSE) exec -T nginx nginx -t
	$(COMPOSE) exec -T nginx nginx -s reload
	@echo "Stack ready. Endpoints: see API_URL and host ports in .env (default https://localhost)."
	@echo "Logs: make logs"

down: 
	$(COMPOSE) --profile monitoring --profile test --profile e2e down

logs: 
	$(COMPOSE) logs -f nginx app_api scanner clamav

cert: 
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

env: 
	@set -eu; cd "$(ROOT)"; \
	if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example"; \
	fi

test: 
	cd "$(ROOT)" && go test ./contracts/... ./scanner/... ./threat_api/... -count=1

integration: init 
	@set -eu; cd "$(ROOT)"; \
	trap '$(COMPOSE) --profile test --profile e2e rm -sf test_migrations test_db >/dev/null 2>&1 || true' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	$(COMPOSE) --profile test up -d --wait test_db; \
	$(COMPOSE) --profile test run --rm test_migrations; \
	test_db_address=$$($(COMPOSE) --profile test port test_db 5432); \
	(cd threat_api && TEST_DB_URL="postgres://test:test@$$test_db_address/threats_test?sslmode=disable" go test -tags=integration -v ./internal/... -count=1)

e2e: init 
	@set -eu; cd "$(ROOT)"; \
	trap '$(COMPOSE) --profile test --profile e2e rm -sf e2e_app test_migrations test_db >/dev/null 2>&1 || true' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	$(COMPOSE) --profile test --profile e2e up -d --build --wait e2e_app; \
	e2e_address=$$($(COMPOSE) port e2e_app 8080); \
	(cd threat_api && E2E_BASE_URL=http://$$e2e_address go test -tags=e2e -v ./tests/e2e -count=1)

monitoring-up: init 
	$(COMPOSE) --profile monitoring up -d --build --wait --wait-timeout 900 prometheus postgres_exporter grafana app_api scanner

monitoring-down: 
	$(COMPOSE) stop grafana prometheus postgres_exporter

.PHONY: redis-up redis-down redis-restart redis-logs redis-status smoke
redis-up: env 
	$(COMPOSE) up -d --no-deps --wait redis

redis-down: 
	$(COMPOSE) stop redis

redis-restart: 
	$(COMPOSE) restart redis

redis-logs: 
	$(COMPOSE) logs -f redis

redis-status: 
	$(COMPOSE) ps -a redis

smoke: 
	$(COMPOSE) exec -T db sh -ec 'pg_isready -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'
	$(COMPOSE) exec -T app_api wget -q -T 5 -O /dev/null http://127.0.0.1:8080/metrics
	$(COMPOSE) exec -T scanner wget -q -T 5 -O /dev/null http://127.0.0.1:8082/health
	$(COMPOSE) exec -T scanner wget -q -T 5 -O /dev/null http://127.0.0.1:8082/ready
	$(COMPOSE) exec -T scanner wget -q -T 5 -O /dev/null http://127.0.0.1:8082/metrics
	$(COMPOSE) exec -T nginx wget -q -T 5 --no-check-certificate -O /dev/null https://127.0.0.1/ready
	@test "$$($(COMPOSE) exec -T redis redis-cli ping)" = PONG
	@echo "Smoke checks passed."
