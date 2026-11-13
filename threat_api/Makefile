.PHONY: up down test integration e2e logs cert env

up: cert env
	docker compose up -d --build nginx
	@echo "API: https://localhost"
	@echo "Logs: make logs"

down:
	docker compose --profile test --profile e2e down

logs:
	docker compose logs -f nginx app

cert:
	@mkdir -p nginx/certs
	@if [ ! -s nginx/certs/localhost.crt ] || \
	    [ ! -s nginx/certs/localhost.key ] || \
	    ! openssl x509 -checkend 86400 -noout -in nginx/certs/localhost.crt >/dev/null 2>&1; then \
		echo "Generating local TLS certificate..."; \
		openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
			-keyout nginx/certs/localhost.key \
			-out nginx/certs/localhost.crt \
			-config nginx/openssl.cnf \
			-extensions v3_req; \
		chmod 600 nginx/certs/localhost.key; \
	fi

env:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example"; \
	fi

test:
	go test ./... -count=1

integration: env
	@set -eu; \
	set -a; . ./.env; set +a; \
	: "$${TEST_DB_URL:?TEST_DB_URL is not set}"; \
	trap 'docker compose --profile test --profile e2e rm -sf test_migrations test_db >/dev/null 2>&1 || true' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	docker compose --profile test up -d --wait test_db; \
	docker compose --profile test run --rm test_migrations; \
	go test -tags=integration -v ./internal/... -count=1

e2e: env
	@set -eu; \
	trap 'docker compose --profile test --profile e2e rm -sf e2e_app test_migrations test_db >/dev/null 2>&1 || true' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	docker compose --profile test --profile e2e up -d --build --wait e2e_app; \
	n=0; \
	until [ "$$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/info/invalid)" = '400' ]; do \
		n=$$((n + 1)); \
		[ $$n -lt 30 ] || { echo 'E2E application did not become ready'; exit 1; }; \
		sleep 1; \
	done; \
	E2E_BASE_URL=http://127.0.0.1:8081 go test -tags=e2e -v ./tests/e2e -count=1
