
.PHONY: up down test integration e2e logs cert env

up: env cert
	docker compose up -d --build --wait nginx
	@echo "API: https://localhost/info/{md5}"
	@echo "Scanner: https://localhost/scans"
	@echo "Logs: make logs"

down:
	docker compose --profile test --profile e2e down

logs:
	docker compose logs -f nginx app_api scanner clamav

cert:
	@set -eu; \
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
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example"; \
	fi

test:
	go test ./contracts/... ./scanner/... ./threat_api/... -count=1

integration: env
	@set -eu; \
	set -a; . ./.env; set +a; \
	: "$${TEST_DB_URL:?TEST_DB_URL is not set}"; \
	trap 'docker compose --profile test --profile e2e rm -sf test_migrations test_db >/dev/null 2>&1 || true' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	docker compose --profile test up -d --wait test_db; \
	docker compose --profile test run --rm test_migrations; \
	(cd threat_api && go test -tags=integration -v ./internal/... -count=1)

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
	(cd threat_api && E2E_BASE_URL=http://127.0.0.1:8081 go test -tags=e2e -v ./tests/e2e -count=1)
