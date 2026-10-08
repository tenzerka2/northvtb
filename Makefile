.PHONY: test fmt vet build schema-test migrate

test:
	go test -race -count=1 ./...
fmt:
	gofmt -w cmd internal
vet:
	go vet ./...
build:
	go build ./cmd/north
migrate:
	psql -X -v ON_ERROR_STOP=1 -f migrations/apply.sql
schema-test: migrate
	psql -X -v ON_ERROR_STOP=1 -f migrations/apply.sql
	psql -X -v ON_ERROR_STOP=1 -f tests/schema.sql

.PHONY: demo contract
demo:
	python3 scripts/dev_init.py
	docker compose up --build -d --wait --wait-timeout 120
	python3 scripts/demo.py
contract:
	go run ./cmd/openapi > api/openapi.json
