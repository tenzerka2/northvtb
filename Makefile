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
